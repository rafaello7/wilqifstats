#include <stdio.h>
#include <arpa/inet.h>
#include <memory.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "wilqifstats.h"
#include "wlqifcapture.h"
#include "wlqconfig.h"
#include <errno.h>
#include <dirent.h>

typedef struct {
    char *ifaceName;
    ipv4_statistics *v4stats;
    int v4statCount;
    ipv6_statistics *v6stats;
    int v6statCount;
    unsigned unsavedBytes;
} IfaceStats;

typedef struct {
    IfaceStats *ifaceStats;
    int ifaceCount;
    unsigned statHour;
} WilqStats;


static void loadStats(WilqStats *wstats)
{
    char fname[40];
    DIR *dp;
    FILE *fp;
    time_t curTm = time(NULL);
    struct dirent *de;
    IfaceStats *ifaceStats;
    const char *statsDir = wlqconf_getStatsDir();

    wstats->ifaceStats = NULL;
    wstats->ifaceCount = 0;
    wstats->statHour = curTm / 3600;
    if( (dp = opendir(statsDir)) == NULL ) {
        fprintf(stderr, "unable to open stats dir %s: %s\n",
                statsDir, strerror(errno));
        exit(1);
    }
    while( (de = readdir(dp)) != NULL ) {
        if( de->d_name[0] == '.' || de->d_type != DT_DIR )
            continue;
        sprintf(fname, "%s/%s/%u", statsDir, de->d_name, wstats->statHour);
        if( (fp = fopen(fname, "r")) == NULL ) {
            if( errno == ENOENT )
                continue;
            fprintf(stderr, "unable to open %s for reading: %s\n",
                    fname, strerror(errno));
            exit(1);
        }
        wstats->ifaceStats = realloc(wstats->ifaceStats,
                ++wstats->ifaceCount * sizeof(IfaceStats));
        ifaceStats = wstats->ifaceStats + wstats->ifaceCount - 1;
        ifaceStats->ifaceName = strdup(de->d_name);
        ifaceStats->v4stats = NULL;
        ifaceStats->v4statCount = 0;
        ifaceStats->v6stats = NULL;
        ifaceStats->v6statCount = 0;
        ifaceStats->unsavedBytes = 0;
        int rd;
        while( 1 ) {
            ifaceStats->v4stats = realloc(ifaceStats->v4stats,
                    (ifaceStats->v4statCount + 1) *
                    sizeof(ipv4_statistics));
            rd = fread(ifaceStats->v4stats + ifaceStats->v4statCount,
                    sizeof(ipv4_statistics), 1, fp);
            if( rd < 1 ||
                    ifaceStats->v4stats[ifaceStats->v4statCount].nbytes == 0)
                break;
            ++ifaceStats->v4statCount;
        }
        while( rd == 1 ) {
            ifaceStats->v6stats = realloc(ifaceStats->v6stats,
                    (ifaceStats->v6statCount + 1) *
                    sizeof(ipv6_statistics));
            rd = fread(ifaceStats->v6stats + ifaceStats->v6statCount,
                    sizeof(ipv6_statistics), 1, fp);
            if( rd == 1 )
                ++ifaceStats->v6statCount;
        }
        if( rd < 0 ) {
            fprintf(stderr, "%s read error: %s\n",
                    fname, strerror(errno));
            exit(1);
        }
        fclose(fp);
    }
    closedir(dp);
}

static void saveIfaceStats(IfaceStats *ifaceStats, unsigned statHour,
        int clearStats)
{
    char fname[100];
    FILE *fp;
    const char *statsDir = wlqconf_getStatsDir();

    sprintf(fname, "%s/%s/%u", statsDir,
            ifaceStats->ifaceName, statHour);
    if( (fp = fopen(fname, "w")) == NULL ) {
        if( errno == ENOENT ) {
            char dname[100];
            sprintf(dname, "%s/%s", statsDir, ifaceStats->ifaceName);
            if( mkdir(dname, 0755) != 0 && errno != EEXIST ) {
                fprintf(stderr, "unable to create directory %s: %s\n",
                        dname, strerror(errno));
                exit(1);
            }
            fp = fopen(fname, "w");
        }
        if( fp == NULL ) {
            fprintf(stderr, "unable to open %s for writing: %s\n",
                    fname, strerror(errno));
            exit(1);
        }
    }
    fwrite(ifaceStats->v4stats, sizeof(ipv4_statistics),
            ifaceStats->v4statCount, fp);
    if( ifaceStats->v6statCount > 0 ) {
        ipv4_statistics endstat;
        memset(&endstat, 0, sizeof(endstat));
        fwrite(&endstat, sizeof(ipv4_statistics), 1, fp);
        fwrite(ifaceStats->v6stats, sizeof(ipv6_statistics),
                ifaceStats->v6statCount, fp);
    }
    fclose(fp);
    if( clearStats ) {
        free(ifaceStats->v4stats);
        ifaceStats->v4stats = NULL;
        ifaceStats->v4statCount = 0;
        free(ifaceStats->v6stats);
        ifaceStats->v6stats = NULL;
        ifaceStats->v6statCount = 0;
    }
    ifaceStats->unsavedBytes = 0;
}

static void saveStats(WilqStats *wstats, int clearStats)
{
    int i;

    for(i = 0; i < wstats->ifaceCount; ++i) {
        IfaceStats *ifaceStats = wstats->ifaceStats + i;
        if( ifaceStats->unsavedBytes == 0 )
            continue;
        saveIfaceStats(ifaceStats, wstats->statHour, clearStats);
    }
}

static void ipv4PacketHandler(const char *ifaceName,
        struct in_addr src, struct in_addr dst,
        unsigned pktlen, PacketDirection pd, void *handlerParam)
{
    int i;
    struct in_addr local, remote;
    time_t curTm = time(NULL);
    WilqStats *wstats = handlerParam;
    IfaceStats *ifaceStats;

    unsigned curHour = curTm / 3600;
    if( curHour != wstats->statHour ) {
        saveStats(wstats, 1);
        wstats->statHour = curHour;
    }
    if( pd == PD_LOCAL_TO_REMOTE ) {
        local = src;
        remote = dst;
    }else{
        local = dst;
        remote = src;
    }
    for(i = 0; i < wstats->ifaceCount
            && strcmp(wstats->ifaceStats[i].ifaceName, ifaceName); ++i)
        ;
    if( i == wstats->ifaceCount ) {
        wstats->ifaceStats = realloc(wstats->ifaceStats,
                ++wstats->ifaceCount * sizeof(IfaceStats));
        memset(wstats->ifaceStats + i, 0, sizeof(IfaceStats));
        wstats->ifaceStats[i].ifaceName = strdup(ifaceName);
    }
    ifaceStats = wstats->ifaceStats + i;
    for(i = 0; i < ifaceStats->v4statCount; ++i) {
        if( !memcmp(&ifaceStats->v4stats[i].local, &local.s_addr, 4) &&
                !memcmp(&ifaceStats->v4stats[i].remote, &remote.s_addr, 4) )
            break;
    }
    if( i == ifaceStats->v4statCount ) {
        ++ifaceStats->v4statCount;
        ifaceStats->v4stats = realloc(ifaceStats->v4stats,
                ifaceStats->v4statCount * sizeof(ipv4_statistics));
        ifaceStats->v4stats[i].local = local.s_addr;
        ifaceStats->v4stats[i].remote = remote.s_addr;
        ifaceStats->v4stats[i].nbytes = 0;
    }
    ifaceStats->v4stats[i].nbytes += pktlen;
    ifaceStats->unsavedBytes += pktlen;
    if( ifaceStats->unsavedBytes >= 50 * 1024 * 1024 )
        saveIfaceStats(ifaceStats, curHour, 0);
}

void ipv6PacketHandler(const char *ifaceName, const struct in6_addr *src,
    const struct in6_addr *dst, unsigned pktlen, PacketDirection pd,
    void *handlerParam)
{
    int i;
    const struct in6_addr *local, *remote;
    time_t curTm = time(NULL);
    WilqStats *wstats = handlerParam;
    IfaceStats *ifaceStats;

    unsigned curHour = curTm / 3600;
    if( curHour != wstats->statHour ) {
        saveStats(wstats, 1);
        wstats->statHour = curHour;
    }
    if( pd == PD_LOCAL_TO_REMOTE ) {
        local = src;
        remote = dst;
    }else{
        local = dst;
        remote = src;
    }
    for(i = 0; i < wstats->ifaceCount
            && strcmp(wstats->ifaceStats[i].ifaceName, ifaceName); ++i)
        ;
    if( i == wstats->ifaceCount ) {
        wstats->ifaceStats = realloc(wstats->ifaceStats,
                ++wstats->ifaceCount * sizeof(IfaceStats));
        memset(wstats->ifaceStats + i, 0, sizeof(IfaceStats));
        wstats->ifaceStats[i].ifaceName = strdup(ifaceName);
    }
    ifaceStats = wstats->ifaceStats + i;
    for(i = 0; i < ifaceStats->v6statCount; ++i) {
        if( !memcmp(ifaceStats->v6stats[i].local.s6_addr, local->s6_addr, 16) &&
            !memcmp(ifaceStats->v6stats[i].remote.s6_addr, remote->s6_addr, 16))
            break;
    }
    if( i == ifaceStats->v6statCount ) {
        ++ifaceStats->v6statCount;
        ifaceStats->v6stats = realloc(ifaceStats->v6stats,
                ifaceStats->v6statCount * sizeof(ipv6_statistics));
        ifaceStats->v6stats[i].local = *local;
        ifaceStats->v6stats[i].remote = *remote;
        ifaceStats->v6stats[i].nbytes = 0;
    }
    ifaceStats->v6stats[i].nbytes += pktlen;
    ifaceStats->unsavedBytes += pktlen;
    if( ifaceStats->unsavedBytes >= 50 * 1024 * 1024 )
        saveIfaceStats(ifaceStats, curHour, 0);
}

static WilqStats *gWstats;

static void capture_finish(int sig)
{
    saveStats(gWstats, 0);
    printf("exiting...\n");
    exit(0);
}

static void capture_dump(int sig)
{
    saveStats(gWstats, 0);
}

int main(int argc, char *argv[])
{
    WilqStats stats;
    const char *statsDir;

    wlqconf_read();
    wlqconf_createStatsDir();
    statsDir = wlqconf_getStatsDir();
    if( mkdir(statsDir, 0755) == 0 ) {
        if( chown(statsDir, 1000, 1000) != 0 )
            fprintf(stderr, "chown(%s): %s\n", statsDir, strerror(errno));
    }
    loadStats(&stats);
    fflush(stdout);
    gWstats = &stats;
    struct sigaction sa;
    sa.sa_handler = capture_finish;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = capture_dump;
    sigaction(SIGHUP, &sa, NULL);
    wlqifcap_loop(wlqconf_getInterfaces(), wlqconf_getLocalNet(),
            ipv4PacketHandler, ipv6PacketHandler, &stats);
    return 0;
}
