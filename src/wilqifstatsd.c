#include <pcap.h>
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
#include <errno.h>
#include <dirent.h>

static const char WLQSTATSDIR[] = "/var/lib/wilqifstats";

typedef struct {
    char *ifaceName;
    ip_statistics *stats;
    int statCount;
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

    wstats->ifaceStats = NULL;
    wstats->ifaceCount = 0;
    wstats->statHour = curTm / 3600;
    if( (dp = opendir(WLQSTATSDIR)) == NULL ) {
        fprintf(stderr, "unable to open stats dir %s: %s\n",
                WLQSTATSDIR, strerror(errno));
        exit(1);
    }
    while( (de = readdir(dp)) != NULL ) {
        if( de->d_name[0] == '.' || de->d_type != DT_DIR )
            continue;
        sprintf(fname, "%s/%s/%u", WLQSTATSDIR, de->d_name, wstats->statHour);
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
        ifaceStats->stats = NULL;
        ifaceStats->statCount = 0;
        ifaceStats->unsavedBytes = 0;
        while( 1 ) {
            ifaceStats->stats = realloc(ifaceStats->stats,
                    (ifaceStats->statCount + 16) * sizeof(ip_statistics));
            int rd = fread(ifaceStats->stats + ifaceStats->statCount,
                    sizeof(ip_statistics), 16, fp);
            if( rd < 0 ) {
                fprintf(stderr, "%s read error: %s\n",
                        fname, strerror(errno));
                exit(1);
            }
            ifaceStats->statCount += rd;
            if( rd < 16 )
                break;
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

    sprintf(fname, "%s/%s/%u", WLQSTATSDIR,
            ifaceStats->ifaceName, statHour);
    if( (fp = fopen(fname, "w")) == NULL ) {
        if( errno == ENOENT ) {
            char dname[100];
            sprintf(dname, "%s/%s", WLQSTATSDIR, ifaceStats->ifaceName);
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
    fwrite(ifaceStats->stats, sizeof(ip_statistics),
            ifaceStats->statCount, fp);
    fclose(fp);
    if( clearStats ) {
        free(ifaceStats->stats);
        ifaceStats->stats = NULL;
        ifaceStats->statCount = 0;
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

static void packetHandler(const char *ifaceName,
        struct in_addr src, struct in_addr dst,
        unsigned pktlen, void *handlerParam)
{
    int i;
    struct in_addr local, remote;
    unsigned char localnet[2] = { 192, 168 };
    time_t curTm = time(NULL);
    WilqStats *wstats = handlerParam;
    IfaceStats *ifaceStats;

    unsigned curHour = curTm / 3600;
    if( curHour != wstats->statHour ) {
        saveStats(wstats, 1);
        wstats->statHour = curHour;
    }
    if( ! memcmp(&src.s_addr, localnet, 2) ) {
        if( ! memcmp(&dst.s_addr, localnet, 2) ) {
            printf("local packet: %s", inet_ntoa(src));
            printf(" -> %s\n", inet_ntoa(dst));
            fflush(stdout);
            return;
        }
        local = src;
        remote = dst;
    }else{
        if( memcmp(&dst.s_addr, localnet, 2) ) {
            printf("martian: %s", inet_ntoa(src));
            printf(" -> %s\n", inet_ntoa(dst));
            fflush(stdout);
            return;
        }
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
    for(i = 0; i < ifaceStats->statCount; ++i) {
        if( !memcmp(&ifaceStats->stats[i].local, &local.s_addr, 4) &&
                !memcmp(&ifaceStats->stats[i].remote, &remote.s_addr, 4) )
            break;
    }
    if( i == ifaceStats->statCount ) {
        ++ifaceStats->statCount;
        ifaceStats->stats = realloc(ifaceStats->stats,
                ifaceStats->statCount * sizeof(ip_statistics));
        ifaceStats->stats[i].local = local.s_addr;
        ifaceStats->stats[i].remote = remote.s_addr;
        ifaceStats->stats[i].nbytes = 0;
    }
    ifaceStats->stats[i].nbytes += pktlen;
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
    const char *dev = argc == 1 ? "eth0" : argv[1];
    WilqStats stats;

    if( mkdir(WLQSTATSDIR, 0755) == 0 ) {
        if( chown(WLQSTATSDIR, 1000, 1000) != 0 )
            fprintf(stderr, "chown(%s): %s\n", WLQSTATSDIR, strerror(errno));
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
    wlqifcap_loop(NULL, "not src net 192.168 or not dst net 192.168",
            packetHandler, &stats);
    return 0;
}
