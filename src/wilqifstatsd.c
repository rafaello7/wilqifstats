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

static const char WLQSTATSDIR[] = "/var/lib/wilqifstats";

static ip_statistics *gStats = NULL;
static int gStatCnt = 0;
unsigned statHour = 0;

static void loadStats(void)
{
    char fname[40];
    FILE *fp;
    time_t curTm = time(NULL);

    statHour = curTm / 3600;
    sprintf(fname, "%s/%u", WLQSTATSDIR, statHour);
    if( (fp = fopen(fname, "r")) == NULL ) {
        if( errno == ENOENT )
            return;
        fprintf(stderr, "unable to open %s for reading: %s\n",
                fname, strerror(errno));
        exit(1);
    }
    while( 1 ) {
        gStats = realloc(gStats, (gStatCnt + 16) * sizeof(ip_statistics));
        int rd = fread(gStats + gStatCnt, sizeof(ip_statistics),
                16, fp);
        if( rd < 0 ) {
            fprintf(stderr, "%s read error: %s\n",
                    fname, strerror(errno));
            exit(1);
        }
        gStatCnt += rd;
        if( rd < 16 )
            break;
    }
    fclose(fp);
    printf("%d stats loaded from hour %u\n", gStatCnt, statHour);
}

static void dumpStats(void)
{
    char fname[40];
    FILE *fp;

    if( gStatCnt == 0 )
        return;
    sprintf(fname, "%s/%u", WLQSTATSDIR, statHour);
    if( (fp = fopen(fname, "w")) == NULL ) {
        fprintf(stderr, "unable to open %s for writing: %s\n",
                fname, strerror(errno));
        exit(1);
    }
    fwrite(gStats, sizeof(ip_statistics), gStatCnt, fp);
    fclose(fp);
}

static void packetHandler(const char *ifaceName,
        struct in_addr src, struct in_addr dst,
        unsigned pktlen, void *handlerParam)
{
    static unsigned unsavedBytes = 0;
    int i;
    struct in_addr local, remote;
    unsigned char localnet[2] = { 192, 168 };
    time_t curTm = time(NULL);

    unsigned curHour = curTm / 3600;
    if( curHour != statHour ) {
        dumpStats();
        free(gStats);
        gStats = NULL;
        gStatCnt = 0;
        statHour = curHour;
        unsavedBytes = 0;
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
    for(i = 0; i < gStatCnt; ++i) {
        if( !memcmp(&gStats[i].local, &local.s_addr, 4) &&
                !memcmp(&gStats[i].remote, &remote.s_addr, 4) )
            break;
    }
    if( i == gStatCnt ) {
        ++gStatCnt;
        gStats = realloc(gStats, gStatCnt * sizeof(ip_statistics));
        gStats[i].local = local.s_addr;
        gStats[i].remote = remote.s_addr;
        gStats[i].nbytes = 0;
    }
    gStats[i].nbytes += pktlen;
    //printf("local: %s", inet_ntoa(local));
    //printf("  remote: %s", inet_ntoa(remote));
    //printf("  [%d]\n", htons(iptr->ip_len));
    unsavedBytes += pktlen;
    if( unsavedBytes >= 50 * 1024 * 1024 ) {
        dumpStats();
        unsavedBytes = 0;
    }
}

static void capture_finish(int sig)
{
    dumpStats();
    printf("exiting...\n");
    exit(0);
}

static void capture_dump(int sig)
{
    dumpStats();
}

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    const char *dev = argc == 1 ? "eth0" : argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    int dlt;
    int i = 0;
    pcap_handler packet_handler;
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if( mkdir(WLQSTATSDIR, 0755) == 0 ) {
        if( chown(WLQSTATSDIR, 1000, 1000) != 0 )
            fprintf(stderr, "chown(%s): %s\n", WLQSTATSDIR, strerror(errno));
    }
    loadStats();
    fflush(stdout);
    struct sigaction sa;
    sa.sa_handler = capture_finish;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = capture_dump;
    sigaction(SIGHUP, &sa, NULL);
    wlqifcap_loop(NULL, "not src net 192.168 or not dst net 192.168",
            packetHandler, NULL);
    return 0;
}
