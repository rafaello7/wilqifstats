#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/sll.h>
#include <net/ethernet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <memory.h>
#include <malloc.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "wilqifstats.h"
#include <errno.h>

#define PPP_ADDRESS	0xff	/* The address byte value */
#define PPP_IP		0x0021	/* Raw IP */

struct vlan_8021q_header {
	u_int16_t	priority_cfi_vid;
	u_int16_t	ether_type;
};

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

static void handle_ip_packet(struct ip* iptr)
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
    if( ! memcmp(&iptr->ip_src.s_addr, localnet, 2) ) {
        if( ! memcmp(&iptr->ip_dst.s_addr, localnet, 2) ) {
            printf("local packet: %s", inet_ntoa(iptr->ip_src));
            printf(" -> %s\n", inet_ntoa(iptr->ip_dst));
            fflush(stdout);
            return;
        }
        local = iptr->ip_src;
        remote = iptr->ip_dst;
    }else{
        if( memcmp(&iptr->ip_dst.s_addr, localnet, 2) ) {
            printf("martian: %s", inet_ntoa(iptr->ip_src));
            printf(" -> %s\n", inet_ntoa(iptr->ip_dst));
            fflush(stdout);
            return;
        }
        local = iptr->ip_dst;
        remote = iptr->ip_src;
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
    unsigned bytes = htons(iptr->ip_len);
    gStats[i].nbytes += bytes;
    //printf("local: %s", inet_ntoa(local));
    //printf("  remote: %s", inet_ntoa(remote));
    //printf("  [%d]\n", htons(iptr->ip_len));
    unsavedBytes += bytes;
    if( unsavedBytes >= 50 * 1024 * 1024 ) {
        dumpStats();
        unsavedBytes = 0;
    }
}

static void handle_raw_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    handle_ip_packet((struct ip*)packet);
}

static void handle_null_packet(unsigned char* args,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    handle_ip_packet((struct ip*)(packet + 4));
}

static void handle_ppp_packet(unsigned char* args,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
	register u_int length = pkthdr->len;
	register u_int caplen = pkthdr->caplen;
	u_int proto;

	if (caplen < 2) 
        return;

	if(packet[0] == PPP_ADDRESS) {
		if (caplen < 4) 
            return;

		packet += 2;
		length -= 2;

		proto = htons(*(const uint16_t*)packet);
		packet += 2;
		length -= 2;

        if(proto == PPP_IP || proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6) {
            handle_ip_packet((struct ip*)packet);
        }
    }
}

static void handle_cooked_packet(unsigned char *args, const struct pcap_pkthdr * thdr, const unsigned char * packet)
{
    handle_ip_packet((struct ip*)(packet+SLL_HDR_LEN));
}

static void handle_eth_packet(unsigned char* args,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    struct ether_header *eptr;
    int ether_type;
    const unsigned char *payload;

    eptr = (struct ether_header*)packet;
    ether_type = ntohs(eptr->ether_type);
    payload = packet + sizeof(struct ether_header);
    if(ether_type == ETH_P_8021Q) {
        struct vlan_8021q_header* vptr;
        vptr = (struct vlan_8021q_header*)payload;
        ether_type = ntohs(vptr->ether_type);
        payload += sizeof(struct vlan_8021q_header);
    }

    if(ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6) {
        struct ip* iptr;
        
        if( memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", eptr->ether_dhost, 6) == 0) {
            //printf("broadcast\n");
        }else if( !memcmp("\x1\x0\x5e\x0\x0\xfb", eptr->ether_dhost, 6)) {
            //printf("mDNS multicast\n");
        }else{
            iptr = (struct ip*)(payload); /* alignment? */
            handle_ip_packet(iptr);
        }
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

    handle = pcap_open_live(dev, 256, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    mkdir(WLQSTATSDIR, 0755);
    chown(WLQSTATSDIR, 1000, 1000);
    setuid(1000);
    setgid(1000);
    dlt = pcap_datalink(handle);
    if(dlt == DLT_EN10MB) {
        printf("link: EN10MB\n");
        packet_handler = handle_eth_packet;
    }else if(dlt == DLT_RAW) {
        printf("link: RAW\n");
        packet_handler = handle_raw_packet;
    }else if(dlt == DLT_NULL) {
        printf("link: NULL\n");
        packet_handler = handle_null_packet;
    }else if(dlt == DLT_LOOP) {
        printf("link: LOOP\n");
        packet_handler = handle_null_packet;
    }else if(dlt == DLT_PPP) {
        printf("link: PPP\n");
        packet_handler = handle_ppp_packet;
    }else if(dlt == DLT_LINUX_SLL) {
        printf("link: LINUX_SLL\n");
        packet_handler = handle_cooked_packet;
    }else{
        fprintf(stderr, "Unsupported datalink type: %d\n", dlt);
        return 1;
    }
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    if( pcap_compile(handle, &fp, "not src net 192.168 or not dst net 192.168",
                1, net) == -1 )
    {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if( pcap_setfilter(handle, &fp) == -1 ) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 1;
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
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
