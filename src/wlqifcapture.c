#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include "wlqifcapture.h"
#include "wlqconfig.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>


#define PPP_ADDRESS	0xff	/* The address byte value */
#define PPP_IP		0x0021	/* Raw IP */

struct vlan_8021q_header {
	u_int16_t	priority_cfi_vid;
	u_int16_t	ether_type;
};

struct LocalNet {
    int version;    /* 4 or 6 */
    union {
        struct in_addr net4;
        struct in6_addr net6;
    };
    int masklen;
};

struct PcapHandlerParam {
    const char *ifaceName;
    pcap_t *handle;
    pcap_handler pcapHandler;
    void (*ipv4handler)(const char *ifaceName, struct in_addr src,
        struct in_addr dst, unsigned pktlen, PacketDirection,
        void *handlerParam);
    void (*ipv6handler)(const char *ifaceName, const struct in6_addr *src,
        const struct in6_addr *dst, unsigned pktlen, PacketDirection,
        void *handlerParam);
    void *handlerParam;
    int selectableFd;
    struct LocalNet *localNets;
};

static void parseLocalNet(struct LocalNet *dst, const char *addr,
        int len)
{
    char *buf, *net;
    int isNet6;

    buf = malloc(len+1);
    memcpy(buf, addr, len);
    buf[len] = '\0';
    net = strchr(buf, '/');
    if( net != NULL )
        *net++ = '\0';
    isNet6 = strchr(buf, ':') != NULL;
    dst->version = isNet6 ? 6 : 4;
    if( inet_pton(isNet6 ? AF_INET6 : AF_INET, buf, &dst->net6) != 1 ) {
        fprintf(stderr, "invalid localnet address %s\n", buf);
        exit(1);
    }
    if( net != NULL ) {
        dst->masklen = atoi(net);
    }else
        dst->masklen = isNet6 ? 128 : 32;
    free(buf);
}

static int isLocalNet4(const struct PcapHandlerParam *php, struct in_addr addr)
{
    int i;
    in_addr_t mask;

    for(i = 0; i < php->localNets[i].version; ++i) {
        if( php->localNets[i].version != 4 )
            continue;
        mask = ~((1 << php->localNets[i].masklen) - 1);
        if( (php->localNets[i].net4.s_addr & mask) == (addr.s_addr & mask) )
            return 1;
    }
    return 0;
}

static int isLocalNet6(const struct PcapHandlerParam *php,
        const struct in6_addr *addr)
{
    int i, j, masklen, isEqual;

    for(i = 0; i < php->localNets[i].version; ++i) {
        if( php->localNets[i].version != 6 )
            continue;
        masklen = php->localNets[i].masklen;
        isEqual = 1;
        for(j = 0; isEqual && masklen >= 32; masklen -= 32) {
            if( php->localNets[i].net6.s6_addr32[j] != addr->s6_addr32[j] )
                isEqual = 0;
        }
        if( isEqual && masklen ) {
            uint32_t mask = ~((1 << masklen) - 1);
            if( (php->localNets[i].net6.s6_addr[j] & mask)
                    != (addr->s6_addr[j] & mask) )
                isEqual = 0;
        }
        if( isEqual )
            return 1;
    }
    return 0;
}

static void invokeIpHandler(u_char *param,
        const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
    int version = packet[0] >> 4;

    if( version == 4 ) {
        struct ip *ipPkt = (struct ip*)packet;
        PacketDirection pd;

        if( isLocalNet4(php, ipPkt->ip_src) ) {
            if( isLocalNet4(php, ipPkt->ip_dst) ) {
                printf("local packet: %s", inet_ntoa(ipPkt->ip_src));
                printf(" -> %s\n", inet_ntoa(ipPkt->ip_dst));
                fflush(stdout);
                return;
            }else{
                pd = PD_LOCAL_TO_REMOTE;
            }
        }else{
            if( isLocalNet4(php, ipPkt->ip_dst) ) {
                pd = PD_REMOTE_TO_LOCAL;
            }else{
                printf("martian: %s", inet_ntoa(ipPkt->ip_src));
                printf(" -> %s\n", inet_ntoa(ipPkt->ip_dst));
                fflush(stdout);
                return;
            }
        }
        php->ipv4handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
                ntohs(ipPkt->ip_len), pd, php->handlerParam);
    }else{
        struct ip6_hdr *ipPkt = (struct ip6_hdr*)packet;
        PacketDirection pd;
        char addrbuf[INET6_ADDRSTRLEN];

        if( isLocalNet6(php, &ipPkt->ip6_src) ) {
            if( isLocalNet6(php, &ipPkt->ip6_dst) ) {
                printf("local packet: %s", inet_ntop(AF_INET6, &ipPkt->ip6_src,
                            addrbuf, sizeof(addrbuf)));
                printf(" -> %s\n", inet_ntop(AF_INET6, &ipPkt->ip6_dst,
                            addrbuf, sizeof(addrbuf)));
                fflush(stdout);
                return;
            }else{
                pd = PD_LOCAL_TO_REMOTE;
            }
        }else{
            if( isLocalNet6(php, &ipPkt->ip6_dst) ) {
                pd = PD_REMOTE_TO_LOCAL;
            }else{
                printf("martian: %s", inet_ntop(AF_INET6, &ipPkt->ip6_src,
                            addrbuf, sizeof(addrbuf)));
                printf(" -> %s\n", inet_ntop(AF_INET6, &ipPkt->ip6_dst,
                            addrbuf, sizeof(addrbuf)));
                fflush(stdout);
                return;
            }
        }
        php->ipv6handler(php->ifaceName, &ipPkt->ip6_src, &ipPkt->ip6_dst,
                ntohs(ipPkt->ip6_plen) + 40, pd, php->handlerParam);
    }
}

static void handle_null_packet(u_char *param,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    invokeIpHandler(param, pkthdr, packet + 4);
}

static void handle_ppp_packet(u_char *param,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
	u_int caplen = pkthdr->caplen;
	u_int proto;

	if(caplen >= 4 && packet[0] == PPP_ADDRESS) {
		proto = htons(*(const uint16_t*)(packet+2));
        if(proto == PPP_IP || proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6)
            invokeIpHandler(param, pkthdr, packet + 4);
    }
}

static void handle_cooked_packet(u_char *param,
        const struct pcap_pkthdr *pkthdr, const unsigned char * packet)
{
    invokeIpHandler(param, pkthdr, packet + SLL_HDR_LEN);
}

static void handle_eth_packet(u_char *param,
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
        }else
            invokeIpHandler(param, pkthdr, payload);
    }
}

pcap_handler getPcapHandler(const char *ifaceName, pcap_t *handle)
{
    int dlt;
    pcap_handler pcapHandler;

    dlt = pcap_datalink(handle);
    if(dlt == DLT_EN10MB) {
        printf("%s: EN10MB\n", ifaceName);
        pcapHandler = handle_eth_packet;
    }else if(dlt == DLT_RAW) {
        printf("%s: RAW\n", ifaceName);
        pcapHandler = invokeIpHandler;
    }else if(dlt == DLT_NULL) {
        printf("%s: NULL\n", ifaceName);
        pcapHandler = handle_null_packet;
    }else if(dlt == DLT_LOOP) {
        printf("%s: LOOP\n", ifaceName);
        pcapHandler = handle_null_packet;
    }else if(dlt == DLT_PPP) {
        printf("%s: PPP\n", ifaceName);
        pcapHandler = handle_ppp_packet;
    }else if(dlt == DLT_LINUX_SLL) {
        printf("%s: LINUX_SLL\n", ifaceName);
        pcapHandler = handle_cooked_packet;
    }else{
        fprintf(stderr, "Unsupported datalink type for %s: %d\n",
                ifaceName, dlt);
        pcapHandler = NULL;
    }
    return pcapHandler;
}

static char *getPcapFilter(const char *localNet)
{
    char *res = NULL;
    const char *netBeg, *netEnd;
    int len, iter;

    /* localNet ex.: "192.168.1.0/24 192.168.8.0/24"
     * result: "not(src net 192.168.1.0/24 or src net 192.168.8.0/24)or "
     *         "not(dst net 192.168.1.0/24 or dst net 192.168.8.0/24)"
     */
    localNet += strspn(localNet, " \t");
    if( *localNet ) {
        res = strdup("not(");
        len = 4;
        for(iter = 0; iter < 2; ++iter) {
            netBeg = localNet;
            while( *netBeg ) {
                if( netBeg != localNet ) {
                    res = realloc(res, len + 5);
                    strcpy(res + len, " or ");
                    len += 4;
                }
                netEnd = netBeg + strcspn(netBeg, " \t");
                res = realloc(res, len + netEnd - netBeg + 9);
                strcpy(res + len, iter == 0 ? "src net " : "dst net ");
                len += 8;
                strncpy(res + len, netBeg, netEnd - netBeg);
                len += netEnd - netBeg;
                netBeg = netEnd + strspn(netEnd, " \t");
            }
            if( iter == 0 ) {
                res = realloc(res, len + 9);
                strcpy(res + len, ")or not(");
                len += 8;
            }
        }
        res = realloc(res, len + 2);
        strcpy(res + len, ")");
    }
    return res;
}

static struct LocalNet *getLocalNets(const char *localNetStr)
{
    struct LocalNet *res = NULL;
    const char *netBeg, *netEnd;
    int localNetCount = 0;

    localNetStr += strspn(localNetStr, " \t");
    if( *localNetStr ) {
        netBeg = localNetStr;
        while( *netBeg ) {
            netEnd = netBeg + strcspn(netBeg, " \t");
            res = realloc(res, (localNetCount+1) * sizeof(struct LocalNet));
            parseLocalNet(res + localNetCount, netBeg, netEnd - netBeg);
            ++localNetCount;
            netBeg = netEnd + strspn(netEnd, " \t");
        }
        res = realloc(res, (localNetCount+1) * sizeof(struct LocalNet));
        res[localNetCount].version = 0;
    }
    return res;
}

void wlqifcap_loop(const char *const *interfaces, const char *localNet,
        void (*ipv4handler)(const char *ifaceName, struct in_addr src,
            struct in_addr dst, unsigned pktlen, PacketDirection,
            void *handlerParam),
        void (*ipv6handler)(const char *ifaceName, const struct in6_addr *src,
            const struct in6_addr *dst, unsigned pktlen, PacketDirection,
            void *handlerParam),
        void *handlerParam)
{
    pcap_if_t *allDevs, *curDev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct PcapHandlerParam *handlers = NULL, *curHandler;
    int handlerCount = 0, nfds = 0;
    fd_set fds;
    char *pcapFilter;
    struct LocalNet *localNets;

    if( localNet != NULL )
        pcapFilter = getPcapFilter(localNet);
    localNets = getLocalNets(localNet);
    if( pcap_findalldevs(&allDevs, errbuf) != 0 ) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    for(curDev = allDevs; curDev != NULL; curDev = curDev->next) {
        struct pcap_addr *addr = curDev->addresses;
        int ifno, isInet = 0, selectableFd;
        pcap_handler pcapHandler;
        pcap_t *handle;

        if( interfaces ) {
            for(ifno = 0; interfaces[ifno]
                    && strcmp(interfaces[ifno], curDev->name); ++ifno)
                ;
            if( interfaces[ifno] == NULL )
                continue;
        }else if( curDev->flags & PCAP_IF_LOOPBACK )
            continue;
        for(addr = curDev->addresses; !isInet && addr; addr = addr->next) {
            if( addr->addr->sa_family == AF_INET ||
                    addr->addr->sa_family == AF_INET6 )
                isInet = 1;
        }
        if( ! isInet )
            continue;
        handle = pcap_open_live(curDev->name, 256, 0, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "%s\n", errbuf);
            continue;
        }
        pcapHandler = getPcapHandler(curDev->name, handle);
        if( pcapHandler == NULL ) {
            pcap_close(handle);
            continue;
        }
        if( pcap_setnonblock(handle, 1, errbuf) == -1 ) {
            fprintf(stderr, "pcap_setnonblock(%s): %s\n", curDev->name, errbuf);
            pcap_close(handle);
            continue;
        }
        selectableFd = pcap_get_selectable_fd(handle);
        if( selectableFd == -1 ) {
            fprintf(stderr, "%s is not capable to use select()\n",
                    curDev->name);
            pcap_close(handle);
            continue;
        }
        if( pcapFilter != NULL ) {
            struct bpf_program bfpprog;
            bpf_u_int32 net, mask;

            if(pcap_lookupnet(curDev->name, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "WARN: can't get netmask for device %s\n",
                        curDev->name);
                net = PCAP_NETMASK_UNKNOWN;
            }
            if( pcap_compile(handle, &bfpprog, pcapFilter, 1, net) != -1) {
                if( pcap_setfilter(handle, &bfpprog) == -1 ) {
                    fprintf(stderr, "WARN: couldn't install filter: %s\n",
                            pcap_geterr(handle));
                }
                pcap_freecode(&bfpprog);
            }else{
                fprintf(stderr, "WARN: couldn't parse filter: %s\n",
                        pcap_geterr(handle));
            }
        }
        handlers = realloc(handlers,
                ++handlerCount * sizeof(struct PcapHandlerParam));
        curHandler = handlers + handlerCount - 1;
        curHandler->ifaceName = strdup(curDev->name);
        curHandler->handle = handle;
        curHandler->pcapHandler = pcapHandler;
        curHandler->ipv4handler = ipv4handler;
        curHandler->ipv6handler = ipv6handler;
        curHandler->handlerParam = handlerParam;
        curHandler->selectableFd = selectableFd;
        if( selectableFd >= nfds )
            nfds = selectableFd + 1;
        curHandler->localNets = localNets;
    }
    pcap_freealldevs(allDevs);
    free(pcapFilter);
    wlqconf_switchToTargetUser();
    FD_ZERO(&fds);
    while( 1 ) {
        int i;
        for(i = 0; i < handlerCount; ++i)
            FD_SET(handlers[i].selectableFd, &fds);
        while( select(nfds, &fds, NULL, NULL, NULL) < 0 ) {
            if( errno != EINTR ) {
                perror("select");
                exit(1);
            }
        }
        for(i = 0; i < handlerCount; ++i) {
            curHandler = handlers + i;
            if( FD_ISSET(curHandler->selectableFd, &fds) ) {
                pcap_dispatch(curHandler->handle, -1, curHandler->pcapHandler,
                        (void*)curHandler);
            }
        }
    }
}

