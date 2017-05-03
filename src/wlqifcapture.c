#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include "wlqifcapture.h"
#include "wlqconfig.h"
#include <netinet/ip.h>
#include <net/ethernet.h>
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

struct PcapHandlerParam {
    const char *ifaceName;
    pcap_t *handle;
    pcap_handler pcapHandler;
    void (*handler)(const char *ifaceName, struct in_addr src,
        struct in_addr dst, unsigned pktlen, void *handlerParam);
    void *handlerParam;
    int selectableFd;
};

static void handle_raw_packet(u_char *param,
        const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
    struct ip *ipPkt = (struct ip*)packet;

    php->handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
            ntohs(ipPkt->ip_len), php->handlerParam);
}

static void handle_null_packet(u_char *param,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
    struct ip *ipPkt = (struct ip*)(packet + 4);

    php->handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
            ntohs(ipPkt->ip_len), php->handlerParam);
}

static void handle_ppp_packet(u_char *param,
        const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
	u_int caplen = pkthdr->caplen;
	u_int proto;

	if(caplen >= 4 && packet[0] == PPP_ADDRESS) {
		proto = htons(*(const uint16_t*)(packet+2));
        if(proto == PPP_IP || proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6)
        {
            struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
            struct ip *ipPkt = (struct ip*)(packet + 4);

            php->handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
                    ntohs(ipPkt->ip_len), php->handlerParam);
        }
    }
}

static void handle_cooked_packet(u_char *param,
        const struct pcap_pkthdr * thdr, const unsigned char * packet)
{
    struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
    struct ip *ipPkt = (struct ip*)(packet + SLL_HDR_LEN);

    php->handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
            ntohs(ipPkt->ip_len),
            php->handlerParam);
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
        }else{
            struct PcapHandlerParam *php = (struct PcapHandlerParam*)param;
            struct ip *ipPkt = (struct ip*)(payload);

            php->handler(php->ifaceName, ipPkt->ip_src, ipPkt->ip_dst,
                    ntohs(ipPkt->ip_len), php->handlerParam);
        }
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
        pcapHandler = handle_raw_packet;
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

void wlqifcap_loop(const char *const *interfaces, const char *filter,
        void (*handler)(const char *ifaceName, struct in_addr src,
            struct in_addr dst, unsigned pktlen, void *handlerParam),
        void *handlerParam)
{
    pcap_if_t *allDevs, *curDev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct PcapHandlerParam *handlers = NULL, *curHandler;
    int handlerCount = 0, nfds = 0;
    fd_set fds;

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
        if( filter != NULL ) {
            struct bpf_program bfpprog;
            bpf_u_int32 net, mask;

            if(pcap_lookupnet(curDev->name, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "WARN: can't get netmask for device %s\n",
                        curDev->name);
                net = PCAP_NETMASK_UNKNOWN;
            }
            if( pcap_compile(handle, &bfpprog, filter, 1, net) != -1 ) {
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
        curHandler->handler = handler;
        curHandler->handlerParam = handlerParam;
        curHandler->selectableFd = selectableFd;
        if( selectableFd >= nfds )
            nfds = selectableFd + 1;
    }
    pcap_freealldevs(allDevs);
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

