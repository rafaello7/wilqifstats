#ifndef WLQIFCAPTURE_H
#define WLQIFCAPTURE_H

void wlqifcap_loop(const char *const *interfaces, const char *filter,
        void (*ipv4handler)(const char *ifaceName, struct in_addr src,
            struct in_addr dst, unsigned pktlen, void *handlerParam),
        void (*ipv6handler)(const char *ifaceName, const struct in6_addr *src,
            const struct in6_addr *dst, unsigned pktlen, void *handlerParam),
        void *handlerParam);

#endif /* WLQIFCAPTURE_H */
