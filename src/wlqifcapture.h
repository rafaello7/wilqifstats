#ifndef WLQIFCAPTURE_H
#define WLQIFCAPTURE_H

void wlqifcap_loop(const char *interfaces, const char *filter,
        void (*handler)(const char *ifaceName, struct in_addr src,
            struct in_addr dst, unsigned pktlen, void *handlerParam),
        void *handlerParam);

#endif /* WLQIFCAPTURE_H */
