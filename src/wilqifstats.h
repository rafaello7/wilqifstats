#ifndef WILQIFSTATS_H
#define WILQIFSTATS_H

typedef struct {
    in_addr_t local;
    in_addr_t remote;
    unsigned long long nbytes;
} ip_statistics;

#endif /* WILQIFSTATS_H */
