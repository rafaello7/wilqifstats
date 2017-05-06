#ifndef WILQIFSTATS_H
#define WILQIFSTATS_H

/* Structures used in statistics file.
 * The file consists of ipv4_statistics structures followed by
 * (optionally) ipv6_statistics structures. If the file contains any
 * ipv6_statistics structures, the last ipv4_statistics structure
 * has nbytes value set to 0.
 */

typedef struct {
    in_addr_t local;
    in_addr_t remote;
    unsigned long long nbytes;
} ipv4_statistics;

typedef struct {
    struct in6_addr local;
    struct in6_addr remote;
    unsigned long long nbytes;
} ipv6_statistics;

#endif /* WILQIFSTATS_H */
