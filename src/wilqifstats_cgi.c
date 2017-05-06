#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "wilqifstats.h"
#include "wlqconfig.h"
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


struct InetAddress {
    int version;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    };
};

struct IpStatistics {
    struct InetAddress remote;
    struct InetAddress local;
    unsigned long long nbytes;
};

typedef struct {
    struct InetAddress remote;
    unsigned long long nbytes;
} HostStat;

typedef struct {
    struct InetAddress host;
    unsigned long long nbytes;
} MonthlyStatByHost;

typedef struct {
    struct InetAddress host;
    unsigned long long nbytes;
    struct {
        unsigned long long nbytes;
        HostStat *hosts;
        int hostCount;
    } hourlyStat[24];
} DailyStatByHost;

typedef struct {
    int year;
    int month;  /* 1 .. 12 */
    unsigned long long nbytes;
    struct {
        unsigned long long nbytes;
        DailyStatByHost *hosts;
        int hostCount;
    } dailyStat[31];
    MonthlyStatByHost *hosts;
    int hostCount;
} MonthlyStat;

typedef struct {
    char *ifaceName;
    MonthlyStat *stats;
    int statCount;
} IfaceStat;

static int isAddrEq(const struct InetAddress *addr1,
        const struct InetAddress *addr2)
{
    int res;

    if( addr1->version != addr2->version )
        res = 0;
    else if( addr1->version == 4 ) {
        res = addr1->v4.s_addr == addr2->v4.s_addr;
    }else{
        res = !memcmp(addr1->v6.s6_addr, addr2->v6.s6_addr, 16);
    }
    return res;
}

static int readStatsFromFile(FILE *fp, int isInet6, struct IpStatistics *stats)
{
    int rd;

    if( isInet6 ) {
        ipv6_statistics v6stats;
        if( (rd = fread(&v6stats, sizeof(v6stats), 1, fp)) == 1 ) {
            stats->remote.version = 6;
            memcpy(stats->remote.v6.s6_addr, v6stats.remote.s6_addr, 16);
            stats->local.version = 6;
            memcpy(stats->local.v6.s6_addr, v6stats.local.s6_addr, 16);
            stats->nbytes = v6stats.nbytes;
        }
    }else{
        ipv4_statistics v4stats;

        if( (rd = fread(&v4stats, sizeof(v4stats), 1, fp)) == 1 ) {
            stats->remote.version = 4;
            memcpy(&stats->remote.v4.s_addr, &v4stats.remote, 4);
            stats->local.version = 4;
            memcpy(&stats->local.v4.s_addr, &v4stats.local, 4);
            stats->nbytes = v4stats.nbytes;
        }
    }
    return rd;
}

static void loadIfaceStats(const char *ifaceName, IfaceStat *ifaceStat)
{
    DIR *dp;
    const struct dirent *de;
    char dname[100], fname[120], *endp;
    unsigned hour;
    FILE *fp;
    struct IpStatistics stats;
    MonthlyStat *mstats = NULL;
    int rd, statCount = 0;

    sprintf(dname, "%s/%s", wlqconf_getStatsDir(), ifaceName);
    dp = opendir(dname);
    if( dp != NULL ) {
        while( (de = readdir(dp)) != NULL ) {
            if( de->d_type != DT_REG )
                continue;
            hour = strtoul(de->d_name, &endp, 10);
            if( hour == 0 || *endp ) {
                printf("%s/%s: not a stats file, ignored\n",
                        dname, de->d_name);
                continue;
            }
            sprintf(fname, "%s/%s", dname, de->d_name);
            if( (fp = fopen(fname, "r")) == NULL ) {
                fprintf(stderr, "unable to open %s for reading: %s\n",
                        fname, strerror(errno));
                continue;
            }
            time_t tim = hour * 3600;
            struct tm *t = localtime(&tim);
            int year = t->tm_year + 1900;
            int month = t->tm_mon + 1;
            int mday = t->tm_mday;
            int dhour = t->tm_hour;
            if( mday == 1 ) {
                // 1st day is included in previous month
                if( month == 0 ) {
                    --year;
                    month = 11;
                }else{
                    --month;
                }
            }
            int msIdx = 0;
            while( msIdx < statCount && (mstats[msIdx].year > year
                    || mstats[msIdx].year == year
                        && mstats[msIdx].month > month) )
                ++msIdx;
            if( msIdx == statCount || mstats[msIdx].year < year
                    || mstats[msIdx].year == year
                        && mstats[msIdx].month < month )
            {
                mstats = realloc(mstats, (statCount+1) * sizeof(MonthlyStat));
                memmove(mstats + msIdx + 1, mstats + msIdx,
                        (statCount-msIdx) * sizeof(MonthlyStat));
                memset(mstats + msIdx, 0, sizeof(MonthlyStat));
                mstats[msIdx].year = year;
                mstats[msIdx].month = month;
                ++statCount;
            }
            MonthlyStat *ms = mstats + msIdx;
            int isInet6 = 0;
            while( (rd = readStatsFromFile(fp, isInet6, &stats)) == 1 ) {
                if( stats.nbytes == 0 ) {
                    isInet6 = 1;
                    continue;
                }
                ms->nbytes += stats.nbytes;
                ms->dailyStat[mday-1].nbytes += stats.nbytes;
                int i = 0;
                while( i < ms->hostCount
                        && !isAddrEq(&ms->hosts[i].host, &stats.local) )
                    ++i;
                if( i == ms->hostCount ) {
                    ms->hosts = realloc(ms->hosts, ++ms->hostCount *
                            sizeof(MonthlyStatByHost));
                    memset(ms->hosts + i, 0, sizeof(MonthlyStatByHost));
                    ms->hosts[i].host = stats.local;
                }
                MonthlyStatByHost *msbh = ms->hosts + i;
                msbh->nbytes += stats.nbytes;
                i = 0;
                while( i < ms->dailyStat[mday-1].hostCount &&
                        !isAddrEq(&ms->dailyStat[mday-1].hosts[i].host,
                            &stats.local) )
                    ++i;
                if( i == ms->dailyStat[mday-1].hostCount ) {
                    ms->dailyStat[mday-1].hosts =
                        realloc(ms->dailyStat[mday-1].hosts,
                            ++ms->dailyStat[mday-1].hostCount
                            * sizeof(DailyStatByHost));
                    memset(ms->dailyStat[mday-1].hosts + i, 0,
                            sizeof(DailyStatByHost));
                    ms->dailyStat[mday-1].hosts[i].host = stats.local;
                }
                DailyStatByHost *dsbh = ms->dailyStat[mday-1].hosts + i;
                dsbh->nbytes += stats.nbytes;
                dsbh->hourlyStat[dhour].nbytes += stats.nbytes;
                HostStat *hs = dsbh->hourlyStat[dhour].hosts;
                int hostCount = dsbh->hourlyStat[dhour].hostCount;
                int hsIdx = 0;
                while( hsIdx < hostCount &&
                        !isAddrEq(&hs[hsIdx].remote, &stats.remote) )
                    ++hsIdx;
                if( hsIdx == hostCount ) {
                    hs = realloc(hs, ++hostCount * sizeof(HostStat));
                    memset(hs + hsIdx, 0, sizeof(HostStat));
                    hs[hsIdx].remote = stats.remote;
                    dsbh->hourlyStat[dhour].hosts = hs;
                    dsbh->hourlyStat[dhour].hostCount = hostCount;
                }
                hs[hsIdx].nbytes += stats.nbytes;
            }
            if( rd < 0 ) {
                fprintf(stderr, "%s read error: %s\n",
                        fname, strerror(errno));
            }
            fclose(fp);
        }
        closedir(dp);
    }
    /* sort by bytes used */
    for(int i = 0; i < statCount; ++i) {
        MonthlyStat *ms = mstats + i;
        for(int j = 0; j < ms->hostCount; ++j) {
            int jmax = j;
            for(int k = j + 1; k < ms->hostCount; ++k) {
                if( ms->hosts[k].nbytes > ms->hosts[jmax].nbytes )
                    jmax = k;
            }
            if( jmax != j ) {
                MonthlyStatByHost msbh = ms->hosts[j];
                ms->hosts[j] = ms->hosts[jmax];
                ms->hosts[jmax] = msbh;
            }
        }
        for(int mday = 0; mday < 31; ++mday) {
            if( ms->dailyStat[mday].nbytes == 0 )
                continue;
            for(int j = 0; j < ms->dailyStat[mday].hostCount; ++j) {
                int jmax = j;
                for(int k = j + 1; k < ms->dailyStat[mday].hostCount; ++k) {
                    if( ms->dailyStat[mday].hosts[k].nbytes
                            > ms->dailyStat[mday].hosts[jmax].nbytes )
                        jmax = k;
                }
                if( jmax != j ) {
                    DailyStatByHost dsbh = ms->dailyStat[mday].hosts[j];
                    ms->dailyStat[mday].hosts[j]
                        = ms->dailyStat[mday].hosts[jmax];
                    ms->dailyStat[mday].hosts[jmax] = dsbh;
                }
            }
            for(int j = 0; j < ms->dailyStat[mday].hostCount; ++j) {
                DailyStatByHost *dsbh = ms->dailyStat[mday].hosts + j;
                for(int dhour = 0; dhour < 24; ++dhour) {
                    if( dsbh->hourlyStat[dhour].nbytes == 0 )
                        continue;
                    HostStat *hs = dsbh->hourlyStat[dhour].hosts;
                    int hostCount = dsbh->hourlyStat[dhour].hostCount;
                    for(int rhost = 0; rhost < hostCount; ++rhost) {
                        int hmax = rhost;
                        for(int k = rhost + 1; k < hostCount; ++k) {
                            if( hs[k].nbytes > hs[hmax].nbytes )
                                hmax = k;
                        }
                        if( hmax != rhost ) {
                            HostStat hs1 = hs[rhost];
                            hs[rhost] = hs[hmax];
                            hs[hmax] = hs1;
                        }
                    }
                }
            }
        }
    }
    ifaceStat->ifaceName = statCount == 0 ? NULL : strdup(ifaceName);
    ifaceStat->stats = mstats;
    ifaceStat->statCount = statCount;
}

static IfaceStat *loadStats(void)
{
    IfaceStat *res;
    int i, ifaceCount = 0;
    const char *const *interfaces;

    interfaces = wlqconf_getInterfaces();
    res = malloc(sizeof(IfaceStat));
    memset(res, 0, sizeof(IfaceStat));
    if( interfaces != NULL ) {
        for(i = 0; interfaces[i]; ++i) {
            loadIfaceStats(interfaces[i], res + ifaceCount);
            if( res[ifaceCount].ifaceName != NULL ) {
                res = realloc(res,
                        (++ifaceCount + 1) * sizeof(IfaceStat));
                memset(res + ifaceCount, 0, sizeof(IfaceStat));
            }
        }
    }else{
        DIR *dp;
        const struct dirent *de;

        dp = opendir(wlqconf_getStatsDir());
        if( dp != NULL ) {
            while( (de = readdir(dp)) != NULL ) {
                if( de->d_type == DT_DIR ) {
                    loadIfaceStats(de->d_name, res + ifaceCount);
                    if( res[ifaceCount].ifaceName != NULL ) {
                        res = realloc(res,
                                (++ifaceCount + 1) * sizeof(IfaceStat));
                        memset(res + ifaceCount, 0, sizeof(IfaceStat));
                    }
                }
            }
            for(i = 0; i < ifaceCount; ++i) {
                int imin = i;
                for(int j = i + 1; j < ifaceCount; ++j) {
                    if( strcmp(res[j].ifaceName, res[i].ifaceName) < 0 )
                        imin = j;
                }
                if( imin != i ) {
                    IfaceStat is = res[i];
                    res[i] = res[imin];
                    res[imin] = is;
                }
            }
        }
    }
    return res;
}

static const char *lookupDnsName(struct InetAddress *addr,
        const char *resultIfNotFound)
{
    static struct {
        struct InetAddress addr;
        char *name;
    } *map = NULL;
    static int mapCnt = 0;
    int i;
    struct hostent *he;

    for(i = 0; i < mapCnt; ++i) {
        if( isAddrEq(&map[i].addr, addr) )
            return map[i].name == NULL ? resultIfNotFound : map[i].name;
    }
    if( addr->version == 4 ) {
        he = gethostbyaddr(&addr->v4, sizeof(addr->v4), AF_INET);
    }else{
        he = gethostbyaddr(&addr->v6, sizeof(addr->v6), AF_INET6);
    }
    map = realloc(map, (mapCnt + 1) * sizeof(*map));
    map[mapCnt].addr = *addr;
    map[mapCnt].name = he == NULL ? NULL : strdup(he->h_name);
    i = mapCnt++;
    return map[i].name == NULL ? resultIfNotFound : map[i].name;
}

static const char *addrToStr(const struct InetAddress *addr)
{
    static char addrstr[INET6_ADDRSTRLEN];

    if( addr->version == 4 )
        inet_ntop(AF_INET, &addr->v4, addrstr, sizeof(addrstr));
    else
        inet_ntop(AF_INET6, &addr->v6, addrstr, sizeof(addrstr));
    return addrstr;
}

static char *monthName(char *buf, int buflen, int month)
{
    struct tm tmbuf;
    tmbuf.tm_sec = 0;
    tmbuf.tm_min = 0;
    tmbuf.tm_hour = 0;
    tmbuf.tm_mday = 1;
    tmbuf.tm_mon = month - 1;
    tmbuf.tm_year = 117;
    strftime(buf, buflen, "%B", &tmbuf);
    return buf;
}

static void dumpIfaceStat(const IfaceStat *is)
{
    char addrbuf[40], monthbuf[20];
    int idx;
    unsigned netLimit = wlqconf_getNetLimit();

    for(idx = 0; idx < is->statCount; ++idx) {
        MonthlyStat *ms = is->stats + idx;
        printf("<h3>%s %04d&emsp;&emsp;",
                monthName(monthbuf, sizeof(monthbuf), ms->month), ms->year);
        if( ms->nbytes < 1073741824 )
            printf("%.3f MiB", ms->nbytes / 1048576.0);
        else
            printf("%.3f GiB", ms->nbytes / 1073741824.0);
        if( netLimit != 0 ) {
            printf("&emsp;&emsp;(remain: ");
            if( netLimit - ms->nbytes / 1073741824.0 < 1.0 )
                printf("%3f MiB", netLimit - ms->nbytes / 1048576.0);
            else
                printf("%.3f GiB", netLimit - ms->nbytes / 1073741824.0);
            printf(")");

        }
        printf("</h3>\n");
        printf("<div><table><thead><tr><th colspan='4'>by host</th>"
                "</tr></thead><tbody>\n");
        for(int hostNum = 0; hostNum < ms->hostCount; ++hostNum) {
            fflush(stdout);
            printf("<tr><td class='plusminus' onclick='showDet(this)'>+</td>"
                    "<td>%s</td><td>%s</td>",
                    lookupDnsName(&ms->hosts[hostNum].host, ""),
                    addrToStr(&ms->hosts[hostNum].host));
            printf("<td>%.3f MiB</td></tr>\n",
                    ms->hosts[hostNum].nbytes / 1048576.0);
            fflush(stdout);
            printf("<tr style='display: none'><td></td>"
                    "<td colspan='3'><table><tbody>\n");
            for(int didx = 1; didx < 32; ++didx) {
                int mday = didx % 31;
                DailyStatByHost *dsbh = NULL;
                for(int i = 0; i < ms->dailyStat[mday].hostCount; ++i) {
                    if( isAddrEq(&ms->dailyStat[mday].hosts[i].host,
                            &ms->hosts[hostNum].host) )
                    {
                        dsbh = ms->dailyStat[mday].hosts + i;
                        break;
                    }
                }
                if( dsbh == NULL )
                    continue;
                printf("<tr><td class='plusminus' "
                        "onclick='showDet(this)'>+</td><td>%02d/%02d</td>"
                        "<td>%.3f MiB</td></tr>\n",
                        ms->month + (mday != didx), mday + 1,
                        dsbh->nbytes / 1048576.0);
                printf("<tr style='display: none'><td></td>"
                        "<td colspan='2'><table><tbody>\n");
                for(int dhour = 0; dhour < 24; ++dhour) {
                    if(dsbh->hourlyStat[dhour].nbytes == 0)
                        continue;
                    printf(
                        "<tr><td class='plusminus' "
                        "onclick='showDetLook(this)'>+</td><td>%02d</td>"
                        "<td>%.3f MiB</td></tr>\n",
                        dhour,
                        dsbh->hourlyStat[dhour].nbytes
                            / 1048576.0);
                    printf("<tr style='display: none'><td></td>"
                            "<td colspan='2'><table><tbody>\n");
                    const HostStat *hosts = 
                        dsbh->hourlyStat[dhour].hosts;
                    int hostCount =
                        dsbh->hourlyStat[dhour].hostCount;
                    for(int rhost = 0; rhost < hostCount; ++rhost) {
                        printf("<tr><td></td><td>%s</td><td></td>"
                            "<td>%.3f MiB</td></tr>\n",
                            addrToStr(&hosts[rhost].remote),
                                hosts[rhost].nbytes / 1048576.0);
                    }
                    printf("</tbody></table></td></tr>\n");
                }
                printf("</tbody></table></td></tr>\n");
            }
            printf("</tbody></table></td></tr>\n");
        }
        printf("</tbody></table><br>\n");
        printf("<table><thead><tr><th colspan='3'>daily</th>"
                "</tr></thead><tbody>\n");
        for(int didx = 1; didx < 32; ++didx) {
            int mday = didx % 31;
            if( ms->dailyStat[mday].nbytes == 0 )
                continue;
            printf("<tr><td class='plusminus' "
                    "onclick='showDet(this)'>+</td><td>%02d/%02d</td>"
                    "<td>%.3f MiB</td></tr>\n",
                    ms->month + (mday != didx), mday + 1,
                    ms->dailyStat[mday].nbytes / 1048576.0);
            printf("<tr style='display: none'><td></td>"
                    "<td colspan='2'><table><tbody>\n");
            for(int hostNum = 0; hostNum < ms->dailyStat[mday].hostCount;
                    ++hostNum)
            {
                DailyStatByHost *dsbh = ms->dailyStat[mday].hosts + hostNum;
                printf("<tr><td class='plusminus' "
                        "onclick='showDet(this)'>+</td>"
                        "<td>%s</td><td>%s</td>",
                        lookupDnsName(&dsbh->host, ""), addrToStr(&dsbh->host));
                printf("<td>%.3f MiB</td></tr>\n", dsbh->nbytes / 1048576.0);
                printf("<tr style='display: none'><td></td>"
                        "<td colspan='2'><table><tbody>\n");
                for(int dhour = 0; dhour < 24; ++dhour) {
                    if(dsbh->hourlyStat[dhour].nbytes == 0)
                        continue;
                    printf(
                        "<tr><td class='plusminus' "
                        "onclick='showDetLook(this)'>+</td><td>%02d</td>"
                        "<td>%.3f MiB</td></tr>\n",
                        dhour,
                        dsbh->hourlyStat[dhour].nbytes / 1048576.0);
                    printf("<tr style='display: none'><td></td>"
                            "<td colspan='2'><table><tbody>\n");
                    const HostStat *hosts = dsbh->hourlyStat[dhour].hosts;
                    int hostCount = dsbh->hourlyStat[dhour].hostCount;
                    for(int rhost = 0; rhost < hostCount; ++rhost) {
                        printf("<tr><td></td><td>%s</td><td></td>"
                            "<td>%.3f MiB</td></tr>\n",
                            addrToStr(&hosts[rhost].remote),
                                hosts[rhost].nbytes / 1048576.0);
                    }
                    printf("</tbody></table></td></tr>\n");
                }
                printf("</tbody></table></td></tr>\n");
            }
            printf("</tbody></table>\n");
        }
        printf("</tbody></table></div>\n");
        ++ms;
    }
}

static void dumpStats(const IfaceStat *is)
{
    char hostname[HOST_NAME_MAX+1];
    const char *const *interfaces = wlqconf_getInterfaces();

    gethostname(hostname, sizeof(hostname));
    printf("HTTP/1.1 Ok\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<!DOCTYPE html>\n"
        "<html><head>\n"
        "<title>%s network usage</title>\n"
        "<script>\n"
        "function showDet(th) {\n"
        "  th.parentNode.nextElementSibling.style.display = 'table-row';\n"
        "  th.innerHTML = '&minus;';\n"
        "  th.onclick = function() { hideDet(th); };\n"
        "}\n"
        "function showDetLook(th) {\n"
        "  var n = th.parentNode.nextElementSibling;\n"
        "  n.style.display = 'table-row';\n"
        "  th.innerHTML = '&minus;';\n"
        "  th.onclick = function() { hideDet(th); };\n"
        "  var tr = n.firstElementChild.nextElementSibling.firstElementChild"
                ".firstElementChild.firstElementChild;\n"
        "  while( tr !== null ) {\n"
        "    var td = tr.firstElementChild.nextElementSibling;\n"
        "    var xhr = new XMLHttpRequest();\n"
        "    xhr.loadTarget = td.nextElementSibling;\n"
        "    xhr.onload = function() {\n"
        "      this.loadTarget.textContent = this.responseText;\n"
        "    }\n"
        "    xhr.open('GET', '?lookup=' + td.textContent);\n"
        "    xhr.send();\n"
        "    tr = tr.nextElementSibling;\n"
        " }\n"
        "}\n"
        "function hideDet(th) {\n"
        "  th.parentNode.nextElementSibling.style.display = 'none';\n"
        "  th.textContent = '+';\n"
        "  th.onclick = function() { showDet(th); };\n"
        "}\n"
        "</script>\n"
        "<style>\n"
        "body {\n"
        "  background-color: #F2EBDF;\n"
        "}\n"
        "td {\n"
        "  border-color: #ded4f2;\n"
        "  border-width: 1px;\n"
        "  border-bottom-style: solid;\n"
        "  padding: 0px 2em 0px 3px;\n"
        "}\n"
        "td:first-child {\n"
        "  padding: 0px;\n"
        "  cursor: default;\n"
        "}\n"
        "td.plusminus {\n"
        "  font-family: monospace;\n"
        "  font-weight: bold;\n"
        "  background-color: #937D51;\n"
        "  color: white;\n"
        "  padding: 0px 4px;\n"
        "  cursor: default;\n"
        "}\n"
        "h1 {\n"
        "  background-color: #3B4762;\n"
        "  color: #E4D9C5;\n"
        "  padding: 2px 1ex;\n"
        "  text-align: center;\n"
        "}\n"
        "h2 {\n"
        "  font-family: monospace;\n"
        "  background-color: #3B4762;\n"
        "  color: #E4D9C5;\n"
        "  padding: 2px 1ex;\n"
        "  margin-top: 4em;\n"
        "  text-align: center;\n"
        "}\n"
        "h3 {\n"
        "  background-color: #60481A;\n"
        "  color: #F2EBDF;\n"
        "  padding: 2px 1ex;\n"
        "  margin-top: 3ex;\n"
        "  margin-bottom: 2px;\n"
        "}\n"
        "h3 + div {\n"
        "  border: solid #60481A 2px;\n"
        "  margin-bottom: 1em;\n"
        "}\n"
        "th {\n"
        "  color: #60481A;\n"
        "  background-color: #E4D9C5;\n"
        "  padding: 2px;\n"
        "  text-align: left;\n"
        "  font-weight: normal;\n"
        "}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>%s network usage</h1>\n", hostname, hostname);
    while( is->ifaceName ) {
        if( interfaces == NULL || interfaces[1] )
            printf("<h2>interface: %s</h2>\n", is->ifaceName);
        dumpIfaceStat(is);
        ++is;
    }
    printf("</body></html>\n");
}

static void dumpLookup(const char *addr)
{
    struct InetAddress inaddr;
    const char *name = "";

    if( strchr(addr, ':') != NULL ) {
        inaddr.version = inet_pton(AF_INET6, addr, &inaddr.v6) == 1 ? 6 : 0;
    }else{
        inaddr.version = inet_pton(AF_INET, addr, &inaddr.v4) == 1 ? 4 : 0;
    }
    if( inaddr.version != 0 ) {
        name = lookupDnsName(&inaddr, "(unknown)");
    }else{
        name = "(invalid address)";
    }
    printf("HTTP/1.1 Ok\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "%s\n", name);
}

int main(int argc, char *argv[])
{
    const char *queryStr = getenv("QUERY_STRING");

    wlqconf_read();
    if( queryStr != NULL && !strncmp(queryStr, "lookup=", 7) ) {
        dumpLookup(queryStr+7);
    }else{
        IfaceStat *is = loadStats();
        dumpStats(is);
    }
    return 0;
}

