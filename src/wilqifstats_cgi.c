#include <stdio.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "wilqifstats.h"
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char WLQSTATSDIR[] = "/var/lib/wilqifstats";

typedef struct {
    in_addr_t remote;
    unsigned long long nbytes;
} HostStat;

typedef struct {
    in_addr_t host;
    unsigned long long nbytes;
} MonthlyStatByHost;

typedef struct {
    in_addr_t host;
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

static MonthlyStat *loadStats(void)
{
    DIR *dp;
    const struct dirent *de;
    char fname[40], *endp;
    unsigned hour;
    FILE *fp;
    ip_statistics stats;
    MonthlyStat *res;
    int rd, statCount = 0;

    res = malloc(sizeof(MonthlyStat));
    memset(res, 0, sizeof(MonthlyStat));
    dp = opendir(WLQSTATSDIR);
    if( dp == NULL )
        return res;
    while( (de = readdir(dp)) != NULL ) {
        if( de->d_type != DT_REG )
            continue;
        hour = strtoul(de->d_name, &endp, 10);
        if( hour == 0 || *endp ) {
            printf("%s/%s: not a stats file, ignored\n",
                    WLQSTATSDIR, de->d_name);
            continue;
        }
        sprintf(fname, "%s/%s", WLQSTATSDIR, de->d_name);
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
        while( res[msIdx].year > year
                || res[msIdx].year == year && res[msIdx].month > month )
            ++msIdx;
        if( res[msIdx].year < year
                || res[msIdx].year == year && res[msIdx].month < month )
        {
            res = realloc(res, (++statCount + 1) * sizeof(MonthlyStat));
            memmove(res + msIdx + 1, res + msIdx,
                    (statCount-msIdx) * sizeof(MonthlyStat));
            memset(res + msIdx, 0, sizeof(MonthlyStat));
            res[msIdx].year = year;
            res[msIdx].month = month;
        }
        MonthlyStat *ms = res + msIdx;
        while( (rd = fread(&stats, sizeof(ip_statistics), 1, fp)) == 1 ) {
            ms->nbytes += stats.nbytes;
            ms->dailyStat[mday-1].nbytes += stats.nbytes;
            int i = 0;
            while( i < ms->hostCount && ms->hosts[i].host != stats.local )
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
            while( i < ms->dailyStat[mday-1].hostCount
                    && ms->dailyStat[mday-1].hosts[i].host != stats.local )
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
            while( hsIdx < hostCount && hs[hsIdx].remote != stats.remote )
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
    /* sort by bytes used */
    for(int i = 0; i < statCount; ++i) {
        MonthlyStat *ms = res + i;
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
    return res;
}

static const char *lookupDnsName(in_addr_t addr, const char *resultIfNotFound)
{
    static struct {
        in_addr_t addr;
        char *name;
    } *map = NULL;
    static int mapCnt = 0;
    int i;
    struct hostent *he;
    struct in_addr a;

    for(i = 0; i < mapCnt; ++i) {
        if( map[i].addr == addr )
            return map[i].name == NULL ? resultIfNotFound : map[i].name;
    }
    a.s_addr = addr;
    he = gethostbyaddr(&a, sizeof(a), AF_INET);
    map = realloc(map, (mapCnt + 1) * sizeof(*map));
    map[mapCnt].addr = addr;
    map[mapCnt].name = he == NULL ? NULL : strdup(he->h_name);
    i = mapCnt++;
    return map[i].name == NULL ? resultIfNotFound : map[i].name;
}

static const char *addrToStr(in_addr_t addr)
{
    struct in_addr a;

    a.s_addr = addr;
    return inet_ntoa(a);
}

static void dumpStats(MonthlyStat *ms)
{
    char addrbuf[40];

    printf("HTTP/1.1 Ok\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<!DOCTYPE html>\n"
        "<html><head>\n"
        "<title>Network usage statistics</title>\n"
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
        "</style>\n"
        "</head>\n"
        "<body>\n");
    while( ms->year ) {
        printf("<h3>%04d/%02d &emsp; %.3f MiB</h3>\n",
                ms->year, ms->month, ms->nbytes / 1048576.0);
        printf("<table><tbody>\n");
        for(int hostNum = 0; hostNum < ms->hostCount; ++hostNum) {
            fflush(stdout);
            printf("<tr><td class='plusminus' onclick='showDet(this)'>+</td>"
                    "<td>%s</td><td>%s</td>",
                    lookupDnsName(ms->hosts[hostNum].host, ""),
                    addrToStr(ms->hosts[hostNum].host));
            printf("<td>%.3f MiB</td></tr>\n",
                    ms->hosts[hostNum].nbytes / 1048576.0);
            fflush(stdout);
            printf("<tr style='display: none'><td></td>"
                    "<td colspan='3'><table><tbody>\n");
            for(int didx = 1; didx < 32; ++didx) {
                int mday = didx % 31;
                DailyStatByHost *dsbh = NULL;
                for(int i = 0; i < ms->dailyStat[mday].hostCount; ++i) {
                    if( ms->dailyStat[mday].hosts[i].host
                            == ms->hosts[hostNum].host )
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
                            addrToStr(hosts[rhost].remote),
                                hosts[rhost].nbytes / 1048576.0);
                    }
                    printf("</tbody></table></td></tr>\n");
                }
                printf("</tbody></table></td></tr>\n");
            }
            printf("</tbody></table></td></tr>\n");
        }
        printf("</tbody></table>\n");
        printf("<p></p>\n");
        printf("<table><tbody>\n");
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
                        lookupDnsName(dsbh->host, ""), addrToStr(dsbh->host));
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
                            addrToStr(hosts[rhost].remote),
                                hosts[rhost].nbytes / 1048576.0);
                    }
                    printf("</tbody></table></td></tr>\n");
                }
                printf("</tbody></table></td></tr>\n");
            }
            printf("</tbody></table>\n");
        }
        printf("</tbody></table>\n");
        ++ms;
    }
    printf("<p></p></body></html>\n");
}

static void dumpLookup(const char *addr)
{
    struct in_addr a;
    const char *name = "";

    if( inet_aton(addr, &a) ) {
        name = lookupDnsName(a.s_addr, "(unknown)");
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
    if( queryStr != NULL && !strncmp(queryStr, "lookup=", 7) ) {
        dumpLookup(queryStr+7);
    }else{
        MonthlyStat *ms = loadStats();
        dumpStats(ms);
    }
    return 0;
}
