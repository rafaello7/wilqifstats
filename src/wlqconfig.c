#include "wlqconfig.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>

static const char WLQCONFDIR[] = "/etc/wilqifstats.d";

static const char *const *gInterfaces = NULL;
static const char *gSwitchUser = "www-data";
static const char *gFilter = "not src net 192.168 or not dst net 192.168";
static const char *gStatsDir = "/var/lib/wilqifstats";

static int parseParam(const char *name, const char *value)
{
    int res = 1;

    if( !strcmp(name, "interfaces") ) {
        char *s = strdup(value);
        const char **interfaces = NULL;
        int interfaceCount = 0;
        while( 1 ) {
            s += strspn(s, " \t");
            if( *s == '\0' )
                break;
            interfaces = realloc(interfaces,
                    (interfaceCount+2) * sizeof(char*));
            interfaces[interfaceCount++] = s;
            s += strcspn(s, " \t");
            if( *s == '\0' )
                break;
            *s++ = '\0';
        }
        if( interfaces )
            interfaces[interfaceCount] = NULL;
        gInterfaces = interfaces;
    }else if( !strcmp(name, "srvuser") ) {
        gSwitchUser = strdup(value);
    }else if( !strcmp(name, "filter") ) {
        gFilter = strdup(value);
    }else if( !strcmp(name, "statsdir") ) {
        gStatsDir = strdup(value);
    }else{
        res = 0;
    }
    return res;
}

static char *readLine(FILE *fp)
{
    char *res = NULL;
    int c, len = 0, alloc = 0;

    while( (c = getc(fp)) != EOF && c != '\n' ) {
        if( len == alloc ) {
            alloc += 128;
            res = realloc(res, alloc);
        }
        res[len++] = c;
    }
    if( len > 0 || c == '\n' ) {
        if( len == alloc )
            res = realloc(res, len+1);
        res[len] = '\0';
    }
    return res;
}

static void trimRight(char *line)
{
    char *lineEnd = line + strlen(line);

    while( lineEnd != line && strchr(" \t", lineEnd[-1]) != NULL )
        --lineEnd;
    *lineEnd = '\0';
}

static void parseFile(const char *fname)
{
    FILE *fp;
    char *line, *name, *value;
    int lineNo = 0;

    if( (fp = fopen(fname, "r")) == NULL ) {
        fprintf(stderr, "fatal: unable to open configuration file %s: %s\n",
                fname, strerror(errno));
        exit(1);
    }
    while( (line = readLine(fp)) != NULL ) {
        ++lineNo;
        name = line + strspn(line, " \t");
        if( *name && *name != '#' ) {
            value = strchr(name, '=');
            if( value != NULL ) {
                *value++ = '\0';
                trimRight(name);
                value += strspn(value, " \t");
                trimRight(value);
                if( !parseParam(name, value) ) {
                    fprintf(stderr, "WARN: %s:%d: urecognized parameter "
                            "\"%s\" (line ignored)\n", fname, lineNo, name);
                }
            }else{
                fprintf(stderr, "WARN: missing '=' in %s:%d (line ignored)\n",
                        fname, lineNo);
            }
        }
        free(line);
    }
    fclose(fp);
}

void wlqconf_read(void)
{
    DIR *dp;
    struct dirent *de;
    int namelen;
    char fname[100];

    dp = opendir(WLQCONFDIR);
    if( dp != NULL ) {
        while( (de = readdir(dp)) != NULL ) {
            namelen = strlen(de->d_name);
            if( de->d_type != DT_REG || namelen < 5 ||
                    strcmp(de->d_name + namelen - 5, ".conf") )
                continue;
            sprintf(fname, "%s/%s", WLQCONFDIR, de->d_name);
            parseFile(fname);
        }
    }
}

void wlqconf_createStatsDir(void)
{
    struct passwd *pwd;

    if( mkdir(gStatsDir, 0755) == 0 ) {
        if( gSwitchUser[0] && geteuid() == 0 ) {
            if( (pwd = getpwnam(gSwitchUser)) != NULL ) {
                if( chown(gStatsDir, pwd->pw_uid, pwd->pw_gid) != 0 ) {
                    fprintf(stderr, "chown(%s): %s\n", gStatsDir,
                            strerror(errno));
                    exit(1);
                }
            }else{
                fprintf(stderr, "No such user \"%s\"; please specify a valid "
                        "switch user in configuration file\n", gSwitchUser);
                exit(1);
            }
        }
    }else if( errno != EEXIST ) {
        fprintf(stderr, "Unable to create directory %s: %s\n",
                gStatsDir, strerror(errno));
        exit(1);
    }
}

void wlqconf_switchToTargetUser(void)
{
    struct passwd *pwd;

    if( gSwitchUser[0] && geteuid() == 0 ) {
        if( (pwd = getpwnam(gSwitchUser)) != NULL ) {
            if( setgid(pwd->pw_gid) != 0 )
                fprintf(stderr, "WARN: setgid: %s\n", strerror(errno));
            if( setuid(pwd->pw_uid) < 0 ) {
                fprintf(stderr, "setuid: %s\n", strerror(errno));
                exit(1);
            }
        }else{
            fprintf(stderr, "No such user \"%s\"; please specify a valid "
                    "switch user in configuration file\n", gSwitchUser);
            exit(1);
        }
    }
}

const char *const *wlqconf_getInterfaces(void)
{
    return gInterfaces;
}

const char *wlqconf_getFilter(void)
{
    return gFilter;
}

const char *wlqconf_getStatsDir(void)
{
    return gStatsDir;
}

