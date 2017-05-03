#ifndef WLQCONFIG_H
#define WLQCONFIG_H

void wlqconf_read(void);

void wlqconf_switchToTargetUser(void);
const char *const *wlqconf_getInterfaces(void);
const char *wlqconf_getStatsDir(void);
const char *wlqconf_getFilter(void);

#endif /* WLQCONFIG_H */
