#ifndef WLQCONFIG_H
#define WLQCONFIG_H

void wlqconf_read(void);

void wlqconf_createStatsDir(void);
void wlqconf_switchToTargetUser(void);
const char *const *wlqconf_getInterfaces(void);
const char *wlqconf_getStatsDir(void);
const char *wlqconf_getLocalNet(void);
unsigned wlqconf_getNetLimit(void);

#endif /* WLQCONFIG_H */
