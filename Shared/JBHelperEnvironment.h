#ifndef JB_HELPER_ENVIRONMENT_H
#define JB_HELPER_ENVIRONMENT_H
#include <stddef.h>

// Maintenance helpers must not initialize systemhook/tweaks before main.
// _SafeMode is the existing spawn hook's per-child no-injection protocol;
// it does not create .safe_mode or change the global tweak setting. Do not
// inherit DYLD_* or DOPAMINE_APP_HIDE from the caller. The hook consumes the
// marker in normal boot; the early-boot bypass already performs no injection.
static inline char *const *jb_helper_environment(void)
{
    static char *const environment[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin",
        "_SafeMode=1",
        NULL
    };
    return environment;
}
#endif
