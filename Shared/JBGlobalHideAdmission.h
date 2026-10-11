#ifndef JB_GLOBAL_HIDE_ADMISSION_H
#define JB_GLOBAL_HIDE_ADMISSION_H
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifndef JB_HIDE_ADMISSION_LSTAT
#define JB_HIDE_ADMISSION_LSTAT lstat
#endif
// Conservative compatibility gate, NOT general writer isolation. Use the stable
// bootstrap root, not /var/jb. Installed components are checked instead of a PID
// snapshot: a KeepAlive daemon can restart after a process scan. No signals,
// writes, config changes, recursive scans, or automatic fallback to weaker hide.
// A zero return means only that none of these known components were observed.
static inline int jb_global_hide_admission(const char *root, const char **reason)
{
    if (reason) *reason = NULL;
    if (!root || root[0] != '/' || !root[1]) return EINVAL;
    if (strlen(root) >= PATH_MAX) return ENAMETOOLONG;
    struct stat st;
    if (JB_HIDE_ADMISSION_LSTAT(root, &st) != 0) return errno ? errno : EIO;
    if (!S_ISDIR(st.st_mode)) return ENOTDIR;
    const char *components[] = {
        "usr/bin/CTHermesChargeTool",
        "usr/bin/CTHermesMountTool",
        "Library/MobileSubstrate/DynamicLibraries/CTHermes.dylib",
        "Library/LaunchDaemons/com.qq391160.cpucore.charge.plist",
        "Library/LaunchDaemons/com.qq391160.cpucore.mount.plist"
    };
    for (unsigned i = 0; i < sizeof(components) / sizeof(components[0]); i++) {
        char path[PATH_MAX];
        int length = snprintf(path, sizeof(path), "%s/%s", root, components[i]);
        if (length < 0 || (size_t)length >= sizeof(path)) return ENAMETOOLONG;
        if (JB_HIDE_ADMISSION_LSTAT(path, &st) == 0) {
            if (reason) *reason = components[i];
            return EBUSY; // Also deny a dangling symlink or an unexpected type.
        }
        int error = errno;
        if (error != ENOENT) return error ? error : EIO;
    }
    return 0;
}
#endif
