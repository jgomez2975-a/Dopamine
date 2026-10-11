// Directory-relative query handling for the process-local hide path.
// No global visibility changes and no writes. Keep this outside hook bodies.
#include "hidejb_rules.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool hidejb_relative_path_is_simple(const char *path)
{
    // Do not lexically collapse '..': an intervening symlink can change its
    // meaning. Leave such queries to the original API until resolved safely.
    for (const char *p = path; *p;) {
        while (*p == '/') p++;
        const char *component = p;
        while (*p && *p != '/') p++;
        if (p - component == 2 && component[0] == '.' && component[1] == '.')
            return false;
    }
    return true;
}

bool hidejb_rules_path_at_is_jailbreak(int fd, const char *path)
{
    if (!path || !path[0]) return false;
    // Absolute queries ignore dirfd, including an invalid fd.
    if (path[0] == '/') return hidejb_rules_path_is_jailbreak(path);
    int savedErrno = errno;
    bool hidden = false;
    char base[PATH_MAX] = {0};
    char combined[PATH_MAX] = {0};
    if (!hidejb_relative_path_is_simple(path)) goto done;
    if (fd == AT_FDCWD) {
        if (!getcwd(base, sizeof(base))) goto done;
    } else {
        struct stat st;
        // A regular-file fd must retain the original API's ENOTDIR behavior.
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) goto done;
        if (fcntl(fd, F_GETPATH, base) != 0) goto done;
    }
    if (base[0] != '/') goto done;
    size_t used = strnlen(base, sizeof(base));
    if (used == sizeof(base)) goto done;
    while (used > 1 && base[used - 1] == '/') used--;
    memcpy(combined, base, used);
    // Drop redundant separators and '.' only. No realpath calls (which could
    // recurse into our hooks), no fd/CWD cache (fds and CWD can be reused).
    for (const char *p = path; *p;) {
        while (*p == '/') p++;
        const char *component = p;
        while (*p && *p != '/') p++;
        size_t length = (size_t)(p - component);
        if (!length || (length == 1 && component[0] == '.')) continue;
        size_t slash = combined[used - 1] == '/' ? 0 : 1;
        if (length >= sizeof(combined) - used - slash) goto done;
        if (slash) combined[used++] = '/';
        memcpy(combined + used, component, length);
        used += length;
        combined[used] = 0;
    }
    combined[used] = 0;
    hidden = hidejb_rules_path_is_jailbreak(combined);
done:
    errno = savedErrno;
    return hidden;
}
