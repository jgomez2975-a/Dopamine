#ifndef JB_ENTRY_GUARD_H
#define JB_ENTRY_GUARD_H
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* Used by the launchd restore path (stage 1: entry integrity only).
 * No unlink/rename: an already-correct link is a no-op. A directory conflict
 * is an explicit error, never success and never recursively removed.
 * Does not serialize deliberate hiding, prevent external writers, or repair
 * existing conflicts. Those need lifecycle coordination and verified recovery.
 */
static int jb_entry_link_matches(const char *entry, const struct stat *root)
{
    struct stat link, target;
    if (lstat(entry, &link) != 0) return errno;
    if (!S_ISLNK(link.st_mode)) return S_ISDIR(link.st_mode) ? EISDIR : EINVAL;
    if (stat(entry, &target) != 0) return errno;
    return target.st_dev == root->st_dev && target.st_ino == root->st_ino ? 0 : EINVAL;
}

static int jb_entry_ensure_visible(const char *entry, const char *rootPath)
{
    if (!entry || !rootPath || !entry[0] || !rootPath[0]) return EINVAL;
    struct stat root, entryStat;
    if (stat(rootPath, &root) != 0) return errno;
    if (!S_ISDIR(root.st_mode)) return ENOTDIR;
    if (lstat(entry, &entryStat) == 0) return jb_entry_link_matches(entry, &root);
    if (errno != ENOENT) return errno;
    if (symlink(rootPath, entry) != 0) {
        int code = errno;
        // Concurrent successful restoration is acceptable; a directory created
        // by another writer is not. Neither case gets overwritten.
        if (code != EEXIST) return code;
    }
    return jb_entry_link_matches(entry, &root);
}
#endif
