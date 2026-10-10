#ifndef JB_MANUAL_ENTRY_H
#define JB_MANUAL_ENTRY_H
#import <Foundation/Foundation.h>
#include <stdio.h>
#include "JBEntryGuard.h"
#ifndef JB_MANUAL_RENAME
#define JB_MANUAL_RENAME renamex_np
#endif

// Missing is a distinct state, not a dangling link or an inaccessible path.
static inline int jb_manual_probe(NSString *entry, NSString *root, BOOL *hidden)
{
    if (!entry.length || !root.length || !hidden) return EINVAL;
    *hidden = NO;
    struct stat target, item;
    if (stat(root.fileSystemRepresentation, &target) != 0) return errno;
    if (!S_ISDIR(target.st_mode)) return ENOTDIR;
    if (lstat(entry.fileSystemRepresentation, &item) != 0) {
        if (errno != ENOENT) return errno;
        *hidden = YES;
        return 0;
    }
    return jb_entry_link_matches(entry.fileSystemRepresentation, &target);
}

// Move the validated link to a unique sibling first, then verify its identity.
// If another process replaced it, restore that item without overwriting anything.
// Never recursively delete an entry, and never delete an unverified moved item.
// A process exit after rename leaves a recoverable sibling, not lost directory data.
static inline int jb_manual_hide(NSString *entry, NSString *root, NSString **retained)
{
    if (retained) *retained = nil;
    BOOL hidden = NO;
    int result = jb_manual_probe(entry, root, &hidden);
    if (result != 0 || hidden) return result;
    struct stat original;
    if (lstat(entry.fileSystemRepresentation, &original) != 0) return errno;
    if (!S_ISLNK(original.st_mode)) return EINVAL;
    NSString *backup = [entry stringByAppendingFormat:@".DopamineHide-%@", NSUUID.UUID.UUIDString];
    if (JB_MANUAL_RENAME(entry.fileSystemRepresentation, backup.fileSystemRepresentation, RENAME_EXCL) != 0) return errno;
    if (retained) *retained = backup;
    struct stat moved;
    if (lstat(backup.fileSystemRepresentation, &moved) != 0 ||
        !S_ISLNK(moved.st_mode) || moved.st_dev != original.st_dev || moved.st_ino != original.st_ino ||
        jb_manual_probe(backup, root, &hidden) != 0 || hidden) {
        if (JB_MANUAL_RENAME(backup.fileSystemRepresentation, entry.fileSystemRepresentation, RENAME_EXCL) == 0) {
            if (retained) *retained = nil;
        }
        return ESTALE;
    }
    if (unlink(backup.fileSystemRepresentation) != 0) return errno;
    if (retained) *retained = nil;
    if (lstat(entry.fileSystemRepresentation, &moved) == 0) return EBUSY;
    return errno == ENOENT ? 0 : errno;
}
#endif
