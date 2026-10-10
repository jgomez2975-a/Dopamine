#pragma once
#import "../../../../Shared/JBHelperTransitionStore.h"
#ifndef DO_QC_UID
#define DO_QC_UID geteuid
#endif
#ifndef DO_QC_ROOT
#define DO_QC_ROOT @"/var/mobile/.DopamineHideQuarantine"
#endif
#ifndef DO_QC_SOURCES
#define DO_QC_SOURCES @[@"/var/mobile/Library/Preferences/com.qq391160.cpucore.plist", @"/var/mobile/Library/Caches/CTHermes"]
#endif

static inline BOOL DOQCSameObject(NSString *path, NSDictionary *identity)
{
    struct stat st;
    return lstat(path.fileSystemRepresentation, &st) == 0 &&
        (unsigned long long)st.st_dev == [identity[@"dev"] unsignedLongLongValue] &&
        (unsigned long long)st.st_ino == [identity[@"ino"] unsignedLongLongValue] &&
        (st.st_mode & S_IFMT) == [identity[@"type"] unsignedIntValue];
}
static inline NSDictionary *DOQCIdentity(struct stat st)
{
    return @{@"dev": @((unsigned long long)st.st_dev), @"ino": @((unsigned long long)st.st_ino), @"type": @(st.st_mode & S_IFMT)};
}

// Explicit conflict resolution, NOT original-content restoration. Never moves,
// replaces or deletes either data object. Transfer selected map references into
// a fsynced, permanent full-map backup before atomically replacing the live map.
// The old UUID objects remain at their original quarantine paths. No helper runs.
static NSDictionary *DOResolveKnownQuarantineConflicts(void)
{
    if (DO_QC_UID() != 0) return @{@"status": @"root_access_unavailable", @"changed": @NO};
    NSString *root = DO_QC_ROOT;
    struct stat rootStat;
    if (lstat(root.fileSystemRepresentation, &rootStat) != 0 || !S_ISDIR(rootStat.st_mode))
        return @{@"status": @"invalid_quarantine_root", @"changed": @NO};
    NSString *lockPath = [root stringByAppendingPathComponent:@".transaction.lock"];
    int fd = open(lockPath.fileSystemRepresentation, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0) return @{@"status": @"lock_open_failed", @"errno": @(errno), @"changed": @NO};
    struct stat opened, named;
    if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) || opened.st_nlink != 1) {
        close(fd); return @{@"status": @"invalid_lock", @"changed": @NO};
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int error = errno; close(fd); return @{@"status": @"busy", @"errno": @(error), @"changed": @NO};
    }
    @try {
        if (lstat(lockPath.fileSystemRepresentation, &named) != 0 || named.st_ino != opened.st_ino || named.st_dev != opened.st_dev)
            return @{@"status": @"lock_changed", @"changed": @NO};
        NSString *mapPath = [root stringByAppendingPathComponent:@"map.plist"];
        int error = 0; struct stat metadata;
        NSData *bytes = JBTransitionRead(mapPath, &metadata, &error);
        if (!bytes || error || bytes.length > 256 * 1024)
            return @{@"status": @"map_unavailable", @"errno": @(error), @"changed": @NO};
        id map = [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:NULL error:NULL];
        if (![map isKindOfClass:NSArray.class] || [map count] > 4096)
            return @{@"status": @"invalid_map", @"changed": @NO};
        NSMutableArray *next = [NSMutableArray array], *archived = [NSMutableArray array];
        NSMutableSet *sources = [NSMutableSet set], *destinations = [NSMutableSet set];
        NSArray *allowed = DO_QC_SOURCES;
        for (id item in map) {
            if (![item isKindOfClass:NSDictionary.class]) return @{@"status": @"invalid_map", @"changed": @NO};
            id src = item[@"src"], dst = item[@"dst"];
            if (!JBHelperTransitionPathIsClean(src) || !JBHelperTransitionPathIsClean(dst) ||
                ![[dst stringByDeletingLastPathComponent] isEqual:root] ||
                ![[NSUUID alloc] initWithUUIDString:[dst lastPathComponent]] ||
                [sources containsObject:src] || [destinations containsObject:dst])
                return @{@"status": @"invalid_map", @"changed": @NO};
            [sources addObject:src]; [destinations addObject:dst];
            NSUInteger index = [allowed indexOfObject:src];
            if (index == NSNotFound) { [next addObject:item]; continue; }
            struct stat live, old;
            if (lstat([src fileSystemRepresentation], &live) != 0 || lstat([dst fileSystemRepresentation], &old) != 0)
                return @{@"status": @"target_not_both_present", @"changed": @NO};
            BOOL valid = index == 0 ? (S_ISREG(live.st_mode) && S_ISREG(old.st_mode) && live.st_nlink == 1 && old.st_nlink == 1)
                                   : (S_ISDIR(live.st_mode) && S_ISDIR(old.st_mode));
            if (!valid || (live.st_dev == old.st_dev && live.st_ino == old.st_ino))
                return @{@"status": @"unexpected_target_type", @"changed": @NO};
            [archived addObject:@{@"src":src, @"dst":dst, @"live_identity":DOQCIdentity(live), @"old_identity":DOQCIdentity(old)}];
        }
        if (!archived.count) return @{@"status": @"no_known_conflicts", @"changed": @NO};
        for (NSDictionary *item in archived) {
            if (!DOQCSameObject(item[@"src"], item[@"live_identity"]) || !DOQCSameObject(item[@"dst"], item[@"old_identity"]))
                return @{@"status": @"target_changed", @"changed": @NO};
        }
        NSData *replacement = [NSPropertyListSerialization dataWithPropertyList:next format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        NSMutableDictionary *result = [JBTransitionReplace(mapPath, bytes, replacement) mutableCopy];
        result[@"resolution"] = @"keep_current_archive_original_references";
        result[@"archived_items"] = archived;
        result[@"remaining_journal_entries"] = @(next.count);
        result[@"original_contents_restored"] = @NO;
        if ([result[@"status"] isEqual:@"applied"]) {
            BOOL intact = YES;
            for (NSDictionary *item in archived)
                intact = intact && DOQCSameObject(item[@"src"], item[@"live_identity"]) && DOQCSameObject(item[@"dst"], item[@"old_identity"]);
            result[@"status"] = intact ? @"conflicts_archived_current_kept" : @"postflight_target_changed_backups_preserved";
        }
        return result;
    } @finally { flock(fd, LOCK_UN); close(fd); }
}
