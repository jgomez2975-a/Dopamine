#pragma once
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#ifndef DOJB_RENAME
#define DOJB_RENAME renamex_np
#endif

static BOOL DOJBIdentity(NSString *path, struct stat expected, BOOL follow)
{
    struct stat actual;
    int rc = follow ? stat(path.fileSystemRepresentation, &actual) : lstat(path.fileSystemRepresentation, &actual);
    return rc == 0 && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
}

static NSString *DOJBRealPath(NSString *path)
{
    if (!path.length) return nil;
    char buf[PATH_MAX];
    return realpath(path.fileSystemRepresentation, buf) ? [NSString stringWithUTF8String:buf] : nil;
}

static NSDictionary *DOJBResult(BOOL ok, NSString *stage, int code, NSString *backup)
{
    return @{@"success": @(ok), @"stage": stage, @"errno": @(code), @"backup": backup ?: @""};
}

// Caller supplies trusted, canonical root and fixed entry. Only swaps a plain
// directory with our freshly-created symlink. Never recursively deletes anything.
static NSDictionary *DOJBRecoverEntry(NSString *entry, NSString *root)
{
    NSString *resolvedRoot = DOJBRealPath(root);
    NSString *parent = DOJBRealPath(entry.stringByDeletingLastPathComponent);
    if (!resolvedRoot || !parent) return DOJBResult(NO, @"invalid_root_or_parent", ENOENT, nil);
    entry = [parent stringByAppendingPathComponent:entry.lastPathComponent];
    if ([resolvedRoot isEqual:entry] || [resolvedRoot hasPrefix:[entry stringByAppendingString:@"/"]])
        return DOJBResult(NO, @"root_inside_entry", EINVAL, nil);
    struct stat rootStat, original;
    if (stat(resolvedRoot.fileSystemRepresentation, &rootStat) != 0 || !S_ISDIR(rootStat.st_mode))
        return DOJBResult(NO, @"root_not_directory", ENOTDIR, nil);
    NSArray *required = @[@"basebin/jbctl", @"basebin/systemhook.dylib", @"Applications/Sileo.app/Sileo",
        @"usr/lib/libellekit.dylib", @"usr/lib/ellekit/libinjector.dylib"];
    for (NSString *suffix in required) {
        NSString *path = [resolvedRoot stringByAppendingPathComponent:suffix];
        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) != 0)
            return DOJBResult(NO, [@"preflight_missing:" stringByAppendingString:suffix], errno, nil);
        if (!S_ISREG(st.st_mode) || st.st_size <= 0)
            return DOJBResult(NO, [@"preflight_not_regular:" stringByAppendingString:suffix], EINVAL, nil);
    }
    if (lstat(entry.fileSystemRepresentation, &original) != 0)
        return DOJBResult(NO, @"entry_not_present_no_change", errno, nil);
    if (S_ISLNK(original.st_mode)) {
        return DOJBIdentity(entry, rootStat, YES) ? DOJBResult(YES, @"already_correct_no_change", 0, nil)
            : DOJBResult(NO, @"unexpected_symlink_no_change", EINVAL, nil);
    }
    if (!S_ISDIR(original.st_mode)) return DOJBResult(NO, @"unexpected_entry_type_no_change", EINVAL, nil);
    struct statfs fs;
    if (statfs(entry.fileSystemRepresentation, &fs) != 0) return DOJBResult(NO, @"mount_check_failed", errno, nil);
    NSString *mountpoint = DOJBRealPath([NSString stringWithUTF8String:fs.f_mntonname]);
    if ([mountpoint isEqual:entry]) return DOJBResult(NO, @"entry_is_mountpoint_no_change", EBUSY, nil);

    NSString *backup = [parent stringByAppendingPathComponent:
        [NSString stringWithFormat:@"%@.DopamineBackup-%@", entry.lastPathComponent, NSUUID.UUID.UUIDString]];
    if (symlink(resolvedRoot.fileSystemRepresentation, backup.fileSystemRepresentation) != 0)
        return DOJBResult(NO, @"staging_symlink_failed", errno, nil);
    struct stat staged;
    if (lstat(backup.fileSystemRepresentation, &staged) != 0 || !S_ISLNK(staged.st_mode))
        return DOJBResult(NO, @"staging_changed_no_swap", EBUSY, backup);
    if (!DOJBIdentity(entry, original, NO) || !DOJBIdentity(resolvedRoot, rootStat, YES)) {
        if (DOJBIdentity(backup, staged, NO)) unlink(backup.fileSystemRepresentation);
        return DOJBResult(NO, @"concurrent_change_no_swap", EBUSY, nil);
    }
    // Atomic exchange: the original directory becomes the backup, without a
    // missing-entry window. Unsupported filesystems fail closed (no fallback).
    if (DOJB_RENAME(entry.fileSystemRepresentation, backup.fileSystemRepresentation, RENAME_SWAP) != 0) {
        int savedErrno = errno;
        if (DOJBIdentity(backup, staged, NO)) unlink(backup.fileSystemRepresentation);
        return DOJBResult(NO, @"atomic_swap_failed_no_change", savedErrno, nil);
    }
    BOOL ownLink = DOJBIdentity(entry, staged, NO);
    BOOL preserved = DOJBIdentity(backup, original, NO);
    BOOL verified = ownLink && preserved && DOJBIdentity(entry, rootStat, YES);
    NSArray *verify = @[@"basebin/jbctl", @"Applications/Sileo.app/Sileo", @"usr/lib/TweakLoader.dylib",
        @"usr/lib/libellekit.dylib", @"Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"];
    NSString *failed = @"postflight_identity";
    if (verified) {
        for (NSString *suffix in verify) {
            struct stat st;
            if (stat([entry stringByAppendingPathComponent:suffix].fileSystemRepresentation, &st) != 0 ||
                !S_ISREG(st.st_mode) || st.st_size <= 0) {
                verified = NO;
                failed = [@"postflight:" stringByAppendingString:suffix];
                break;
            }
        }
    }
    if (!verified) {
        // Only roll back if both names still refer to objects owned by this
        // transaction. Never overwrite an unexpected concurrently-created path.
        if (DOJBIdentity(entry, staged, NO) && DOJBIdentity(backup, original, NO) &&
            DOJB_RENAME(entry.fileSystemRepresentation, backup.fileSystemRepresentation, RENAME_SWAP) == 0) {
            if (DOJBIdentity(backup, staged, NO)) unlink(backup.fileSystemRepresentation);
            return DOJBResult(NO, [failed stringByAppendingString:@":rolled_back"], EIO, nil);
        }
        return DOJBResult(NO, [failed stringByAppendingString:@":manual_review_backup_preserved"], EBUSY, backup);
    }
    return DOJBResult(YES, @"repaired_backup_preserved", 0, backup);
}
