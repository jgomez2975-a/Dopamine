#pragma once
#import "JBHelperTransitionPlan.h"
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#ifndef JB_TRANSITION_EXCHANGE
#define JB_TRANSITION_EXCHANGE renamex_np
#endif

// Bounded, no-follow snapshots; nil data with errno=0 means absent.
static NSData *JBTransitionRead(NSString *path, struct stat *metadata, int *error)
{
    *error = 0;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { if (errno != ENOENT) *error = errno; return nil; }
    struct stat after;
    if (fstat(fd, metadata) != 0) { *error = errno; close(fd); return nil; }
    if (!S_ISREG(metadata->st_mode) || metadata->st_nlink != 1 || metadata->st_size < 0 || metadata->st_size > 1024 * 1024) {
        *error = EINVAL; close(fd); return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)metadata->st_size];
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t count = read(fd, (char *)data.mutableBytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { *error = EIO; close(fd); return nil; }
        offset += (NSUInteger)count;
    }
    if (fstat(fd, &after) != 0 || metadata->st_ino != after.st_ino || metadata->st_size != after.st_size ||
        metadata->st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || metadata->st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec)
        *error = ESTALE;
    close(fd); return *error ? nil : data;
}

// The transaction directory is private and unique; every file is exclusive.
static int JBTransitionWrite(NSString *path, NSData *data, mode_t mode, uid_t uid, gid_t gid, const struct timespec *times)
{
    int fd = open(path.fileSystemRepresentation, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return errno;
    int error = 0;
    if (fchown(fd, uid, gid) != 0 || fchmod(fd, mode & 0777) != 0) error = errno;
    NSUInteger offset = 0;
    while (!error && offset < data.length) {
        ssize_t count = write(fd, (const char *)data.bytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { error = count < 0 ? errno : EIO; break; }
        offset += (NSUInteger)count;
    }
    if (!error && times && futimens(fd, times) != 0) error = errno;
    if (!error && fsync(fd) != 0) error = errno;
    close(fd); return error;
}

// On a conflicting external writer, retain BOTH displaced and staged files.
// flock serializes cooperating App calls, not unrelated processes. An atomic
// swap closes the destructive overwrite gap; it is not a filesystem CAS.
static NSDictionary *JBTransitionReplace(NSString *path, NSData *expected, NSData *replacement)
{
    if (!replacement || replacement.length > 256 * 1024 || expected.length > 256 * 1024) return @{@"status": @"invalid_replacement", @"errno": @(EINVAL)};
    NSString *parent = path.stringByDeletingLastPathComponent;
    NSString *lockPath = [parent stringByAppendingPathComponent:@".DopamineHelperTransition.lock"];
    int lock = open(lockPath.fileSystemRepresentation, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0) return @{@"status": @"lock_open_failed", @"errno": @(errno)};
    struct stat lockStat;
    if (fstat(lock, &lockStat) != 0 || !S_ISREG(lockStat.st_mode) || lockStat.st_nlink != 1) {
        close(lock); return @{@"status": @"invalid_lock", @"errno": @(EINVAL)};
    }
    if (flock(lock, LOCK_EX | LOCK_NB) != 0) { int error = errno; close(lock); return @{@"status": @"busy", @"errno": @(error)}; }
    @try {
        struct stat before = {0}; int error = 0;
        NSData *actual = JBTransitionRead(path, &before, &error);
        if (error || actual.length > 256 * 1024 || (expected ? ![actual isEqual:expected] : actual != nil))
            return @{@"status": @"preflight_conflict", @"errno": @(error ?: ESTALE)};
        NSString *directory = [parent stringByAppendingPathComponent:[@".DopamineHelperTransition-" stringByAppendingString:NSUUID.UUID.UUIDString]];
        if (mkdir(directory.fileSystemRepresentation, 0700) != 0)
            return @{@"status": @"backup_directory_failed", @"errno": @(errno)};
        NSString *backup = [directory stringByAppendingPathComponent:@"original.plist"];
        NSString *stage = [directory stringByAppendingPathComponent:@"exchange.plist"];
        NSMutableDictionary *result = [@{@"status": @"preparation_failed", @"backup_directory": directory, @"changed": @NO} mutableCopy];
        NSDictionary *journal = @{@"schema": @1, @"config_path": path, @"original_exists": @(actual != nil),
            @"original": actual ?: [NSData data], @"replacement": replacement,
            @"mode": @(actual ? before.st_mode & 0777 : 0644),
            @"uid": @(actual ? before.st_uid : geteuid()), @"gid": @(actual ? before.st_gid : getegid())};
        NSData *record = [NSPropertyListSerialization dataWithPropertyList:journal format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
        error = record ? JBTransitionWrite(backup, record, 0600, geteuid(), getegid(), NULL) : EINVAL;
        long long seconds = MAX((long long)time(NULL), actual ? (long long)before.st_mtimespec.tv_sec : 0);
        if (!error && seconds >= LLONG_MAX - 1) error = EOVERFLOW;
        struct timespec times[2] = {{seconds < LLONG_MAX - 1 ? seconds + 1 : seconds, 0}, {seconds < LLONG_MAX - 1 ? seconds + 1 : seconds, 0}};
        if (!error) error = JBTransitionWrite(stage, replacement, [journal[@"mode"] unsignedIntValue],
            [journal[@"uid"] unsignedIntValue], [journal[@"gid"] unsignedIntValue], times);
        int dirfd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (!error && (dirfd < 0 || fsync(dirfd) != 0)) error = errno;
        if (dirfd >= 0) close(dirfd);
        int backupParent = open(parent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (!error && (backupParent < 0 || fsync(backupParent) != 0)) error = errno;
        if (backupParent >= 0) close(backupParent);
        if (error) { result[@"errno"] = @(error); return result; }
        struct stat recheck = {0}; NSData *latest = JBTransitionRead(path, &recheck, &error);
        if (error || (actual ? ![latest isEqual:actual] || before.st_ino != recheck.st_ino : latest != nil)) {
            result[@"status"] = @"preflight_changed"; result[@"errno"] = @(error ?: ESTALE); return result;
        }
        if (JB_TRANSITION_EXCHANGE(stage.fileSystemRepresentation, path.fileSystemRepresentation, actual ? RENAME_SWAP : RENAME_EXCL) != 0) {
            result[@"status"] = @"exchange_failed"; result[@"errno"] = @(errno); return result;
        }
        result[@"changed"] = @YES;
        struct stat post = {0}; NSData *installed = JBTransitionRead(path, &post, &error);
        BOOL matched = !error && [installed isEqual:replacement] &&
            JBHelperTransitionTimestampIsNewer(post.st_mtimespec.tv_sec, post.st_mtimespec.tv_nsec,
                actual ? before.st_mtimespec.tv_sec : 0, actual ? before.st_mtimespec.tv_nsec : 0);
        if (actual) {
            struct stat displaced = {0}; NSData *saved = JBTransitionRead(stage, &displaced, &error);
            matched = matched && !error && [saved isEqual:actual] && displaced.st_ino == before.st_ino;
        }
        int parentfd = open(parent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        BOOL synced = parentfd >= 0 && fsync(parentfd) == 0;
        if (parentfd >= 0) close(parentfd);
        result[@"status"] = matched && synced ? @"applied" : @"postflight_failed_backups_preserved";
        result[@"errno"] = matched && synced ? @0 : @(error ?: EIO);
        return result;
    } @finally { flock(lock, LOCK_UN); close(lock); }
}

// Restore content only if nobody changed the applied configuration. Originally
// absent configs become an empty dictionary with a NEW timestamp: deleting the
// file would not clear an existing launchd cache. Never erase backup directories.
static NSDictionary *JBTransitionRollback(NSString *configPath, NSString *backupDirectory)
{
    struct stat st; int error = 0;
    NSData *raw = JBTransitionRead([backupDirectory stringByAppendingPathComponent:@"original.plist"], &st, &error);
    id journal = raw ? [NSPropertyListSerialization propertyListWithData:raw options:0 format:NULL error:NULL] : nil;
    if (error || ![journal isKindOfClass:NSDictionary.class] || ![journal[@"config_path"] isEqual:configPath] ||
        ![journal[@"original"] isKindOfClass:NSData.class] || ![journal[@"replacement"] isKindOfClass:NSData.class] ||
        ![journal[@"original_exists"] isKindOfClass:NSNumber.class])
        return @{@"status": @"invalid_backup", @"errno": @(error ?: EINVAL)};
    NSData *restore = [journal[@"original_exists"] boolValue] ? journal[@"original"] :
        [NSPropertyListSerialization dataWithPropertyList:@{} format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    return JBTransitionReplace(configPath, journal[@"replacement"], restore);
}
