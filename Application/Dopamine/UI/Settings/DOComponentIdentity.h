#pragma once
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Read only three fixed component files, bounded to 32 MiB each. A file changing
// during the read is not reported as a valid identity. This is DISK identity,
// never evidence that launchd has loaded this image into memory.
static NSDictionary *DOComponentHash(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return @{@"errno":@(errno)};
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0 || before.st_size > 32*1024*1024) {
        close(fd); return @{@"error":@"not_regular_or_too_large"};
    }
    unsigned char buffer[32768], digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX context;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256_Init(&context);
    ssize_t length;
    off_t total = 0;
    while ((length = read(fd, buffer, sizeof(buffer))) != 0) {
        if (length < 0) {
            if (errno == EINTR) continue;
            int error = errno; close(fd); return @{@"errno":@(error)};
        }
        total += length;
        if (total > 32*1024*1024) { close(fd); return @{@"error":@"changed_or_too_large"}; }
        CC_SHA256_Update(&context, buffer, (CC_LONG)length);
    }
    BOOL stable = fstat(fd, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && total == before.st_size &&
        before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
        before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
    close(fd);
    if (!stable) return @{@"error":@"changed_during_read"};
    CC_SHA256_Final(digest, &context);
#pragma clang diagnostic pop
    NSMutableString *hex = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i=0; i<sizeof(digest); i++) [hex appendFormat:@"%02x",digest[i]];
    return @{@"sha256":hex,@"size":@(total)};
}

static NSDictionary *DOComponentIdentity(NSString *root, NSString *bundlePath)
{
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"DopamineBuildIdentity.plist"]];
    id components = manifest[@"components"];
    if (![components isKindOfClass:NSDictionary.class] || !root.length) {
        return @{@"status":@"unavailable",@"runtime_activation":@"not_proven_by_disk_hashes"};
    }
    NSMutableDictionary *files = [NSMutableDictionary dictionary];
    BOOL known = YES, matches = YES;
    for (NSString *name in @[@"jbctl",@"launchdhook.dylib",@"systemhook.dylib",@"libjailbreak.dylib"]) {
        id expected = components[name];
        NSDictionary *actual = DOComponentHash([[root stringByAppendingPathComponent:@"basebin"] stringByAppendingPathComponent:name]);
        BOOL valid = [expected isKindOfClass:NSString.class] && [expected length] == 64 && actual[@"sha256"] != nil;
        if (!valid) known = NO;
        BOOL same = valid && [expected isEqualToString:actual[@"sha256"]];
        if (!same) matches = NO;
        files[name] = @{@"actual":actual,@"expected_sha256":[expected isKindOfClass:NSString.class] ? expected : @"<unavailable>",@"matches":@(same)};
    }
    return @{@"status":known ? (matches ? @"match" : @"mismatch") : @"unavailable",
        @"bundle_commit":manifest[@"commit"] ?: @"<unavailable>",@"components":files,
        @"runtime_activation":@"not_proven_by_disk_hashes"};
}

// Same release number does not imply the same development build. Unknown read
// results never trigger an update offer, and this does not offer downgrades.
static inline BOOL DOComponentUpdateRequired(long long bundled, long long running, NSDictionary *identity)
{
    return bundled > running || (bundled == running && [identity[@"status"] isEqual:@"mismatch"]);
}
