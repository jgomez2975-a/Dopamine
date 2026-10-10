#pragma once
#import <Foundation/Foundation.h>
#ifndef JB_TRANSITION_ROOT_PREFIX
#define JB_TRANSITION_ROOT_PREFIX @"/private/preboot/"
#endif

// Pure preparation only. The caller must snapshot, persist a backup and perform
// guarded writes separately. Never silently replace malformed existing config:
// the old launchd reader assumes every ProcessBlacklist member is a string.
static inline NSDictionary *JBHelperTransitionPlan(NSData *original, NSString *root)
{
    if (![root isKindOfClass:NSString.class] || ![root hasPrefix:JB_TRANSITION_ROOT_PREFIX] ||
        ![root.lastPathComponent isEqual:@"procursus"] ||
        ![root isEqual:root.stringByStandardizingPath])
        return @{@"status": @"invalid_root"};
    if (original.length > 256 * 1024) return @{@"status": @"config_too_large"};
    NSDictionary *config = @{};
    if (original) {
        id decoded = [NSPropertyListSerialization propertyListWithData:original options:NSPropertyListImmutable format:NULL error:NULL];
        if (![decoded isKindOfClass:NSDictionary.class]) return @{@"status": @"invalid_config"};
        config = decoded;
    }
    id blacklist = config[@"ProcessBlacklist"];
    if (blacklist && ![blacklist isKindOfClass:NSArray.class]) return @{@"status": @"invalid_blacklist"};
    for (id path in blacklist) {
        if (![path isKindOfClass:NSString.class] || ![path length] ||
            ![path isAbsolutePath] || [path rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0, 1)]].location != NSNotFound)
            return @{@"status": @"invalid_blacklist_entry"};
    }
    NSString *helper = [root stringByAppendingPathComponent:@"basebin/jbctl"];
    NSMutableArray *next = blacklist ? [blacklist mutableCopy] : [NSMutableArray array];
    BOOL added = ![next containsObject:helper];
    if (added) [next addObject:helper];
    NSMutableDictionary *updated = [config mutableCopy];
    updated[@"ProcessBlacklist"] = next;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:updated format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if (!data || data.length > 256 * 1024) return @{@"status": @"encoded_config_too_large"};
    return @{@"status": @"prepared", @"helper": helper, @"added": @(added),
        @"original_exists": @(original != nil), @"original": original ?: [NSData data], @"updated": data};
}

// The old reader reloads only for a strictly newer nanosecond timestamp.
// This predicate is also needed when restoring a previous config: restoring
// its old timestamp can leave the temporary exception cached in launchd.
static inline BOOL JBHelperTransitionTimestampIsNewer(long long seconds, long nanoseconds,
    long long previousSeconds, long previousNanoseconds)
{
    if (nanoseconds < 0 || nanoseconds >= 1000000000 ||
        previousNanoseconds < 0 || previousNanoseconds >= 1000000000) return NO;
    return seconds > previousSeconds || (seconds == previousSeconds && nanoseconds > previousNanoseconds);
}
