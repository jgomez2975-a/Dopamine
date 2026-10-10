#pragma once
#import "../../../../Shared/JBHelperTransitionStore.h"
#include "../../../../Shared/JBEntryGuard.h"

#ifndef DO_HT_ENTRY
#define DO_HT_ENTRY "/var/jb"
#endif
#ifndef DO_HT_EUID
#define DO_HT_EUID geteuid
#endif

static NSDictionary *DOHelperTransition(NSString *root, NSString *rollbackDirectory)
{
    if (DO_HT_EUID() != 0) return @{@"status": @"root_access_unavailable", @"errno": @(EACCES)};
    char resolved[PATH_MAX];
    if (!root || !realpath(root.fileSystemRepresentation, resolved)) return @{@"status": @"root_unavailable"};
    NSString *canonical = [NSString stringWithUTF8String:resolved];
    NSDictionary *emptyPlan = JBHelperTransitionPlan(nil, canonical);
    if (![emptyPlan[@"status"] isEqual:@"prepared"]) return emptyPlan;
    struct stat metadata;
    if (stat(resolved, &metadata) != 0) return @{@"status": @"root_stat_failed", @"errno": @(errno)};
    int entry = jb_entry_link_matches(DO_HT_ENTRY, &metadata);
    if (entry) return @{@"status": @"entry_not_ready", @"errno": @(entry)};
    NSString *base = [canonical stringByAppendingPathComponent:@"basebin"];
    if (lstat(base.fileSystemRepresentation, &metadata) != 0 || !S_ISDIR(metadata.st_mode))
        return @{@"status": @"invalid_basebin"};
    NSString *helper = emptyPlan[@"helper"];
    if (lstat(helper.fileSystemRepresentation, &metadata) != 0 || !S_ISREG(metadata.st_mode))
        return @{@"status": @"invalid_helper"};
    NSString *config = [base stringByAppendingPathComponent:@"config.plist"];
    if (rollbackDirectory) {
        if (![rollbackDirectory isKindOfClass:NSString.class] ||
            ![rollbackDirectory.stringByDeletingLastPathComponent isEqual:base] ||
            ![rollbackDirectory.lastPathComponent hasPrefix:@".DopamineHelperTransition-"] ||
            ![rollbackDirectory isEqual:rollbackDirectory.stringByStandardizingPath] ||
            lstat(rollbackDirectory.fileSystemRepresentation, &metadata) != 0 || !S_ISDIR(metadata.st_mode))
            return @{@"status": @"invalid_backup_directory"};
        return JBTransitionRollback(config, rollbackDirectory);
    }
    int error = 0;
    NSData *original = JBTransitionRead(config, &metadata, &error);
    if (error) return @{@"status": @"config_read_failed", @"errno": @(error)};
    NSDictionary *plan = JBHelperTransitionPlan(original, canonical);
    if (![plan[@"status"] isEqual:@"prepared"]) return @{@"status": plan[@"status"]};
    if (![plan[@"added"] boolValue]) return @{@"status": @"already_configured", @"changed": @NO};
    return JBTransitionReplace(config, original, plan[@"updated"]);
}
