#pragma once
#import <Foundation/Foundation.h>
#import "DOComponentIdentity.h"
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>

// Read-only metadata and fixed-component hashes; no recursive traversal or scripts.
static NSDictionary *DODiagnosticPath(NSString *path)
{
    NSMutableDictionary *result = [@{@"path": path} mutableCopy];
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        result[@"lstat_errno"] = @(errno);
        return result;
    }
    result[@"mode"] = [NSString stringWithFormat:@"%04o", st.st_mode & 07777];
    result[@"uid"] = @(st.st_uid);
    result[@"gid"] = @(st.st_gid);
    result[@"size"] = @(st.st_size);
    result[@"mtime"] = @(st.st_mtime);
    result[@"type"] = S_ISLNK(st.st_mode) ? @"symlink" : S_ISDIR(st.st_mode) ? @"directory" : @"file";
    if (S_ISLNK(st.st_mode)) {
        char target[4097];
        ssize_t n = readlink(path.fileSystemRepresentation, target, sizeof(target) - 1);
        if (n < 0) result[@"readlink_errno"] = @(errno);
        else { target[n] = 0; result[@"target"] = [NSString stringWithUTF8String:target] ?: @"<invalid UTF8>"; }
    }
    if (stat(path.fileSystemRepresentation, &st) != 0) result[@"target_stat_errno"] = @(errno);
    else result[@"target_exists"] = @YES;
    return result;
}

static NSDictionary *DODiagnosticMount(NSString *path)
{
    struct statfs fs;
    if (statfs(path.fileSystemRepresentation, &fs) != 0) return @{@"path": path, @"errno": @(errno)};
    return @{@"path": path,
        @"mounted_on": [NSString stringWithUTF8String:fs.f_mntonname] ?: @"?",
        @"mounted_from": [NSString stringWithUTF8String:fs.f_mntfromname] ?: @"?",
        @"filesystem": [NSString stringWithUTF8String:fs.f_fstypename] ?: @"?",
        @"flags": @(fs.f_flags)};
}

static NSDictionary *DODiagnosticLog(NSString *path)
{
    NSError *error = nil;
    NSFileHandle *file = [NSFileHandle fileHandleForReadingFromURL:[NSURL fileURLWithPath:path] error:&error];
    if (!file) return @{@"path": path, @"error": error.localizedDescription ?: @"open failed"};
    @try {
        unsigned long long size = [file seekToEndOfFile];
        [file seekToFileOffset:size > 65536 ? size - 65536 : 0];
        NSData *data = [file readDataOfLength:65536];
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!text) text = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        NSMutableArray *selected = [NSMutableArray array];
        NSArray *needles = @[@"manual_entry_v1", @"audit_transaction_v2", @"audit_restore_v1", @"entry_guard_v1", @"entry_state_v2", @"global_hide", @"global_restore", @"resurrect", @"watch_exit", @"appstate_check",
            @"Sileo", @"sileo", @"ellekit", @"ElleKit", @".safe_mode", @"fakelib", @"DopamineAppHideRules"];
        for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
            for (NSString *needle in needles) {
                if ([line containsString:needle]) {
                    [selected addObject:line.length > 1000 ? [line substringToIndex:1000] : line];
                    break;
                }
            }
        }
        if (selected.count > 80) [selected removeObjectsInRange:NSMakeRange(0, selected.count - 80)];
        return @{@"path": path, @"size": @(size), @"filtered_tail": selected};
    } @catch (NSException *exception) {
        return @{@"path": path, @"error": exception.reason ?: @"read failed"};
    } @finally { [file closeFile]; }
}

static NSDictionary *DOCollectEnvironmentDiagnostics(NSString *root)
{
    NSMutableArray *paths = [NSMutableArray array];
    NSArray *fixed = @[@"/var/jb", @"/usr/lib/systemhook.dylib", @"/var/mobile/.DopamineHideQuarantine/map.plist",
        @"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist", @"/var/mobile/.DopamineMonitorDidHide",
        @"/var/mobile/.DopamineCrashReporterDisabled"];
    for (NSString *path in fixed) [paths addObject:DODiagnosticPath(path)];
    NSArray *relative = @[@"basebin/.safe_mode", @"basebin/.version", @"basebin/launchdhook.dylib",
        @"basebin/systemhook.dylib", @"basebin/jbctl", @"basebin/forkfix.dylib",
        @"usr/lib/ellekit", @"usr/lib/ellekit/libellekit.dylib", @"usr/lib/libellekit.dylib",
        @"usr/lib/TweakLoader.dylib", @"usr/lib/ellekit/libinjector.dylib", @"usr/lib/TweakInject", @"Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        @"Library/MobileSubstrate/DynamicLibraries", @"Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
        @"Library/PreferenceBundles", @"Library/PreferenceLoader/Preferences", @"Applications/Sileo.app",
        @"Applications/Sileo.app/Sileo", @"Applications/Sileo.app/Info.plist",
        @"var/lib/dpkg/info/ellekit.list", @"var/lib/dpkg/info/org.coolstar.sileo.postinst"];
    for (NSString *base in root.length ? @[@"/var/jb", root] : @[@"/var/jb"]) {
        for (NSString *suffix in relative) [paths addObject:DODiagnosticPath([base stringByAppendingPathComponent:suffix])];
    }
    NSString *rulesPath = @"/var/mobile/Library/Preferences/.DopamineAppHideRules.plist";
    NSDictionary *rules = [NSDictionary dictionaryWithContentsOfFile:rulesPath];
    NSMutableDictionary *ruleSummary = [NSMutableDictionary dictionary];
    NSUInteger hidden = 0, noInject = 0;
    if ([rules isKindOfClass:NSDictionary.class]) {
        for (id key in rules) {
            id entry = rules[key];
            if (![entry isKindOfClass:NSDictionary.class]) continue;
            id h = entry[@"HideEnvironment"], n = entry[@"HideNoInject"];
            if ([h isKindOfClass:NSNumber.class] && [h boolValue]) hidden++;
            if ([n isKindOfClass:NSNumber.class] && [n boolValue]) noInject++;
        }
        ruleSummary[@"readable"] = @YES;
        ruleSummary[@"entries"] = @(rules.count);
        ruleSummary[@"hidden_count"] = @(hidden);
        ruleSummary[@"no_inject_count"] = @(noInject);
        // Only inspect rules for the management apps, not the user's app list.
        for (NSString *key in @[@"com.apple.Preferences", @"com.opa334.Dopamine", @"org.coolstar.SileoStore"]) {
            id entry = rules[key];
            if ([entry isKindOfClass:NSDictionary.class]) {
                NSMutableDictionary *flags = [NSMutableDictionary dictionary];
                for (NSString *flag in @[@"HideEnvironment", @"HideNoInject"]) {
                    if ([entry[flag] isKindOfClass:NSNumber.class]) flags[flag] = entry[flag];
                }
                ruleSummary[key] = flags;
            }
        }
    } else ruleSummary[@"readable"] = @NO;
    id map = [NSArray arrayWithContentsOfFile:@"/var/mobile/.DopamineHideQuarantine/map.plist"];
    NSMutableArray *relevant = [NSMutableArray array];
    if ([map isKindOfClass:NSArray.class]) {
        for (id item in map) {
            if (![item isKindOfClass:NSDictionary.class]) continue;
            NSString *src = item[@"src"], *dst = item[@"dst"];
            if (![src isKindOfClass:NSString.class] || ![dst isKindOfClass:NSString.class]) continue;
            BOOL known = [src isEqualToString:@"/var/mobile/Library/Sileo"] ||
                [src isEqualToString:@"/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist"];
            NSString *safeDestination = dst.stringByStandardizingPath;
            if (known && [safeDestination hasPrefix:@"/var/mobile/.DopamineHideQuarantine/"] && relevant.count < 32) {
                [relevant addObject:@{@"original": DODiagnosticPath(src), @"quarantined": DODiagnosticPath(safeDestination)}];
            }
        }
    }
    return @{@"root": root ?: @"<unavailable>", @"euid": @(geteuid()), @"paths": paths,
        @"component_identity": DOComponentIdentity(root, NSBundle.mainBundle.bundlePath),
        @"mounts": @[DODiagnosticMount(@"/usr/lib"), DODiagnosticMount(@"/var/jb")],
        @"rule_summary": ruleSummary,
        @"quarantine_map_readable": @([map isKindOfClass:NSArray.class]),
        @"quarantine_entries": @([map isKindOfClass:NSArray.class] ? [map count] : 0),
        @"quarantine_relevant": relevant,
        @"logs": @[DODiagnosticLog(@"/var/mobile/Documents/noinject_log.txt"), DODiagnosticLog(@"/var/mobile/audit_log.txt")]};
}
