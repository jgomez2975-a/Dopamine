#pragma once
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Only jbctl JSON crash reports. Never export the full report, environment,
// application list, registers, or unrelated processes' crash contents.
static NSDictionary *DOHelperCrashSummary(NSData *data)
{
    id report = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![report isKindOfClass:NSDictionary.class]) {
        // Modern IPS: a metadata JSON line followed by the report JSON.
        const unsigned char *bytes = data.bytes;
        NSUInteger split = 0;
        while (split < data.length && bytes[split] != '\n') split++;
        if (split < data.length) report = [NSJSONSerialization JSONObjectWithData:
            [data subdataWithRange:NSMakeRange(split + 1, data.length - split - 1)] options:0 error:NULL];
    }
    if (![report isKindOfClass:NSDictionary.class]) return @{@"status": @"unsupported_or_invalid_json"};
    if (![report[@"procName"] isEqual:@"jbctl"]) return @{@"status": @"not_jbctl"};
    NSMutableDictionary *result = [@{@"status": @"parsed", @"process": @"jbctl"} mutableCopy];
    for (NSString *key in @[@"captureTime", @"pid", @"parentPid", @"cpuType", @"translated", @"faultingThread"])
        if ([report[key] isKindOfClass:NSString.class] || [report[key] isKindOfClass:NSNumber.class]) result[key] = report[key];
    for (NSString *section in @[@"exception", @"termination"]) {
        NSDictionary *value = report[section];
        if (![value isKindOfClass:NSDictionary.class]) continue;
        NSMutableDictionary *safe = [NSMutableDictionary dictionary];
        for (NSString *key in @[@"type", @"signal", @"subtype", @"codes", @"namespace", @"code", @"indicator"])
            if ([value[key] isKindOfClass:NSString.class] || [value[key] isKindOfClass:NSNumber.class]) safe[key] = value[key];
        result[section] = safe;
    }
    NSArray *threads = report[@"threads"], *images = report[@"usedImages"];
    id fault = report[@"faultingThread"];
    NSDictionary *thread = nil;
    if ([threads isKindOfClass:NSArray.class] && [fault isKindOfClass:NSNumber.class] &&
        [fault integerValue] >= 0 && [fault unsignedIntegerValue] < threads.count) thread = threads[[fault unsignedIntegerValue]];
    if ([thread isKindOfClass:NSDictionary.class] && [thread[@"frames"] isKindOfClass:NSArray.class]) {
        NSMutableArray *frames = [NSMutableArray array];
        for (id frame in thread[@"frames"]) {
            if (frames.count >= 24) break;
            if (![frame isKindOfClass:NSDictionary.class]) continue;
            NSMutableDictionary *safe = [NSMutableDictionary dictionary];
            for (NSString *key in @[@"imageOffset", @"symbol", @"symbolLocation"])
                if ([frame[key] isKindOfClass:NSString.class] || [frame[key] isKindOfClass:NSNumber.class]) safe[key] = frame[key];
            id idx = frame[@"imageIndex"];
            if ([images isKindOfClass:NSArray.class] && [idx isKindOfClass:NSNumber.class] &&
                [idx integerValue] >= 0 && [idx unsignedIntegerValue] < images.count) {
                id image = images[[idx unsignedIntegerValue]];
                if ([image isKindOfClass:NSDictionary.class]) {
                    for (NSString *key in @[@"name", @"uuid", @"arch"])
                        if ([image[key] isKindOfClass:NSString.class]) safe[key] = image[key];
                }
            }
            [frames addObject:safe];
        }
        result[@"faulting_frames"] = frames;
    }
    return result;
}

static NSDictionary *DOReadHelperCrash(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return @{@"status": @"open_failed", @"errno": @(errno)};
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 || before.st_size > 2 * 1024 * 1024) {
        close(fd); return @{@"status": @"unsupported_type_or_size"};
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t count = read(fd, (char *)data.mutableBytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return @{@"status": @"read_failed"}; }
        offset += (NSUInteger)count;
    }
    BOOL stable = fstat(fd, &after) == 0 && before.st_size == after.st_size &&
        before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec;
    close(fd);
    return stable ? DOHelperCrashSummary(data) : @{@"status": @"changed_during_read"};
}

static NSArray *DOCollectHelperCrashes(NSArray<NSString *> *directories)
{
    NSMutableArray *results = [NSMutableArray array];
    for (NSString *directory in directories) {
        NSError *error = nil;
        NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:&error];
        if (!names) {
            [results addObject:@{@"directory": directory, @"status": @"listing_failed", @"error_code": @(error.code)}];
            continue;
        }
        NSMutableArray *candidates = [NSMutableArray array];
        for (NSString *name in names) {
            if (![name hasPrefix:@"jbctl-"] || ![name.pathExtension isEqual:@"ips"]) continue;
            NSString *path = [directory stringByAppendingPathComponent:name];
            struct stat st;
            if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            [candidates addObject:@{@"path": path, @"mtime": @(st.st_mtime)}];
        }
        [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [b[@"mtime"] compare:a[@"mtime"]];
        }];
        NSUInteger count = 0;
        for (NSDictionary *candidate in candidates) {
            if (count++ >= 3) break;
            NSMutableDictionary *item = [DOReadHelperCrash(candidate[@"path"]) mutableCopy];
            item[@"file"] = [candidate[@"path"] lastPathComponent];
            item[@"mtime"] = candidate[@"mtime"];
            [results addObject:item];
        }
        if (!candidates.count) [results addObject:@{@"directory": directory, @"status": @"no_matching_reports"}];
    }
    return results;
}
