#!/usr/bin/env python3
"""Compile the real persistence methods on macOS; credential wrappers are mocked.
This is not an iOS integration test and never touches real device preferences.
"""
import pathlib, subprocess, tempfile, sys
root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
methods = source.split('// AppHide persistence: begin', 1)[1]
methods = methods[methods.index('\n'):].split('// AppHide persistence: end.', 1)[0]
prelude = r'''
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
@interface DOEnvironmentManager : NSObject
@property NSString *appHideRulesPath;
@property BOOL isJailbroken;
@property BOOL denyRoot;
- (void)runAsRoot:(void (^)(void))block;
- (void)runUnsandboxed:(void (^)(void))block;
@end
@implementation DOEnvironmentManager
- (void)runAsRoot:(void (^)(void))block { if (!self.denyRoot) block(); }
- (void)runUnsandboxed:(void (^)(void))block { block(); }
'''
tests = r'''
@end
#define CHECK(condition) do { if (!(condition)) { NSLog(@"FAIL line %d: %s", __LINE__, #condition); exit(1); } passes++; } while (0)
int main(int argc, char **argv) { @autoreleasepool {
    int passes = 0;
    NSString *dir = [NSString stringWithUTF8String:argv[1]];
    NSString *path = [dir stringByAppendingPathComponent:@"rules.plist"];
    DOEnvironmentManager *m = [DOEnvironmentManager new];
    m.appHideRulesPath = path;
    m.isJailbroken = YES;
    NSError *error = nil;
    CHECK([[m appHideRulesWithError:&error] isEqual:@{}] && !error);
    CHECK([m setEnvironmentHidden:YES forBundleID:@"test.one" error:&error] && !error);
    DOEnvironmentManager *reload = [DOEnvironmentManager new];
    reload.appHideRulesPath = path;
    CHECK([reload isEnvironmentHiddenForBundleID:@"test.one"]);
    CHECK([m setEnvironmentNoInject:YES forBundleID:@"test.one" error:&error]);
    CHECK([reload isEnvironmentNoInjectForBundleID:@"test.one"]);
    CHECK([m setEnvironmentHidden:YES forBundleID:@"test.two" error:&error]);
    CHECK([m setEnvironmentHidden:NO forBundleID:@"test.one" error:&error]);
    CHECK(![reload isEnvironmentNoInjectForBundleID:@"test.one"] && ![reload isEnvironmentHiddenForBundleID:@"test.one"]);
    CHECK([reload isEnvironmentHiddenForBundleID:@"test.two"]);
    CHECK([m setEnvironmentNoInject:YES forBundleID:@"test.one" error:&error]);
    CHECK([m setEnvironmentNoInject:NO forBundleID:@"test.one" error:&error]);
    CHECK([reload isEnvironmentHiddenForBundleID:@"test.one"] && ![reload isEnvironmentNoInjectForBundleID:@"test.one"]);
    struct stat st; CHECK(stat(path.fileSystemRepresentation, &st) == 0 && (st.st_mode & 0777) == 0644);
    NSData *before = [NSData dataWithContentsOfFile:path];
    m.denyRoot = YES;
    CHECK(![m setEnvironmentHidden:YES forBundleID:@"test.denied" error:&error] && error);
    CHECK([[NSData dataWithContentsOfFile:path] isEqual:before]);
    m.denyRoot = NO;
    CHECK(![m setEnvironmentHidden:YES forBundleID:@"" error:&error] && error);
    [@"not a plist" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    before = [NSData dataWithContentsOfFile:path];
    CHECK([m appHideRulesWithError:&error] == nil && error);
    CHECK(![m setEnvironmentHidden:YES forBundleID:@"test.one" error:&error]);
    CHECK([[NSData dataWithContentsOfFile:path] isEqual:before]);
    [@{@"test.one": @"bad type"} writeToFile:path atomically:YES];
    CHECK([m appHideRulesWithError:&error] == nil && error);
    [@{@"test.one": @{@"HideEnvironment": @"bad flag"}} writeToFile:path atomically:YES];
    CHECK([m appHideRulesWithError:&error] == nil && error);
    m.appHideRulesPath = dir; // directory, not a file
    CHECK(![m setEnvironmentHidden:YES forBundleID:@"test.one" error:&error] && error);
    m.appHideRulesPath = [dir stringByAppendingPathComponent:@"missing-parent/rules.plist"];
    CHECK(![m setEnvironmentHidden:YES forBundleID:@"test.one" error:&error] && error);
    m.appHideRulesPath = path;
    [@{@"test.one": @{@"Custom": @"preserve", @"HideEnvironment": @YES}} writeToFile:path atomically:YES];
    CHECK([m setEnvironmentHidden:NO forBundleID:@"test.one" error:&error]);
    CHECK([[[m appHideRules][@"test.one"] objectForKey:@"Custom"] isEqual:@"preserve"]);
    dispatch_apply(12, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t i) {
        @autoreleasepool { NSError *e = nil;
            BOOL ok = [m setEnvironmentHidden:YES forBundleID:[NSString stringWithFormat:@"parallel.%zu", i] error:&e];
            if (!ok) abort();
        }
    });
    CHECK([m appHideRules].count == 13);
    NSLog(@"PASS: %d persistence assertions (credential wrappers mocked)", passes);
    return 0;
}}
'''
if sys.platform != 'darwin':
    print('SKIP: Objective-C Foundation tests require macOS; run in GitHub Actions.')
    sys.exit(0)
with tempfile.TemporaryDirectory(prefix='dopamine-apphide-') as tmp:
    tmp = pathlib.Path(tmp)
    src = tmp / 'test.m'; binary = tmp / 'test'
    src.write_text(prelude + methods + tests)
    subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-Werror=return-type','-Werror=incompatible-pointer-types','-framework','Foundation',str(src),'-o',str(binary)], check=True)
    subprocess.run([str(binary),str(tmp)], check=True)
