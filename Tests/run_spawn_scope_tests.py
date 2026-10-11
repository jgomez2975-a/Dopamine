#!/usr/bin/env python3
"""Source scope guards everywhere; real denial formatter execution on macOS.

Source guards are not proof of runtime isolation or detection resistance.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
spawn = (root / 'BaseBin/launchdhook/src/spawn_hook.m').read_text(encoding='utf8')
impl = (root / 'BaseBin/launchdhook/src/app_hide.m').read_text(encoding='utf8')
diag = (root / 'Application/Dopamine/UI/Settings/DOReadOnlyDiagnostics.h').read_text(encoding='utf8')

def block(text, marker):
    start = text.index(marker)
    i = text.index('{', start)
    depth = 1
    end = i + 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[start:end]

denied = block(spawn, 'if (hideResult != 0)')
assert 'app_hide_record_spawn_denial(path, darwinRole, hideResult);' in denied
assert 'return hideResult;' in denied
assert '__posix_spawn_orig_wrapper' not in denied
local = spawn[spawn.index('// ★ 按 App 隐藏'):spawn.index('void initSpawnHooks')]
for forbidden in ('app_hide_begin_spawn(', 'app_hide_global_hide(', 'unlink(',
                  'unmount(', 'app_hide_run_jbctl(', 'app_hide_cancel_spawn('):
    assert forbidden not in local, forbidden
assert '"DOPAMINE_APP_HIDE", "1"' in local
assert '"DYLD_INSERT_LIBRARIES", HOOK_DYLIB_PATH' in local
assert '@"app_hide_spawn_v1"' in diag
fn = block(impl, 'void app_hide_record_spawn_denial(')
assert 'errno = savedErrno;' in fn
assert 'argv' not in fn.replace('// No argv, environment, full container paths, or preference contents in the log.', '')
print('PASS: source scope guards (not runtime isolation tests)', flush=True)

if sys.platform != 'darwin':
    print('SKIP: actual Objective-C denial formatter execution requires macOS Foundation.')
    sys.exit(0)

code = r'''#import <Foundation/Foundation.h>
#include <errno.h>
static NSString *lastLine;
static void app_hide_log(NSString *line) { lastLine = [line copy]; errno = EIO; }
''' + fn + r'''
#define CHECK(x) do { if (!(x)) { NSLog(@"FAIL %d: %s", __LINE__, #x); return 1; } count++; } while(0)
int main(int argc, char **argv) { @autoreleasepool {
    int count=0;
    NSString *dir = [NSString stringWithUTF8String:argv[1]];
    NSString *app = [dir stringByAppendingPathComponent:@"Fixture.app"];
    CHECK([[NSFileManager defaultManager] createDirectoryAtPath:app withIntermediateDirectories:NO attributes:nil error:NULL]);
    NSString *info = [app stringByAppendingPathComponent:@"Info.plist"];
    NSString *exe = [app stringByAppendingPathComponent:@"Fixture"];
    CHECK([@{@"CFBundleIdentifier": @"test.scope.fixture"} writeToFile:info atomically:YES]);
    NSData *before = [NSData dataWithContentsOfFile:info];
    errno=EACCES;
    app_hide_record_spawn_denial(exe.fileSystemRepresentation, 1, EBUSY);
    CHECK(errno==EACCES);
    CHECK([lastLine containsString:@"bundle=test.scope.fixture"]);
    CHECK([lastLine containsString:@"stage=begin_denied"]);
    CHECK([lastLine containsString:@"child_spawned=0"]);
    CHECK(![lastLine containsString:dir]);
    CHECK([[NSData dataWithContentsOfFile:info] isEqual:before]);
    for (id value in @[@17, @"forged\nentry_state_v2", @"", [@"x" stringByPaddingToLength:256 withString:@"x" startingAtIndex:0]]) {
        CHECK([@{@"CFBundleIdentifier": value} writeToFile:info atomically:YES]);
        app_hide_record_spawn_denial(exe.fileSystemRepresentation, -1, EBUSY);
        CHECK([lastLine containsString:@"bundle=unknown"]);
        CHECK(![lastLine containsString:@"\n"]);
    }
    app_hide_record_spawn_denial(NULL, -1, EIO);
    CHECK([lastLine containsString:@"bundle=unknown"]);
    NSLog(@"PASS: %d actual denial formatter assertions", count);
    return 0;
}}
'''
with tempfile.TemporaryDirectory(prefix='dopamine-spawn-scope-') as tmp:
    tmp = Path(tmp)
    src = tmp / 'test.m'
    src.write_text(code, encoding='utf8')
    binary = tmp / 'test'
    subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-Werror=return-type',
                    '-framework', 'Foundation', str(src), '-o', str(binary)], check=True)
    subprocess.run([str(binary), str(tmp)], check=True)
