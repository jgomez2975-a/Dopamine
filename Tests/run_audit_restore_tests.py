#!/usr/bin/env python3
"""Execute production quarantine restoration against temporary macOS fixtures.

Only paths/logging are substituted. Never touches device or host user data.
Windows checks extraction only, and reports a runtime SKIP, not a PASS.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
source = (repo / 'BaseBin/jbctl/src/hide_global.m').read_text(encoding='utf8')
body = (repo / 'Shared/JBQuarantine.h').read_text(encoding='utf8')
public = source[source.index('int hide_global_audit_restore(void)'):]
assert 'int result = restoreHiddenItems();' in public
assert 'return auditWithLock(' in public
assert 'if (result != 0) return result;' in body
assert body.index('if (result != 0) return result;', body.index('static inline int restoreHiddenItems')) < body.index('removeItemAtPath:hideMapPath()')

program = r'''
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
static NSString *fixture;
#define JBQ_ROOT [fixture stringByAppendingPathComponent:@"quarantine"]
#define JBQ_LOG(message) ((void)(message))
#import "JBQuarantine.h"
''' + public + r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } count++; } while(0)
static BOOL put(NSString *path, NSString *text) {
 return [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
static NSString *get(NSString *path) {
 return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
}
int main(int argc, char **argv) { @autoreleasepool {
 if (argc != 2) return 2;
 fixture = [NSString stringWithUTF8String:argv[1]];
 NSFileManager *fm = [NSFileManager defaultManager]; int count = 0;
 CHECK([fm createDirectoryAtPath:hideQuarantineRoot() withIntermediateDirectories:YES attributes:nil error:nil]);
 NSString *src = [fixture stringByAppendingPathComponent:@"original"];
 NSString *dst = [hideQuarantineRoot() stringByAppendingPathComponent:@"copy"];
 NSArray *map = @[@{@"src":src, @"dst":dst}];
 CHECK(hide_global_audit_restore() == 0); // no journal
 CHECK(put(hideMapPath(), @"malformed"));
 CHECK(hide_global_audit_restore() != 0);
 CHECK([get(hideMapPath()) isEqualToString:@"malformed"]);
 CHECK([map writeToFile:hideMapPath() atomically:YES]);
 CHECK(hide_global_audit_restore() != 0); // both missing
 CHECK(auditPathState(hideMapPath()) == 1);
 CHECK(put(src,@"new") && put(dst,@"old"));
 CHECK(hide_global_audit_restore() == EEXIST);
 CHECK([get(src) isEqualToString:@"new"] && [get(dst) isEqualToString:@"old"]);
 CHECK(auditPathState(hideMapPath()) == 1);
 CHECK(unlink(src.fileSystemRepresentation) == 0);
 CHECK(symlink("/nonexistent-audit-fixture",src.fileSystemRepresentation) == 0);
 CHECK(hide_global_audit_restore() == EEXIST); // dangling symlink is occupied
 CHECK(auditPathState(dst) == 1 && auditPathState(hideMapPath()) == 1);
 CHECK(unlink(src.fileSystemRepresentation) == 0);
 CHECK(hide_global_audit_restore() == 0);
 CHECK([get(src) isEqualToString:@"old"] && auditPathState(dst) == 0);
 CHECK(auditPathState(hideMapPath()) == 0);
 CHECK([map writeToFile:hideMapPath() atomically:YES]); // crash after move before journal cleanup
 CHECK(hide_global_audit_restore() == 0 && [get(src) isEqualToString:@"old"]);

 // A parent that is a file must not cause journal loss.
 NSString *blocked = [src stringByAppendingPathComponent:@"child"];
 CHECK(put(dst,@"blocked-copy"));
 NSArray *blockedMap = @[@{@"src":blocked,@"dst":dst}];
 CHECK([blockedMap writeToFile:hideMapPath() atomically:YES]);
 CHECK(hide_global_audit_restore() != 0);
 CHECK([get(dst) isEqualToString:@"blocked-copy"] && auditPathState(hideMapPath()) == 1);

 // Validate all records before any move, including malformed records.
 NSArray *badMap = @[@{@"src":@42,@"dst":dst},@{@"src":blocked,@"dst":dst}];
 CHECK([badMap writeToFile:hideMapPath() atomically:YES]);
 CHECK(hide_global_audit_restore() == EINVAL && auditPathState(dst) == 1);
 NSArray *outside = @[@{@"src":blocked,@"dst":src}];
 CHECK([outside writeToFile:hideMapPath() atomically:YES]);
 CHECK(hide_global_audit_restore() == EINVAL && [get(src) isEqualToString:@"old"]);

 // Partial success retains the complete journal and supports a subsequent retry.
 NSString *src2 = [fixture stringByAppendingPathComponent:@"second"];
 NSString *dst2 = [hideQuarantineRoot() stringByAppendingPathComponent:@"second-copy"];
 CHECK(put(dst2,@"second-data"));
 NSArray *mixed = @[@{@"src":src,@"dst":dst},@{@"src":src2,@"dst":dst2}];
 CHECK([mixed writeToFile:hideMapPath() atomically:YES]);
 CHECK(hide_global_audit_restore() != 0);
 CHECK([get(src2) isEqualToString:@"second-data"] && auditPathState(dst2) == 0);
 CHECK([[NSArray arrayWithContentsOfFile:hideMapPath()] isEqualToArray:mixed]);
 CHECK(unlink(src.fileSystemRepresentation) == 0);
 CHECK(hide_global_audit_restore() == 0);
 CHECK([get(src) isEqualToString:@"blocked-copy"] && [get(src2) isEqualToString:@"second-data"]);
 CHECK(auditPathState(hideMapPath()) == 0);
 printf("PASS: %d production audit restore assertions (temporary files only)\n",count);
 return 0;
}}
'''
if sys.platform != 'darwin':
    print('Source extraction/checks OK; SKIP runtime: macOS Foundation required.')
    sys.exit(0)
with tempfile.TemporaryDirectory(prefix='audit-restore-') as td:
    p = Path(td)
    (p / 'test.m').write_text(program, encoding='utf8')
    subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation',
                    '-Wall','-Wextra','-Werror','-fblocks','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test'),td],check=True)
