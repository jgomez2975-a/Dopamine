#!/usr/bin/env python3
"""Read-only diagnostic probe tests. Runs only on macOS Foundation."""
from pathlib import Path
import subprocess,tempfile,sys
root=Path(__file__).resolve().parents[1]
source=r'''
#import "DOReadOnlyDiagnostics.h"
#define CHECK(x) do { if (!(x)) { NSLog(@"FAIL %d %s", __LINE__, #x); return 1; } count++; } while(0)
int main(int argc,char **argv) { @autoreleasepool {
 int count=0; NSString *dir=[NSString stringWithUTF8String:argv[1]];
 NSString *file=[dir stringByAppendingPathComponent:@"data"];
 NSData *original=[@"original" dataUsingEncoding:NSUTF8StringEncoding];
 [original writeToFile:file atomically:YES];
 NSDictionary *info=DODiagnosticPath(file);
 CHECK([info[@"size"] integerValue]==8);
 CHECK([info[@"target_exists"] boolValue]);
 CHECK([DODiagnosticPath(dir)[@"type"] isEqual:@"directory"]);
 NSString *link=[dir stringByAppendingPathComponent:@"link"];
 symlink(file.fileSystemRepresentation,link.fileSystemRepresentation);
 CHECK([DODiagnosticPath(link)[@"type"] isEqual:@"symlink"]);
 CHECK([DODiagnosticPath(link)[@"target"] isEqual:file]);
 CHECK([DODiagnosticPath([dir stringByAppendingPathComponent:@"missing"])[@"lstat_errno"] intValue]==ENOENT);
 NSString *broken=[dir stringByAppendingPathComponent:@"broken"];
 symlink("/missing-dopamine-diagnostic-target",broken.fileSystemRepresentation);
 CHECK([DODiagnosticPath(broken)[@"target_stat_errno"] intValue]==ENOENT);
 CHECK(DODiagnosticMount(dir)[@"mounted_on"]!=nil);
 NSString *log=[dir stringByAppendingPathComponent:@"test.log"];
 [@"unrelated private line\nglobal_hide: refcount now 1\nglobal_restore: refcount 0\nentry_guard_v1: restore blocked\nentry_state_v2: launchdhook initialized\nentry_state_v2: pid_release result=0\n" writeToFile:log atomically:YES encoding:NSUTF8StringEncoding error:NULL];
 NSData *before=[NSData dataWithContentsOfFile:log];
 NSDictionary *result=DODiagnosticLog(log);
 CHECK([result[@"filtered_tail"] count]==5);
 CHECK([[result[@"filtered_tail"] componentsJoinedByString:@"\n"] containsString:@"entry_guard_v1"]);
 CHECK([[result[@"filtered_tail"] componentsJoinedByString:@"\n"] containsString:@"entry_state_v2: launchdhook initialized"]);
 CHECK([[NSData dataWithContentsOfFile:log] isEqual:before]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 NSMutableString *large=[NSMutableString string];
 for(int i=0;i<100;i++) [large appendFormat:@"global_restore: %d\n",i];
 [large writeToFile:log atomically:YES encoding:NSUTF8StringEncoding error:NULL];
 CHECK([DODiagnosticLog(log)[@"filtered_tail"] count]==80);
 CHECK(DODiagnosticLog([dir stringByAppendingPathComponent:@"absent.log"])[@"error"]!=nil);
 CHECK([NSJSONSerialization dataWithJSONObject:result options:0 error:NULL]!=nil);
 NSString *q=[dir stringByAppendingPathComponent:@"quarantine"];
 CHECK([[NSFileManager defaultManager] createDirectoryAtPath:q withIntermediateDirectories:NO attributes:nil error:NULL]);
 NSString *saved=[q stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
 CHECK([original writeToFile:saved atomically:YES]);
 NSArray *map=@[@{@"src":file,@"dst":saved}];
 NSDictionary *conflicts=DODiagnosticConflicts(map,q,@[file]);
 CHECK([conflicts[@"items"] count]==1);
 CHECK([conflicts[@"items"][0][@"state"] isEqual:@"both_present"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 CHECK([[NSData dataWithContentsOfFile:saved] isEqual:original]);
 CHECK(unlink(file.fileSystemRepresentation)==0);
 CHECK([DODiagnosticConflicts(map,q,@[file])[@"items"][0][@"state"] isEqual:@"quarantine_only"]);
 CHECK(unlink(saved.fileSystemRepresentation)==0);
 CHECK([DODiagnosticConflicts(map,q,@[file])[@"items"][0][@"state"] isEqual:@"both_missing"]);
 CHECK([original writeToFile:file atomically:YES]);
 CHECK([DODiagnosticConflicts(map,q,@[file])[@"items"][0][@"state"] isEqual:@"original_only"]);
 CHECK([DODiagnosticConflicts(map,q,@[]) [@"items"] count]==0);
 CHECK([DODiagnosticConflicts(@[@{@"src":file,@"dst":file}],q,@[file])[@"rejected_entries"] intValue]==1);
 CHECK([DODiagnosticConflicts(@[@{@"src":file,@"dst":[q stringByAppendingPathComponent:@"../escape"]}],q,@[file])[@"rejected_entries"] intValue]==1);
 CHECK([DODiagnosticConflicts(@[@1],q,@[file])[@"rejected_entries"] intValue]==1);
 CHECK([DODiagnosticConflicts(@{},q,@[file])[@"status"] isEqual:@"unreadable_map"]);
 CHECK([NSJSONSerialization dataWithJSONObject:conflicts options:0 error:NULL]!=nil);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 NSLog(@"PASS: %d read-only diagnostic assertions",count); return 0;
}}
'''
if sys.platform!='darwin':
 print('SKIP: diagnostic tests require macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='dopamine-diag-test-') as tmp:
 t=Path(tmp);(t/'test.m').write_text(source)
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-Werror=return-type','-Werror=incompatible-pointer-types','-framework','Foundation','-I',str(root/'Application/Dopamine/UI/Settings'),str(t/'test.m'),'-o',str(t/'test')],check=True)
 subprocess.run([str(t/'test'),str(t)],check=True)
