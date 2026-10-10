#!/usr/bin/env python3
"""Read-only, allowlisted jbctl IPS extraction; no device operations."""
from pathlib import Path
import subprocess, tempfile, sys
repo = Path(__file__).resolve().parents[1]
source = r'''#import "DOHelperCrashDiagnostics.h"
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
static NSData *encode(id value) { return [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL]; }
int main(int argc, char **argv) { @autoreleasepool {
 int count=0; NSString *dir=[NSString stringWithUTF8String:argv[1]];
 NSDictionary *report=@{@"procName":@"jbctl", @"pid":@42, @"faultingThread":@0,
 @"exception":@{@"signal":@"SIGBUS", @"type":@"EXC_BAD_ACCESS", @"private":@"SECRET"},
 @"termination":@{@"namespace":@"SIGNAL", @"code":@10}, @"private":@"SECRET",
 @"threads":@[@{@"frames":@[@{@"imageIndex":@0,@"imageOffset":@123,@"symbol":@"main"}], @"registers":@"SECRET"}],
 @"usedImages":@[@{@"name":@"jbctl",@"uuid":@"test-uuid",@"arch":@"arm64e",@"path":@"/SECRET"}]};
 NSData *raw=encode(report); NSDictionary *s=DOHelperCrashSummary(raw);
 CHECK([s[@"status"] isEqual:@"parsed"]);
 CHECK([s[@"exception"][@"signal"] isEqual:@"SIGBUS"]);
 CHECK([s[@"termination"][@"code"] intValue]==10);
 CHECK([s[@"faulting_frames"] count]==1);
 CHECK([s[@"faulting_frames"][0][@"uuid"] isEqual:@"test-uuid"]);
 CHECK(![[[NSString alloc] initWithData:encode(s) encoding:NSUTF8StringEncoding] containsString:@"SECRET"]);
 NSMutableData *ips=[[@"{\"app_name\":\"jbctl\"}\n" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy]; [ips appendData:raw];
 CHECK([DOHelperCrashSummary(ips)[@"status"] isEqual:@"parsed"]);
 CHECK([DOHelperCrashSummary([@"bad" dataUsingEncoding:NSUTF8StringEncoding])[@"status"] isEqual:@"unsupported_or_invalid_json"]);
 CHECK([DOHelperCrashSummary(encode(@{@"procName":@"Preferences"}))[@"status"] isEqual:@"not_jbctl"]);
 NSMutableDictionary *bad=[report mutableCopy];bad[@"faultingThread"]=@99;
 CHECK(DOHelperCrashSummary(encode(bad))[@"faulting_frames"]==nil);
 bad[@"faultingThread"]=@-1;
 CHECK(DOHelperCrashSummary(encode(bad))[@"faulting_frames"]==nil);
 bad[@"faultingThread"]=@0;bad[@"threads"]=@[@"wrong-type"];
 CHECK(DOHelperCrashSummary(encode(bad))[@"faulting_frames"]==nil);
 NSString *file=[dir stringByAppendingPathComponent:@"jbctl-test.ips"];
 CHECK([ips writeToFile:file atomically:YES]);
 CHECK([DOReadHelperCrash(file)[@"status"] isEqual:@"parsed"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:ips]);
 CHECK([DOReadHelperCrash([dir stringByAppendingPathComponent:@"absent"])[@"status"] isEqual:@"open_failed"]);
 NSString *link=[dir stringByAppendingPathComponent:@"jbctl-link.ips"];
 CHECK(symlink(file.fileSystemRepresentation,link.fileSystemRepresentation)==0);
 CHECK([DOReadHelperCrash(link)[@"status"] isEqual:@"open_failed"]);
 NSString *fifo=[dir stringByAppendingPathComponent:@"jbctl-fifo.ips"];
 CHECK(mkfifo(fifo.fileSystemRepresentation,0600)==0);
 CHECK([DOReadHelperCrash(fifo)[@"status"] isEqual:@"unsupported_type_or_size"]);
 CHECK([DOCollectHelperCrashes(@[dir]) count]==1);
 for(int i=0;i<5;i++) [ips writeToFile:[dir stringByAppendingPathComponent:[NSString stringWithFormat:@"jbctl-%d.ips",i]] atomically:YES];
 CHECK([DOCollectHelperCrashes(@[dir]) count]==3);
 CHECK([DOCollectHelperCrashes(@[[dir stringByAppendingPathComponent:@"absent"]])[0][@"status"] isEqual:@"listing_failed"]);
 NSString *huge=[dir stringByAppendingPathComponent:@"huge"];
 [[NSMutableData dataWithLength:2*1024*1024+1] writeToFile:huge atomically:YES];
 CHECK([DOReadHelperCrash(huge)[@"status"] isEqual:@"unsupported_type_or_size"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:ips]);
 printf("PASS: %d read-only helper crash assertions\n",count);return 0;
}}
'''
if sys.platform != 'darwin':
    print('SKIP: helper crash tests require macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='helper-crash-') as td:
    path=Path(td);(path/'test.m').write_text(source)
    subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Werror=return-type','-Werror=incompatible-pointer-types','-I',str(repo/'Application/Dopamine/UI/Settings'),str(path/'test.m'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test'),td],check=True)
