#!/usr/bin/env python3
"""Compile production recovery helper; tests only modify temporary fixtures."""
from pathlib import Path
import subprocess,tempfile,sys
root=Path(__file__).resolve().parents[1]
source=r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <errno.h>
static int swapCalls=0, failSwapAt=0;
static int testSwap(const char *a,const char *b,unsigned int flags) {
 swapCalls++; if(swapCalls==failSwapAt) {errno=EIO;return -1;} return renamex_np(a,b,flags);
}
#define DOJB_RENAME testSwap
#import "DOJBEntryRecovery.h"
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;} count++;}while(0)
static void writeFile(NSString *path) {
 [[NSFileManager defaultManager] createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:NULL];
 [@"fixture" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}
static NSDictionary *fixture(NSString *base,NSString *name) {
 NSString *dir=[base stringByAppendingPathComponent:name];
 NSString *entry=[dir stringByAppendingPathComponent:@"jb"];
 NSString *root=[dir stringByAppendingPathComponent:@"real/procursus"];
 writeFile([entry stringByAppendingPathComponent:@"keep-me.txt"]);
 for(NSString *p in @[@"basebin/jbctl",@"basebin/systemhook.dylib",@"Applications/Sileo.app/Sileo",@"usr/lib/libellekit.dylib",@"usr/lib/ellekit/libinjector.dylib"])
  writeFile([root stringByAppendingPathComponent:p]);
 symlink([entry stringByAppendingPathComponent:@"usr/lib/ellekit/libinjector.dylib"].fileSystemRepresentation,
         [root stringByAppendingPathComponent:@"usr/lib/TweakLoader.dylib"].fileSystemRepresentation);
 NSString *substrate=[root stringByAppendingPathComponent:@"Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"];
 [[NSFileManager defaultManager] createDirectoryAtPath:substrate.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:NULL];
 symlink([entry stringByAppendingPathComponent:@"usr/lib/libellekit.dylib"].fileSystemRepresentation,substrate.fileSystemRepresentation);
 return @{@"entry":entry,@"root":root};
}
int main(int argc,char **argv){@autoreleasepool {
 int count=0;NSString *base=[NSString stringWithUTF8String:argv[1]];
 NSDictionary *f=fixture(base,@"success");NSString *entry=f[@"entry"],*root=f[@"root"];
 struct stat original; lstat(entry.fileSystemRepresentation,&original);
 NSDictionary *result=DOJBRecoverEntry(entry,root);
 CHECK([result[@"success"] boolValue]);
 CHECK([result[@"stage"] isEqual:@"repaired_backup_preserved"]);
 CHECK(DOJBIdentity(result[@"backup"],original,NO));
 CHECK([[[NSString alloc] initWithContentsOfFile:[result[@"backup"] stringByAppendingPathComponent:@"keep-me.txt"] encoding:NSUTF8StringEncoding error:NULL] isEqual:@"fixture"]);
 struct stat st; CHECK(lstat(entry.fileSystemRepresentation,&st)==0 && S_ISLNK(st.st_mode));
 CHECK(stat([entry stringByAppendingPathComponent:@"usr/lib/TweakLoader.dylib"].fileSystemRepresentation,&st)==0);
 int calls=swapCalls;
 result=DOJBRecoverEntry(entry,root);
 CHECK([result[@"success"] boolValue] && [result[@"stage"] isEqual:@"already_correct_no_change"]);
 CHECK(swapCalls==calls);
 f=fixture(base,@"missing-library");entry=f[@"entry"];root=f[@"root"];
 unlink([root stringByAppendingPathComponent:@"usr/lib/ellekit/libinjector.dylib"].fileSystemRepresentation);
 lstat(entry.fileSystemRepresentation,&original);
 result=DOJBRecoverEntry(entry,root);
 CHECK(![result[@"success"] boolValue]);
 CHECK(DOJBIdentity(entry,original,NO));
 f=fixture(base,@"swap-failure");entry=f[@"entry"];root=f[@"root"];
 lstat(entry.fileSystemRepresentation,&original);failSwapAt=swapCalls+1;
 result=DOJBRecoverEntry(entry,root);
 CHECK([result[@"stage"] isEqual:@"atomic_swap_failed_no_change"]);
 CHECK(DOJBIdentity(entry,original,NO));
 CHECK([[[NSFileManager defaultManager] contentsOfDirectoryAtPath:entry.stringByDeletingLastPathComponent error:NULL] count]==2);
 failSwapAt=0;
 f=fixture(base,@"postflight-failure");entry=f[@"entry"];root=f[@"root"];
 unlink([root stringByAppendingPathComponent:@"usr/lib/TweakLoader.dylib"].fileSystemRepresentation);
 lstat(entry.fileSystemRepresentation,&original);
 result=DOJBRecoverEntry(entry,root);
 CHECK(![result[@"success"] boolValue] && [result[@"stage"] hasSuffix:@":rolled_back"]);
 CHECK(DOJBIdentity(entry,original,NO));
 f=fixture(base,@"rollback-failure");entry=f[@"entry"];root=f[@"root"];
 unlink([root stringByAppendingPathComponent:@"usr/lib/TweakLoader.dylib"].fileSystemRepresentation);
 lstat(entry.fileSystemRepresentation,&original);failSwapAt=swapCalls+2;
 result=DOJBRecoverEntry(entry,root);
 CHECK(![result[@"success"] boolValue] && [result[@"stage"] hasSuffix:@":manual_review_backup_preserved"]);
 CHECK(DOJBIdentity(result[@"backup"],original,NO));
 failSwapAt=0;
 f=fixture(base,@"unexpected");entry=f[@"entry"];root=f[@"root"];
 NSString *other=[entry.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"other"];
 writeFile(other);result=DOJBRecoverEntry(other,root);
 CHECK([result[@"stage"] isEqual:@"unexpected_entry_type_no_change"]);
 NSString *link=[entry.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"bad-link"];
 symlink("/no-such-fixture",link.fileSystemRepresentation);
 result=DOJBRecoverEntry(link,root);
 CHECK([result[@"stage"] isEqual:@"unexpected_symlink_no_change"]);
 NSString *missing=[entry.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"missing"];
 result=DOJBRecoverEntry(missing,root);
 CHECK([result[@"stage"] isEqual:@"entry_not_present_no_change"]);
 result=DOJBRecoverEntry(entry,missing);
 CHECK(![result[@"success"] boolValue]);
 result=DOJBRecoverEntry(entry,[entry stringByAppendingPathComponent:@"nested"]);
 CHECK(![result[@"success"] boolValue]);
 CHECK([NSJSONSerialization dataWithJSONObject:result options:0 error:NULL]!=nil);
 NSLog(@"PASS: %d atomic entry-recovery assertions (temporary fixtures only)",count);return 0;
}}
'''
if sys.platform!='darwin':
 print('SKIP: recovery tests require macOS Foundation and renamex_np.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='dopamine-recovery-test-') as tmp:
 t=Path(tmp);(t/'test.m').write_text(source)
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-Werror=return-type','-Werror=incompatible-pointer-types','-framework','Foundation','-I',str(root/'Application/Dopamine/UI/Settings'),str(t/'test.m'),'-o',str(t/'test')],check=True)
 subprocess.run([str(t/'test'),str(t)],check=True)
