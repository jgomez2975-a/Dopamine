#!/usr/bin/env python3
"""Compile actual conflict resolver; only UID, fixed paths and failure points stubbed."""
from pathlib import Path
import subprocess,tempfile,sys
repo=Path(__file__).resolve().parents[1]
ui=(repo/'Application/Dopamine/UI/Settings/DOSettingsController.m').read_text(encoding='utf8')
body=ui.split('- (void)performQuarantineConflictRecovery\n',1)[1].split('- (void)helperTransitionPressed',1)[0]
assert 'DOResolveKnownQuarantineConflicts()' in body
assert all(x not in body for x in ['rebootUserspace','updateEnvironment','spawnJbctl','removeItemAtPath'])
source=r"""
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
static NSString *fixtureRoot;
static NSArray *fixtureSources;
static uid_t pretendUID=0;
static uid_t fakeUID(void){ return pretendUID; }
static int exchangeMode=0;
static BOOL failSync=NO;
static int testSync(int fd){if(failSync){errno=EIO;return -1;}return fsync(fd);}
#define fsync testSync
static int testExchange(const char *a,const char *b,unsigned int flags){
 if(exchangeMode==1){errno=EIO;return -1;}
 if(exchangeMode==2)_exit(72);
 int r=renamex_np(a,b,flags);
 if(exchangeMode==3)_exit(r==0?73:74);
 return r;
}
#define JB_TRANSITION_EXCHANGE testExchange
#define DO_QC_ROOT fixtureRoot
#define DO_QC_SOURCES fixtureSources
#define DO_QC_UID fakeUID
#import "DOQuarantineConflictRecovery.h"
#define CHECK(x) do{if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
static NSData *encode(id value){return [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];}
static NSData *readData(NSString *p){return [NSData dataWithContentsOfFile:p];}
int main(int argc,char **argv){@autoreleasepool{(void)argc;int count=0;
 NSString *dir=[NSString stringWithUTF8String:argv[1]];
 fixtureRoot=[dir stringByAppendingPathComponent:@"quarantine"];
 NSString *live=[dir stringByAppendingPathComponent:@"cpu.plist"],*cache=[dir stringByAppendingPathComponent:@"cache"];
 fixtureSources=@[live,cache];
 pretendUID=501;CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"root_access_unavailable"]);pretendUID=0;
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"invalid_quarantine_root"]);
 CHECK(mkdir(fixtureRoot.fileSystemRepresentation,0700)==0);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"map_unavailable"]);
 NSString *old=[fixtureRoot stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
 NSString *oldCache=[fixtureRoot stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
 NSString *unrelated=[dir stringByAppendingPathComponent:@"unrelated"],*unrelatedOld=[fixtureRoot stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
 NSData *currentData=encode(@{@"current":@1}),*oldData=encode(@{@"old":@2});
 CHECK([currentData writeToFile:live atomically:YES]);CHECK([oldData writeToFile:old atomically:YES]);
 CHECK(mkdir(cache.fileSystemRepresentation,0700)==0);CHECK(mkdir(oldCache.fileSystemRepresentation,0700)==0);
 NSString *currentChild=[cache stringByAppendingPathComponent:@"current"],*oldChild=[oldCache stringByAppendingPathComponent:@"old"];
 CHECK([currentData writeToFile:currentChild atomically:YES]);CHECK([oldData writeToFile:oldChild atomically:YES]);
 CHECK([currentData writeToFile:unrelated atomically:YES]);CHECK([oldData writeToFile:unrelatedOld atomically:YES]);
 NSArray *map=@[@{@"src":live,@"dst":old},@{@"src":cache,@"dst":oldCache},@{@"src":unrelated,@"dst":unrelatedOld}];
 NSString *mapPath=[fixtureRoot stringByAppendingPathComponent:@"map.plist"];
 NSData *originalMap=encode(map);CHECK([originalMap writeToFile:mapPath atomically:YES]);
 int lock=open([fixtureRoot stringByAppendingPathComponent:@".transaction.lock"].fileSystemRepresentation,O_RDWR);
 CHECK(lock>=0);CHECK(flock(lock,LOCK_EX|LOCK_NB)==0);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"busy"]);flock(lock,LOCK_UN);close(lock);
 CHECK([readData(mapPath) isEqual:originalMap]);
 failSync=YES;NSDictionary *syncFailure=DOResolveKnownQuarantineConflicts();failSync=NO;
 CHECK([syncFailure[@"status"] isEqual:@"preparation_failed"]);
 CHECK(![syncFailure[@"changed"] boolValue]);CHECK([readData(mapPath) isEqual:originalMap]);
 exchangeMode=1;NSDictionary *r=DOResolveKnownQuarantineConflicts();exchangeMode=0;
 CHECK([r[@"status"] isEqual:@"exchange_failed"]);CHECK(![r[@"changed"] boolValue]);
 CHECK([readData(mapPath) isEqual:originalMap]);CHECK([readData(live) isEqual:currentData]);CHECK([readData(old) isEqual:oldData]);
 // Abrupt exit before/after atomic map exchange. Both data objects survive.
 for(int mode=2;mode<=3;mode++){
  CHECK([originalMap writeToFile:mapPath atomically:YES]);
  pid_t child=fork();CHECK(child>=0);
  if(child==0){exchangeMode=mode;DOResolveKnownQuarantineConflicts();_exit(75);}
  int status=0;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status));CHECK(WEXITSTATUS(status)==(mode==2?72:73));
  CHECK([readData(live) isEqual:currentData]);CHECK([readData(old) isEqual:oldData]);
  CHECK([readData(currentChild) isEqual:currentData]);CHECK([readData(oldChild) isEqual:oldData]);
  CHECK([[NSArray arrayWithContentsOfFile:mapPath] count]==(mode==2?3:1));
 }
 CHECK([originalMap writeToFile:mapPath atomically:YES]);
 r=DOResolveKnownQuarantineConflicts();
 CHECK([r[@"status"] isEqual:@"conflicts_archived_current_kept"]);CHECK([r[@"changed"] boolValue]);
 CHECK([r[@"archived_items"] count]==2);CHECK([r[@"remaining_journal_entries"] intValue]==1);
 CHECK(![r[@"original_contents_restored"] boolValue]);
 CHECK([[NSArray arrayWithContentsOfFile:mapPath] isEqual:@[map[2]]]);
 CHECK([readData(live) isEqual:currentData]);CHECK([readData(old) isEqual:oldData]);
 CHECK([readData(currentChild) isEqual:currentData]);CHECK([readData(oldChild) isEqual:oldData]);
 CHECK([readData(unrelated) isEqual:currentData]);CHECK([readData(unrelatedOld) isEqual:oldData]);
 NSString *backup=r[@"backup_directory"];
 NSDictionary *journal=[NSDictionary dictionaryWithContentsOfFile:[backup stringByAppendingPathComponent:@"original.plist"]];
 CHECK([journal[@"original"] isEqual:originalMap]);
 CHECK([readData([backup stringByAppendingPathComponent:@"exchange.plist"]) isEqual:originalMap]);
 CHECK([NSJSONSerialization dataWithJSONObject:r options:0 error:NULL]!=nil);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"no_known_conflicts"]);
 // Reuse existing guarded rollback on fixture only; user UI exposes no blind rollback.
 CHECK([JBTransitionRollback(mapPath,backup)[@"status"] isEqual:@"applied"]);
 CHECK([readData(mapPath) isEqual:originalMap]);
 CHECK(unlink(live.fileSystemRepresentation)==0);CHECK(symlink(old.fileSystemRepresentation,live.fileSystemRepresentation)==0);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"unexpected_target_type"]);
 CHECK([readData(mapPath) isEqual:originalMap]);CHECK(unlink(live.fileSystemRepresentation)==0);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"target_not_both_present"]);
 CHECK([currentData writeToFile:live atomically:YES]);
 CHECK([encode(@[map[0],map[0]]) writeToFile:mapPath atomically:YES]);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"invalid_map"]);
 CHECK([encode(@[@{@"src":live,@"dst":@"/outside"}]) writeToFile:mapPath atomically:YES]);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"invalid_map"]);
 CHECK([encode(@{@"bad":@YES}) writeToFile:mapPath atomically:YES]);
 CHECK([DOResolveKnownQuarantineConflicts()[@"status"] isEqual:@"invalid_map"]);
 CHECK([readData(live) isEqual:currentData]);CHECK([readData(old) isEqual:oldData]);
 printf("PASS: %d production conflict archival assertions\n",count);return 0;
}}
"""
if sys.platform!='darwin':
 print('SKIP: conflict archival runtime tests require macOS Foundation');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='conflict-archive-') as td:
 p=Path(td);(p/'test.m').write_text(source,encoding='utf8')
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Application/Dopamine/UI/Settings'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test'),td],check=True)
