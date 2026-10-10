#!/usr/bin/env python3
"""Actual manual entry helper and App methods, with privileged side effects stubbed."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

repo=Path(__file__).resolve().parents[1]
src=(repo/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf8')
def method(start):
    a=src.index(start);b=src.index('{',a);depth=1;i=b+1
    while depth:
        if src[i]=='{':depth+=1
        elif src[i]=='}':depth-=1
        i+=1
    return src[a:i]+'\n'
methods=''.join(method(m) for m in ['- (int)setJailbreakHidden:', '- (int)ensureJailbreakVisibleBeforeRestart',
    '- (int)respring', '- (int)rebootUserspace\n', '- (NSError*)updateEnvironment'])
assert 'removeItemAtPath:@"/var/jb"' not in methods
assert 'jb_manual_probe' in methods and 'jb_manual_hide' in methods
bootstrap=(repo/'Application/Dopamine/Jailbreak/DOBootstrapper.m').read_text(encoding='utf8')
body=bootstrap.split('- (NSError *)updateVarJbSymlink',1)[1].split('- (void)prepareBootstrapWithCompletion:',1)[0]
assert 'jb_entry_ensure_visible' in body and 'removeItemAtPath' not in body
# Replace ONLY fixed device paths; retain the production decision/control flow.
methods=methods.replace('@"/var/jb"','entry').replace('"/var/jb"','entry.fileSystemRepresentation')
methods=re.sub(r'@"/var/mobile/([^"]*)"',r'[fixture stringByAppendingPathComponent:@"\1"]',methods)
program=r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
static NSString *fixture,*entry,*root;
static int renameMode,renameCalls;
static int fixtureRename(const char *a,const char *b,unsigned flags) {
 renameCalls++;
 if(renameMode==1 && renameCalls==1) { errno=EIO;return -1; }
 if((renameMode==2 || renameMode==3) && renameCalls==1) {
  if(unlink(a)!=0 || mkdir(a,0700)!=0) abort();
  NSString *keep=[[NSString stringWithUTF8String:a] stringByAppendingPathComponent:@"keep"];
  [@"preserved" writeToFile:keep atomically:YES encoding:NSUTF8StringEncoding error:nil];
  int result=renamex_np(a,b,flags);
  if(renameMode==3) { FILE *f=fopen(a,"w"); if(!f)abort();fputs("new",f);fclose(f); }
  return result;
 }
 return renamex_np(a,b,flags);
}
#define JB_MANUAL_RENAME fixtureRename
#define JBQ_ROOT [fixture stringByAppendingPathComponent:@"quarantine"]
#define JBQ_LOG(message) ((void)(message))
#import "JBManualEntry.h"
#import "JBQuarantine.h"
#define JBROOT_PATH(suffix) [root stringByAppendingString:(suffix)]
static struct { struct { const char *rootPath; } jailbreakInfo; } gSystemInfo;
static BOOL jailbroken=YES,allowPrivilege=YES,mounted=YES;
static int audits,restores,spawnCalls,stageCalls,mountCalls,refreshCalls;
static int auditError,restoreError,mountError,spawnError,stageError;
static void jbclient_platform_set_systemwide_domain_enabled(BOOL value){(void)value;}
static void jbclient_platform_set_crashreporter_enabled(BOOL value){(void)value;}
static int jbclient_platform_stage_jailbreak_update(const char *path){(void)path;stageCalls++;return stageError;}
@interface Fixture : NSObject
- (BOOL)isJailbroken;
- (BOOL)isFakelibMounted;
- (int)setJailbreakHidden:(BOOL)hidden;
- (int)ensureJailbreakVisibleBeforeRestart;
- (int)respring;
- (int)rebootUserspace;
- (NSError *)updateEnvironment;
- (void)runAsRoot:(void (^)(void))block;
- (void)runUnsandboxed:(void (^)(void))block;
- (int)runJailbreakLibraryAudit;
- (int)restoreHiddenItems;
- (int)setFakelibMounted:(BOOL)value;
- (int)setPrivatePrebootProtected:(BOOL)value;
- (int)spawnJbctlAsRootWithArgs:(NSArray *)args;
- (int)runTrollStoreAction:(NSString *)action;
- (void)setForkfixEnabled:(BOOL)value;
- (void)unregisterJailbreakApps;
- (void)refreshJailbreakApps;
- (void)hideJailbreakURLSchemes;
- (void)restoreJailbreakURLSchemes;
@end
@implementation Fixture
- (BOOL)isJailbroken{return jailbroken;}
- (BOOL)isFakelibMounted{return mounted;}
- (void)runAsRoot:(void (^)(void))block{if(allowPrivilege)block();}
- (void)runUnsandboxed:(void (^)(void))block{block();}
- (int)runJailbreakLibraryAudit{audits++;return auditError;}
- (int)restoreHiddenItems{restores++;return restoreError;}
- (int)setFakelibMounted:(BOOL)value{mountCalls++;if(!mountError)mounted=value;return mountError;}
- (int)setPrivatePrebootProtected:(BOOL)value{(void)value;return 0;}
- (int)spawnJbctlAsRootWithArgs:(NSArray *)args{(void)args;spawnCalls++;return spawnError;}
- (int)runTrollStoreAction:(NSString *)action{(void)action;return EPERM;}
- (void)setForkfixEnabled:(BOOL)value{(void)value;}
- (void)unregisterJailbreakApps{}
- (void)refreshJailbreakApps{refreshCalls++;}
- (void)hideJailbreakURLSchemes{}
- (void)restoreJailbreakURLSchemes{}
''' + methods + r'''
@end
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);return 1;}count++;}while(0)
static void reset(void){audits=restores=spawnCalls=stageCalls=mountCalls=refreshCalls=0;auditError=restoreError=mountError=spawnError=stageError=0;}
int main(int argc,char **argv){@autoreleasepool{
 if(argc!=2)return 2;
 int count=0;fixture=[NSString stringWithUTF8String:argv[1]];
 root=[fixture stringByAppendingPathComponent:@"root"];entry=[fixture stringByAppendingPathComponent:@"jb"];
 gSystemInfo.jailbreakInfo.rootPath=root.fileSystemRepresentation;
 NSFileManager *fm=NSFileManager.defaultManager;
 CHECK([fm createDirectoryAtPath:[root stringByAppendingPathComponent:@"basebin"] withIntermediateDirectories:YES attributes:nil error:nil]);
 BOOL hidden=NO;NSString *retained=nil;
 CHECK(jb_manual_probe(entry,root,&hidden)==0 && hidden);
 CHECK(jb_manual_hide(entry,root,&retained)==0 && retained==nil);
 CHECK(jb_entry_ensure_visible(entry.fileSystemRepresentation,root.fileSystemRepresentation)==0);
 CHECK(jb_manual_probe(entry,root,&hidden)==0 && !hidden);
 renameMode=1;renameCalls=0;
 CHECK(jb_manual_hide(entry,root,&retained)==EIO && auditPathState(entry)==1);
 renameMode=2;renameCalls=0;
 CHECK(jb_manual_hide(entry,root,&retained)==ESTALE && retained==nil);
 CHECK([[NSString stringWithContentsOfFile:[entry stringByAppendingPathComponent:@"keep"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"preserved"]);
 CHECK(jb_manual_probe(entry,root,&hidden)==EISDIR);
 CHECK([fm removeItemAtPath:entry error:nil]); // test fixture cleanup only
 CHECK(jb_entry_ensure_visible(entry.fileSystemRepresentation,root.fileSystemRepresentation)==0);
 renameMode=3;renameCalls=0;
 CHECK(jb_manual_hide(entry,root,&retained)==ESTALE && retained!=nil);
 CHECK([[NSString stringWithContentsOfFile:entry encoding:NSUTF8StringEncoding error:nil] isEqual:@"new"]);
 CHECK([[NSString stringWithContentsOfFile:[retained stringByAppendingPathComponent:@"keep"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"preserved"]);
 CHECK([fm removeItemAtPath:entry error:nil] && [fm removeItemAtPath:retained error:nil]);
 renameMode=0;
 CHECK(symlink("/nonexistent-manual-fixture",entry.fileSystemRepresentation)==0);
 CHECK(jb_manual_probe(entry,root,&hidden)==ENOENT && !hidden);
 CHECK(jb_manual_hide(entry,root,&retained)==ENOENT && auditPathState(entry)==1);
 CHECK(unlink(entry.fileSystemRepresentation)==0);

 Fixture *env=[Fixture new];
 CHECK([env setJailbreakHidden:NO]==0 && auditPathState(entry)==1);
 reset();CHECK([env setJailbreakHidden:YES]==0 && auditPathState(entry)==0);
 CHECK(audits==1 && mountCalls==1);
 reset();restoreError=EIO;
 CHECK([env rebootUserspace]==EIO && spawnCalls==0);
 CHECK(auditPathState(entry)==1); // entry is restored; retry must still finish mount
 reset();CHECK([env rebootUserspace]==0 && mounted && spawnCalls>0);
 reset();auditError=EIO;CHECK([env setJailbreakHidden:YES]==EIO);
 CHECK(auditPathState(entry)==1 && mountCalls==0);
 reset();mountError=EIO;CHECK([env setJailbreakHidden:YES]==EIO && auditPathState(entry)==1);
 reset();CHECK(unlink(entry.fileSystemRepresentation)==0 && mkdir(entry.fileSystemRepresentation,0700)==0);
 CHECK([env setJailbreakHidden:YES]==EISDIR && audits==0 && spawnCalls==0);
 CHECK([env setJailbreakHidden:NO]==EISDIR && restores==0);
 CHECK([env rebootUserspace]==EISDIR && spawnCalls==0);
 CHECK([env respring]==EISDIR && spawnCalls==0);
 CHECK([env updateEnvironment]!=nil && stageCalls==0 && spawnCalls==0);
 CHECK(rmdir(entry.fileSystemRepresentation)==0);
 CHECK(jb_entry_ensure_visible(entry.fileSystemRepresentation,root.fileSystemRepresentation)==0);
 reset();mounted=YES;stageError=EIO;
 CHECK([env updateEnvironment]!=nil && stageCalls==1 && spawnCalls==0);
 reset();spawnError=EIO;
 CHECK([env updateEnvironment]!=nil && stageCalls==1 && spawnCalls==1);
 reset();CHECK([env updateEnvironment]==nil && stageCalls==1 && spawnCalls==1);
 reset();allowPrivilege=NO;
 CHECK([env setJailbreakHidden:NO]==EPERM && restores==0);
 CHECK([env ensureJailbreakVisibleBeforeRestart]==EPERM && spawnCalls==0);
 allowPrivilege=YES;jailbroken=NO;reset();
 CHECK([env ensureJailbreakVisibleBeforeRestart]==0 && restores==0 && spawnCalls==0);
 printf("PASS: %d manual entry and actual App restart/update assertions (privileged effects mocked)\n",count);
 return 0;
}}
'''
if sys.platform!='darwin':
    print('Manual entry wiring checks OK; SKIP runtime: macOS Foundation required.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='manual-entry-') as td:
    p=Path(td);(p/'test.m').write_text(program,encoding='utf8')
    subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Wall','-Wextra','-Werror',
                    '-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test'),td],check=True)
