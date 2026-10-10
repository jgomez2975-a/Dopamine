#!/usr/bin/env python3
"""Actual launchdhook wrappers + GCD lease callbacks on macOS; helper/kernel stubs."""
from pathlib import Path
import subprocess,tempfile,sys
repo=Path(__file__).resolve().parents[1]
src=(repo/'BaseBin/launchdhook/src/app_hide.m').read_text(encoding='utf8')
def function(start):
 a=src.index(start);b=src.index('{',a);depth=1;i=b+1
 while depth:
  if src[i]=='{':depth+=1
  elif src[i]=='}':depth-=1
  i+=1
 return src[a:i]+'\n'
globals_=src[src.index('static JBVisibilityState gVisibility'):src.index('// Pids of jailbreak apps')]
functions=''.join(function(x) for x in [
 'static int app_hide_apply_hide(', 'static int app_hide_apply_restore(',
 'static int app_hide_transition_result(', 'int app_hide_global_hide(',
 'int app_hide_global_restore(', 'int app_hide_begin_spawn(',
 'void app_hide_cancel_spawn(', 'bool app_hide_is_currently_hidden(',
 'int app_hide_resurrect_for_jb_app(', 'void app_hide_watch_exit(',
 'int app_hide_prepare_userspace_restart(', 'void app_hide_cancel_userspace_restart('])
spawn=(repo/'BaseBin/launchdhook/src/spawn_hook.m').read_text(encoding='utf8')
assert 'if (restoreResult != 0) return restoreResult;' in spawn
assert 'if (hideResult != 0) return hideResult;' in spawn
assert 'app_hide_watch_exit(childPid, hideContext)' in spawn
assert 'app_hide_check_role_after_spawn' not in spawn
a=spawn.index('if (!strcmp(path, executablePath))')
b=spawn.index('{',a);depth=1;i=b+1
while depth:
 if spawn[i]=='{':depth+=1
 elif spawn[i]=='}':depth-=1
 i+=1
restart_body=spawn[a:i]
assert restart_body.index('app_hide_prepare_userspace_restart') < restart_body.index('hookd_provider_teardown')
assert 'ensure_fakelib_mounted' not in restart_body
restart = r'''static bool gInEarlyBoot;
static int teardowns,spawnCalls,spawnResult;
static bool pinnedAtSpawn;
static void hookd_provider_teardown(void){teardowns++;}
static void boomerang_stashPrimitives(void){}
static int fixture_unmount(const char *path,int flags){(void)path;(void)flags;return 0;}
static int jbupdate_basebin(const char *path){(void)path;return 0;}
static void abort_with_reason(int a,int b,const char *msg,int flags){(void)a;(void)b;(void)msg;(void)flags;abort();}
static int __posix_spawn_orig_wrapper(pid_t *pid,const char *path,void *desc,char *const *argv,char *const *envp){
 (void)pid;(void)path;(void)desc;(void)argv;(void)envp;
 spawnCalls++;pinnedAtSpawn=gVisibility.restartPrepared;return spawnResult;
}
#define unmount fixture_unmount
static int replay_launchd_restart(void){
 pid_t child=0;pid_t *pid=&child;const char *path="/sbin/launchd",*executablePath=path;
 void *desc=NULL;char *argv[]={"/sbin/launchd",NULL};extern char **environ;
''' + restart_body + r'''
 return EINVAL;
}
#undef unmount
'''
source=r'''#import <Foundation/Foundation.h>
#include "JBVisibilityState.h"
#include <spawn.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>
static int hideError,restoreError;
static dispatch_semaphore_t released;
static int app_hide_do_hide(void){return hideError;}
static int app_hide_do_restore(void){return restoreError;}
static void app_hide_log(NSString *s){if(released && [s containsString:@"pid_release"])dispatch_semaphore_signal(released);}
// Kernel identity/role probes are mocked. The child process exit source and
// delayed callback below are real libdispatch operations.
static int proc_get_pidversion(pid_t pid){return pid>0?1:0;}
static void app_hide_remove_pid(pid_t pid,int version){(void)pid;(void)version;}
static int app_hide_get_app_state(pid_t pid){(void)pid;return 3;}
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
''' + globals_ + functions + restart + r'''
int main(void){@autoreleasepool {
 int count=0;
 CHECK(app_hide_global_hide()==0);CHECK(app_hide_global_hide()==0);
 CHECK(gVisibility.references==1);CHECK(app_hide_global_restore()==0);CHECK(!app_hide_is_currently_hidden());
 void *a=NULL,*b=NULL;
 CHECK(app_hide_begin_spawn(&a)==0);CHECK(app_hide_begin_spawn(&b)==0);CHECK(a && b);
 CHECK(gVisibility.references==2);CHECK(app_hide_global_restore()==0);CHECK(gVisibility.references==2);
 restoreError=EACCES;CHECK(app_hide_resurrect_for_jb_app()==EIO);CHECK(app_hide_is_currently_hidden());
 CHECK(gVisibility.phase==JB_VISIBILITY_FAILED && gVisibility.lastError==EACCES);
 restoreError=0;CHECK(app_hide_resurrect_for_jb_app()==0);CHECK(!app_hide_is_currently_hidden());
 app_hide_cancel_spawn(a);app_hide_cancel_spawn(b);CHECK(gVisibility.references==0);
 hideError=ENOSPC;a=(void *)1;CHECK(app_hide_begin_spawn(&a)==EIO);CHECK(a==NULL);CHECK(gVisibility.references==0);
 CHECK(!app_hide_is_currently_hidden());hideError=0;
 CHECK(app_hide_begin_spawn(&a)==0);CHECK(app_hide_begin_spawn(&b)==0);
 released=dispatch_semaphore_create(0);
 pid_t child=0;extern char **environ;char *args[]={"/bin/sleep","1",NULL};
 CHECK(posix_spawn(&child,args[0],NULL,NULL,args,environ)==0);
 app_hide_watch_exit(child,a); // transfers exactly one retained lease
 CHECK(dispatch_semaphore_wait(released,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC))==0);
 CHECK(dispatch_semaphore_wait(released,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC))==0);
 pthread_mutex_lock(&gVisibility.lock);unsigned refs=gVisibility.references;JBVisibilityPhase phase=gVisibility.phase;pthread_mutex_unlock(&gVisibility.lock);
 CHECK(refs==1 && phase==JB_HIDDEN);int status=0;CHECK(waitpid(child,&status,0)==child);
 app_hide_cancel_spawn(b);CHECK(gVisibility.references==0);CHECK(!app_hide_is_currently_hidden());
 // Execute the actual launchd self-spawn branch with destructive operations
 // stubbed. Failed preparation must precede teardown; failed spawn unpins.
 unsetenv("STAGED_JAILBREAK_UPDATE");setenv("DOPAMINE_IS_HIDDEN","1",1);
 restoreError=EACCES;CHECK(replay_launchd_restart()==EIO);
 CHECK(teardowns==0 && spawnCalls==0 && !gInEarlyBoot && !gVisibility.restartPrepared);
 CHECK(getenv("DOPAMINE_IS_HIDDEN")!=NULL);
 restoreError=0;spawnResult=ENOENT;CHECK(replay_launchd_restart()==ENOENT);
 CHECK(teardowns==1 && spawnCalls==1 && pinnedAtSpawn);
 CHECK(!gInEarlyBoot && !gVisibility.restartPrepared);CHECK(getenv("DOPAMINE_IS_HIDDEN")==NULL);
 spawnResult=0;CHECK(replay_launchd_restart()==0);CHECK(gInEarlyBoot && gVisibility.restartPrepared && pinnedAtSpawn);
 CHECK(app_hide_begin_spawn(&a)==EBUSY);CHECK(a==NULL);
 app_hide_cancel_userspace_restart();CHECK(!gVisibility.restartPrepared);
 NSLog(@"PASS: %d production wrapper/GCD assertions (helper and kernel probes mocked)",count);
 return 0;
}}
'''
if sys.platform!='darwin':
 print('SKIP: integration fixtures require macOS Foundation/libdispatch.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='jb-visibility-integration-') as td:
 p=Path(td);(p/'test.m').write_text(source)
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=20)
