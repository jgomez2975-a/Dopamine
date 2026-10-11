#!/usr/bin/env python3
"""Production reconciliation and PID policy; effects/proc metadata mocked.

Windows uses real SRW locks through a narrow pthread adapter; macOS uses pthread.
The existing visibility suite separately covers threaded contention and TSAN.
"""
from pathlib import Path
import argparse,shlex,subprocess,sys,tempfile,json
p=argparse.ArgumentParser()
p.add_argument('--cc',default='xcrun clang' if sys.platform=='darwin' else 'cc')
p.add_argument('--report')
a=p.parse_args()
repo=Path(__file__).resolve().parents[1]
app=(repo/'BaseBin/launchdhook/src/app_hide.m').read_text(encoding='utf8')
start=app.index('static bool app_hide_pid_has_exited(')
end=app.index('void app_hide_watch_exit(',start)
pid_policy=app[start:end]
watch=app[end:]
assert 'if (appState > 0 && appState != 1) releaseOnce()' not in watch
assert 'DISPATCH_SOURCE_TYPE_TIMER' in watch
assert 'DISPATCH_SOURCE_TYPE_PROC' in watch
assert 'DISPATCH_QUEUE_SERIAL' in watch
assert 'app_hide_pid_has_exited(pid, version)' in watch
assert 'jb_visibility_reconcile_idle(&gVisibility' in app
timer=app[app.index('static void app_hide_start_watchdog(void)\n{'):app.index('static int app_hide_apply_hide')]
assert 'app_hide_do_hide' not in timer and 'unlink(' not in timer

src=r'''
#include "JBVisibilityWatchdog.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
static int observedVersion,killError,killCalls;
static int proc_get_pidversion(pid_t pid){(void)pid;errno=EIO;return observedVersion;}
static int fixture_kill(pid_t pid,int sig){(void)pid;(void)sig;killCalls++;errno=killError;return killError?-1:0;}
#define kill fixture_kill
'''+pid_policy+r'''
#undef kill
static JBVisibilityState state=JB_VISIBILITY_INITIALIZER;
static JBVisibilityWatchdog watchdog;
static JBVisibilityLease lease,duplicate;
static int calls,result,nestedResult;
static bool reenter,duplicateRelease;
static int operation(void *context){
    (void)context;calls++;
    if(reenter)nestedResult=jb_visibility_acquire(&state,&lease,operation,operation,NULL);
    if(duplicateRelease)nestedResult=jb_visibility_release(&state,&duplicate,operation,NULL);
    return result;
}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(void){
    int count=0;bool attempted=true;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==0);
    CHECK(!attempted && calls==0); // no unknown/manual-hide recovery
    state.phase=JB_HIDDEN;state.references=1;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==EBUSY);
    CHECK(!attempted && calls==0 && state.references==1);
    state.references=0;state.busy=true;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==EBUSY);
    CHECK(!attempted && calls==0);
    state.busy=false;state.restartPrepared=true;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==EBUSY);
    CHECK(!attempted && calls==0);
    state.restartPrepared=false;reenter=true;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==0);
    CHECK(attempted && calls==1 && nestedResult==EBUSY && !lease.held);
    CHECK(state.phase==JB_VISIBLE && state.references==0 && !state.busy);
    reenter=false;state.phase=JB_VISIBILITY_FAILED;state.lastError=EISDIR;result=EISDIR;
    for(int i=1;i<=3;i++){
        CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==EISDIR);
        CHECK(attempted && watchdog.consecutiveFailures==(unsigned)i);
        CHECK(state.phase==JB_VISIBILITY_FAILED && state.lastError==EISDIR && !state.busy);
    }
    int before=calls;
    for(int i=0;i<10;i++)CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==ECANCELED);
    CHECK(!attempted && calls==before && state.lastError==EISDIR);
    result=0;CHECK(jb_visibility_restore(&state,operation,NULL)==0);
    before=calls;CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==0);
    CHECK(!attempted && calls==before && watchdog.consecutiveFailures==0);
    state.phase=JB_HIDDEN;duplicateRelease=true;before=calls;
    CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==0);
    CHECK(attempted && calls==before+1 && nestedResult==EBUSY);
    CHECK(!state.restorePending && state.phase==JB_VISIBLE);
    duplicateRelease=false;
    // Pending spawn lease protects the acquire -> real spawn -> monitor gap.
    CHECK(jb_visibility_acquire(&state,&lease,operation,operation,NULL)==0);
    before=calls;CHECK(jb_visibility_reconcile_idle(&state,&watchdog,operation,NULL,&attempted)==EBUSY);
    CHECK(!attempted && calls==before && lease.held);
    CHECK(jb_visibility_release(&state,&lease,operation,NULL)==0);
    // Version metadata unavailable, permission denied, or background state is
    // not evidence of death. Only a positive generation change / ESRCH is.
    observedVersion=7;killError=0;errno=ERANGE;
    CHECK(!app_hide_pid_has_exited(42,7) && errno==ERANGE);
    observedVersion=8;before=killCalls;errno=ERANGE;
    CHECK(app_hide_pid_has_exited(42,7) && errno==ERANGE && killCalls==before);
    observedVersion=0;killError=0;errno=ERANGE;
    CHECK(!app_hide_pid_has_exited(42,7) && errno==ERANGE);
    killError=EPERM;CHECK(!app_hide_pid_has_exited(42,7));
    killError=EIO;CHECK(!app_hide_pid_has_exited(42,7));
    killError=ESRCH;CHECK(app_hide_pid_has_exited(42,7));
    observedVersion=9;killError=0;CHECK(!app_hide_pid_has_exited(42,0));
    killError=ESRCH;CHECK(app_hide_pid_has_exited(42,0));
    CHECK(app_hide_pid_has_exited(0,0));
    printf("PASS: %d State5-inspired reconciliation/PID assertions (effects and process metadata mocked)\n",count);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='state5-reconcile-') as t:
    t=Path(t);(t/'test.c').write_text(src,encoding='utf8')
    if sys.platform=='win32':
        (t/'pthread.h').write_text('''#pragma once
#include <windows.h>
typedef SRWLOCK pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT
static inline int pthread_mutex_lock(pthread_mutex_t *m){AcquireSRWLockExclusive(m);return 0;}
static inline int pthread_mutex_unlock(pthread_mutex_t *m){ReleaseSRWLockExclusive(m);return 0;}
''',encoding='utf8')
    binary=t/('test.exe' if sys.platform=='win32' else 'test')
    subprocess.run(shlex.split(a.cc)+['-std=gnu11','-Wall','-Wextra','-Werror','-I',str(t),'-I',str(repo/'Shared'),str(t/'test.c'),'-o',str(binary)],check=True)
    r=subprocess.run([str(binary)],text=True,capture_output=True,check=True,timeout=15)
    print(r.stdout,end='')
    if a.report:Path(a.report).write_text(json.dumps({'result':r.stdout.strip(),'device_test':False,'os':sys.platform,'effects':'mocked'},indent=2),encoding='utf8')
