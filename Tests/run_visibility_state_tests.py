#!/usr/bin/env python3
"""Compile the production coordinator: callbacks mocked, real pthread contention."""
from pathlib import Path
import subprocess,sys,tempfile
repo=Path(__file__).resolve().parents[1]
source=r'''
#include "JBVisibilityState.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} checks++;}while(0)
static unsigned checks;
typedef struct {
 JBVisibilityState state;
 JBVisibilityLease first,second,legacy;
 pthread_mutex_t mutex;pthread_cond_t condition;
 int hideCalls,restoreCalls,hideError,restoreError,blockOn;
 bool entered,resume,reenter;
 int nestedResult;
} Harness;
static int restore(void *);
static int operation(Harness *h,int kind) {
 pthread_mutex_lock(&h->mutex);
 if(kind==1)h->hideCalls++;else h->restoreCalls++;
 bool reenter=h->reenter;
 pthread_mutex_unlock(&h->mutex);
 if(reenter) h->nestedResult=jb_visibility_restore(&h->state,restore,h);
 pthread_mutex_lock(&h->mutex);
 if(h->blockOn==kind){h->entered=true;pthread_cond_broadcast(&h->condition);while(!h->resume)pthread_cond_wait(&h->condition,&h->mutex);}
 int result=kind==1?h->hideError:h->restoreError;
 pthread_mutex_unlock(&h->mutex);return result;
}
static int hide(void *h){return operation(h,1);}
static int restore(void *h){return operation(h,2);}
static void init(Harness *h) {
 memset(h,0,sizeof(*h));pthread_mutex_init(&h->state.lock,NULL);
 pthread_mutex_init(&h->mutex,NULL);pthread_cond_init(&h->condition,NULL);
}
static void destroy(Harness *h){pthread_mutex_destroy(&h->state.lock);pthread_mutex_destroy(&h->mutex);pthread_cond_destroy(&h->condition);}
static void snapshot(Harness *h,JBVisibilityPhase phase,unsigned refs,bool busy,int error) {
 pthread_mutex_lock(&h->state.lock);
 bool ok=h->state.phase==phase && h->state.references==refs && h->state.busy==busy && h->state.lastError==error;
 pthread_mutex_unlock(&h->state.lock);CHECK(ok);
}
static int acquire(Harness *h,JBVisibilityLease *l){return jb_visibility_acquire(&h->state,l,hide,restore,h);}
static int release(Harness *h,JBVisibilityLease *l){return jb_visibility_release(&h->state,l,restore,h);}
typedef struct {Harness *h;JBVisibilityLease *lease;int action,result;} Work;
static void *worker(void *arg){Work *w=arg;w->result=w->action==1?acquire(w->h,w->lease):w->action==2?release(w->h,w->lease):jb_visibility_restore(&w->h->state,restore,w->h);return NULL;}
static void waitEntered(Harness *h){pthread_mutex_lock(&h->mutex);while(!h->entered)pthread_cond_wait(&h->condition,&h->mutex);pthread_mutex_unlock(&h->mutex);}
static void resume(Harness *h){pthread_mutex_lock(&h->mutex);h->resume=true;pthread_cond_broadcast(&h->condition);pthread_mutex_unlock(&h->mutex);}
int main(void){
 Harness h;init(&h);
 CHECK(acquire(&h,&h.first)==0);CHECK(acquire(&h,&h.first)==0);CHECK(acquire(&h,&h.second)==0);
 snapshot(&h,JB_HIDDEN,2,false,0);CHECK(h.hideCalls==1);
 CHECK(release(&h,&h.first)==0);CHECK(release(&h,&h.first)==0);
 snapshot(&h,JB_HIDDEN,1,false,0);CHECK(h.restoreCalls==0);
 CHECK(release(&h,&h.legacy)==0);snapshot(&h,JB_HIDDEN,1,false,0);
 CHECK(release(&h,&h.second)==0);snapshot(&h,JB_VISIBLE,0,false,0);CHECK(h.restoreCalls==1);
 CHECK(acquire(&h,&h.first)==0);h.restoreError=EACCES;
 CHECK(release(&h,&h.first)==EACCES);snapshot(&h,JB_VISIBILITY_FAILED,0,false,EACCES);
 CHECK(acquire(&h,&h.second)==EACCES);CHECK(!h.second.held);
 h.restoreError=0;CHECK(jb_visibility_restore(&h.state,restore,&h)==0);snapshot(&h,JB_VISIBLE,0,false,0);
 h.hideError=EIO;CHECK(acquire(&h,&h.first)==EIO);CHECK(!h.first.held);snapshot(&h,JB_VISIBLE,0,false,0);
 h.restoreError=ENOSPC;CHECK(acquire(&h,&h.first)==EIO);snapshot(&h,JB_VISIBILITY_FAILED,0,false,ENOSPC);
 h.restoreError=0;h.hideError=0;CHECK(jb_visibility_restore(&h.state,restore,&h)==0);
 h.reenter=true;CHECK(acquire(&h,&h.first)==0);CHECK(h.nestedResult==EBUSY);
 CHECK(release(&h,&h.first)==0);CHECK(h.nestedResult==EBUSY);h.reenter=false;
 destroy(&h);
 // A restore must not publish visible while its helper is still running.
 init(&h);CHECK(acquire(&h,&h.first)==0);h.blockOn=2;
 Work w={&h,NULL,3,0};pthread_t t;CHECK(pthread_create(&t,NULL,worker,&w)==0);waitEntered(&h);
 snapshot(&h,JB_HIDDEN,1,true,0);CHECK(acquire(&h,&h.second)==EBUSY);CHECK(!h.second.held);
 CHECK(jb_visibility_restore(&h.state,restore,&h)==EBUSY);
 CHECK(release(&h,&h.first)==EBUSY);snapshot(&h,JB_HIDDEN,0,true,0);
 resume(&h);CHECK(pthread_join(t,NULL)==0);CHECK(w.result==0);snapshot(&h,JB_VISIBLE,0,false,0);CHECK(h.restoreCalls==1);destroy(&h);
 // Last release during a hide is drained by the owner, not lost or overlapped.
 init(&h);h.blockOn=1;w=(Work){&h,&h.first,1,0};CHECK(pthread_create(&t,NULL,worker,&w)==0);waitEntered(&h);
 snapshot(&h,JB_VISIBLE,1,true,0);CHECK(release(&h,&h.first)==EBUSY);
 CHECK(acquire(&h,&h.second)==EBUSY);resume(&h);CHECK(pthread_join(t,NULL)==0);
 CHECK(w.result==ECANCELED);snapshot(&h,JB_VISIBLE,0,false,0);CHECK(h.restoreCalls==1);destroy(&h);
 // Delayed role and exit callbacks race on the same lease. A different app's
 // lease survives, even after the other app has been resurrected/reacquired.
 init(&h);
 for(int i=0;i<500;i++){
  CHECK(acquire(&h,&h.first)==0);CHECK(acquire(&h,&h.second)==0);
  Work a={&h,&h.first,2,0},b={&h,&h.first,2,0};pthread_t t1,t2;
  CHECK(pthread_create(&t1,NULL,worker,&a)==0);CHECK(pthread_create(&t2,NULL,worker,&b)==0);
  CHECK(pthread_join(t1,NULL)==0);CHECK(pthread_join(t2,NULL)==0);CHECK(a.result==0 && b.result==0);
  snapshot(&h,JB_HIDDEN,1,false,0);CHECK(release(&h,&h.second)==0);snapshot(&h,JB_VISIBLE,0,false,0);
 }
 destroy(&h);
 printf("PASS: %u production visibility assertions including 500 concurrent duplicate-release rounds\n",checks);
 return 0;
}
'''
if sys.platform!='darwin':
 print('SKIP: run pthread coordinator test in macOS CI.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='jb-visibility-') as td:
 p=Path(td);(p/'test.c').write_text(source)
 base=['xcrun','clang','-pthread','-Wall','-Wextra','-Werror','-g','-I',str(repo/'Shared'),str(p/'test.c')]
 subprocess.run(base+['-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=45)
 subprocess.run(base+['-fsanitize=thread','-o',str(p/'test-tsan')],check=True)
 subprocess.run([str(p/'test-tsan')],check=True,timeout=90)
 print('PASS: coordinator contention suite under ThreadSanitizer')
