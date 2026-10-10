#!/usr/bin/env python3
"""Execute a pinned pre-fix state implementation with failure/reentry stubs."""
from pathlib import Path
import subprocess,tempfile,sys
repo=Path(__file__).resolve().parents[1]
old=(repo/'Tests/fixtures/legacy_visibility_state.txt').read_text(encoding='utf8')
source=r'''#import <Foundation/Foundation.h>
#include <pthread.h>
#include <errno.h>
static bool gNoInjectActive;
static int gNoInjectRefCount;
static pthread_mutex_t gNoInjectLock=PTHREAD_MUTEX_INITIALIZER;
static int failure,restores,insideRestore,overlaps,reenter;
void app_hide_global_hide(void);
static void app_hide_log(NSString *msg){(void)msg;}
static void app_hide_do_hide(void){if(insideRestore)overlaps++;}
static int app_hide_do_restore(void){restores++;insideRestore=1;if(reenter)app_hide_global_hide();insideRestore=0;return failure;}
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %s",#x);return 1;}}while(0)
'''+old+r'''
int main(void){@autoreleasepool {
 app_hide_global_hide();failure=EACCES;app_hide_global_restore();
 CHECK(!app_hide_is_currently_hidden());CHECK(gNoInjectRefCount==0);CHECK(restores==1);
 NSLog(@"REPRODUCED: failed restore reported visible, with refcount zero");
 failure=0;restores=0;app_hide_global_hide();app_hide_global_hide();
 app_hide_global_restore();app_hide_global_restore();
 CHECK(gNoInjectRefCount==0 && restores==1);
 NSLog(@"REPRODUCED: two callbacks from one app release both apps' references");
 app_hide_global_hide();reenter=1;app_hide_global_restore();
 CHECK(overlaps==1);
 NSLog(@"REPRODUCED: hide body overlaps an unfinished restore body");
 return 0;
}}
'''
if sys.platform!='darwin':
 print('SKIP: pinned legacy state repro requires macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='jb-legacy-state-') as td:
 p=Path(td);(p/'test.m').write_text(source)
 subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=10)
