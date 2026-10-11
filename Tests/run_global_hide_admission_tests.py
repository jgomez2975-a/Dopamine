#!/usr/bin/env python3
"""Production read-only admission policy; metadata probe mocked, no device work."""
from pathlib import Path
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
launch = (repo / 'BaseBin/launchdhook/src/app_hide.m').read_text(encoding='utf8')
hide = launch.split('static int app_hide_do_hide(void)', 1)[1].split('static int app_hide_do_restore', 1)[0]
assert hide.index('app_hide_admission()') < hide.index('app_hide_kill_jailbreak_apps()')
assert hide.index('app_hide_admission()') < hide.index('unmount(') < hide.index('unlink(')
begin = launch.split('int app_hide_begin_spawn(', 1)[1].split('void app_hide_cancel_spawn', 1)[0]
assert begin.index('*context = NULL') < begin.index('app_hide_admission()') < begin.index('jb_visibility_acquire(')
manual = (repo / 'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf8')
manual = manual.split('- (int)setJailbreakHidden:', 1)[1]
assert manual.index('jb_global_hide_admission(') < manual.index('[self runJailbreakLibraryAudit]')
ui = (repo / 'Application/Dopamine/UI/Settings/DOSettingsController.m').read_text(encoding='utf8')
ui = ui.split('- (void)handleLongPress:', 1)[1]
assert ui.index('jb_global_hide_admission(') < ui.index('setEnvironmentNoInject:')
print('PASS: admission source ordering checks (not runtime proof)', flush=True)

source = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
static int calls, installed=-1, metadataError, rootError;
static mode_t kind=S_IFREG, rootKind=S_IFDIR;
static int probe(const char *path, struct stat *st) {
    memset(st,0,sizeof(*st));
    int index=calls++;
    if(index==0) {
        if(rootError){errno=rootError;return -1;}
        st->st_mode=rootKind;return 0;
    }
    if(strncmp(path,"/fixture/",9)!=0){errno=EINVAL;return -1;}
    if(metadataError){errno=metadataError;return -1;}
    if(index-1==installed){st->st_mode=kind;return 0;}
    errno=ENOENT;return -1;
}
#define JB_HIDE_ADMISSION_LSTAT probe
#include "JBGlobalHideAdmission.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(void) {
    int count=0;const char *reason=(void*)1;
    CHECK(jb_global_hide_admission(NULL,&reason)==EINVAL && reason==NULL);
    CHECK(jb_global_hide_admission("",NULL)==EINVAL);
    CHECK(jb_global_hide_admission("relative",NULL)==EINVAL);
    CHECK(jb_global_hide_admission("/",NULL)==EINVAL);
    CHECK(calls==0);
    calls=0;CHECK(jb_global_hide_admission("/fixture",&reason)==0 && reason==NULL);
    CHECK(calls==6);
    mode_t kinds[]={S_IFREG,S_IFDIR,S_IFLNK};
    for(unsigned k=0;k<3;k++)for(int i=0;i<5;i++){
        calls=0;installed=i;kind=kinds[k];reason=NULL;
        CHECK(jb_global_hide_admission("/fixture",&reason)==EBUSY);
        CHECK(reason!=NULL && calls==i+2);
    }
    installed=-1;kind=S_IFREG;
    int errors[]={EACCES,EIO,ENOTDIR,ELOOP};
    for(unsigned i=0;i<4;i++){
        calls=0;metadataError=errors[i];reason=(void*)1;
        CHECK(jb_global_hide_admission("/fixture",&reason)==errors[i]);
        CHECK(reason==NULL && calls==2);
    }
    metadataError=0;rootError=ENOENT;calls=0;
    CHECK(jb_global_hide_admission("/fixture",NULL)==ENOENT && calls==1);
    rootError=0;rootKind=S_IFREG;calls=0;
    CHECK(jb_global_hide_admission("/fixture",NULL)==ENOTDIR);
    rootKind=S_IFLNK;calls=0;
    CHECK(jb_global_hide_admission("/fixture",NULL)==ENOTDIR);
    rootKind=S_IFDIR;
    char longRoot[PATH_MAX+1];memset(longRoot,'x',sizeof(longRoot));longRoot[0]='/';longRoot[PATH_MAX]=0;calls=0;
    CHECK(jb_global_hide_admission(longRoot,NULL)==ENAMETOOLONG && calls==0);
    longRoot[PATH_MAX-2]=0;calls=0;
    CHECK(jb_global_hide_admission(longRoot,NULL)==ENAMETOOLONG && calls==1);
    calls=0;CHECK(jb_global_hide_admission("/fixture",NULL)==0);
    printf("PASS: %d production global-hide admission assertions (metadata probe mocked)\n",count);
    return 0;
}
'''
if sys.platform != 'darwin':
    print('SKIP: production C execution requires the macOS CI compiler')
    sys.exit(0)
with tempfile.TemporaryDirectory(prefix='global-hide-admission-') as td:
    p = Path(td)
    (p / 'test.c').write_text(source, encoding='utf8')
    subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
