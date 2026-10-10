#!/usr/bin/env python3
"""Compile production helper launch body and spawn injection gate with stubs."""
from pathlib import Path
import subprocess,sys,tempfile
repo=Path(__file__).resolve().parents[1]
src=(repo/'BaseBin/libjailbreak/src/util.c').read_text(encoding='utf8')
body='int jbctl_earlyboot('+src.split('int jbctl_earlyboot(',1)[1].split('void walk_backtrace',1)[0]
common=(repo/'BaseBin/systemhook/src/common/common.c').read_text(encoding='utf8')
gate='bool shouldInsertJBEnv = true;'+common.split('bool shouldInsertJBEnv = true;',1)[1].split('uint8_t *attrStruct',1)[0]
app=(repo/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf8')
assert 'argBuf, jb_helper_environment())' in app
assert 'envbuf_unsetenv(&envc, "_SafeMode")' in common
source=r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include "JBHelperEnvironment.h"
typedef unsigned mach_port_t;
typedef int posix_spawnattr_t;
typedef int pid_t;
#define MACH_PORT_NULL 0
#define JBROOT_PATH(p) "/fixture" p
#define HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"
#define kSpawnConfigInject 1
#define POSIX_SPAWN_PROC_TYPE_DRIVER 2
#define F_OK 0
static int spawnError,waitValue,calls,waits,portsOk,envOk,argsOk,destroyed;
static int posix_spawnattr_init(posix_spawnattr_t *p){*p=0;return 0;}
static int posix_spawnattr_destroy(posix_spawnattr_t *p){(void)p;destroyed++;return 0;}
static int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *p,mach_port_t *ports,unsigned n){(void)p;portsOk=n==3&&ports[0]==42&&ports[1]==0&&ports[2]==0;return 0;}
static const char *envbuf_getenv(const char **env,const char *key){if(!env)return NULL;for(int i=0;env[i];i++)if(!strncmp(env[i],key,strlen(key))&&env[i][strlen(key)]=='=')return env[i]+strlen(key)+1;return NULL;}
static int posix_spawnattr_getprocesstype_np(posix_spawnattr_t *p,int *v){(void)p;*v=0;return 0;}
static int access(const char *p,int mode){(void)p;(void)mode;return 0;}
static bool injected(char *const envp[],int spawnConfig){posix_spawnattr_t attr=0;
"""+gate+r"""
(void)hasSafeModeVariable;return shouldInsertJBEnv;}
static int posix_spawn(pid_t *pid,const char *path,void *actions,posix_spawnattr_t *attr,char *const argv[],char *const envp[]){
 (void)actions;(void)attr;calls++;*pid=123;
 envOk=envp&&envbuf_getenv((const char **)envp,"_SafeMode")&&!strcmp(envbuf_getenv((const char **)envp,"_SafeMode"),"1")&&!envbuf_getenv((const char **)envp,"DYLD_INSERT_LIBRARIES")&&!envbuf_getenv((const char **)envp,"DOPAMINE_APP_HIDE")&&!injected(envp,1);
 argsOk=!strcmp(path,"/fixture/basebin/jbctl")&&!strcmp(argv[0],path)&&!strcmp(argv[1],"internal")&&!strcmp(argv[2],"audit")&&!strcmp(argv[3],"restore")&&!strcmp(argv[4],"earlyboot")&&argv[5]==NULL;
 return spawnError;
}
static int cmd_wait_for_exit(pid_t pid){if(pid!=123)abort();waits++;return waitValue;}
"""+body+r"""
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(void){int count=0;
 char *normal[]={"PATH=/bin",NULL};char *badSafe[]={"_SafeMode=0",NULL};
 CHECK(injected(normal,1)); CHECK(injected(badSafe,1));
 CHECK(!injected(jb_helper_environment(),1));CHECK(!injected(normal,0));
 CHECK(jbctl_earlyboot(42,"internal","audit","restore",NULL)==0);
 CHECK(calls==1&&waits==1&&portsOk&&envOk&&argsOk&&destroyed==1);
 spawnError=EACCES;
 CHECK(jbctl_earlyboot(42,"internal","audit","restore",NULL)==EACCES);
 CHECK(calls==2&&waits==1&&destroyed==2);
 spawnError=0;waitValue=10;
 CHECK(jbctl_earlyboot(42,"internal","audit","restore",NULL)==10);
 CHECK(waits==2&&envOk&&portsOk); // no swallowing raw crash status
 waitValue=7<<8;
 CHECK(jbctl_earlyboot(42,"internal","audit","restore",NULL)==(7<<8));
 CHECK(jb_helper_environment()[2]==NULL);
 printf("PASS: %d helper environment and production spawn-gate assertions\n",count);return 0;
}
"""
if sys.platform!='darwin':
 print('Helper wiring checks OK; SKIP runtime: macOS compiler required.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='helper-env-') as td:
 p=Path(td);(p/'test.c').write_text(source,encoding='utf8')
 subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
