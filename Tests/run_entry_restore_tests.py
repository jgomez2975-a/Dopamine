#!/usr/bin/env python3
"""Compile the actual restore body on macOS with filesystem fixtures/helper stubs.
Does not execute launchd, mount fakelib or validate lifecycle serialization.
"""
from pathlib import Path
import subprocess, tempfile, sys
repo = Path(__file__).resolve().parents[1]
src = (repo/'BaseBin/launchdhook/src/app_hide.m').read_text(encoding='utf8')
helper = src.split('static int app_hide_run_jbctl(', 1)[1].split('// Actual (reversible)', 1)[0]
helper = 'static int app_hide_run_jbctl(' + helper
body = src.split('static int app_hide_do_restore(void)', 1)[1].split('void app_hide_global_hide', 1)[0]
body = 'static int app_hide_do_restore(void)' + body
assert 'unlink(' not in body and 'symlink(' not in body
assert 'jb_entry_ensure_visible' in body
assert 'return result;' in helper
# Substitute only the fixed device entry literal; algorithm stays unchanged.
body = body.replace('"/var/jb"', 'entryPath')
source = r'''#import <Foundation/Foundation.h>
#include "JBEntryGuard.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
static const char *entryPath;
static struct { struct { const char *rootPath; } jailbreakInfo; } gSystemInfo;
typedef unsigned int mach_port_t;
static int starts, stops, calls, auditResult, mountResult, replaceEntry;
static char commands[2][64];
static void systemwide_domain_set_enabled(bool b) {(void)b;}
static mach_port_t jbserver_local_start(void) {starts++; return 42;}
static void jbserver_local_stop(void) {stops++;}
static int jbctl_earlyboot(mach_port_t port, ...) {
 if (port != 42) abort();
 va_list ap; va_start(ap, port);
 const char *internal=va_arg(ap,const char *);
 const char *command=va_arg(ap,const char *);
 const char *arg=va_arg(ap,const char *);
 if (strcmp(internal,"internal") || calls>=2) abort();
 snprintf(commands[calls++],64,"%s/%s",command,arg);
 va_end(ap);
 if (!strcmp(command,"audit")) return auditResult;
 if (replaceEntry) {if(unlink(entryPath)!=0 || mkdir(entryPath,0700)!=0) abort();}
 return mountResult;
}
static void app_hide_log(NSString *msg) {(void)msg;}
static void reset(void) {starts=stops=calls=auditResult=mountResult=replaceEntry=0;}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}count++;}while(0)
''' + helper + body + r'''
int main(int argc, char **argv) { @autoreleasepool {
 if (argc!=2) return 2;
 int count=0; char root[4096], entry[4096];
 snprintf(root,sizeof(root),"%s/root",argv[1]);
 snprintf(entry,sizeof(entry),"%s/jb",argv[1]);
 entryPath=entry;gSystemInfo.jailbreakInfo.rootPath=root;
 CHECK(mkdir(root,0700)==0);
 CHECK(app_hide_do_restore()==0);
 CHECK(calls==2 && starts==2 && stops==2);
 CHECK(!strcmp(commands[0],"audit/restore") && !strcmp(commands[1],"fakelib/mount"));
 struct stat before,after;CHECK(lstat(entry,&before)==0);
 reset();CHECK(app_hide_do_restore()==0);CHECK(lstat(entry,&after)==0 && before.st_ino==after.st_ino);
 reset();auditResult=7;CHECK(app_hide_do_restore()==7);CHECK(calls==1 && starts==stops);
 reset();mountResult=9;CHECK(app_hide_do_restore()==9);CHECK(calls==2 && starts==stops);
 reset();gSystemInfo.jailbreakInfo.rootPath=NULL;CHECK(app_hide_do_restore()==EINVAL);CHECK(calls==0);
 gSystemInfo.jailbreakInfo.rootPath=root;
 CHECK(unlink(entry)==0);CHECK(mkdir(entry,0700)==0);
 reset();CHECK(app_hide_do_restore()==EISDIR);CHECK(calls==0);CHECK(lstat(entry,&after)==0 && S_ISDIR(after.st_mode));
 CHECK(rmdir(entry)==0);CHECK(symlink("/nonexistent-entry-test-target",entry)==0);
 reset();CHECK(app_hide_do_restore()==ENOENT);CHECK(calls==0);CHECK(lstat(entry,&after)==0 && S_ISLNK(after.st_mode));
 CHECK(unlink(entry)==0);
 reset();replaceEntry=1;CHECK(app_hide_do_restore()==EISDIR);CHECK(calls==2 && starts==stops);
 CHECK(lstat(entry,&after)==0 && S_ISDIR(after.st_mode));
 printf("PASS: %d actual restore/helper assertions (helper processes mocked)\n",count);
 return 0;
}}
'''
if sys.platform != 'darwin':
 print('SKIP: actual restore compilation requires macOS Foundation.'); sys.exit(0)
with tempfile.TemporaryDirectory(prefix='jb-restore-') as td:
 p=Path(td); (p/'test.m').write_text(source)
 subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test'),td],check=True)
