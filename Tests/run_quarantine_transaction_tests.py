#!/usr/bin/env python3
"""Production shared engine, real filesystem/locks/process exits on macOS.

Only the root directory, logging, and explicit fault-injection boundaries differ.
No device paths, reboot, plugin execution, or host user-data enumeration.
"""
import errno
import os
from pathlib import Path
import plistlib
import select
import subprocess
import sys
import tempfile

repo = Path(__file__).resolve().parents[1]
header = (repo/'Shared/JBQuarantine.h').read_text(encoding='utf8')
app = (repo/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text(encoding='utf8')
helper = (repo/'BaseBin/jbctl/src/hide_global.m').read_text(encoding='utf8')
assert header.index('JBQ_WRITE_MAP(map, hideMapPath())') < header.index('JBQ_RENAME(src.fileSystemRepresentation')
assert 'LOCK_EX | LOCK_NB' in header and 'RENAME_EXCL' in header
assert 'Shared/JBQuarantine.h' in app and 'Shared/JBQuarantine.h' in helper
assert 'writeToFile:[self hideMapPath]' not in app
assert 'moveItemAtPath:src toPath:dst' not in app
assert 'return auditWithLock(^int { return restoreHiddenItems(); });' in app
assert 'return auditWithLock(^int {' in helper

source = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
static NSString *fixture;
static const char *mode;
static BOOL fixtureWrite(NSArray *map, NSString *path) {
 if (!strcmp(mode,"fail-write")) return NO;
 return [map writeToFile:path atomically:YES];
}
static int fixtureRename(const char *src, const char *dst, unsigned flags) {
 if (!strcmp(mode,"fail-move") || !strcmp(mode,"fail-restore-move")) { errno=EIO; return -1; }
 if (!strcmp(mode,"exit-before-move")) _exit(70);
 if (!strcmp(mode,"race-restore")) {
  FILE *file=fopen(dst,"wx"); if (!file) _exit(92);
  fputs("concurrent-new",file); fclose(file);
 }
 int result=renamex_np(src,dst,flags);
 if (!strcmp(mode,"exit-after-move")) _exit(result==0?71:93);
 return result;
}
#define JBQ_ROOT [fixture stringByAppendingPathComponent:@"quarantine"]
#define JBQ_LOG(message) ((void)(message))
#define JBQ_WRITE_MAP(map,path) fixtureWrite(map,path)
#define JBQ_RENAME fixtureRename
#import "JBQuarantine.h"
int main(int argc,char **argv) { @autoreleasepool {
 if(argc!=3) return 99;
 fixture=[NSString stringWithUTF8String:argv[1]];mode=argv[2];
 NSString *src=[fixture stringByAppendingPathComponent:@"original"];
 int result=auditWithLock(^int {
  if(!strcmp(mode,"hold")) { puts("LOCKED");fflush(stdout);getchar();return 0; }
  if(!strcmp(mode,"restore") || !strcmp(mode,"fail-restore-move") || !strcmp(mode,"race-restore")) return restoreHiddenItems();
  return hideItemAtPath(src);
 });
 printf("RESULT %d\n",result);return 0;
}}
'''
if sys.platform != 'darwin':
    print('Transaction wiring checks OK; SKIP runtime: macOS Foundation required.')
    sys.exit(0)

count = 0
def check(value):
    global count
    assert value
    count += 1

with tempfile.TemporaryDirectory(prefix='jbq-transaction-') as td:
    root=Path(td); (root/'fixture.m').write_text(source,encoding='utf8')
    binary=root/'fixture'
    subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation',
                    '-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(root/'fixture.m'),
                    '-o',str(binary)],check=True)
    def setup(name):
        p=root/name;p.mkdir();(p/'original').write_text('original-data');return p
    def run(p,mode):
        result=subprocess.run([str(binary),str(p),mode],text=True,capture_output=True,timeout=15,check=True)
        return int(result.stdout.strip().split()[-1])
    def journal(p):
        return p/'quarantine/map.plist'
    def entry(p):
        return plistlib.loads(journal(p).read_bytes())[0]

    p=setup('normal');check(run(p,'hide')==0)
    saved=entry(p);check(not (p/'original').exists() and Path(saved['dst']).read_text()=='original-data')
    check(run(p,'hide')==0);check(len(plistlib.loads(journal(p).read_bytes()))==1)
    check(run(p,'restore')==0);check((p/'original').read_text()=='original-data' and not journal(p).exists())

    p=setup('write-failure');check(run(p,'fail-write')==errno.EIO)
    check((p/'original').read_text()=='original-data' and not journal(p).exists())
    check(len(list((p/'quarantine').iterdir()))==1) # stable lock only

    p=setup('move-failure');check(run(p,'fail-move')==errno.EIO)
    check(journal(p).exists() and (p/'original').read_text()=='original-data')
    check(not Path(entry(p)['dst']).exists())
    check(run(p,'restore')==0 and not journal(p).exists())

    for mode,exit_code,moved in [('exit-before-move',70,False),('exit-after-move',71,True)]:
        p=setup(mode)
        proc=subprocess.run([str(binary),str(p),mode],timeout=15)
        check(proc.returncode==exit_code)
        saved=entry(p)
        check((p/'original').exists()!=moved and Path(saved['dst']).exists()==moved)
        check(run(p,'restore')==0) # dead process no longer owns lock
        check((p/'original').read_text()=='original-data' and not journal(p).exists())

    p=setup('restore-failure');check(run(p,'hide')==0);saved=entry(p)
    check(run(p,'fail-restore-move')!=0)
    check(journal(p).exists() and Path(saved['dst']).read_text()=='original-data')
    check(run(p,'restore')==0 and (p/'original').read_text()=='original-data')

    p=setup('restore-race');check(run(p,'hide')==0);saved=entry(p)
    check(run(p,'race-restore')!=0)
    check((p/'original').read_text()=='concurrent-new')
    check(Path(saved['dst']).read_text()=='original-data' and journal(p).exists())

    p=setup('malformed');(p/'quarantine').mkdir();journal(p).write_bytes(b'invalid')
    check(run(p,'hide')==errno.EINVAL)
    check(journal(p).read_bytes()==b'invalid' and (p/'original').read_text()=='original-data')

    p=setup('duplicate-source');check(run(p,'hide')==0);saved=entry(p)
    (p/'original').write_text('new-data');before=journal(p).read_bytes()
    check(run(p,'hide')==errno.EEXIST)
    check(journal(p).read_bytes()==before and Path(saved['dst']).read_text()=='original-data')
    check((p/'original').read_text()=='new-data')

    # Independent processes, not a mocked mutex. Waiting is bounded by select.
    for iteration in range(10):
        p=setup('contention-'+str(iteration))
        check(run(p,'hide')==0);before=journal(p).read_bytes()
        owner=subprocess.Popen([str(binary),str(p),'hold'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            ready,_,_=select.select([owner.stdout],[],[],10);check(bool(ready))
            check(owner.stdout.readline().strip()=='LOCKED')
            check(run(p,'restore')==errno.EBUSY)
            check(run(p,'hide')==errno.EBUSY)
            check(journal(p).read_bytes()==before)
        finally:
            owner.kill();owner.communicate(timeout=10)
        check(run(p,'restore')==0)
        check((p/'original').read_text()=='original-data')
    print(f'PASS: {count} production quarantine transaction assertions (real process contention/exits, injected I/O failures)')
