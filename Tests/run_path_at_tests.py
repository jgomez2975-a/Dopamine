#!/usr/bin/env python3
"""Execute production matcher/helper/hooks with OS metadata calls mocked.

This is not an iPhone kernel or application compatibility test.
--expect-old-gap proves the original hooks miss directory-relative queries.
"""
from pathlib import Path
import argparse
import json
import shlex
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--cc', default='xcrun clang' if sys.platform == 'darwin' else 'cc')
parser.add_argument('--expect-old-gap', action='store_true')
parser.add_argument('--report')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
srcdir = root / 'BaseBin/systemhook/src'
matcher = (srcdir / 'hidejb_rules.c').read_text(encoding='utf8')
matcher = matcher[matcher.index('static char gJbRootReal'):matcher.index('void hidejb_rules_set_jbroot')]
helper = (srcdir / 'hidejb_path_at.c').read_text(encoding='utf8')
helper = '\n'.join(x for x in helper.splitlines() if not x.startswith('#include'))
hooks = (srcdir / 'hidejb.c').read_text(encoding='utf8')
if args.expect_old_gap:
    hooks = subprocess.run(['git', '-C', str(root), 'show',
        '32a15641a4291dc39274523af734ca171064455e:BaseBin/systemhook/src/hidejb.c'],
        check=True, capture_output=True, text=True, encoding='utf8').stdout

def function(marker):
    start = hooks.index(marker)
    end = hooks.index('{', start) + 1
    depth = 1
    while depth:
        if hooks[end] == '{': depth += 1
        if hooks[end] == '}': depth -= 1
        end += 1
    return hooks[start:end] + '\n'

prelude = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef PATH_MAX
#undef PATH_MAX
#endif
#define PATH_MAX 1024
#define AT_FDCWD -2
#define F_GETPATH 50
bool hidejb_rules_path_has_marker(const char *);
static const char *base="/var";
static int metadataError,regularFD,probes,originalCalls,lastFD,lastFlag;
static const char *lastPath;
static int fixture_fstat(int fd,struct stat *st) {
    probes++;if(fd<0 || metadataError){errno=EBADF;return -1;}
    memset(st,0,sizeof(*st));st->st_mode=regularFD?S_IFREG:S_IFDIR;return 0;
}
static int fixture_fcntl(int fd,int command,char *out) {
    (void)fd;(void)command;probes++;
    if(metadataError){errno=EIO;return -1;}
    memset(out,0,PATH_MAX);strncpy(out,base,PATH_MAX);return 0;
}
static char *fixture_getcwd(char *out,size_t size) {
    probes++;if(metadataError || strlen(base)>=size){errno=EACCES;return NULL;}
    strcpy(out,base);return out;
}
#define fstat fixture_fstat
#define fcntl fixture_fcntl
#define getcwd fixture_getcwd
'''
adapters = r'''
#undef fstat
#undef fcntl
#undef getcwd
static bool gEnabled=true;
static int fixture_stat(int fd,const char *path,struct stat *buf,int flag){
    (void)buf;originalCalls++;lastFD=fd;lastPath=path;lastFlag=flag;errno=EACCES;return 17;
}
static int fixture_access(int fd,const char *path,int mode,int flag){
    (void)mode;return fixture_stat(fd,path,NULL,flag);
}
static ssize_t fixture_link(int fd,const char *path,char *buf,size_t size){
    (void)buf;(void)size;return fixture_stat(fd,path,NULL,0);
}
static int (*orig_fstatat)(int,const char *,struct stat *,int)=fixture_stat;
static int (*orig_faccessat)(int,const char *,int,int)=fixture_access;
static ssize_t (*orig_readlinkat)(int,const char *,char *,size_t)=fixture_link;
'''
tests = r'''
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(void){
    int count=0;struct stat st;char output[8]="KEEP";
    memset(&st,0x5a,sizeof(st));struct stat before=st;
    CHECK(!hidejb_rules_path_is_jailbreak("jb"));
    CHECK(hidejb_rules_path_is_jailbreak("/var/jb"));
    if(EXPECT_OLD_GAP){
        CHECK(hidejb_fstatat(7,"jb",&st,0)==17);
        CHECK(hidejb_faccessat(7,"jb",0,0)==17);
        CHECK(hidejb_readlinkat(7,"jb",output,sizeof(output))==17);
        printf("PASS: %d assertions reproducing OLD relative-path gap, not a fix\n",count);return 0;
    }
    CHECK(hidejb_fstatat(7,"jb",&st,0)==-1 && errno==ENOENT);
    CHECK(hidejb_faccessat(7,"jb",0,0)==-1 && errno==ENOENT);
    CHECK(hidejb_readlinkat(7,"jb",output,sizeof(output))==-1 && errno==ENOENT);
    CHECK(originalCalls==0);
    CHECK(memcmp(&st,&before,sizeof(st))==0 && strcmp(output,"KEEP")==0);
    const char *relative[]={"jb","./jb",".//jb//file","jb/./file","jb/"};
    for(size_t i=0;i<sizeof(relative)/sizeof(relative[0]);i++){
        errno=ERANGE;CHECK(hidejb_rules_path_at_is_jailbreak(7,relative[i]));
        CHECK(errno==ERANGE);
    }
    base="/private/var";CHECK(hidejb_rules_path_at_is_jailbreak(7,"jb"));
    base="/var/jb";CHECK(hidejb_rules_path_at_is_jailbreak(AT_FDCWD,"."));
    base="/var";CHECK(hidejb_rules_path_at_is_jailbreak(AT_FDCWD,"jb"));
    base="/";CHECK(hidejb_rules_path_at_is_jailbreak(7,"var/jb"));
    base="/var";probes=0;
    CHECK(hidejb_rules_path_at_is_jailbreak(-99,"/var/jb") && probes==0);
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,NULL));
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,""));
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb/../ordinary"));
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,"link/../jb"));
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jbackup"));
    base="/var/containers/Bundle/Application/test";
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb")); // reused fd must not use stale base
    base="/var";regularFD=1;
    errno=ERANGE;CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb") && errno==ERANGE);
    CHECK(hidejb_fstatat(7,"jb",&st,42)==17 && lastFD==7 && lastFlag==42);
    regularFD=0;metadataError=1;errno=ERANGE;
    CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb") && errno==ERANGE);
    CHECK(hidejb_faccessat(7,"jb",4,42)==17 && errno==EACCES);
    CHECK(lastFD==7 && lastFlag==42 && strcmp(lastPath,"jb")==0);
    CHECK(!hidejb_rules_path_at_is_jailbreak(AT_FDCWD,"jb"));
    metadataError=0;CHECK(!hidejb_rules_path_at_is_jailbreak(-99,"jb"));
    char huge[PATH_MAX+32];memset(huge,'x',sizeof(huge));huge[sizeof(huge)-1]=0;
    errno=ERANGE;CHECK(!hidejb_rules_path_at_is_jailbreak(7,huge) && errno==ERANGE);
    base=huge;CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb"));
    base="relative";CHECK(!hidejb_rules_path_at_is_jailbreak(7,"jb"));
    base="/var";gEnabled=false;probes=0;
    CHECK(hidejb_fstatat(7,"jb",&st,0)==17);
    CHECK(hidejb_faccessat(7,"jb",0,0)==17);
    CHECK(hidejb_readlinkat(7,"jb",output,sizeof(output))==17);
    CHECK(probes==0);
    printf("PASS: %d production matcher/helper/hook assertions (OS probes mocked)\n",count);
    return 0;
}
'''
code = prelude + matcher + helper + adapters + ''.join(function(x) for x in (
    'static int hidejb_fstatat(', 'static int hidejb_faccessat(', 'static ssize_t hidejb_readlinkat('))
code += '\n#define EXPECT_OLD_GAP ' + str(int(args.expect_old_gap)) + '\n' + tests
with tempfile.TemporaryDirectory(prefix='dopamine-path-at-') as temp:
    temp = Path(temp)
    source = temp/'test.c'
    source.write_text(code, encoding='utf8')
    binary = temp/('test.exe' if sys.platform == 'win32' else 'test')
    compiler = shlex.split(args.cc)
    subprocess.run(compiler + ['-std=gnu11', '-O1', '-Werror=implicit-function-declaration',
        str(source), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
    print(result.stdout, end='')
    if args.report:
        Path(args.report).write_text(json.dumps({'result': result.stdout.strip(),
            'old_gap_reproduction': args.expect_old_gap,
            'scope': 'Production C with OS metadata mocked; not iPhone verification'},indent=2), encoding='utf8')

    if sys.platform == 'darwin' and not args.expect_old_gap:
        # Separately exercise Darwin F_GETPATH, real directory descriptors and
        # the real API fallthrough against disposable files (no hooks installed).
        native = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
bool hidejb_rules_path_has_marker(const char *);
'''+matcher+helper+r'''
static bool gEnabled=true;
static int (*orig_fstatat)(int,const char *,struct stat *,int)=fstatat;
static int (*orig_faccessat)(int,const char *,int,int)=faccessat;
static ssize_t (*orig_readlinkat)(int,const char *,char *,size_t)=readlinkat;
'''+''.join(function(x) for x in ('static int hidejb_fstatat(',
    'static int hidejb_faccessat(', 'static ssize_t hidejb_readlinkat('))+r'''
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL native %d: %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(int argc,char **argv){
    int count=0;char root[PATH_MAX];struct stat st;char out[32];
    CHECK(realpath(argv[1],root)!=NULL);
    const char *canonical=root;
    if(strncmp(canonical,"/private/var/",13)==0)canonical+=8;
    CHECK(snprintf(gJbRootReal,sizeof(gJbRootReal),"%s/hidden",canonical)>0);
    int dir=open(root,O_RDONLY|O_DIRECTORY);CHECK(dir>=0);
    CHECK(fstatat(dir,"hidden",&st,0)==0);
    CHECK(hidejb_fstatat(dir,"hidden",&st,0)==-1 && errno==ENOENT);
    CHECK(hidejb_faccessat(dir,"hidden",F_OK,0)==-1 && errno==ENOENT);
    CHECK(hidejb_readlinkat(dir,"hidden",out,sizeof(out))==-1 && errno==ENOENT);
    CHECK(hidejb_fstatat(dir,"ordinary",&st,0)==0);
    CHECK(hidejb_faccessat(dir,"ordinary",F_OK,0)==0);
    CHECK(hidejb_readlinkat(dir,"ordinary-link",out,sizeof(out))==8);
    CHECK(memcmp(out,"ordinary",8)==0);
    CHECK(hidejb_fstatat(-999,"hidden",&st,0)==-1 && errno==EBADF);
    int file=openat(dir,"ordinary",O_RDONLY);CHECK(file>=0);
    CHECK(hidejb_fstatat(file,"hidden",&st,0)==-1 && errno==ENOTDIR);
    CHECK(close(file)==0);
    CHECK(fchdir(dir)==0);
    CHECK(hidejb_fstatat(AT_FDCWD,"hidden",&st,0)==-1 && errno==ENOENT);
    CHECK(fstatat(dir,"hidden",&st,0)==0); // real namespace remains intact
    gEnabled=false;CHECK(hidejb_fstatat(dir,"hidden",&st,0)==0);
    CHECK(close(dir)==0);
    printf("PASS: %d native Darwin path-at assertions (temporary fixture, not iOS)\n",count);
    return 0;
}
'''
        fixture=temp/'fixture'
        fixture.mkdir()
        (fixture/'hidden').mkdir()
        (fixture/'ordinary').write_bytes(b'KEEP')
        (fixture/'ordinary-link').symlink_to('ordinary')
        source.write_text(native,encoding='utf8')
        subprocess.run(compiler+['-std=gnu11','-O1','-fsanitize=address,undefined',
            str(source),'-o',str(binary)],check=True)
        subprocess.run([str(binary),str(fixture)],check=True)
        assert (fixture/'ordinary').read_bytes()==b'KEEP'
        assert (fixture/'hidden').is_dir()
