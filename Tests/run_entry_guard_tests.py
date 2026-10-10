#!/usr/bin/env python3
"""Compile production link guard on macOS in isolated fixtures; not an iOS runtime test."""
import pathlib,tempfile,subprocess,sys
repo=pathlib.Path(__file__).resolve().parents[1]
source=r'''
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
static int raceMode, forcedError;
static int racing_symlink(const char *root, const char *entry) {
 if (forcedError) {errno=forcedError;return -1;}
 if (raceMode) {
  int mode=raceMode;raceMode=0;
  int rc=mode==1 ? symlink(root,entry) : mkdir(entry,0700);
  if(rc!=0)return rc;
  errno=EEXIST;return -1;
 }
 return symlink(root,entry);
}
#define symlink racing_symlink
#include "JBEntryGuard.h"
#undef symlink
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;} count++;}while(0)
static void join(char *out,const char *dir,const char *name){snprintf(out,4096,"%s/%s",dir,name);}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 int count=0;char root[4096],entry[4096],other[4096],file[4096];
 join(root,argv[1],"root");join(entry,argv[1],"jb");join(other,argv[1],"other");
 CHECK(mkdir(root,0700)==0);CHECK(mkdir(other,0700)==0);
 CHECK(jb_entry_ensure_visible(entry,root)==0);
 struct stat first,after;CHECK(lstat(entry,&first)==0 && S_ISLNK(first.st_mode));
 for(int i=0;i<1000;i++)CHECK(jb_entry_ensure_visible(entry,root)==0);
 CHECK(lstat(entry,&after)==0 && first.st_ino==after.st_ino && first.st_dev==after.st_dev);
 CHECK(unlink(entry)==0);CHECK(mkdir(entry,0700)==0);
 join(file,entry,"keep-me");int fd=open(file,O_CREAT|O_EXCL|O_WRONLY,0600);CHECK(fd>=0);CHECK(write(fd,"keep",4)==4);close(fd);
 CHECK(jb_entry_ensure_visible(entry,root)==EISDIR);
 CHECK(lstat(entry,&after)==0 && S_ISDIR(after.st_mode));
 char contents[8]={0};fd=open(file,O_RDONLY);CHECK(fd>=0);CHECK(read(fd,contents,4)==4);close(fd);CHECK(strcmp(contents,"keep")==0);
 // Only test fixtures are removed, never an actual /var/jb.
 CHECK(unlink(file)==0);CHECK(rmdir(entry)==0);CHECK(symlink(other,entry)==0);
 CHECK(jb_entry_ensure_visible(entry,root)==EINVAL);
 CHECK(lstat(entry,&first)==0);CHECK(jb_entry_ensure_visible(entry,"/missing-guard-test-root")==ENOENT);
 CHECK(lstat(entry,&after)==0 && first.st_ino==after.st_ino);
 CHECK(jb_entry_ensure_visible(NULL,root)==EINVAL);
 CHECK(jb_entry_ensure_visible(entry,"")==EINVAL);
 CHECK(unlink(entry)==0);
 raceMode=1;CHECK(jb_entry_ensure_visible(entry,root)==0);
 CHECK(lstat(entry,&after)==0 && S_ISLNK(after.st_mode));CHECK(unlink(entry)==0);
 raceMode=2;CHECK(jb_entry_ensure_visible(entry,root)==EISDIR);
 CHECK(lstat(entry,&after)==0 && S_ISDIR(after.st_mode));CHECK(rmdir(entry)==0);
 forcedError=EACCES;CHECK(jb_entry_ensure_visible(entry,root)==EACCES);
 CHECK(lstat(entry,&after)!=0 && errno==ENOENT);forcedError=0;
 fd=open(entry,O_CREAT|O_EXCL|O_WRONLY,0600);CHECK(fd>=0);close(fd);
 CHECK(jb_entry_ensure_visible(entry,root)==EINVAL);
 CHECK(lstat(entry,&after)==0 && S_ISREG(after.st_mode));
 CHECK(jb_entry_ensure_visible(entry,entry)==ENOTDIR);
 CHECK(unlink(entry)==0);CHECK(symlink("/missing-guard-dangling-target",entry)==0);
 CHECK(jb_entry_ensure_visible(entry,root)==ENOENT);
 CHECK(lstat(entry,&after)==0 && S_ISLNK(after.st_mode));
 printf("PASS: %d guard assertions including 1000 no-op restores\n",count);return 0;
}
'''
if sys.platform!='darwin':
 print('SKIP: compile guard test in macOS CI.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='jb-entry-guard-') as tmp:
 t=pathlib.Path(tmp);(t/'test.c').write_text(source)
 subprocess.run(['xcrun','clang','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(t/'test.c'),'-o',str(t/'test')],check=True)
 subprocess.run([str(t/'test'),str(t)],check=True)
