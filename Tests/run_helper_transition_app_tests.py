#!/usr/bin/env python3
"""Compile production App transition guard; only root uid/device paths stubbed."""
from pathlib import Path
import subprocess,sys,tempfile
repo=Path(__file__).resolve().parents[1]
source=r"""
#import <Foundation/Foundation.h>
#include <unistd.h>
static NSString *fixturePrefix;
static const char *fixtureEntry;
static uid_t pretendUID=0;
static uid_t testUID(void){return pretendUID;}
#define JB_TRANSITION_ROOT_PREFIX fixturePrefix
#define DO_HT_ENTRY fixtureEntry
#define DO_HT_EUID testUID
#import "DOHelperTransition.h"
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
int main(int argc,char **argv){@autoreleasepool{(void)argc;int count=0;
 NSString *dir=[NSString stringWithUTF8String:argv[1]];fixturePrefix=[dir stringByAppendingString:@"/"];
 NSString *root=[dir stringByAppendingPathComponent:@"procursus"],*entry=[dir stringByAppendingPathComponent:@"jb"];
 fixtureEntry=entry.fileSystemRepresentation;
 CHECK(mkdir(root.fileSystemRepresentation,0700)==0);CHECK(symlink(root.fileSystemRepresentation,fixtureEntry)==0);
 pretendUID=501;CHECK([DOHelperTransition(root,nil)[@"status"] isEqual:@"root_access_unavailable"]);pretendUID=0;
 CHECK([DOHelperTransition(nil,nil)[@"status"] isEqual:@"root_unavailable"]);
 CHECK([DOHelperTransition(root,nil)[@"status"] isEqual:@"invalid_basebin"]);
 NSString *base=[root stringByAppendingPathComponent:@"basebin"],*helper=[base stringByAppendingPathComponent:@"jbctl"];
 CHECK(mkdir(base.fileSystemRepresentation,0700)==0);
 CHECK([DOHelperTransition(root,nil)[@"status"] isEqual:@"invalid_helper"]);
 CHECK([[@"fixture" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:helper atomically:YES]);
 CHECK([DOHelperTransition(root,dir)[@"status"] isEqual:@"invalid_backup_directory"]);
 NSDictionary *result=DOHelperTransition(root,nil);CHECK([result[@"status"] isEqual:@"applied"]);
 NSString *backup=result[@"backup_directory"];
 CHECK([DOHelperTransition(root,nil)[@"status"] isEqual:@"already_configured"]);
 CHECK([DOHelperTransition(root,backup)[@"status"] isEqual:@"applied"]);
 CHECK(unlink(fixtureEntry)==0);CHECK(mkdir(fixtureEntry,0700)==0);
 CHECK([DOHelperTransition(root,nil)[@"status"] isEqual:@"entry_not_ready"]);
 printf("PASS: %d production App helper transition guard assertions\n",count);return 0;
}}
"""
if sys.platform!='darwin':
 print('SKIP: App transition tests require macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='helper-app-') as td:
 p=Path(td);(p/'test.m').write_text(source,encoding='utf8')
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Application/Dopamine/UI/Settings'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test'),td],check=True)
