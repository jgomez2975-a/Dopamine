#!/usr/bin/env python3
"""Actual backup/exchange/rollback in a temporary macOS fixture only."""
from pathlib import Path
import subprocess,sys,tempfile
repo=Path(__file__).resolve().parents[1]
source=r"""
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <errno.h>
static int exchangeError;
static int testExchange(const char *a,const char *b,unsigned int flags){if(exchangeError){errno=exchangeError;return -1;}return renamex_np(a,b,flags);}
#define JB_TRANSITION_EXCHANGE testExchange
#import "JBHelperTransitionStore.h"
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
static NSData *encode(id object){return [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];}
static id decode(NSData *data){return [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];}
int main(int argc,char **argv){@autoreleasepool {(void)argc;int count=0;
 NSString *dir=[NSString stringWithUTF8String:argv[1]],*file=[dir stringByAppendingPathComponent:@"config.plist"];
 NSData *replacement=encode(@{@"ProcessBlacklist":@[@"/fixture/jbctl"]});
 NSDictionary *r=JBTransitionReplace(file,nil,replacement);
 CHECK([r[@"status"] isEqual:@"applied"]);CHECK([r[@"changed"] boolValue]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:replacement]);
 NSString *firstBackup=r[@"backup_directory"];
 CHECK([[NSFileManager defaultManager] fileExistsAtPath:[firstBackup stringByAppendingPathComponent:@"original.plist"]]);
 struct stat before,after;CHECK(stat(file.fileSystemRepresentation,&before)==0);
 r=JBTransitionRollback(file,firstBackup);CHECK([r[@"status"] isEqual:@"applied"]);
 CHECK([decode([NSData dataWithContentsOfFile:file]) isEqual:@{}]);
 CHECK(stat(file.fileSystemRepresentation,&after)==0);
 CHECK(JBHelperTransitionTimestampIsNewer(after.st_mtimespec.tv_sec,after.st_mtimespec.tv_nsec,before.st_mtimespec.tv_sec,before.st_mtimespec.tv_nsec));
 NSData *original=encode(@{@"keep":@"value",@"ProcessBlacklist":@[@"/old"]});
 CHECK([original writeToFile:file atomically:YES]);
 r=JBTransitionReplace(file,original,replacement);CHECK([r[@"status"] isEqual:@"applied"]);
 NSString *backup=r[@"backup_directory"];
 CHECK([[NSData dataWithContentsOfFile:[backup stringByAppendingPathComponent:@"exchange.plist"]] isEqual:original]);
 r=JBTransitionRollback(file,backup);CHECK([r[@"status"] isEqual:@"applied"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 r=JBTransitionReplace(file,nil,replacement);CHECK([r[@"status"] isEqual:@"preflight_conflict"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 exchangeError=EIO;r=JBTransitionReplace(file,original,replacement);exchangeError=0;
 CHECK([r[@"status"] isEqual:@"exchange_failed"]);CHECK(![r[@"changed"] boolValue]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 r=JBTransitionReplace(file,original,replacement);CHECK([r[@"status"] isEqual:@"applied"]);backup=r[@"backup_directory"];
 CHECK([original writeToFile:file atomically:YES]);r=JBTransitionRollback(file,backup);
 CHECK([r[@"status"] isEqual:@"preflight_conflict"]);CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 NSString *link=[dir stringByAppendingPathComponent:@"link.plist"];
 CHECK(symlink(file.fileSystemRepresentation,link.fileSystemRepresentation)==0);
 r=JBTransitionReplace(link,nil,replacement);CHECK(![r[@"status"] isEqual:@"applied"]);
 CHECK([[NSData dataWithContentsOfFile:file] isEqual:original]);
 CHECK([JBTransitionRollback(file,dir)[@"status"] isEqual:@"invalid_backup"]);
 printf("PASS: %d helper transition backup/exchange/rollback assertions\n",count);return 0;
}}
"""
if sys.platform!='darwin':
 print('SKIP: helper transition store tests require macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='helper-store-') as td:
 p=Path(td);(p/'test.m').write_text(source,encoding='utf8')
 subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test'),td],check=True)
