#!/usr/bin/env python3
"""Fixed component manifest and read-only on-device digest helper fixtures."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
sys.dont_write_bytecode = True
from write_build_identity import identities, COMPONENTS

repo=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='identity-manifest-') as td:
    archive=Path(td)/'basebin.tar'
    with tarfile.open(archive,'w') as tar:
        for name in COMPONENTS:
            item=tarfile.TarInfo('./basebin/'+name);data=name.encode();item.size=len(data);tar.addfile(item,io.BytesIO(data))
    assert identities(archive)=={name:hashlib.sha256(name.encode()).hexdigest() for name in COMPONENTS}
    with tarfile.open(archive,'w') as tar:
        item=tarfile.TarInfo('basebin/jbctl');item.size=1;tar.addfile(item,io.BytesIO(b'x'))
    try:identities(archive)
    except ValueError:pass
    else:raise AssertionError('Incomplete manifest accepted')
    print('PASS: component manifest normal/missing-component fixtures')

source=r'''
#import "DOComponentIdentity.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);return 1;}count++;}while(0)
int main(int argc,char **argv){@autoreleasepool{
 if(argc!=2)return 2;
 int count=0;NSString *root=[NSString stringWithUTF8String:argv[1]];
 NSFileManager *fm=NSFileManager.defaultManager;
 NSString *base=[root stringByAppendingPathComponent:@"basebin"];
 CHECK([fm createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil]);
 CHECK([DOComponentIdentity(root,root)[@"status"] isEqual:@"unavailable"]);
 NSString *hash=@"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
 NSMutableDictionary *components=[NSMutableDictionary dictionary];
 for(NSString *name in @[@"jbctl",@"launchdhook.dylib",@"systemhook.dylib"]){
  NSString *path=[base stringByAppendingPathComponent:name];
  CHECK([@"abc" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]);
  CHECK([DOComponentHash(path)[@"sha256"] isEqual:hash]);
  components[name]=hash;
 }
 NSString *manifest=[root stringByAppendingPathComponent:@"DopamineBuildIdentity.plist"];
 CHECK([@{@"schema":@1,@"commit":@"fixture",@"components":components} writeToFile:manifest atomically:YES]);
 NSData *before=[NSData dataWithContentsOfFile:manifest];
 NSDictionary *result=DOComponentIdentity(root,root);
 CHECK([result[@"status"] isEqual:@"match"]);
 CHECK([result[@"runtime_activation"] isEqual:@"not_proven_by_disk_hashes"]);
 CHECK(!DOComponentUpdateRequired(10,10,result));
 CHECK(DOComponentUpdateRequired(11,10,result));
 CHECK(!DOComponentUpdateRequired(9,10,@{@"status":@"mismatch"}));
 CHECK(DOComponentUpdateRequired(10,10,@{@"status":@"mismatch"}));
 CHECK(!DOComponentUpdateRequired(10,10,@{@"status":@"unavailable"}));
 CHECK([[NSData dataWithContentsOfFile:manifest] isEqual:before]);
 NSString *file=[base stringByAppendingPathComponent:@"jbctl"];
 CHECK([@"new" writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil]);
 CHECK([DOComponentIdentity(root,root)[@"status"] isEqual:@"mismatch"]);
 CHECK(unlink(file.fileSystemRepresentation)==0);
 CHECK([DOComponentIdentity(root,root)[@"status"] isEqual:@"unavailable"]);
 CHECK(symlink(manifest.fileSystemRepresentation,file.fileSystemRepresentation)==0);
 CHECK(DOComponentHash(file)[@"sha256"]==nil);
 CHECK(unlink(file.fileSystemRepresentation)==0);
 CHECK(mkfifo(file.fileSystemRepresentation,0600)==0);
 CHECK(DOComponentHash(file)[@"sha256"]==nil); // no blocking pipe read
 CHECK(unlink(file.fileSystemRepresentation)==0);
 int fd=open(file.fileSystemRepresentation,O_CREAT|O_WRONLY,0600);CHECK(fd>=0);
 CHECK(ftruncate(fd,32*1024*1024+1)==0);close(fd);
 CHECK(DOComponentHash(file)[@"sha256"]==nil);
 printf("PASS: %d read-only component identity assertions\n",count);return 0;
}}
'''
if sys.platform!='darwin':
    print('SKIP digest runtime: macOS Foundation/CommonCrypto required.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='component-identity-') as td:
    p=Path(td);(p/'test.m').write_text(source,encoding='utf8')
    subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation','-Wall','-Wextra','-Werror',
                    '-I',str(repo/'Application/Dopamine/UI/Settings'),str(p/'test.m'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test'),td],check=True,timeout=20)
