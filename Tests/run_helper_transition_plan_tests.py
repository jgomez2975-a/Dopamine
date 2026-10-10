#!/usr/bin/env python3
"""Pure helper transition planning: never reads/writes device configuration."""
from pathlib import Path
import subprocess,sys,tempfile
repo=Path(__file__).resolve().parents[1]
source=r"""
#import "JBHelperTransitionPlan.h"
#define CHECK(x) do {if(!(x)){NSLog(@"FAIL %d %s",__LINE__,#x);return 1;}count++;}while(0)
static NSData *encode(id object){return [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];}
static id decode(NSData *data){return [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];}
int main(void){@autoreleasepool {int count=0;
 NSString *root=@"/private/preboot/fixture/dopamine-test/procursus";
 NSString *helper=[root stringByAppendingPathComponent:@"basebin/jbctl"];
 NSDictionary *plan=JBHelperTransitionPlan(nil,root);
 CHECK([plan[@"status"] isEqual:@"prepared"]);
 CHECK(![plan[@"original_exists"] boolValue]);CHECK([plan[@"added"] boolValue]);
 CHECK([decode(plan[@"updated"])[@"ProcessBlacklist"] isEqual:@[helper]]);
 NSDictionary *input=@{@"ProcessBlacklist":@[@"/keep/original"],@"unrelated":@{@"flag":@YES}};
 NSData *original=encode(input); plan=JBHelperTransitionPlan(original,root);
 CHECK([plan[@"original"] isEqual:original]);
 CHECK([decode(plan[@"updated"])[@"unrelated"] isEqual:input[@"unrelated"]]);
 CHECK(([decode(plan[@"updated"])[@"ProcessBlacklist"] isEqual:@[@"/keep/original",helper]]));
 CHECK([decode(original) isEqual:input]);
 NSDictionary *repeat=JBHelperTransitionPlan(plan[@"updated"],root);
 CHECK(![repeat[@"added"] boolValue]);CHECK([decode(repeat[@"updated"])[@"ProcessBlacklist"] count]==2);
 CHECK([JBHelperTransitionPlan([NSData data],root)[@"status"] isEqual:@"invalid_config"]);
 CHECK([JBHelperTransitionPlan(encode(@[]),root)[@"status"] isEqual:@"invalid_config"]);
 CHECK([JBHelperTransitionPlan(encode(@{@"ProcessBlacklist":@1}),root)[@"status"] isEqual:@"invalid_blacklist"]);
 CHECK([JBHelperTransitionPlan(encode(@{@"ProcessBlacklist":@[@1]}),root)[@"status"] isEqual:@"invalid_blacklist_entry"]);
 CHECK([JBHelperTransitionPlan(encode(@{@"ProcessBlacklist":@[@"relative"]}),root)[@"status"] isEqual:@"invalid_blacklist_entry"]);
 unichar characters[]={'/',0,'x'};NSString *nul=[NSString stringWithCharacters:characters length:3];
 CHECK([JBHelperTransitionPlan(encode(@{@"ProcessBlacklist":@[nul]}),root)[@"status"] isEqual:@"invalid_blacklist_entry"]);
 CHECK([JBHelperTransitionPlan(nil,@"/var/jb")[@"status"] isEqual:@"invalid_root"]);
 CHECK([JBHelperTransitionPlan(nil,@"/private/preboot/../procursus")[@"status"] isEqual:@"invalid_root"]);
 CHECK(JBHelperTransitionPathIsClean(@"/private/var/tmp/fixture/procursus"));
 CHECK(!JBHelperTransitionPathIsClean(@"/private/preboot//procursus"));
 CHECK(!JBHelperTransitionPathIsClean(@"/private/preboot/./procursus"));
 CHECK(!JBHelperTransitionPathIsClean(@"/private/preboot/procursus/"));
 CHECK(!JBHelperTransitionPathIsClean(@"relative/procursus"));
 CHECK(!JBHelperTransitionPathIsClean(nul));
 CHECK([JBHelperTransitionPlan([NSMutableData dataWithLength:256*1024+1],root)[@"status"] isEqual:@"config_too_large"]);
 CHECK(!JBHelperTransitionTimestampIsNewer(42,1,42,1));
 CHECK(JBHelperTransitionTimestampIsNewer(42,2,42,1));
 CHECK(JBHelperTransitionTimestampIsNewer(43,0,42,999999999));
 CHECK(!JBHelperTransitionTimestampIsNewer(41,999999999,42,0));
 CHECK(!JBHelperTransitionTimestampIsNewer(43,1000000000,42,0));
 printf("PASS: %d pure helper transition planning assertions\n",count);return 0;
}}
"""
if sys.platform!='darwin':
 print('SKIP: helper transition planning tests require macOS Foundation.');sys.exit(0)
with tempfile.TemporaryDirectory(prefix='helper-transition-') as td:
 p=Path(td);(p/'test.m').write_text(source,encoding='utf8')
 subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation','-Wall','-Wextra','-Werror','-I',str(repo/'Shared'),str(p/'test.m'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
