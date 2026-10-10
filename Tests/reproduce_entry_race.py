#!/usr/bin/env python3
"""Deterministic filesystem replay, NOT execution of iOS launchd or apt/dpkg.
Replays the two syscalls found in app_hide_do_restore with an explicitly
scheduled mkdir writer. All paths live in temporary fixtures under --output.
"""
import argparse,errno,json,os,pathlib,tempfile
parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
a=parser.parse_args();out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
repo=pathlib.Path(__file__).resolve().parents[1]
src=(repo/'BaseBin/launchdhook/src/app_hide.m').read_text()
body=src.split('static void app_hide_do_restore(void)',1)[1].split('void app_hide_global_hide',1)[0]
assert 'unlink("/var/jb")' in body and 'symlink(jbroot, "/var/jb")' in body
results=[]
def attempt(op):
 try:op();return 0
 except OSError as e:return e.errno
with tempfile.TemporaryDirectory(prefix='entry-race-',dir=out) as td:
 p=pathlib.Path(td);real=p/'procursus';real.mkdir();entry=p/'jb'
 try:os.symlink(real,entry,target_is_directory=True)
 except OSError as e:
  raise SystemExit('Symlink fixture unavailable, no test passed: '+str(e))
 # R1: redundant restore removes a valid link; a writer wins the gap.
 u=attempt(lambda:os.unlink(entry))
 (entry/'usr'/'lib').mkdir(parents=True)
 payload=entry/'usr'/'lib'/'preserve.txt';payload.write_text('package-writer-fixture')
 s=attempt(lambda:os.symlink(real,entry,target_is_directory=True))
 assert u==0 and s==errno.EEXIST and entry.is_dir() and not entry.is_symlink()
 results.append({'case':'valid_link_restore_mkdir_interleaving','unlink_errno':u,'symlink_errno':s,'result':'ordinary_directory_conflict'})
 # R2: replaying the old recovery again cannot fix the conflict.
 u=attempt(lambda:os.unlink(entry));s=attempt(lambda:os.symlink(real,entry,target_is_directory=True))
 assert u!=0 and s==errno.EEXIST and payload.read_text()=='package-writer-fixture'
 results.append({'case':'repeat_legacy_restore','unlink_errno':u,'symlink_errno':s,'result':'still_broken_data_preserved_by_fixture'})
 # R3: existence-only state says visible despite wrong entry type.
 hidden=not entry.exists();assert hidden is False
 results.append({'case':'existence_only_hidden_check','is_hidden':hidden,'actual_type':'directory','result':'wrongly_treated_as_visible'})
 # R4: writer also wins during the intentionally absent hide interval;
 # eliminating redundant restore unlink alone does NOT solve this case.
 entry2=p/'jb-hidden-interval';(entry2/'usr'/'lib').mkdir(parents=True)
 s=attempt(lambda:os.symlink(real,entry2,target_is_directory=True));assert s==errno.EEXIST
 results.append({'case':'writer_during_deliberate_hide','symlink_errno':s,'result':'requires_lifecycle_coordination_not_only_idempotence'})
report={'scope':'filesystem syscall replay; writer deliberately scheduled, identity NOT attributed to a device process','source_file':'BaseBin/launchdhook/src/app_hide.m','cases':results}
(out/'entry-race-reproduction.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2));print('PASS: 4 deterministic filesystem scenarios')
