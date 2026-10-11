#!/usr/bin/env python3
"""Filesystem-only synthetic replay; NOT iPhone execution or writer attribution.
Keeps fixtures for inspection. Never operates on device or real user preferences.
"""
import argparse, errno, json, pathlib, uuid
parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True)
a = parser.parse_args()
out = pathlib.Path(a.output).resolve()
out.mkdir(parents=True, exist_ok=True)
fixture = out / ('active-writer-' + str(uuid.uuid4()))
fixture.mkdir()
root = fixture / 'bootstrap'
root.mkdir()
entry = fixture / 'jb'
entry.symlink_to(root, target_is_directory=True)
# Mirrors removal of the globally visible entry followed by a competing writer.
entry.unlink()
prefs = entry / 'Library/Preferences/synthetic-cpu.plist'
prefs.parent.mkdir(parents=True)
prefs.write_bytes(b'synthetic-current-status')
assert entry.is_dir() and not entry.is_symlink()
try:
    entry.symlink_to(root, target_is_directory=True)
except FileExistsError:
    entry_conflict = True
else:
    entry_conflict = False
assert entry_conflict and prefs.read_bytes() == b'synthetic-current-status'
# Mirrors a shared config quarantined while a background writer remains active.
shared = fixture / 'shared-config'
saved = fixture / 'quarantined-config'
shared.write_bytes(b'synthetic-original-settings')
shared.rename(saved)
shared.write_bytes(b'synthetic-new-status')
assert shared.exists() and saved.exists()
assert shared.read_bytes() != saved.read_bytes()
report = {
    'scope': 'synthetic filesystem replay only; no device attribution',
    'fixture': str(fixture),
    'entry_recreated_as_directory': entry_conflict,
    'shared_config_both_present': True,
    'both_payloads_preserved': True,
    'root_cause_fixed': False,
    'required_design_constraints': [
        'A transition mutex alone cannot serialize non-cooperating background writers.',
        'Do not classify preserved conflicting data as successful restoration.',
        'Prevent or reject unsafe global mutation before killing apps or moving shared files.'
    ]
}
(out / 'active-writer-conflicts.json').write_text(json.dumps(report, indent=2), encoding='utf8')
print('PASS: 2 active-writer conflict replays (known failures reproduced, not fixed)')
