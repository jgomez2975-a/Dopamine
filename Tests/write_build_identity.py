#!/usr/bin/env python3
"""Write fixed-component SHA256 identities into a built bundle BEFORE signing."""
import hashlib
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile

COMPONENTS = ('jbctl', 'launchdhook.dylib', 'systemhook.dylib')

def identities(archive):
    result = {}
    with tarfile.open(archive) as tar:
        for component in COMPONENTS:
            matches = [m for m in tar.getmembers() if m.isfile() and
                       m.name.lstrip('./') == 'basebin/' + component]
            if len(matches) != 1:
                raise ValueError('Missing/duplicate component: ' + component)
            result[component] = hashlib.sha256(tar.extractfile(matches[0]).read()).hexdigest()
    return result

if __name__ == '__main__':
    bundle = Path(sys.argv[1])
    repo = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    value = {'schema':1, 'commit':commit, 'components':identities(bundle/'basebin.tar')}
    (bundle/'DopamineBuildIdentity.plist').write_bytes(plistlib.dumps(value))
    print('Recorded fixed component identities for ' + commit)
