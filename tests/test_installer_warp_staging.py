import hashlib
import os
import subprocess
from pathlib import Path
import pytest
from installer.adapters import warp


@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_download_never_reuses_attacker_link(tmp_path, monkeypatch, kind):
    stage=tmp_path/'var/lib/proxy-control/warp'
    stage.mkdir(parents=True)
    victim=tmp_path/'victim'
    victim.write_bytes(b'untouched')
    if kind == 'symlink':
        (stage/'key.asc').symlink_to(victim)
    else:
        os.link(victim, stage/'key.asc')
    monkeypatch.setattr(warp, 'KEY_SHA256', hashlib.sha256(b'key').hexdigest())
    monkeypatch.setattr(warp, 'PACKAGE_SHA256', hashlib.sha256(b'deb').hexdigest())
    class Runner:
        def run(self, argv):
            if argv[0]=='curl':
                p=Path(argv[argv.index('--output')+1])
                p.write_bytes(b'key' if p.name=='key.asc' else b'deb')
            return subprocess.CompletedProcess(argv,0,'','')
    package=warp.WarpAdapter(root=tmp_path, runner=Runner())._prepare_package()
    assert package.read_bytes()==b'deb'
    assert victim.read_bytes()==b'untouched'
