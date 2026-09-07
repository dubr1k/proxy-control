import hashlib
import pytest
from installer.adapters.three_xui import ThreeXuiAdapter
from tests.test_installer_three_xui import managed_config


def test_managed_apply_fetches_pinned_archive_without_manual_argument(tmp_path):
    data=b'pinned archive bytes'
    class Runner:
        def fetch_artifact(self, url, destination):
            assert url == 'https://example.com/archive.tar.gz'
            destination.write_bytes(data)
    adapter=ThreeXuiAdapter(root=tmp_path, runner=Runner())
    adapter._pins=lambda: ('https://example.com/archive.tar.gz', hashlib.sha256(data).hexdigest())
    action=adapter._managed_action(managed_config())
    class ReachedVerifiedStaging(Exception):
        pass
    def stage(action, archive):
        assert archive.read_bytes()==data
        raise ReachedVerifiedStaging()
    adapter.stage=stage
    with pytest.raises(ReachedVerifiedStaging):
        adapter.apply(action, {'marker_value':'a'*32, 'ownership':{}})
