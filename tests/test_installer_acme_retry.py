import subprocess

from installer.adapters.nginx import CertificatePlan


def test_renewal_retries_deactivated_authorization_race_without_hiding_errors(tmp_path, monkeypatch):
    calls = []
    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 1 if len(calls) == 1 else 0, '',
                'Unable to update challenge :: authorization must be pending' if len(calls) == 1 else '')
    monkeypatch.setattr('time.sleep', lambda seconds: None)
    CertificatePlan(root=tmp_path, runner=Runner())._run_renewal({'certificate': 'example.com'})
    assert len(calls) == 2
    assert all('--dry-run' in call for call in calls)


def test_renewal_retries_the_order_not_ready_race_once(tmp_path, monkeypatch):
    """Boulder may still call the order `pending` when certbot 2.9 — which polls the
    authorization, not the order — finalizes it (the real install of ams-test, v0.7)."""
    calls = []
    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            first = len(calls) == 1
            return subprocess.CompletedProcess(argv, 1 if first else 0, '',
                'Failed to renew certificate example.com with error: urn:ietf:params:acme:error:orderNotReady :: '
                'The request attempted to finalize an order that is not ready to be finalized' if first else '')
    monkeypatch.setattr('time.sleep', lambda seconds: None)
    CertificatePlan(root=tmp_path, runner=Runner())._run_renewal({'certificate': 'example.com'})
    assert len(calls) == 2


def test_renewal_does_not_retry_a_real_acme_failure(tmp_path, monkeypatch):
    calls = []
    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 1, '', 'Detail: DNS problem: NXDOMAIN looking up A for example.com')
    monkeypatch.setattr('time.sleep', lambda seconds: None)
    import pytest
    with pytest.raises(Exception, match='renewal dry run failed'):
        CertificatePlan(root=tmp_path, runner=Runner())._run_renewal({'certificate': 'example.com'})
    assert len(calls) == 1


def test_renewal_reuses_only_same_process_same_lineage_evidence(tmp_path):
    calls = []
    class Runner:
        def run(self, argv):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, '', '')
    renewal = tmp_path / 'etc/letsencrypt/renewal/example.com.conf'
    renewal.parent.mkdir(parents=True)
    renewal.write_text('webroot=/var/www/example.com')
    cert = tmp_path / 'etc/letsencrypt/live/example.com/fullchain.pem'
    cert.parent.mkdir(parents=True)
    cert.write_text('synthetic certificate identity')
    adapter = CertificatePlan(root=tmp_path, runner=Runner())
    spec = {'certificate': 'example.com'}
    adapter._run_renewal(spec)
    adapter._run_renewal(spec)
    assert len(calls) == 1
    renewal.write_text('webroot=/var/www/changed')
    adapter._run_renewal(spec)
    assert len(calls) == 2
    CertificatePlan(root=tmp_path, runner=Runner())._run_renewal(spec)
    assert len(calls) == 3
