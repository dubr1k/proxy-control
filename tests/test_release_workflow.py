"""Release admission and immutable-file publication contracts."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def guards():
    return importlib.import_module("release.workflow")


def ci_run(**changes):
    return dict(headSha=SHA, headBranch="main", event="push", status="completed", conclusion="success", **changes)


def test_ci_requires_exact_successful_main_push():
    check = guards().require_ci
    check([ci_run()], SHA)
    for field, value in (("headSha", "b" * 40), ("headBranch", "feature"),
                         ("event", "pull_request"), ("status", "in_progress"),
                         ("conclusion", "failure")):
        run = ci_run()
        run[field] = value
        with pytest.raises(ValueError):
            check([run], SHA)
    with pytest.raises(ValueError):
        check([], SHA)


def test_failed_latest_ci_cannot_fall_back_to_old_success():
    newest = ci_run()
    newest["conclusion"] = "failure"
    with pytest.raises(ValueError):
        guards().require_ci([newest, ci_run()], SHA)


def test_candidate_must_be_completed_release_from_same_repository():
    run = dict(path=".github/workflows/release.yml", head_sha=SHA,
               head_repository={"full_name": "owner/project"}, status="completed", conclusion="success")
    assert guards().require_candidate(run, "owner/project") == SHA
    for field, value in (("path", ".github/workflows/test.yml"), ("conclusion", "failure"),
                         ("status", "in_progress"), ("head_sha", "invalid"),
                         ("head_repository", {"full_name": "fork/project"})):
        with pytest.raises(ValueError):
            guards().require_candidate(dict(run, **{field: value}), "owner/project")


def test_published_asset_set_and_bytes_must_equal_tested_artifact(tmp_path):
    artifact, draft = tmp_path / "artifact", tmp_path / "draft"
    artifact.mkdir()
    draft.mkdir()
    for name in ("archive.tar.gz", "install-release.sh", "install-release.sh.sha256", "SHA256SUMS"):
        (artifact / name).write_bytes(name.encode())
        (draft / name).write_bytes(name.encode())
    guards().compare_assets(artifact, draft)
    (draft / "install-release.sh").write_text("changed after acceptance")
    with pytest.raises(ValueError):
        guards().compare_assets(artifact, draft)
    (draft / "install-release.sh").write_bytes(b"install-release.sh")
    (draft / "extra").write_text("unreviewed")
    with pytest.raises(ValueError):
        guards().compare_assets(artifact, draft)
    (draft / "extra").unlink()
    (draft / "SHA256SUMS").unlink()
    with pytest.raises(ValueError):
        guards().compare_assets(artifact, draft)


def test_release_stops_at_draft_and_ci_does_not_repeat_reproducibility():
    release = (ROOT / ".github/workflows/release.yml").read_text()
    ci = (ROOT / ".github/workflows/test.yml").read_text()
    assert "expected_sha256" not in release
    assert "lab-sha256" not in release
    assert "  publish:" not in release
    assert "reproducible-release:" not in ci
    assert "release/workflow.py ci" in release
    publish = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "workflow_dispatch:" in publish
    assert "run: python3 release/workflow.py publish" in publish
    assert "--build-binaries" not in publish
    assert "release/build.py --source" not in publish


@pytest.mark.parametrize("matches", [[], [{"id": 7, "draft": False}],
    [{"id": 7, "draft": True}, {"id": 8, "draft": True}],
    [{"id": True, "draft": True}], [{"id": 0, "draft": True}],
    [{"id": "7", "draft": True}]])
def test_draft_lookup_refuses_missing_ambiguous_published_or_invalid_id(monkeypatch, matches):
    import json

    module = guards()
    pages = [[dict(item, tag_name="v3.2.0") for item in matches]]
    monkeypatch.setattr(module, "gh", lambda *args: json.dumps(pages).encode())
    with pytest.raises(ValueError):
        module.draft_release_id("owner/project", "v3.2.0")


@pytest.mark.parametrize("failure", [None, "archive_digest", "draft_installer", "tag_commit", "draft_tag"])
def test_publication_uses_verified_bytes_and_refuses_changed_candidate(tmp_path, monkeypatch, failure):
    import io
    import json
    import zipfile
    from test_release_build import build, clean_checkout

    module = guards()
    built = build(tmp_path, "built", clean_checkout(tmp_path))
    dist = tmp_path / "built"
    files = {path.name: path.read_bytes() for path in dist.iterdir()}
    compressed = io.BytesIO()
    with zipfile.ZipFile(compressed, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    assets = [dict(id=index, name=name, size=len(data), digest=None, updated_at="fixed")
              for index, (name, data) in enumerate(files.items(), 1)]
    published = []
    release_reads = []
    sha = built.commit

    def remote(*args):
        path = args[-1]
        if args[:2] == ("run", "list"):
            return json.dumps([dict(ci_run(), headSha=sha)]).encode()
        if args == ("api", "--paginate", "--slurp", "repos/owner/project/releases?per_page=100"):
            # Draft-by-tag lookup can return 404; the list endpoint includes drafts.
            return b'[[{"id": 8, "draft": false, "tag_name": "v3.1.0"}], [{"id": 7, "draft": true, "tag_name": "v3.2.0"}]]'
        if path.endswith("actions/runs/42"):
            result = dict(path=".github/workflows/release.yml", head_sha=sha,
                          head_repository={"full_name": "owner/project"}, status="completed", conclusion="success")
        elif path.endswith("/artifacts"):
            result = {"artifacts": [dict(id=99, name="release-dist", expired=False)]}
        elif path.endswith("/99/zip"):
            return compressed.getvalue()
        elif "/git/ref/tags/" in path:
            result = {"object": {"type": "commit", "sha": "b" * 40 if failure == "tag_commit" else sha}}
        elif path.endswith("/releases/7"):
            tag = "v3.2.1" if failure == "draft_tag" and release_reads else "v3.2.0"
            result = dict(draft=not published, tag_name=tag, assets=assets)
            release_reads.append(True)
        elif "/releases/assets/" in path:
            asset = next(asset for asset in assets if str(asset["id"]) == path.rsplit("/", 1)[1])
            if failure == "draft_installer" and asset["name"] == "install-release.sh":
                return b"changed installer"
            return files[asset["name"]]
        else:
            raise AssertionError(f"unexpected remote request: {args}")
        return json.dumps(result).encode()

    def command(args, **kwargs):
        if "PATCH" in args:
            assert args[-2:] == ["-F", "draft=false"]
            published.append(True)
        else:
            assert args[:3] == ["gh", "attestation", "verify"]

    monkeypatch.setattr(module, "gh", remote)
    monkeypatch.setattr(module.subprocess, "run", command)
    digest = "0" * 64 if failure == "archive_digest" else built.archive_sha256
    if failure:
        with pytest.raises(ValueError):
            module.publish_candidate("owner/project", "42", digest, "lab checks passed", tmp_path / "accepted")
        assert not published
    else:
        module.publish_candidate("owner/project", "42", digest, "lab checks passed", tmp_path / "accepted")
        assert published == [True]
