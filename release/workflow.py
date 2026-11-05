"""Admission checks for building once and publishing the accepted release files."""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path


def require_ci(runs: list[dict], sha: str) -> None:
    # gh returns newest first; never accept an older success over a failed rerun.
    if not runs or any(runs[0].get(key) != value for key, value in {
        "headSha": sha, "headBranch": "main", "event": "push",
        "status": "completed", "conclusion": "success",
    }.items()):
        raise ValueError("the exact source commit needs a successful latest main push CI")


def require_candidate(run: dict, repository: str) -> str:
    sha = run.get("head_sha", "")
    if (run.get("path") != ".github/workflows/release.yml"
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or not re.fullmatch(r"[0-9a-f]{40}", sha)):
        raise ValueError("candidate must come from a successful Release run in this repository")
    return sha


def asset_identity(release: dict) -> list[tuple]:
    # Downloads change download_count; it is not part of the file identity.
    return sorted((asset["id"], asset["name"], asset["size"], asset.get("digest"), asset["updated_at"])
                  for asset in release["assets"])


def compare_assets(artifact: Path, draft: Path) -> None:
    expected = {path.name: path for path in artifact.iterdir()}
    actual = {path.name: path for path in draft.iterdir()}
    if not expected or expected.keys() != actual.keys():
        raise ValueError("draft asset set differs from the accepted artifact")
    for name, path in expected.items():
        if not path.is_file() or not actual[name].is_file() or path.read_bytes() != actual[name].read_bytes():
            raise ValueError(f"draft asset differs from the accepted artifact: {name}")


def gh(*args: str) -> bytes:
    return subprocess.check_output(["gh", *args])


def api(repository: str, path: str):
    return json.loads(gh("api", f"repos/{repository}/{path}"))


def check_ci(repository: str, sha: str) -> None:
    runs = json.loads(gh("run", "list", "--repo", repository, "--workflow", "test.yml",
                         "--commit", sha, "--branch", "main", "--event", "push", "--limit", "1",
                         "--json", "headSha,headBranch,event,status,conclusion"))
    require_ci(runs, sha)


def tag_commit(repository: str, tag: str) -> str:
    obj = api(repository, f"git/ref/tags/{tag}")["object"]
    while obj["type"] == "tag":
        obj = api(repository, f"git/tags/{obj['sha']}")["object"]
    if obj["type"] != "commit":
        raise ValueError("release tag does not point to a commit")
    return obj["sha"]


def publish_candidate(repository: str, run_id: str, accepted: str, evidence: str, work: Path) -> None:
    from release.build import verify_release

    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[0-9a-f]{64}", accepted):
        raise ValueError("a numeric Release run ID and accepted archive SHA-256 are required")
    if not evidence.strip():
        raise ValueError("record the completed lab checks before publication")
    run = api(repository, f"actions/runs/{run_id}")
    sha = require_candidate(run, repository)
    check_ci(repository, sha)
    artifacts = api(repository, f"actions/runs/{run_id}/artifacts")["artifacts"]
    artifacts = [entry for entry in artifacts if entry["name"] == "release-dist" and not entry["expired"]]
    if len(artifacts) != 1:
        raise ValueError("expected exactly one unexpired release-dist artifact")
    artifact = artifacts[0]
    dist, draft = work / "dist", work / "draft"
    dist.mkdir(parents=True)
    draft.mkdir()
    archive_bytes = gh("api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or Path(entry.filename).name != entry.filename:
                raise ValueError("unexpected artifact path")
            if (dist / entry.filename).exists():
                raise ValueError("duplicate artifact file")
            (dist / entry.filename).write_bytes(archive.read(entry))
    built = verify_release(dist)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", built.version):
        raise ValueError("invalid release version")
    if built.archive_sha256 != accepted or built.commit != sha:
        raise ValueError("accepted archive digest or source commit differs from the Release run")
    expected = {built.archive.name, "release-manifest.json", "sbom.spdx.json", "SHA256SUMS",
                "install-release.sh", "install-release.sh.sha256"}
    if {path.name for path in dist.iterdir()} != expected:
        raise ValueError("unexpected release file set")
    tag = f"v{built.version}"
    if tag_commit(repository, tag) != sha:
        raise ValueError("release tag moved away from the accepted commit")
    for path in (built.archive, built.installer):
        subprocess.run(["gh", "attestation", "verify", str(path), "--repo", repository,
                        "--signer-workflow", f"{repository}/.github/workflows/release.yml",
                        "--source-digest", sha], check=True)
    release = json.loads(gh("release", "view", tag, "--repo", repository,
                            "--json", "databaseId,isDraft,tagName"))
    if not release["isDraft"] or release["tagName"] != tag:
        raise ValueError("candidate must still be a draft")
    release_id = str(release["databaseId"])
    before = api(repository, f"releases/{release_id}")
    if not before["draft"] or before["tag_name"] != tag:
        raise ValueError("draft release tag changed")
    for asset in before["assets"]:
        if asset["name"] not in expected or (draft / asset["name"]).exists():
            raise ValueError("unexpected or duplicate draft asset")
        (draft / asset["name"]).write_bytes(gh("api", "-H", "Accept: application/octet-stream",
            f"repos/{repository}/releases/assets/{asset['id']}"))
    compare_assets(dist, draft)
    # Recheck identity just before changing visibility. No rebuild or upload occurs.
    after = api(repository, f"releases/{release_id}")
    if not after["draft"] or after["tag_name"] != tag or asset_identity(before) != asset_identity(after) or tag_commit(repository, tag) != sha:
        raise ValueError("draft or tag changed during publication checks")
    subprocess.run(["gh", "api", "--method", "PATCH", f"repos/{repository}/releases/{release_id}",
                    "-F", "draft=false"], check=True, stdout=subprocess.DEVNULL)
    published = api(repository, f"releases/{release_id}")
    if published["draft"] or published["tag_name"] != tag or asset_identity(published) != asset_identity(after):
        raise ValueError("published release identity or assets differ")
    print(f"PUBLISHED {tag} commit={sha} archive={accepted} artifact={artifact['id']} run={run_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("ci", "publish"))
    args = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    if args.command == "ci":
        check_ci(repository, os.environ["GITHUB_SHA"])
        print("Exact source commit CI: OK")
    else:
        publish_candidate(repository, os.environ["SOURCE_RUN_ID"], os.environ["ACCEPTED_SHA256"],
                          os.environ["ACCEPTANCE"], Path(os.environ["RUNNER_TEMP"]) / "accepted-release")


if __name__ == "__main__":
    main()
