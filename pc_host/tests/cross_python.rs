//! Cross-implementation tests against the Python code still in the tree (run on ams-test):
//! the Python operation lock and the Rust one exclude each other in both directions, the Python
//! JSON writers and the Rust ones produce the same bytes, and the malicious archives of the
//! Python release tests are refused by both extractors with the same messages.
//!
//! They run only when `PC_HOST_PYTHON_TREE` names a checkout with the Python `installer`
//! package (and `python3` is on PATH); otherwise each test returns early:
//!
//!     PC_HOST_PYTHON_TREE=/root/dev/rust-host-wp1 cargo test --test cross_python

/// The Python side: one script, several commands.
const SCRIPT: &str = r##""""Python side of `tests/cross_python.rs` (dev-only, run on ams-test with the checkout's
`installer` package): the reference implementation answers the same questions the Rust crate
answers, and the Rust test compares.

    python3 -I cross_python.py <repo-root> <command> <work-dir> [args]

Commands:
  hold-lock <root>          take installer.transaction.operation_lock(root), print "held", wait
                            for a line on stdin, release
  try-lock <root>           try the lock once; print "acquired" or "<Class>: <message>"
  json <corpus.jsonl>       for every line, print [canonical, pretty, agent-state] as written by
                            installer.transaction._canonical_json/_pretty_json and the agent's
                            json.dumps(indent=2, sort_keys=True)
  archives <work-dir>       build the malicious archives of tests/test_installer_release.py and
                            tests/test_release_zip.py, run the Python extractors on them and
                            write cases.json
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, sys.argv[1])
sys.dont_write_bytecode = True

from installer import transaction  # noqa: E402
from installer.release import (  # noqa: E402
    ArchiveEntry,
    ArchiveManifest,
    MemberPin,
    ReleaseError,
    safe_extract_tar,
    safe_extract_zip,
)


def hold_lock(root: str) -> None:
    with transaction.operation_lock(Path(root)):
        print("held", flush=True)
        sys.stdin.readline()


def try_lock(root: str) -> None:
    try:
        with transaction.operation_lock(Path(root)):
            print("acquired", flush=True)
    except Exception as exc:  # noqa: BLE001 - the class name is the answer
        print(f"{type(exc).__name__}: {exc}", flush=True)


def json_forms(corpus: str) -> None:
    out = []
    # Split on "\n" only: str.splitlines() would also split on U+2028 inside a string.
    for line in Path(corpus).read_text(encoding="utf-8").split("\n"):
        if not line:
            continue
        value = json.loads(line)
        out.append([
            transaction._canonical_json(value).decode(),
            transaction._pretty_json(value).decode(),
            json.dumps(value, indent=2, sort_keys=True),
        ])
    sys.stdout.write(json.dumps(out))


def _tar(path: Path, members: list[dict]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            info = tarfile.TarInfo(member["name"])
            info.type = member.get("type", tarfile.REGTYPE)
            info.mode = member.get("mode", 0o644)
            info.uid = member.get("uid", 43210)
            info.gid = member.get("gid", 43210)
            info.linkname = member.get("linkname", "")
            data = member.get("data", b"")
            if info.isreg() or member.get("force_data"):
                info.size = member.get("size", len(data))
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    return path


def _valid_members() -> list[dict]:
    return [
        {"name": "pkg", "type": tarfile.DIRTYPE, "mode": 0o755},
        {"name": "pkg/app", "data": b"verified payload\n", "mode": 0o755},
        {"name": "pkg/current", "type": tarfile.SYMTYPE, "linkname": "app", "mode": 0o777},
    ]


def _valid_entries() -> list[ArchiveEntry]:
    return [
        ArchiveEntry(path="pkg", kind="directory", mode=0o755),
        ArchiveEntry(path="pkg/app", kind="file", mode=0o755, sha256=hashlib.sha256(b"verified payload\n").hexdigest()),
        ArchiveEntry(path="pkg/current", kind="symlink", mode=0o777, link_target="app"),
    ]


def _listing(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result[relative] = ["symlink", oct(mode), os.readlink(path)]
        elif path.is_dir():
            result[relative] = ["directory", oct(mode), ""]
        else:
            result[relative] = ["file", oct(mode), hashlib.sha256(path.read_bytes()).hexdigest()]
    return result


def archives(work: str) -> None:
    out = Path(work)
    cases = []

    def tar_case(name, members, entries, **limits):
        directory = out / name
        directory.mkdir()
        archive = _tar(directory / "artifact.tar.gz", members)
        digest = limits.pop("archive_sha256", None) or hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest = ArchiveManifest(entries=tuple(entries), archive_sha256=digest, **limits)
        destination = directory / "stage"
        try:
            safe_extract_tar(archive, destination, manifest)
            error, tree = None, _listing(destination)
        except ReleaseError as exc:
            error, tree = str(exc), None
        cases.append({
            "case": name, "kind": "tar", "archive": str(archive), "directory": str(directory),
            "entries": [
                {"path": e.path, "kind": e.kind, "mode": e.mode, "sha256": e.sha256, "link_target": e.link_target}
                for e in entries
            ],
            "archive_sha256": digest,
            "limits": {
                "max_entries": manifest.max_entries, "max_total_size": manifest.max_total_size,
                "max_compressed_size": manifest.max_compressed_size,
                "max_decompressed_size": manifest.max_decompressed_size,
                "max_metadata_size": manifest.max_metadata_size,
            },
            "error": error, "tree": tree,
        })

    small = {"max_entries": 4, "max_total_size": 1024}
    for index, member in enumerate(["/etc/shadow", "../../root/.ssh", "safe/../escape"]):
        tar_case(f"escape-{index}", [{"name": member, "data": b"hostile"}], [ArchiveEntry(path="safe", kind="file")], **small)
    for index, member in enumerate([r"..\\escape", r"safe\\..\\escape"]):
        tar_case(f"backslash-{index}", [{"name": member, "data": b"hostile"}], _valid_entries(), max_entries=16, max_total_size=1024)
    for index, target in enumerate(["/etc/shadow", "../../outside"]):
        members = _valid_members()
        members[-1]["linkname"] = target
        tar_case(f"symlink-target-{index}", members, _valid_entries(), max_entries=16, max_total_size=1024)
    for index, kind in enumerate([tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, b"s"]):
        tar_case(f"special-{index}", [{"name": "pkg/app", "type": kind, "linkname": "target"}],
                 [ArchiveEntry(path="pkg/app", kind="file")], max_entries=2, max_total_size=1024)
    for mode in (0o4755, 0o2755, 0o6755):
        tar_case(f"setuid-{mode:o}", [{"name": "pkg/app", "data": b"x", "mode": mode}],
                 [ArchiveEntry(path="pkg/app", kind="file")], max_entries=2, max_total_size=1024)
    layouts = [
        ([{"name": "pkg/app", "data": b"one"}, {"name": "./pkg/app", "data": b"two"}],
         [ArchiveEntry(path="pkg/app", kind="file")], small),
        ([{"name": "pkg/app", "data": b"x"}, {"name": "pkg/extra", "data": b"x"}],
         [ArchiveEntry(path="pkg/app", kind="file")], small),
        ([{"name": "pkg/app", "data": b"x"}],
         [ArchiveEntry(path="pkg/app", kind="file"), ArchiveEntry(path="pkg/required", kind="file")], small),
        ([{"name": "pkg/app", "type": tarfile.DIRTYPE}], [ArchiveEntry(path="pkg/app", kind="file")], small),
        ([{"name": "pkg/app", "data": b"0123456789"}], [ArchiveEntry(path="pkg/app", kind="file")],
         {"max_entries": 4, "max_total_size": 4}),
        ([{"name": "pkg/a", "data": b"a"}, {"name": "pkg/b", "data": b"b"}],
         [ArchiveEntry(path="pkg/a", kind="file"), ArchiveEntry(path="pkg/b", kind="file")],
         {"max_entries": 1, "max_total_size": 1024}),
        ([{"name": "pkg/link", "type": tarfile.SYMTYPE, "linkname": "app"}, {"name": "pkg/link/child", "data": b"hostile"}],
         [ArchiveEntry(path="pkg/link", kind="symlink", link_target="app"), ArchiveEntry(path="pkg/link/child", kind="file")],
         small),
    ]
    for index, (members, entries, limits) in enumerate(layouts):
        tar_case(f"layout-{index}", members, entries, **limits)
    wrong_mode = list(_valid_entries())
    wrong_mode[1] = ArchiveEntry(path="pkg/app", kind="file", mode=0o644, sha256="0" * 64)
    tar_case("mode-mismatch", _valid_members(), wrong_mode, max_entries=16, max_total_size=1024)
    wrong_digest = list(_valid_entries())
    wrong_digest[1] = ArchiveEntry(path="pkg/app", kind="file", mode=0o755, sha256="0" * 64)
    tar_case("digest-mismatch", _valid_members(), wrong_digest, max_entries=16, max_total_size=1024)
    tar_case("payload-directory", [{"name": "pkg", "type": tarfile.DIRTYPE, "mode": 0o755, "size": 4, "data": b"data", "force_data": True}],
             [ArchiveEntry(path="pkg", kind="directory", mode=0o755)],
             max_entries=4, max_total_size=1024, max_decompressed_size=32 * 1024, max_metadata_size=1024)
    tar_case("decompressed-bound", [{"name": "pkg/app", "data": b"x" * 4096}], [ArchiveEntry(path="pkg/app", kind="file")],
             max_entries=4, max_total_size=8192, max_decompressed_size=1024, max_metadata_size=128)
    long_name = f"pkg/{'a' * 600}"
    tar_case("metadata-bound", [{"name": long_name, "data": b"x"}], [ArchiveEntry(path=long_name, kind="file")],
             max_entries=4, max_total_size=1024, max_decompressed_size=32 * 1024, max_metadata_size=128)
    tar_case("long-name-ok", [{"name": long_name, "data": b"x"}], [ArchiveEntry(path=long_name, kind="file")],
             max_entries=4, max_total_size=1024, max_decompressed_size=32 * 1024, max_metadata_size=4096)
    tar_case("compressed-bound", [{"name": "pkg/app", "data": os.urandom(4096)}], [ArchiveEntry(path="pkg/app", kind="file")],
             max_entries=4, max_total_size=8192, max_compressed_size=64, max_decompressed_size=32 * 1024, max_metadata_size=1024)
    tar_case("archive-digest", [{"name": "pkg/app", "data": b"payload"}], [ArchiveEntry(path="pkg/app", kind="file")],
             archive_sha256="0" * 64, max_entries=4, max_total_size=1024, max_decompressed_size=32 * 1024, max_metadata_size=1024)
    tar_case("valid", _valid_members(), _valid_entries(), max_entries=16, max_total_size=1024)

    def zip_case(name, members, pins, *, extras=True, lie=None, max_member_bytes=64 * 1024 * 1024):
        directory = out / name
        directory.mkdir()
        archive = directory / "Xray-linux-64.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for member, data in members.items():
                bundle.writestr(member, data)
            if extras:
                bundle.writestr("README.md", b"# not extracted")
                bundle.writestr("evil/../escape", b"nope")
                info = zipfile.ZipInfo("link")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(info, "/etc/passwd")
        if lie is not None:
            raw = bytearray(archive.read_bytes())
            offset = raw.rfind(lie[0].encode()) - 46 + 24
            raw[offset:offset + 4] = lie[1].to_bytes(4, "little")
            archive.write_bytes(bytes(raw))
        destination = directory / "out"
        try:
            safe_extract_zip(archive, destination, pins, max_member_bytes=max_member_bytes)
            error, tree = None, _listing(destination)
        except ReleaseError as exc:
            error, tree = str(exc), None
        cases.append({
            "case": name, "kind": "zip", "archive": str(archive), "directory": str(directory),
            "pins": [[n, p.sha256, p.size, p.mode] for n, p in pins.items()],
            "max_member_bytes": max_member_bytes, "error": error, "tree": tree,
        })

    def pins(members, modes=None):
        modes = modes or {}
        return {n: MemberPin(sha256=hashlib.sha256(d).hexdigest(), size=len(d), mode=modes.get(n, 0o644)) for n, d in members.items()}

    three = {"xray": b"binary", "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    zip_case("zip-valid", three, pins(three, {"xray": 0o755}))
    bad = pins(three)
    bad["geosite.dat"] = MemberPin(sha256="0" * 64, size=7, mode=0o644)
    zip_case("zip-digest", three, bad)
    short = pins(three)
    short["xray"] = MemberPin(sha256=hashlib.sha256(b"binary").hexdigest(), size=3, mode=0o755)
    zip_case("zip-size", three, short)
    zip_case("zip-member-bound", three, pins(three), max_member_bytes=4)
    two = {"xray": b"binary", "geoip.dat": b"geoip"}
    zip_case("zip-missing", two, pins(three))
    zip_case("zip-name-dotdot", two, {"../xray": MemberPin(sha256="0" * 64, size=1, mode=0o644)})
    zip_case("zip-name-path", two, {"bin/xray": MemberPin(sha256="0" * 64, size=1, mode=0o644)})
    zip_case("zip-symlink-member", two, {"link": MemberPin(sha256=hashlib.sha256(b"/etc/passwd").hexdigest(), size=11, mode=0o644)})
    lying = {"xray": b"x" * 3000, "geoip.dat": b"g", "geosite.dat": b"s"}
    lie_pins = pins(lying)
    lie_pins["xray"] = MemberPin(sha256=hashlib.sha256(b"x" * 3000).hexdigest(), size=10, mode=0o644)
    zip_case("zip-lying-size", lying, lie_pins, extras=False, lie=("xray", 10))

    (out / "cases.json").write_text(json.dumps(cases, indent=1))


def main() -> None:
    command = sys.argv[2]
    if command == "hold-lock":
        hold_lock(sys.argv[3])
    elif command == "try-lock":
        try_lock(sys.argv[3])
    elif command == "json":
        json_forms(sys.argv[3])
    elif command == "archives":
        archives(sys.argv[3])
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main()
"##;

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pc_host::archive::{safe_extract_tar, safe_extract_zip, ArchiveEntry, ArchiveManifest, MemberPin};
use pc_host::json::{canonical, loads, pretty2, pretty2_ascii_nonl};
use pc_host::lock::{operation_lock, BUSY_MESSAGE};
use serde_json::{json, Value};

fn python_tree() -> Option<PathBuf> {
    let tree = std::env::var_os("PC_HOST_PYTHON_TREE").map(PathBuf::from);
    match tree {
        Some(tree) if tree.join("installer/transaction.py").exists() => {
            eprintln!("cross-checking against the Python tree at {}", tree.display());
            Some(tree)
        }
        _ => {
            eprintln!("PC_HOST_PYTHON_TREE does not name a tree with installer/transaction.py; skipping");
            None
        }
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pc-host-cross-{label}-{}", pc_host::fs::token_hex::<8>()));
        fs::create_dir(&path).unwrap();
        Scratch(fs::canonicalize(&path).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The helper script lives outside the checkout (no `.pyc` next to the sources, `-I`).
fn script(dir: &Path) -> PathBuf {
    let path = dir.join("cross_python_helper.py");
    fs::write(&path, SCRIPT).unwrap();
    path
}

fn python(tree: &Path, helper: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("python3");
    command.arg("-I").arg("-B").arg(helper).arg(tree).args(args);
    command
}

#[test]
fn python_lock_holder_excludes_rust() {
    let Some(tree) = python_tree() else { return };
    let dir = Scratch::new("lock-py");
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    let helper = script(dir.path());
    let mut child = python(&tree, &helper, &["hold-lock", root.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "held");
    let error = operation_lock(&root).unwrap_err();
    assert!(error.is_busy(), "{error:?}");
    assert_eq!(error.to_string(), BUSY_MESSAGE);
    child.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
    assert!(child.wait().unwrap().success());
    drop(operation_lock(&root).unwrap());
}

#[test]
fn rust_lock_holder_excludes_python() {
    let Some(tree) = python_tree() else { return };
    let dir = Scratch::new("lock-rs");
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    let helper = script(dir.path());
    let held = operation_lock(&root).unwrap();
    let output = python(&tree, &helper, &["try-lock", root.to_str().unwrap()]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), format!("TransactionBusyError: {BUSY_MESSAGE}"));
    // The golden records the same busy line.
    let golden = loads(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/journals/lock.json"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(golden["busy"], format!("TransactionBusyError: {BUSY_MESSAGE}"));
    drop(held);
    let output = python(&tree, &helper, &["try-lock", root.to_str().unwrap()]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "acquired");
    let mode = fs::metadata(root.join("run/lock/proxy-control.lock")).unwrap().permissions().mode() & 0o7777;
    assert_eq!(format!("{mode:04o}"), golden["mode"].as_str().unwrap());
}

/// A small deterministic generator (no extra crates).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const CHARS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{0}',
    '\u{1}',
    '\u{8}',
    '\t',
    '\n',
    '\u{c}',
    '\r',
    '\u{1f}',
    '\u{7f}',
    '\u{80}',
    '\u{9f}',
    '\u{a0}',
    'é',
    'ß',
    'Ж',
    '日',
    '\u{2028}',
    '\u{feff}',
    '\u{fffd}',
    '\u{ffff}',
    '😀',
    '\u{10ffff}',
    '~',
    '}',
];

fn string(rng: &mut Lcg) -> String {
    (0..rng.below(8)).map(|_| CHARS[rng.below(CHARS.len() as u64) as usize]).collect()
}

fn value(rng: &mut Lcg, depth: u32) -> Value {
    let pick = if depth >= 4 { rng.below(6) } else { rng.below(9) };
    match pick {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => json!([0i64, 1, -1, i64::MAX, i64::MIN, 443, 1767225600][rng.below(7) as usize]),
        3 => json!(u64::MAX - rng.below(3)),
        4 => {
            let pool =
                [0.0, -0.0, 0.1, 1e-05, 1e16, 1e15, 123456789.123, 5e-324, 1.7976931348623157e308, 0.30000000000000004];
            if rng.below(2) == 0 {
                json!(pool[rng.below(pool.len() as u64) as usize])
            } else {
                let bits = rng.next() << 11 | rng.below(2048);
                let float = f64::from_bits(bits);
                if float.is_finite() {
                    json!(float)
                } else {
                    json!(1.5)
                }
            }
        }
        5 => Value::String(string(rng)),
        6 | 7 => Value::Array((0..rng.below(4)).map(|_| value(rng, depth + 1)).collect()),
        _ => Value::Object((0..rng.below(5)).map(|_| (string(rng), value(rng, depth + 1))).collect()),
    }
}

#[test]
fn json_writers_match_the_python_writers() {
    let Some(tree) = python_tree() else { return };
    let dir = Scratch::new("json");
    let helper = script(dir.path());
    let mut rng = Lcg(20261026);
    let mut values: Vec<Value> = (0..400).map(|_| value(&mut rng, 0)).collect();
    // Every golden journal and agent state as well.
    for rel in [
        "installs/kitchen-sink/journal/state.json",
        "journals/handoff/after/ownership.json",
        "agent/updates/05-update-naive-rolled-back/state.json",
    ] {
        values.push(
            loads(
                &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden").join(rel))
                    .unwrap(),
            )
            .unwrap(),
        );
    }
    let corpus = dir.path().join("corpus.jsonl");
    let lines: Vec<String> = values.iter().map(canonical).collect();
    fs::write(&corpus, lines.join("\n") + "\n").unwrap();
    let output = python(&tree, &helper, &["json", corpus.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let forms: Vec<[String; 3]> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(forms.len(), values.len());
    for (value, [canonical_py, pretty_py, agent_py]) in values.iter().zip(forms) {
        assert_eq!(canonical(value), canonical_py);
        assert_eq!(pretty2(value), pretty_py);
        assert_eq!(pretty2_ascii_nonl(value), agent_py);
    }
}

fn listing(root: &Path) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let mode = format!("0o{:o}", metadata.permissions().mode() & 0o7777);
            if metadata.file_type().is_symlink() {
                out.insert(rel, json!(["symlink", mode, fs::read_link(&path).unwrap().to_string_lossy()]));
            } else if metadata.is_dir() {
                out.insert(rel, json!(["directory", mode, ""]));
                stack.push(path);
            } else {
                out.insert(rel, json!(["file", mode, pc_host::fs::sha256_file(&path).unwrap()]));
            }
        }
    }
    out
}

#[test]
fn malicious_archives_are_refused_like_python() {
    let Some(tree) = python_tree() else { return };
    let dir = Scratch::new("archives");
    let helper = script(dir.path());
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let output = python(&tree, &helper, &["archives", work.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let cases = loads(&fs::read(work.join("cases.json")).unwrap()).unwrap();
    let mut compared = 0;
    for case in cases.as_array().unwrap() {
        let name = case["case"].as_str().unwrap();
        let archive = PathBuf::from(case["archive"].as_str().unwrap());
        let destination = PathBuf::from(case["directory"].as_str().unwrap()).join("rust-out");
        let result = if case["kind"] == "tar" {
            let entries = case["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| ArchiveEntry {
                    path: e["path"].as_str().unwrap().into(),
                    kind: e["kind"].as_str().unwrap().into(),
                    mode: e["mode"].as_u64().map(|m| m as u32),
                    sha256: e["sha256"].as_str().map(Into::into),
                    link_target: e["link_target"].as_str().map(Into::into),
                })
                .collect();
            let mut manifest = ArchiveManifest::new(entries, case["archive_sha256"].as_str().unwrap());
            let limits = &case["limits"];
            manifest.max_entries = limits["max_entries"].as_u64().unwrap();
            manifest.max_total_size = limits["max_total_size"].as_u64().unwrap();
            manifest.max_compressed_size = limits["max_compressed_size"].as_u64().unwrap();
            manifest.max_decompressed_size = limits["max_decompressed_size"].as_u64().unwrap();
            manifest.max_metadata_size = limits["max_metadata_size"].as_u64().unwrap();
            safe_extract_tar(&archive, &destination, &manifest)
        } else {
            let pins: Vec<(String, MemberPin)> = case["pins"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let sha256 = p[1].as_str().unwrap().to_string();
                    (
                        p[0].as_str().unwrap().to_string(),
                        MemberPin { sha256, size: p[2].as_u64().unwrap(), mode: p[3].as_u64().unwrap() as u32 },
                    )
                })
                .collect();
            safe_extract_zip(&archive, &destination, &pins, case["max_member_bytes"].as_u64().unwrap())
        };
        match (case["error"].as_str(), result) {
            (None, Ok(())) => {
                let python_tree: BTreeMap<String, Value> = serde_json::from_value(case["tree"].clone()).unwrap();
                assert_eq!(listing(&destination), python_tree, "{name}: extracted trees differ");
            }
            (Some(expected), Err(err)) => {
                if name == "zip-lying-size" {
                    // Python's zipfile stops at the central directory size and fails the CRC
                    // ("could not extract archive"); the zip crate streams the local entry and
                    // the byte count refuses it first. Both refuse and leave nothing behind.
                    assert!(!destination.exists(), "{name}");
                } else {
                    assert_eq!(err.0, expected, "{name}");
                }
            }
            (expected, got) => panic!("{name}: Python {expected:?}, Rust {got:?}"),
        }
        compared += 1;
    }
    assert!(compared >= 35, "{compared}");
}
