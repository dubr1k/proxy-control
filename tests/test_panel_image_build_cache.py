"""Verify release binary packaging and the independent source-build fallback."""

from pathlib import Path
import os
import subprocess
import shutil
import uuid


ROOT = Path(__file__).resolve().parents[1]


def test_release_panel_binary_skips_cargo(tmp_path: Path) -> None:
    dockerfile = (ROOT / "panel/Dockerfile").read_text()
    dockerfile = dockerfile.replace(
        "WORKDIR /src\n",
        "WORKDIR /src\nCOPY --chmod=0755 fake-cargo /usr/local/fake-bin/cargo\nENV PATH=/usr/local/fake-bin:$PATH\n",
    )
    _put(tmp_path, "Dockerfile", dockerfile)
    _put(tmp_path, "fake-cargo", "#!/bin/sh\necho UNEXPECTED_CARGO >&2\nexit 90\n")
    for name, data in {
        "VERSION": "4.0.7\n", "pc_common/RELEASE": "4.0.7\n",
        "pc_common/Cargo.toml": "", "pc_common/Cargo.lock": "", "pc_common/src/lib.rs": "",
        "panel/Cargo.toml": "", "panel/Cargo.lock": "", "panel/crates/web/src/main.rs": "",
        "panel/bin/linux-amd64/panel": "#!/bin/sh\necho release-panel\n",
        "panel/static/style.css": "body {}\n", "panel/entrypoint.sh": "#!/bin/sh\nexit 0\n",
    }.items():
        _put(tmp_path, name, data)
    (tmp_path / "panel/bin/linux-amd64/panel").chmod(0o755)
    result = _build(tmp_path)
    assert result.returncode == 0, result.stdout
    assert "UNEXPECTED_CARGO" not in result.stdout
    _put(tmp_path, "pc_common/RELEASE", "4.0.6\n")
    stale = _build(tmp_path)
    assert stale.returncode != 0, stale.stdout
    assert "panel source generation is incomplete" in stale.stdout


def _put(root: Path, name: str, data: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def _build(context: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "buildx", "build", "--progress=plain", "--output=type=cacheonly", "-f", str(context / "Dockerfile"), str(context)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
        check=False,
    )


def test_source_build_uses_changed_source_even_with_old_timestamp(tmp_path: Path) -> None:
    dockerfile = (ROOT / "panel/Dockerfile").read_text()
    dockerfile += "\nFROM scratch AS test-binary\nCOPY --from=build /out/panel /panel\n"
    _put(tmp_path, "Dockerfile", dockerfile)
    for name, data in {
        "VERSION": "4.0.6\n",
        "pc_common/RELEASE": "4.0.6\n",
        "pc_common/Cargo.toml": "[package]\nname = 'pc_common'\nversion = '0.1.0'\nedition = '2021'\n",
        "pc_common/Cargo.lock": "version = 3\n",
        "pc_common/src/lib.rs": "pub fn value() -> u8 { 1 }\n",
        "panel/Cargo.toml": "[workspace]\nmembers = ['crates/*']\nresolver = '2'\n",
        "panel/Cargo.lock": (
            'version = 3\n[[package]]\nname = "panel-web"\nversion = "0.1.0"\n'
            'dependencies = ["pc_common"]\n[[package]]\nname = "pc_common"\nversion = "0.1.0"\n'
        ),
        "panel/crates/web/Cargo.toml": (
            "[package]\nname = 'panel-web'\nversion = '0.1.0'\nedition = '2021'\n"
            "[[bin]]\nname = 'panel'\npath = 'src/main.rs'\n"
            "[dependencies]\npc_common = { path = '../../../pc_common' }\n"
        ),
        "panel/crates/web/src/main.rs": 'fn main() { println!("{}", pc_common::value()); }\n',
    }.items():
        _put(tmp_path, name, data)
    source = tmp_path / "pc_common/src/lib.rs"
    os.utime(source, (946684800, 946684800))
    output = tmp_path / "binary-output"

    def build() -> str:
        context = tmp_path.parent / ("verified-archive-" + uuid.uuid4().hex)
        context.mkdir()
        for name in ("pc_common", "panel"):
            shutil.copytree(tmp_path / name, context / name)
        shutil.copy2(tmp_path / "Dockerfile", context / "Dockerfile")
        result = subprocess.run(
            [
                "docker", "buildx", "build", "--no-cache", "--progress=plain", "--target=test-binary",
                f"--output=type=local,dest={output}", "-f", str(context / "Dockerfile"), str(context),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "DOCKER_BUILDKIT": "1"},
            check=False,
        )
        assert result.returncode == 0, result.stdout
        value = subprocess.check_output([str(output / "panel")], text=True).strip()
        return value

    assert build() == "1"
    _put(tmp_path, "pc_common/src/lib.rs", "pub fn value() -> u8 { 2 }\n")
    os.utime(source, (946684800, 946684800))
    assert build() == "2"
