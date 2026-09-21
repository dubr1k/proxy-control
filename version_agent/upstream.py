"""Ask the upstream projects what they published (v0.11): GitHub Releases for Xray-core,
mieru and Caddy, the ghcr.io and Docker Hub registries for image digests. Fixed hosts,
bounded bodies, and a candidate only when the publisher also published a digest.
"""
from __future__ import annotations

import json
import re
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ALLOWED_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "ghcr.io",
        "registry-1.docker.io",
        "auth.docker.io",
        "index.docker.io",
    }
)
# Ten releases of Caddy come to ~3 MB of JSON (every asset of every platform is listed).
MAX_JSON = 16 * 1024 * 1024
MAX_DIGEST_FILE = 4096
MAX_MANIFEST = 64 * 1024
MAX_TOKEN = 16 * 1024
USER_AGENT = "proxy-control-version-agent/1"
COMPONENTS = ("telemt", "naive", "mita", "xray")
XRAY_MEMBERS = {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}
TELEMT_REPOSITORY = "samnet-dev/mtproxymax-telemt"
_HEX64 = re.compile(r"\b([0-9a-f]{64})\b")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# The Telemt registry tags `<version>-<short commit>` (`3.5.2-b6b9a1f`); the version is
# the numeric part, the digest is looked up by the whole tag.
_IMAGE_TAG = re.compile(r"^(\d+(?:\.\d+){1,3})(?:-[0-9a-f]{6,12})?$")
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

Fetcher = Callable[[str, dict | None, int], tuple[int, dict, bytes]]


class UpstreamError(RuntimeError):
    """The upstream answered something the agent will not act on."""


class _AllowedRedirects(HTTPRedirectHandler):
    """Follow a redirect only while it stays on HTTPS and inside the allowed hosts.

    urllib follows redirects before the caller sees the final URL, so checking
    only the last hop would already have sent a request elsewhere.
    """

    def __init__(self, allowed: frozenset[str]):
        super().__init__()
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in self.allowed:
            raise HTTPError(newurl, code, "redirect left the allowed hosts", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_host(url: str, allowed: frozenset[str]) -> None:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.hostname not in allowed
        or parts.username
        or parts.password
    ):
        raise UpstreamError("upstream host is not allowed")


def open_allowed(url: str, *, allowed: frozenset[str], headers: dict | None = None, timeout: float = 30):
    """Open an HTTPS URL that must stay on `allowed` hosts across every redirect."""
    _check_host(url, allowed)
    request = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    opener = build_opener(_AllowedRedirects(allowed))
    return opener.open(request, timeout=timeout)  # noqa: S310 - host checked above


def fetch_https(url: str, headers: dict | None, maximum: int) -> tuple[int, dict, bytes]:
    try:
        with open_allowed(url, allowed=ALLOWED_HOSTS, headers=headers) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
                raise UpstreamError("upstream redirect left the allowed hosts")
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise UpstreamError("upstream answer is too large")
            return response.status, {k.title(): v for k, v in response.headers.items()}, body
    except HTTPError as exc:
        if exc.reason == "redirect left the allowed hosts":
            raise UpstreamError("upstream redirect left the allowed hosts") from exc
        return exc.code, {k.title(): v for k, v in (exc.headers or {}).items()}, b""
    except (URLError, OSError, ValueError) as exc:
        raise UpstreamError(f"upstream unreachable: {exc}") from exc


def _json(fetcher: Fetcher, url: str, maximum: int = MAX_JSON, headers: dict | None = None):
    status, _, body = fetcher(url, headers, maximum)
    if status != 200:
        raise UpstreamError(f"upstream answered {status} for {urlsplit(url).path}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise UpstreamError("upstream answer is not JSON") from exc


def _header(headers: dict, name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def parse_dgst(text: str) -> str:
    for line in text.splitlines():
        key, _, value = line.partition("=")
        value = value.strip().lower()
        if key.strip() in ("SHA2-256", "SHA256") and _HEX64.fullmatch(value):
            return value
    raise UpstreamError("no SHA2-256 line in .dgst")


def parse_sha256_txt(text: str) -> str:
    match = _HEX64.search(text.lower())
    if not match:
        raise UpstreamError("no SHA-256 in .sha256.txt")
    return match.group(1)


def _parts(version: str) -> tuple[tuple[int, ...], str]:
    core, _, suffix = version.partition("-")
    numbers = tuple(int(piece) if piece.isdigit() else 0 for piece in core.split("."))
    return numbers, suffix


def compare_versions(a: str, b: str) -> int:
    """Numeric dotted compare; a `-suffix` (pre-release) sorts below the bare version."""
    (na, sa), (nb, sb) = _parts(a), _parts(b)
    width = max(len(na), len(nb))
    na, nb = na + (0,) * (width - len(na)), nb + (0,) * (width - len(nb))
    if na != nb:
        return 1 if na > nb else -1
    if sa == sb:
        return 0
    if not sa:
        return 1
    if not sb:
        return -1
    return 1 if sa > sb else -1


def _releases(fetcher: Fetcher, repository: str, *, prereleases: bool = False) -> list[dict]:
    """The repository's last ten releases, newest first. Drafts never count; a pre-release
    counts only where the project marks every release so (Xray-core does, and so does
    this project's own beta line)."""
    items = _json(fetcher, f"https://api.github.com/repos/{repository}/releases?per_page=10")
    if not isinstance(items, list):
        raise UpstreamError("releases answer is not a list")
    result = []
    for item in items:
        if not isinstance(item, dict) or item.get("draft") or (item.get("prerelease") and not prereleases):
            continue
        tag = str(item.get("tag_name") or "")
        version = tag[1:] if tag.startswith("v") else tag
        if not _VERSION.fullmatch(version):
            continue
        raw_assets = item.get("assets")
        assets = {
            asset.get("name"): asset.get("browser_download_url")
            for asset in (raw_assets if isinstance(raw_assets, list) else [])
            if isinstance(asset, dict)
        }
        published = item.get("published_at")
        result.append(
            {
                "tag": tag,
                "version": version,
                "published_at": published if isinstance(published, str) else None,
                "assets": assets,
            }
        )
    result.sort(key=lambda release: _parts(release["version"]), reverse=True)
    return result


def _asset_url(assets: dict, name: str, repository: str) -> str | None:
    url = assets.get(name)
    if not isinstance(url, str):
        return None
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != "github.com"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or not parts.path.startswith(f"/{repository}/releases/download/")
    ):
        raise UpstreamError("asset URL is not the release download of its repository")
    return url


def _github_binary(
    fetcher: Fetcher,
    current: str | None,
    repository: str,
    asset_for: Callable[[str], str],
    digest_suffix: str,
    parse: Callable[[str], str],
    archive_for: Callable[[str], dict],
    *,
    prereleases: bool = False,
) -> dict:
    releases = _releases(fetcher, repository, prereleases=prereleases)
    if not releases:
        return {"latest": None, "installable": False, "reason": "no_releases", "candidates": []}
    latest = releases[0]["version"]
    candidates: list[dict] = []
    reason = None
    for release in releases:
        if current is not None and compare_versions(release["version"], current) <= 0:
            continue
        name = asset_for(release["version"])
        url = _asset_url(release["assets"], name, repository)
        digest_url = _asset_url(release["assets"], name + digest_suffix, repository)
        if not url or not digest_url:
            reason = reason or "no_published_digest"
            continue
        status, _, body = fetcher(digest_url, None, MAX_DIGEST_FILE)
        if status != 200:
            reason = reason or "no_published_digest"
            continue
        try:
            digest = parse(body.decode("utf-8", "replace"))
        except UpstreamError:
            reason = reason or "no_published_digest"
            continue
        candidates.append(
            {
                "version": release["version"],
                "tag": release["tag"],
                "kind": "binary",
                "source": "upstream",
                "url": url,
                "sha256": digest,
                "archive": archive_for(release["version"]),
                "published_at": release["published_at"],
            }
        )
    return {
        "latest": latest,
        "installable": bool(candidates),
        "reason": None if candidates else reason,
        "candidates": candidates,
    }


def _token(fetcher: Fetcher, token_url: str) -> str:
    answer = _json(fetcher, token_url, MAX_TOKEN)
    token = answer.get("token") if isinstance(answer, dict) else None
    if not isinstance(token, str) or not token:
        raise UpstreamError("registry did not issue a pull token")
    return token


def _registry_digest(fetcher: Fetcher, registry: str, repository: str, tag: str, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}", "Accept": _MANIFEST_ACCEPT}
    status, response_headers, _ = fetcher(
        f"https://{registry}/v2/{repository}/manifests/{tag}", headers, MAX_MANIFEST
    )
    digest = _header(response_headers, "Docker-Content-Digest")
    if status != 200 or not _DIGEST.fullmatch(digest):
        raise UpstreamError("registry did not answer with a content digest")
    return digest


def _telemt(fetcher: Fetcher, current: str | None) -> dict:
    repository = TELEMT_REPOSITORY
    token = _token(fetcher, f"https://ghcr.io/token?scope=repository:{repository}:pull")
    listed = _json(
        fetcher,
        f"https://ghcr.io/v2/{repository}/tags/list?n=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    tags = listed.get("tags") if isinstance(listed, dict) else None
    by_version: dict[str, str] = {}
    for tag in tags or []:
        match = _IMAGE_TAG.fullmatch(tag) if isinstance(tag, str) else None
        if match:
            # Two tags of one version (a rebuild) — the registry lists the newer one last.
            by_version[match.group(1)] = tag
    versions = sorted(by_version, key=lambda value: _parts(value)[0], reverse=True)
    if not versions:
        return {"latest": None, "installable": False, "reason": "no_releases", "candidates": []}
    candidates = []
    for version in versions[:5]:
        if current is not None and compare_versions(version, current) <= 0:
            continue
        digest = _registry_digest(fetcher, "ghcr.io", repository, by_version[version], token)
        candidates.append(
            {
                "version": version,
                "tag": by_version[version],
                "kind": "image",
                "source": "upstream",
                "image": f"ghcr.io/{repository}@{digest}",
                "published_at": None,
            }
        )
    return {"latest": versions[0], "installable": bool(candidates), "reason": None, "candidates": candidates}


def _naive(fetcher: Fetcher, current: str | None) -> dict:
    releases = _releases(fetcher, "caddyserver/caddy")
    if not releases:
        return {"latest": None, "installable": False, "reason": "no_releases", "candidates": []}
    latest = releases[0]
    if current is not None and compare_versions(latest["version"], current) <= 0:
        return {"latest": latest["version"], "installable": False, "reason": None, "candidates": []}
    head = _json(fetcher, "https://api.github.com/repos/klzgrad/forwardproxy/commits/caddy2")
    commit = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise UpstreamError("forwardproxy commit is missing")
    token = _token(
        fetcher,
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/caddy:pull",
    )
    digest = _registry_digest(
        fetcher, "registry-1.docker.io", "library/caddy", f"{latest['version']}-builder", token
    )
    candidate = {
        "version": latest["version"],
        "tag": latest["tag"],
        "kind": "build",
        "source": "upstream",
        "published_at": latest["published_at"],
        "build": {
            "caddy_version": latest["version"],
            "builder_image": f"caddy:{latest['version']}-builder@{digest}",
            "forwardproxy_commit": commit,
        },
    }
    return {"latest": latest["version"], "installable": True, "reason": None, "candidates": [candidate]}


def check_component(component: str, current: str | None, *, fetcher: Fetcher, router_enabled: bool) -> dict:
    if component == "xray":
        if not router_enabled:
            return {"latest": None, "installable": False, "reason": "router_not_installed", "candidates": []}
        return _github_binary(
            fetcher,
            current,
            "XTLS/Xray-core",
            lambda _v: "Xray-linux-64.zip",
            ".dgst",
            parse_dgst,
            lambda _v: {"format": "zip", "members": dict(XRAY_MEMBERS)},
            # XTLS marks every Xray-core release a pre-release; the pinned 26.3.27 is one too.
            prereleases=True,
        )
    if component == "mita":
        return _github_binary(
            fetcher,
            current,
            "enfein/mieru",
            lambda v: f"mita_{v}_linux_amd64.tar.gz",
            ".sha256.txt",
            parse_sha256_txt,
            lambda _v: {"format": "tar.gz", "member": "mita"},
        )
    if component == "telemt":
        return _telemt(fetcher, current)
    if component == "naive":
        return _naive(fetcher, current)
    raise UpstreamError("unknown component")


def check_all(current: dict[str, str | None], *, fetcher: Fetcher, router_enabled: bool) -> dict[str, dict]:
    result = {}
    for component in COMPONENTS:
        try:
            result[component] = check_component(
                component, current.get(component), fetcher=fetcher, router_enabled=router_enabled
            )
        except UpstreamError as exc:
            result[component] = {
                "latest": None,
                "installable": False,
                "reason": None,
                "candidates": [],
                "last_error": str(exc),
            }
    return result
