# Interactive Release Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a bilingual interactive and TOML-driven installer that safely deploys Proxy Control Core, NaiveProxy, Mieru, and optional new or existing 3x-ui from verified GitHub Release assets.

**Architecture:** A standard-library Python package turns wizard or TOML input into one canonical plan and executes that plan through journaled component adapters. Release manifests pin every external artifact, while disposable Ubuntu 24.04 QEMU guests prove fresh-host, coexistence, recovery, rollback, and real protocol behavior before publication.

**Tech Stack:** Python 3.12 standard library, Bash, Docker Compose v2, systemd, Nginx stream, UFW, Certbot, pytest/unittest, ShellCheck, QEMU, GitHub Actions artifact attestations, SPDX JSON.

**Spec:** `docs/superpowers/specs/2026-09-03-interactive-release-installer-design.md`

## Global Constraints

- Support only Ubuntu 24.04 with systemd on Linux `amd64` and `arm64`.
- Development and acceptance MUST NOT mutate `ams-server`, `AMS_R`, `AMS_P`, or `AMS_Z`.
- The installer package MUST use the Python standard library; TOML input is parsed with `tomllib`.
- Fleet mTLS remains outside this installer.
- DNS provider APIs and cloud-firewall APIs remain outside this installer.
- UFW mutation is allowed only in `fresh` mode; `coexist` is firewall-read-only.
- Config, canonical plans, logs, reports, argv, process listings, release assets, and CI artifacts MUST contain no generated credential values.
- Runtime downloads MUST use release-pinned immutable tags and SHA-256 values; mutable `main`, `master`, `latest`, and `curl | bash` execution are forbidden.
- Managed-new 3x-ui MUST create VLESS Reality TCP, VLESS Reality XHTTP, and Hysteria2 TLS using newly generated credentials.
- Existing 3x-ui databases, clients, generated Xray config, units, and binary trees remain foreign and unchanged during Proxy Control installation.
- MSS clamping remains a separate explicit diagnostic action and is never enabled by a normal profile.
- Every production behavior change follows red-green-refactor and completes the exact isolated verification named by its task.
- The unrelated untracked `docker/Dockerfile.telemt` MUST remain untouched and uncommitted.

## Planned File Structure

| Path | Responsibility |
|---|---|
| `installer/__init__.py` | Installer package version and public exports. |
| `installer/model.py` | Enums and immutable config/audit/plan/action data models. |
| `installer/config.py` | Versioned TOML parsing, normalization, and profile/domain validation. |
| `installer/audit.py` | Secret-safe host fact collection and command boundary. |
| `installer/planner.py` | Adapter ordering, canonical plan JSON, digest, and stale-fact checks. |
| `installer/transaction.py` | Durable journal, ownership records, resume, rollback, and operation lock. |
| `installer/wizard.py` | Bilingual terminal prompts that produce `InstallerConfig`. |
| `installer/cli.py` | `wizard`, `plan`, `install`, `status`, `repair`, `uninstall`, and `upgrade` routing. |
| `installer/release.py` | Release-manifest validation, artifact hashing, and safe archive extraction. |
| `installer/report.py` | Sanitized progress and acceptance report plus root-only credential handoff. |
| `installer/adapters/base.py` | Adapter protocol and verification evidence types. |
| `installer/adapters/nginx.py` | Effective shared-443 topology, certificates, owned route blocks, restore. |
| `installer/adapters/firewall.py` | Fresh-only ownership-scoped UFW rules and SSH preservation. |
| `installer/adapters/core.py` | Core packages, Compose rendering, Telemt/panel bootstrap and acceptance. |
| `installer/adapters/naive.py` | Caddy/Naive identities, state, unit, overlay, bootstrap and acceptance. |
| `installer/adapters/mieru.py` | Pinned mita artifact, stable UDS, state, overlay and acceptance. |
| `installer/adapters/three_xui.py` | Existing audit and managed-new 3x-ui staged install/configuration. |
| `release/external-artifacts.json` | Reviewed per-architecture upstream tags, URLs, hashes, versions, licenses. |
| `release/build.py` | Reproducible source archive, checksums, manifest and SPDX generation. |
| `release/verify.py` | Offline checksum/manifest verification used by bootstrap and tests. |
| `examples/installer/*.toml` | Secret-free examples for every profile and 3x-ui mode. |
| `tests/test_installer_*.py` | Unit/contract tests for each installer boundary. |
| `tests/lab/*` | Disposable VM topology, protocol clients, failure injection, reports. |
| `.github/workflows/release.yml` | Gated reproducible build, isolated acceptance, attestation and draft release. |

---

### Task 1: Immutable configuration model and TOML schema

**Files:**
- Create: `installer/__init__.py`
- Create: `installer/model.py`
- Create: `installer/config.py`
- Create: `tests/test_installer_config.py`
- Create: `examples/installer/core.toml`
- Create: `examples/installer/core-naive.toml`
- Create: `examples/installer/core-mieru.toml`
- Create: `examples/installer/full-three-xui.toml`
- Create: `examples/installer/existing-three-xui.toml`

**Interfaces:**
- Produces: `HostMode`, `Profile`, `ThreeXuiMode`, `DomainConfig`, `MieruConfig`, `ThreeXuiConfig`, `FirewallConfig`, and immutable `InstallerConfig` in `installer.model`.
- Produces: `load_config(path: Path) -> InstallerConfig`, `parse_config(text: str) -> InstallerConfig`, and `render_config(config: InstallerConfig) -> str` in `installer.config`.
- Produces: `InstallerConfig.required_domains() -> tuple[str, ...]` and `InstallerConfig.canonical_dict() -> dict[str, object]` for later planner and wizard tasks.

- [ ] **Step 1: Write failing schema tests**

```python
from installer.config import parse_config, render_config
from installer.model import HostMode, Profile, ThreeXuiMode


def test_full_managed_config_collects_every_domain():
    config = parse_config(FULL_MANAGED_TOML)
    assert config.host_mode is HostMode.FRESH
    assert config.profile is Profile.FULL
    assert config.three_xui.mode is ThreeXuiMode.MANAGED_NEW
    assert config.required_domains() == (
        "edge.example.com",
        "hy2.example.com",
        "mieru.example.com",
        "panel.example.com",
        "relay.example.com",
        "vless.example.com",
        "xhttp.example.com",
        "xui.example.com",
    )
    assert parse_config(render_config(config)) == config


def test_coexist_rejects_ufw_mutation():
    with pytest.raises(ConfigError, match="UFW can be managed only in fresh mode"):
        parse_config(COEXIST_WITH_UFW_TOML)


def test_config_rejects_irrelevant_and_unknown_fields():
    with pytest.raises(ConfigError, match="unknown key: three_xui.private_key"):
        parse_config(CONFIG_WITH_SECRET_FIELD)
```

- [ ] **Step 2: Run the tests and verify the import failure**

Run: `.venv/bin/pytest tests/test_installer_config.py -q`

Expected: FAIL because `installer.config` does not exist.

- [ ] **Step 3: Implement enums, frozen dataclasses, strict field tables, domain/port/name validation, and deterministic TOML rendering**

```python
class HostMode(StrEnum):
    FRESH = "fresh"
    COEXIST = "coexist"


@dataclass(frozen=True)
class InstallerConfig:
    schema: int
    host_mode: HostMode
    profile: Profile
    acme_email: str
    initial_user: str
    domains: DomainConfig
    mieru: MieruConfig | None
    three_xui: ThreeXuiConfig
    firewall: FirewallConfig

    def canonical_dict(self) -> dict[str, object]:
        return _canonical_dataclass(self)
```

Reject duplicate TCP SNI domains while allowing an explicitly validated UDP/443 Hysteria hostname or dedicated-port Mieru hostname to reuse DNS.

- [ ] **Step 4: Add and validate all five example configurations**

Run: `.venv/bin/pytest tests/test_installer_config.py -q`

Expected: PASS, including a parametrized test that loads every `examples/installer/*.toml` file.

- [ ] **Step 5: Run static checks and commit**

```bash
.venv/bin/ruff check installer tests/test_installer_config.py
python3 scripts/check-doc-links.py
git add installer examples/installer tests/test_installer_config.py
git commit -m "feat(installer): add strict profile configuration"
```

### Task 2: Canonical plan and adapter contracts

**Files:**
- Create: `installer/adapters/__init__.py`
- Create: `installer/adapters/base.py`
- Create: `installer/planner.py`
- Create: `tests/test_installer_plan.py`

**Interfaces:**
- Consumes: `InstallerConfig.canonical_dict()` from Task 1.
- Produces: `AuditFacts`, `Action`, `Evidence`, `InstallPlan`, and `Adapter` protocol.
- Produces: `build_plan(config: InstallerConfig, facts: AuditFacts, adapters: Sequence[Adapter], release: ReleaseIdentity) -> InstallPlan`.
- Produces: `InstallPlan.to_canonical_json() -> bytes`, `InstallPlan.digest -> str`, and `InstallPlan.assert_fresh(current: AuditFacts) -> None`.

- [ ] **Step 1: Write failing deterministic-plan tests**

```python
def test_equivalent_inputs_have_identical_plan_bytes_and_digest():
    first = build_plan(config(), facts(order="forward"), adapters(), release())
    second = build_plan(config(), facts(order="reverse"), adapters(), release())
    assert first.to_canonical_json() == second.to_canonical_json()
    assert first.digest == second.digest
    assert b"password" not in first.to_canonical_json().lower()


def test_apply_rejects_changed_relevant_fact():
    plan = build_plan(config(), facts(free_ports={8443}), adapters(), release())
    with pytest.raises(StalePlanError, match="listener facts changed"):
        plan.assert_fresh(facts(free_ports=set()))
```

- [ ] **Step 2: Run the focused tests and observe missing symbols**

Run: `.venv/bin/pytest tests/test_installer_plan.py -q`

Expected: FAIL because `installer.planner` does not exist.

- [ ] **Step 3: Implement canonical JSON and explicit adapter dependencies**

```python
class Adapter(Protocol):
    name: str
    requires: frozenset[str]

    def plan(self, config: InstallerConfig, facts: AuditFacts) -> tuple[Action, ...]: ...
    def verify(self, action: Action) -> Evidence: ...
    def rollback(self, action: Action, checkpoint: Mapping[str, object]) -> Evidence: ...
```

Topologically sort adapters by `requires`; reject cycles and duplicate action IDs. Hash only stable, security-relevant audit facts. Every action declares owner, mutations, preconditions, verification, inverse operation, and whether credentials are required internally.

- [ ] **Step 4: Run deterministic and cycle tests**

Run: `.venv/bin/pytest tests/test_installer_plan.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the plan contract**

```bash
git add installer/adapters installer/planner.py tests/test_installer_plan.py
git commit -m "feat(installer): define canonical plan contracts"
```

### Task 3: Durable transaction engine and ownership journal

**Files:**
- Create: `installer/transaction.py`
- Create: `tests/test_installer_transaction.py`
- Modify: `scripts/proxyctl.py`

**Interfaces:**
- Consumes: `InstallPlan`, `Action`, `Adapter`, and `Evidence` from Task 2.
- Produces: `TransactionStore(root: Path)`, `TransactionEngine(store: TransactionStore, adapters: Mapping[str, Adapter])`.
- Produces: `TransactionEngine.apply(plan, accepted_digest)`, `resume()`, `repair()`, and `uninstall(purge_data: bool)`.
- Maintains: `/var/lib/proxy-control/installer/state.json`, `plan.json`, `ownership.json`, `backups/`, `report.json`, and `credentials/` below a supplied test root.

- [ ] **Step 1: Write failing crash/recovery and ownership tests**

```python
@pytest.mark.parametrize("crash_after", ["prepared", "applied", "verified"])
def test_resume_after_each_checkpoint_does_not_repeat_committed_mutation(tmp_path, crash_after):
    adapter = RecordingAdapter(crash_after=crash_after)
    engine = engine_for(tmp_path, adapter)
    with pytest.raises(InjectedCrash):
        engine.apply(plan_for(adapter), accepted_digest=plan_for(adapter).digest)
    recovered = engine_for(tmp_path, RecordingAdapter()).resume()
    assert recovered.status == "active"
    assert read_counter(tmp_path, "mutation") == 1


def test_rollback_refuses_foreign_drift_before_deletion(tmp_path):
    engine = installed_engine(tmp_path)
    owned_file(tmp_path).write_text("foreign edit")
    with pytest.raises(OwnershipError, match="owned file drifted"):
        engine.uninstall(purge_data=False)
```

- [ ] **Step 2: Run the transaction tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_transaction.py -q`

Expected: FAIL because `TransactionEngine` is absent.

- [ ] **Step 3: Implement atomic writes, fsync boundaries, lock, phase state machine, and reverse rollback**

Reuse the proven `_atomic_write`, `_durable_remove`, `_operation_lock`, hash, and checkpoint semantics from `scripts/proxyctl.py`; move them without retaining parallel copies. State permissions are `0700` directories and `0600` files. Catch normal exceptions for rollback but allow injected process death to leave a resumable checkpoint.

- [ ] **Step 4: Migrate current Core runtime state through an explicit importer**

```python
def import_runtime_v2(root: Path, legacy: Mapping[str, object]) -> TransactionState:
    validate_legacy_runtime_v2(root, legacy)
    return TransactionState.from_verified_legacy(legacy)
```

Add tests proving credential files, Nginx routes, and Compose data remain byte-identical during import.

- [ ] **Step 5: Run old and new lifecycle tests**

Run: `.venv/bin/pytest tests/test_installer_transaction.py tests/test_proxyctl_runtime.py tests/test_proxyctl_transactions.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the transaction engine**

```bash
git add installer/transaction.py scripts/proxyctl.py tests/test_installer_transaction.py tests/test_proxyctl_runtime.py tests/test_proxyctl_transactions.py
git commit -m "feat(installer): add resumable transaction journal"
```

### Task 4: Bilingual wizard and unified CLI

**Files:**
- Create: `installer/wizard.py`
- Create: `installer/cli.py`
- Create: `installer/i18n.py`
- Create: `tests/test_installer_wizard.py`
- Create: `tests/test_installer_cli.py`
- Modify: `install.sh`
- Modify: `uninstall.sh`
- Modify: `scripts/proxyctl.py`

**Interfaces:**
- Consumes: config types from Task 1, planner from Task 2, and transaction lifecycle from Task 3.
- Produces: `WizardIO` protocol, `TerminalWizard.run(facts: AuditFacts) -> InstallerConfig`, and `installer.cli.main(argv: Sequence[str] | None) -> int`.
- `install.sh` with no arguments starts `python3 -m installer.cli wizard`; explicit lifecycle commands route to the same CLI.

- [ ] **Step 1: Write pseudo-terminal transcript tests**

```python
def test_russian_full_wizard_exports_same_config_as_toml(tmp_path):
    transcript = run_wizard(
        locale="ru_RU.UTF-8",
        answers=["fresh", "full", "managed-new", *DOMAIN_ANSWERS, "no", "save"],
        output=tmp_path / "proxy-control.toml",
    )
    assert "Пароли и ключи будут созданы только при установке" in transcript.output
    assert load_config(tmp_path / "proxy-control.toml") == transcript.config


def test_wizard_quit_before_digest_confirmation_has_no_mutations(tmp_path):
    result = run_cli_in_pty(tmp_path, answers=["core", "quit"])
    assert result.returncode == 0
    assert host_tree(tmp_path) == initial_host_tree()
```

- [ ] **Step 2: Run wizard tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_wizard.py tests/test_installer_cli.py -q`

Expected: FAIL because wizard/CLI modules are absent.

- [ ] **Step 3: Implement typed prompts and deterministic review table**

Prompt methods accept enums, validated strings, integer ports, repeatable routes, and yes/no values. `WizardIO` owns terminal echo control. Passwords are never requested because all runtime secrets are generated during apply.

- [ ] **Step 4: Implement CLI plan-digest confirmation and JSON status**

```python
if args.command == "install":
    plan = planner.plan_from_path(args.config)
    if not secrets.compare_digest(args.accept_plan, plan.digest):
        raise CliError("accepted plan digest does not match")
    engine.apply(plan, accepted_digest=args.accept_plan)
```

Interactive confirmation asks the operator to type the first 12 hex characters; automation requires the complete digest.

- [ ] **Step 5: Run legacy and new CLI tests**

Run: `.venv/bin/pytest tests/test_installer_wizard.py tests/test_installer_cli.py tests/test_proxyctl_runtime.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the unified CLI**

```bash
git add installer install.sh uninstall.sh scripts/proxyctl.py tests/test_installer_wizard.py tests/test_installer_cli.py
git commit -m "feat(installer): add bilingual interactive wizard"
```

### Task 5: Release manifest, artifact hashing, and safe extraction

**Files:**
- Create: `release/external-artifacts.json`
- Create: `installer/release.py`
- Create: `release/verify.py`
- Create: `tests/test_installer_release.py`
- Create: `tests/fixtures/releases/valid-manifest.json`

**Interfaces:**
- Produces: `ReleaseManifest.from_bytes(data: bytes) -> ReleaseManifest`, `verify_artifact(path: Path, expected_sha256: str) -> None`, and `safe_extract_tar(archive: Path, destination: Path, manifest: ArchiveManifest) -> None`.
- Produces: `ExternalArtifact.for_platform(name: str, arch: str) -> ArtifactPin`.
- The manifest starts with Mieru 3.36.0 pins from `MIERU.ru.md` and 3x-ui 3.7.0 pins verified from the upstream GitHub release API.

- [ ] **Step 1: Write failing digest and archive-attack tests**

```python
@pytest.mark.parametrize("member", ["/etc/shadow", "../../root/.ssh", "safe/../escape"])
def test_safe_extract_rejects_escaping_member(tmp_path, member):
    archive = malicious_tar(tmp_path, member)
    with pytest.raises(ReleaseError, match="unsafe archive path"):
        safe_extract_tar(archive, tmp_path / "stage", expected_archive(archive))


def test_external_artifact_is_arch_specific_and_version_pinned():
    manifest = ReleaseManifest.from_bytes(VALID_MANIFEST.read_bytes())
    pin = manifest.external_artifact("three_xui", "arm64")
    assert pin.version == "3.7.0"
    assert pin.sha256 == "3caf1db1e8b10bb1fa1324c945522690bcf01c533ee75b377268f1c01a3ce896"
    assert "latest" not in pin.url
```

- [ ] **Step 2: Run release tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_release.py -q`

Expected: FAIL because `installer.release` does not exist.

- [ ] **Step 3: Add reviewed artifact pins**

Record 3x-ui 3.7.0:

```json
{
  "amd64": {"sha256": "0f8dd7baef3458f6591574e24814f322cf7f5e1e27f0a594683745e50be84ec5"},
  "arm64": {"sha256": "3caf1db1e8b10bb1fa1324c945522690bcf01c533ee75b377268f1c01a3ce896"}
}
```

Record Mieru/mita 3.36.0 package and executable hashes already documented for both architectures. Include SPDX license identifiers and exact official URLs.

- [ ] **Step 4: Implement strict JSON schema and streaming SHA-256**

Reject unknown manifest keys, duplicate artifacts, unsupported schemes/hosts, non-lowercase hashes, mutable URL paths, tag/version mismatch, and platform mismatch.

- [ ] **Step 5: Implement tar validation before extraction**

Accept regular files/directories and internal relative symlinks only. Reject devices, FIFOs, sockets, absolute paths, traversal, hardlinks, setuid/setgid, duplicate normalized paths, oversized member totals, and unexpected files. Extract without preserving archive uid/gid.

- [ ] **Step 6: Run release tests and commit**

```bash
.venv/bin/pytest tests/test_installer_release.py -q
.venv/bin/ruff check installer/release.py release/verify.py tests/test_installer_release.py
git add release installer/release.py tests/test_installer_release.py tests/fixtures/releases
git commit -m "feat(installer): verify pinned release artifacts"
```

### Task 6: Secret-safe host audit and domain preflight

**Files:**
- Create: `installer/audit.py`
- Create: `tests/test_installer_audit.py`
- Modify: `scripts/proxyctl.py`

**Interfaces:**
- Produces: `CommandRunner.run`, `capture`, and `json` with bounded sanitized errors.
- Produces: `audit_host(config: InstallerConfig, runner: CommandRunner) -> AuditFacts`.
- Produces facts for OS, architecture, disks, memory, addresses, DNS A/AAAA, CAA, certificates, listeners/owners, Nginx, Docker/Compose, systemd, UFW, 3x-ui, and existing installer state.

- [ ] **Step 1: Write failing secret-redaction and DNS tests**

```python
def test_audit_error_redacts_headers_passwords_tokens_and_uuid():
    runner = FailingRunner("Authorization: Bearer abc password=hunter2 id=deadbeef-dead-beef-dead-beefdeadbeef")
    with pytest.raises(AuditError) as caught:
        audit_host(config(), runner)
    text = str(caught.value)
    assert "hunter2" not in text
    assert "deadbeef" not in text
    assert text.count("[REDACTED]") >= 3


def test_unhandled_aaaa_and_incompatible_caa_are_hard_stops():
    facts = audit_with_dns(a=[HOST_V4], aaaa=[FOREIGN_V6], caa=["letsencrypt.org"])
    assert {stop.code for stop in facts.hard_stops} == {"dns.unhandled_aaaa", "dns.caa_mismatch"}
```

- [ ] **Step 2: Run audit tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_audit.py -q`

Expected: FAIL because the new audit module is absent.

- [ ] **Step 3: Move current audit parsers behind the new typed fact model**

Preserve current Xray secret-free fields: tag, protocol, listen, port, transport security, and Reality server names. Never serialize client arrays, UUIDs, passwords, private keys, short IDs, authorization headers, cookies, or panel paths.

- [ ] **Step 4: Add platform and domain checks with injectable resolvers**

Use `socket.getaddrinfo` for A/AAAA and `dig +short CAA` through `CommandRunner` when available. Bound every command, timeout, and captured output. Mark externally unobservable cloud-firewall reachability as an explicit operator prerequisite, not a fabricated pass.

- [ ] **Step 5: Run old and new audit suites**

Run: `.venv/bin/pytest tests/test_installer_audit.py tests/test_proxyctl.py tests/test_proxyctl_transactions.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the typed audit**

```bash
git add installer/audit.py scripts/proxyctl.py tests/test_installer_audit.py tests/test_proxyctl.py
git commit -m "feat(installer): add strict host and domain audit"
```

### Task 7: Effective Nginx shared-443 topology and owned routes

**Files:**
- Create: `installer/adapters/nginx.py`
- Create: `tests/test_installer_nginx.py`
- Create: `tests/fixtures/nginx/multi-map.conf`
- Create: `tests/fixtures/nginx/ambiguous-map.conf`
- Modify: `scripts/proxyctl.py`

**Interfaces:**
- Consumes: `CommandRunner` from Task 6 and adapter contracts from Task 2.
- Produces: `parse_effective_nginx(text: str) -> NginxTopology`, `select_route_target(topology, listener_port=443) -> RouteTarget`, and `NginxAdapter`.
- Owns only a marked include file and marked route block selected by the plan.

- [ ] **Step 1: Write failing multiple-map and ambiguity tests**

```python
def test_selects_only_map_feeding_active_443_proxy_pass():
    topology = parse_effective_nginx(MULTI_MAP.read_text())
    target = select_route_target(topology, listener_port=443)
    assert target.variable == "$proxy_control_backend"
    assert target.source_file == "/etc/nginx/stream.d/routes.conf"


def test_ambiguous_active_data_path_is_hard_stop_and_byte_preserving(tmp_path):
    before = fixture_tree(tmp_path, AMBIGUOUS_MAP)
    with pytest.raises(TopologyError, match="more than one effective map"):
        NginxAdapter(root=tmp_path).plan(config(), facts_for(before))
    assert fixture_tree_digest(tmp_path) == before.digest
```

- [ ] **Step 2: Run Nginx tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_nginx.py -q`

Expected: FAIL because effective topology parsing is absent.

- [ ] **Step 3: Implement tokenizer/parser for the relevant Nginx grammar**

Parse comments, quoted tokens, blocks, includes already expanded by `nginx -T`, stream `listen`, `ssl_preread`, `proxy_pass`, and `map` source/destination variables. Track source-file markers from `nginx -T`. Do not use a domain regex over unrelated files as the effective-topology decision.

- [ ] **Step 4: Implement fresh template and coexist owned include**

Fresh mode owns the complete generated stream router. Coexist mode writes one dedicated included file or one exact marked block only after validating the target, then executes `nginx -t` before atomic switch and reload. Restore preserves owner/group/mode/symlink identity.

- [ ] **Step 5: Run Nginx regression tests**

Run: `.venv/bin/pytest tests/test_installer_nginx.py tests/test_proxyctl_transactions.py tests/test_deploy.py -q`

Expected: PASS, including adjacent-route preservation and multiple-map selection.

- [ ] **Step 6: Commit the Nginx adapter**

```bash
git add installer/adapters/nginx.py scripts/proxyctl.py tests/test_installer_nginx.py tests/fixtures/nginx tests/test_proxyctl_transactions.py
git commit -m "feat(installer): manage effective shared 443 routes"
```

### Task 8: Fresh-host packages, certificates, and UFW ownership

**Files:**
- Create: `installer/adapters/packages.py`
- Create: `installer/adapters/firewall.py`
- Create: `tests/test_installer_fresh_host.py`
- Modify: `installer/adapters/nginx.py`

**Interfaces:**
- Produces: `PackagesAdapter`, `CertificatePlan`, and `FirewallAdapter`.
- `FirewallAdapter` consumes selected profile ports and audited SSH listener; it is unavailable in coexist mode.
- Certificate actions consume strict domain facts and produce service-specific certificate evidence.

- [ ] **Step 1: Write failing package-ownership and firewall tests**

```python
def test_packages_adapter_purges_only_packages_it_installed(tmp_path):
    adapter = PackagesAdapter(runner=FakeApt(installed={"curl"}))
    checkpoint = adapter.apply(action_for_packages("curl", "nginx-full"))
    adapter.rollback(action_for_packages("curl", "nginx-full"), checkpoint)
    assert adapter.runner.purged == ["nginx-full"]


def test_fresh_ufw_rules_preserve_ssh_and_are_exactly_reversible(tmp_path):
    ufw = FakeUfw(existing=["22/tcp ALLOW IN"])
    adapter = FirewallAdapter(ufw, ssh_ports={22})
    checkpoint = adapter.apply(firewall_action(tcp={443, 46001}, udp={443, 46001}))
    adapter.rollback(checkpoint.action, checkpoint.data)
    assert ufw.rules == ["22/tcp ALLOW IN"]


def test_coexist_never_emits_firewall_action():
    assert not any(a.owner == "firewall" for a in build_coexist_plan())
```

- [ ] **Step 2: Run fresh-host tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_fresh_host.py -q`

Expected: FAIL because adapters are absent.

- [ ] **Step 3: Implement exact package ownership and certificate grouping**

Package actions record pre-existing status. Certificate actions use webroot HTTP-01, service-specific cert names, private key permission checks, and `certbot renew --dry-run --no-random-sleep-on-renew` acceptance.

- [ ] **Step 4: Implement UFW parser and comment-scoped rule lifecycle**

Refuse unknown/nonstandard output, missing active SSH listener, ambiguous SSH preservation, non-fresh mode, or non-UFW firewall ownership. Never reset UFW, change default policy, delete unowned rules, or represent cloud-firewall state as local success.

- [ ] **Step 5: Run tests and commit**

```bash
.venv/bin/pytest tests/test_installer_fresh_host.py tests/test_installer_nginx.py -q
git add installer/adapters/packages.py installer/adapters/firewall.py installer/adapters/nginx.py tests/test_installer_fresh_host.py
git commit -m "feat(installer): add fresh host and UFW lifecycle"
```

### Task 9: Core Telemt and panel adapter

**Files:**
- Create: `installer/adapters/core.py`
- Create: `tests/test_installer_core.py`
- Modify: `compose.yaml`
- Modify: `probe/install.sh`
- Modify: `scripts/proxyctl.py`

**Interfaces:**
- Produces: `CoreAdapter`, `CorePaths`, and `CoreAcceptance`.
- Consumes Nginx/certificate evidence and creates the existing Compose project `mtproxy` at `/opt/mtproxy-shared443`.
- Produces protocol evidence for panel health/login and Telemt `resPQ` without exposing secrets.

- [ ] **Step 1: Write failing render and lifecycle tests**

```python
def test_core_render_uses_secret_files_and_internal_telemt_api(tmp_path):
    rendered = CoreAdapter(root=tmp_path).render(core_action())
    assert "9091:" not in rendered.compose_yaml
    assert rendered.mode("secrets/users.conf") == 0o600
    assert rendered.mode("secrets/telemt-api-token") == 0o600
    assert "Bearer " not in rendered.env_text


def test_core_acceptance_requires_real_respq_and_panel_login():
    runner = FakeRunner(respq=False, panel_health=True, panel_login=True)
    with pytest.raises(AcceptanceError, match="resPQ"):
        CoreAdapter(runner=runner).verify(core_action())
```

- [ ] **Step 2: Run Core tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_core.py -q`

Expected: FAIL because `CoreAdapter` does not exist.

- [ ] **Step 3: Move current render/install behavior into `CoreAdapter`**

Preserve Compose names, volumes, fixed paths, secrets, bootstrap-via-stdin, and compatibility imports. Build/install the pinned TDLib probe as a planned action rather than an undocumented manual prerequisite.

- [ ] **Step 4: Implement Core acceptance and sanitized evidence**

Require Compose config, all health checks, local panel health, HTTPS panel login with a temporary session, Telemt API isolation, external `resPQ` for each generated test secret, adjacent SNI, and secret scan. Remove temporary acceptance users.

- [ ] **Step 5: Run Core and legacy tests**

Run: `.venv/bin/pytest tests/test_installer_core.py tests/test_proxyctl_runtime.py tests/test_deploy.py panel/tests -q`

Expected: PASS.

- [ ] **Step 6: Commit Core migration**

```bash
git add installer/adapters/core.py compose.yaml probe/install.sh scripts/proxyctl.py tests/test_installer_core.py tests/test_proxyctl_runtime.py
git commit -m "feat(installer): manage core runtime through adapter"
```

### Task 10: NaiveProxy adapter

**Files:**
- Create: `installer/adapters/naive.py`
- Create: `tests/test_installer_naive.py`
- Modify: `compose.naive.yaml`
- Create: `scripts/prepare-naive-state.py`
- Modify: `deploy/caddy-naive.service`

**Interfaces:**
- Produces: `NaiveAdapter`, `NaivePaths`, and `NaiveAcceptance`.
- Consumes the Naive domain certificate and shared-443 route from Task 7.
- Owns only the selected Caddy binary/unit, split identities, manager state/token, accounting log boundary, Compose overlay, and Naive route.

- [ ] **Step 1: Write failing identity, bootstrap, and accounting tests**

```python
def test_naive_plan_stops_on_fixed_identity_collision():
    facts = facts_with_uid(10003, "foreign-service")
    with pytest.raises(PlanError, match="UID 10003 collision"):
        NaiveAdapter().plan(full_config(), facts)


def test_naive_acceptance_requires_closed_connect_accounting():
    runner = FakeNaiveRunner(connect_bytes=4096, recorded_bytes=0)
    with pytest.raises(AcceptanceError, match="accounting"):
        NaiveAdapter(runner=runner).verify(naive_action())
```

- [ ] **Step 2: Run Naive tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_naive.py -q`

Expected: FAIL because `NaiveAdapter` is absent.

- [ ] **Step 3: Extract one safe Naive state preparer**

Implement `scripts/prepare-naive-state.py` with normalized absolute-path, symlink/hardlink, empty-or-owned-state, UID/GID collision, parent ownership, file mode, and idempotence checks. Replace manual shell ownership sequences without recursive `chown`.

- [ ] **Step 4: Implement ordered Naive apply and rollback**

Order: artifact verify, identities, directories/token, staged Caddyfile, pinned Caddy checker, unit, host Caddy, manager bootstrap-only, reload, combined Compose. Rollback restores binary/unit/config/state/log ownership as one generation.

- [ ] **Step 5: Implement real acceptance hooks**

Require loopback Admin API, loopback Caddy TLS backend, public cover HTTPS, authenticated CONNECT with known payload, closed tunnel, accounting delta, manager/panel health, and adjacent SNI. Acceptance credentials are temporary and removed.

- [ ] **Step 6: Run Naive suites and commit**

```bash
.venv/bin/pytest tests/test_installer_naive.py tests/test_naive_manager.py panel/tests/test_naive_management.py tests/test_deploy.py -q
git add installer/adapters/naive.py scripts/prepare-naive-state.py compose.naive.yaml deploy/caddy-naive.service tests/test_installer_naive.py
git commit -m "feat(installer): automate safe Naive deployment"
```

### Task 11: Mieru adapter

**Files:**
- Create: `installer/adapters/mieru.py`
- Create: `tests/test_installer_mieru.py`
- Modify: `compose.mieru.yaml`
- Modify: `deploy/mita.service`
- Modify: `scripts/prepare-mieru-state.sh`
- Modify: `scripts/prepare-mieru-token.sh`

**Interfaces:**
- Produces: `MieruAdapter`, `MieruPaths`, and `MieruAcceptance`.
- Consumes architecture-specific mita 3.36.0 package and executable pins from Task 5.
- Owns mita identity/binary/config/service/stable UDS, manager identity/token/state, selected public listeners, and Compose overlay.

- [ ] **Step 1: Write failing artifact, bootstrap, and listener tests**

```python
def test_mieru_rejects_valid_package_with_wrong_executable_digest(tmp_path):
    artifact = fake_deb(tmp_path, package_hash=PINNED_PACKAGE, binary_hash="0" * 64)
    with pytest.raises(ArtifactError, match="mita executable digest"):
        MieruAdapter().stage(artifact_action(artifact))


def test_mieru_never_starts_empty_generation():
    with pytest.raises(PlanError, match="bootstrap user is required"):
        MieruAdapter().plan(config_without_initial_user(), clean_facts())
```

- [ ] **Step 2: Run Mieru tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_mieru.py -q`

Expected: FAIL because `MieruAdapter` is absent.

- [ ] **Step 3: Implement verified `.deb` extraction and binary staging**

Use `dpkg-deb -x` in a private staging directory after package digest verification, then verify `/usr/bin/mita` digest and `mita version`. Install only the binary and license material; do not install the package for side effects.

- [ ] **Step 4: Implement valid bootstrap generation and stable UDS lifecycle**

Generate the bootstrap password into a `0600` file, create selected TCP/UDP bindings and SOCKS5 egress, apply through the local UDS, preserve the bootstrap user, install the unit/tmpfiles boundary, then start manager overlay. Secret JSON is removed after successful apply and never logged.

- [ ] **Step 5: Implement official-client acceptance**

Run the pinned official Mieru client in the isolated acceptance container with a full Native configuration. Require SOCKS request and HTTP 204 over each enabled transport family, exact server RUNNING output, empty Send-Q for the test flow, manager health, and cleanup of the temporary user. Do not enable MSS clamp.

- [ ] **Step 6: Run Mieru suites and commit**

```bash
.venv/bin/pytest tests/test_installer_mieru.py tests/test_mieru_deployment.py tests/test_mieru_manager.py panel/tests/test_mieru_management.py -q
git add installer/adapters/mieru.py compose.mieru.yaml deploy/mita.service scripts/prepare-mieru-state.sh scripts/prepare-mieru-token.sh tests/test_installer_mieru.py
git commit -m "feat(installer): automate pinned Mieru deployment"
```

### Task 12: Existing and staged 3x-ui lifecycle

**Files:**
- Create: `installer/adapters/three_xui.py`
- Create: `tests/test_installer_three_xui.py`
- Create: `tests/fixtures/three_xui/config-sanitized.json`
- Create: `tests/fixtures/three_xui/release-layout.json`

**Interfaces:**
- Produces: `ThreeXuiAdapter`, `ThreeXuiAudit`, `ThreeXuiInboundFact`, and `ThreeXuiPaths`.
- Consumes 3x-ui 3.7.0 per-architecture pins from Task 5 and safe extraction from `installer.release`.
- Existing mode emits only secret-free facts and Nginx route actions; managed-new mode owns staged binaries, unit, database, generated configuration, and panel route.
- Produces: `ThreeXuiAdapter.plan_existing_upgrade(target: ArtifactPin, facts: ThreeXuiAudit) -> InstallPlan`; this is never called by the normal Proxy Control install plan.

- [ ] **Step 1: Write failing existing-state preservation tests**

```python
def test_existing_mode_never_serializes_clients_or_private_keys(tmp_path):
    write_xray_config(tmp_path, config_with_clients_and_reality_secret())
    audit = ThreeXuiAdapter(root=tmp_path).audit_existing()
    encoded = json.dumps(dataclasses.asdict(audit), sort_keys=True)
    assert "clients" not in encoded
    assert TEST_UUID not in encoded
    assert TEST_PRIVATE_KEY not in encoded


def test_existing_install_plan_has_no_three_xui_mutation():
    actions = ThreeXuiAdapter().plan(existing_config(), existing_facts())
    assert {action.owner for action in actions} == {"nginx.routes.three_xui"}
```

- [ ] **Step 2: Run 3x-ui tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_three_xui.py -q`

Expected: FAIL because `ThreeXuiAdapter` is absent.

- [ ] **Step 3: Implement secret-safe existing audit**

Whitelist tag, protocol, listen, port, transport, security, Reality server names/target, TLS certificate paths, sniffing flags, outbound tags, balancer tags, and non-secret routing selectors. Count clients without reading values into report structures. Hash database/config/unit/binary trees for later byte-identity verification.

- [ ] **Step 4: Implement managed-new staging**

Reject any existing x-ui database, binary tree, unit, service user, or listener. Download the correct versioned asset, verify SHA-256, validate/extract with Task 5, execute `x-ui -v`, stage systemd files, and atomically install only after preconditions remain fresh.

- [ ] **Step 5: Implement and test the separate existing-version upgrade transaction**

`plan_existing_upgrade()` requires an explicit CLI subcommand, stops x-ui, snapshots the database, binary tree and unit as one generation, rehearses the new binary's migration against a private database copy, stages the verified release, starts it, and runs existing-inbound protocol acceptance. Rollback stops the new binary and restores the complete database/binary/unit generation before restart. Add failure injection for download, extraction, migration rehearsal, binary switch, database migration, first start, and acceptance; require the target root byte-identical after every rollback.

Run: `.venv/bin/pytest tests/test_installer_three_xui.py -q`

Expected: PASS, and a normal `existing` Proxy Control install still emits no 3x-ui mutation.

- [ ] **Step 6: Commit 3x-ui lifecycle**

```bash
git add installer/adapters/three_xui.py tests/test_installer_three_xui.py tests/fixtures/three_xui
git commit -m "feat(installer): add pinned 3x-ui lifecycle"
```

### Task 13: Managed 3x-ui inbounds, clients, and optional WARP

**Files:**
- Modify: `installer/adapters/three_xui.py`
- Create: `installer/three_xui_api.py`
- Create: `tests/test_three_xui_api.py`
- Create: `tests/fixtures/three_xui/api-contract-3.7.0.json`

**Interfaces:**
- Produces: `ThreeXuiClient`, `ThreeXuiApi.login()`, `add_inbound(template, client)`, `delete_client(inbound_id, client_id)`, and `effective_config()`.
- Produces managed templates: `vless_reality_tcp`, `vless_reality_xhttp`, `hysteria2_tls`, and optional `warp_routing`.
- Requests are sent over loopback with secrets in private request files/bodies, not argv or logs.

- [ ] **Step 1: Write failing request-shape and secret-surface tests**

```python
def test_managed_templates_match_reference_transports_without_reusing_secrets():
    first = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=1))
    second = build_managed_inbounds(config(), generator=DeterministicSecrets(seed=2))
    assert [(x.protocol, x.network, x.security) for x in first] == [
        ("vless", "tcp", "reality"),
        ("vless", "xhttp", "reality"),
        ("hysteria", "udp", "tls"),
    ]
    assert secret_values(first).isdisjoint(secret_values(second))


def test_api_failure_log_contains_no_cookie_uuid_password_or_private_key():
    with pytest.raises(ThreeXuiApiError) as caught:
        failing_api().add_inbound(template(), client())
    assert sensitive_values().isdisjoint(set(str(caught.value).split()))
```

- [ ] **Step 2: Run API tests and verify RED**

Run: `.venv/bin/pytest tests/test_three_xui_api.py -q`

Expected: FAIL because API client/templates are absent.

- [ ] **Step 3: Implement pinned 3.7.0 local API client**

Use `http.client` with loopback-only URL validation, bounded bodies, explicit timeouts, secure cookie handling in memory, strict response schema, and sanitized errors. Bootstrap the first start inside a temporary network namespace with no non-loopback interface, authenticate locally with the upstream first-run credential, replace username/password/web path through the pinned authenticated API request body, verify the defaults no longer work, then stop the bootstrap process before enabling the normal unit. Do not pass generated secrets to the local CLI and do not directly edit SQLite.

- [ ] **Step 4: Implement reference inbound templates**

Set loopback VLESS backends, unique Reality keys/short IDs/server names, TCP and XHTTP transports, Hysteria2 public UDP/443 with its certificate, tested sniffing flags, direct/blocked routes, private-IP and BitTorrent blocks, and an internal API inbound. Verify the effective generated Xray config after API apply.

- [ ] **Step 5: Implement WARP as a separate opt-in action**

When `warp=false`, emit no WARP outbound or rules. When enabled, generate a new WARP credential boundary, validate the operator-confirmed domains, create the outbound, and append rules without replacing the mandatory final policy. Never copy WARP credentials from reference servers.

- [ ] **Step 6: Add persistent initial users and removable acceptance users**

Persistent credentials go only to the root-only handoff. Acceptance clients are distinct, used by real probes, deleted through the API, and proven absent from the effective configuration before commit.

- [ ] **Step 7: Run API/adapter tests and commit**

```bash
.venv/bin/pytest tests/test_three_xui_api.py tests/test_installer_three_xui.py -q
git add installer/three_xui_api.py installer/adapters/three_xui.py tests/test_three_xui_api.py tests/test_installer_three_xui.py tests/fixtures/three_xui
git commit -m "feat(installer): configure managed 3x-ui profiles"
```

### Task 14: Profile orchestration, reports, and complete acceptance contract

**Files:**
- Create: `installer/report.py`
- Modify: `installer/planner.py`
- Modify: `installer/cli.py`
- Modify: `installer/adapters/core.py`
- Modify: `installer/adapters/naive.py`
- Modify: `installer/adapters/mieru.py`
- Modify: `installer/adapters/three_xui.py`
- Create: `tests/test_installer_profiles.py`
- Create: `tests/test_installer_reports.py`

**Interfaces:**
- Produces: `adapters_for(config: InstallerConfig) -> tuple[Adapter, ...]` and `AcceptanceReport`.
- Produces: `ReportWriter.write_public(report)` and `write_credentials(handoff)` with enforced permissions and disjoint schemas.
- Full profile order is packages → Nginx/certificates → firewall when fresh → Core → Naive → Mieru → 3x-ui → cross-protocol acceptance.

- [ ] **Step 1: Write failing full profile action-order tests**

```python
@pytest.mark.parametrize("profile,xui,expected", PROFILE_MATRIX)
def test_profile_selects_exact_adapters(profile, xui, expected):
    config = config_for(profile=profile, three_xui=xui)
    assert tuple(adapter.name for adapter in adapters_for(config)) == expected


def test_public_report_and_credential_handoff_are_schema_disjoint(tmp_path):
    writer = ReportWriter(tmp_path)
    writer.write_public(report_with_evidence())
    writer.write_credentials(handoff_with_secrets())
    assert sensitive_values().isdisjoint(public_report_values(tmp_path))
    assert stat.S_IMODE((tmp_path / "credentials/handoff.json").stat().st_mode) == 0o600
```

- [ ] **Step 2: Run profile/report tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_profiles.py tests/test_installer_reports.py -q`

Expected: FAIL because orchestration/report boundaries are absent.

- [ ] **Step 3: Implement exact profile adapter selection and dependency order**

Reject unsupported combinations instead of silently omitting a component. Render one canonical Compose file list and root-only non-secret environment file; do not rely on exported interactive shell variables.

- [ ] **Step 4: Implement cross-protocol acceptance and cleanup**

Aggregate only named evidence: health state, response class/status, byte counts, version/digest, listener owner, certificate SAN/expiry, and route result. Remove temporary users/sessions/configs even when a later acceptance check fails.

- [ ] **Step 5: Run all installer unit and existing product tests**

Run: `.venv/bin/pytest tests/test_installer_*.py tests/test_three_xui_api.py tests panel/tests -q`

Expected: PASS.

- [ ] **Step 6: Commit orchestration**

```bash
git add installer tests/test_installer_profiles.py tests/test_installer_reports.py
git commit -m "feat(installer): orchestrate complete safe profiles"
```

### Task 15: Disposable QEMU release-acceptance lab

**Files:**
- Modify: `scripts/lab/qemu_lab.py`
- Modify: `scripts/lab/guest-runner.sh`
- Modify: `scripts/lab/image.json`
- Modify: `tests/lab/test_qemu_lab.py`
- Modify: `tests/lab/README.md`
- Create: `tests/lab/clients/compose.yaml`
- Create: `tests/lab/fixtures/three-xui-existing.sh`
- Create: `tests/lab/fixtures/nginx-multi-map.conf`
- Modify: `Makefile`

**Interfaces:**
- Adds lab modes `release-amd64` and `release-arm64` that accept an exact release archive and checksum.
- Adds scenario filters but treats every required scenario missing from a full report as failure.
- Emits sanitized `report.json`, JUnit XML, and guest log with archive/plan/release digests.

- [ ] **Step 1: Write failing scenario-manifest tests**

```python
def test_release_matrix_contains_required_lifecycle_and_protocol_cases():
    names = set(qemu_lab.release_scenarios())
    assert REQUIRED_RELEASE_SCENARIOS <= names
    assert {"fresh-full-xui", "coexist-existing-xui", "crash-every-phase", "uninstall-foreign-identity"} <= names


def test_missing_scenario_result_fails_report_even_when_guest_exits_zero(tmp_path):
    report = report_without("mieru-official-client")
    assert qemu_lab.validate_report(report).exit_code == 1
```

- [ ] **Step 2: Run host lab tests and verify RED**

Run: `python3 -m unittest -v tests/lab/test_qemu_lab.py`

Expected: FAIL because release scenarios are absent.

- [ ] **Step 3: Add architecture-specific pinned Ubuntu images and release archive input**

Store official image URLs, SHA-256, architecture, and minimum QEMU machine in `image.json`. The controller verifies image and release archive hashes before boot/copy. No production SSH key, DNS, token, domain, or credential enters the guest.

- [ ] **Step 4: Add fresh/coexist topology fixtures and byte-identity baselines**

Fixtures cover one map, multiple maps, ambiguous maps, adjacent sites, non-Nginx 443, existing 3x-ui 3.6.0 and 3.7.0, occupied ports, A/AAAA/CAA failures, UFW policies, interrupted state, and corrupt artifacts. Foreign trees are hashed before/after.

- [ ] **Step 5: Add real protocol clients in isolated containers**

The client Compose project runs pinned Telemt/TDLib, Naive, Mieru, VLESS TCP/XHTTP, Hysteria2, and HTTPS probes against synthetic guest DNS. It records status/byte counts only and deletes ephemeral credentials with the guest overlay.

- [ ] **Step 6: Add failure injection, reboot, repair, repeated install, and uninstall scenarios**

Exercise every durable phase. Verify recovery performs each committed mutation once, retains user data by default, restores foreign state byte-for-byte, and removes only explicitly owned firewall/routes/files/packages.

- [ ] **Step 7: Run host lab checks and smoke guest**

```bash
make lab-test
make lab-prepare
make lab-start
make lab-smoke
make lab-stop
```

Expected: all host tests and smoke scenarios PASS.

- [ ] **Step 8: Commit the isolated lab**

```bash
git add scripts/lab tests/lab Makefile
git commit -m "test(installer): add isolated release acceptance lab"
```

### Task 16: Reproducible release builder and GitHub workflow

**Files:**
- Create: `VERSION`
- Create: `release/build.py`
- Create: `release/sbom.py`
- Create: `install-bootstrap`
- Create: `tests/test_release_build.py`
- Create: `.github/workflows/release.yml`
- Modify: `.github/workflows/test.yml`
- Modify: `Makefile`

**Interfaces:**
- Produces: `python3 release/build.py --source . --output dist --version 0.1.0 --commit <sha>`.
- Produces deterministic tar.gz, SHA-256 file, SPDX JSON, `release-manifest.json`, and bootstrap.
- Adds `make release-candidate VERSION=0.1.0` and `make verify-release DIST=dist`.

- [ ] **Step 1: Write failing reproducibility and exclusion tests**

```python
def test_two_release_builds_are_byte_identical(tmp_path):
    first = build_release(tmp_path / "one", source=clean_checkout(), epoch=FIXED_EPOCH)
    second = build_release(tmp_path / "two", source=clean_checkout(), epoch=FIXED_EPOCH)
    assert sha256(first.archive) == sha256(second.archive)
    assert first.manifest_bytes == second.manifest_bytes


def test_release_excludes_untracked_ignored_private_and_lab_state(tmp_path):
    archive = build_release(tmp_path, source=checkout_with_private_files()).archive
    names = tar_names(archive)
    assert not {".git", ".env", "secrets", ".lab-state", "lab-results"} & top_level_names(names)
```

- [ ] **Step 2: Run release build tests and verify RED**

Run: `.venv/bin/pytest tests/test_release_build.py -q`

Expected: FAIL because release builder files are absent.

- [ ] **Step 3: Implement tracked-file reproducible packaging and SPDX generation**

Use `git ls-files -z`, reject a dirty staged index in release mode, normalize uid/gid to zero, names to `root`, mode from Git executable bit, and mtime to the release commit timestamp. Include file checksums, lockfile packages, container images/digests, external artifacts/licenses, and relationships in SPDX JSON.

- [ ] **Step 4: Implement non-root download/bootstrap verification**

Bootstrap accepts a local archive, checksum, manifest, and already verified provenance marker. It validates ownership/mode, hashes, manifest identity, and extraction before `sudo` dispatch. A network helper may resolve a stable version without privilege but cannot execute or select a prerelease.

- [ ] **Step 5: Add release workflow with minimal permissions**

Use pinned action commit SHAs. Separate jobs:

```text
quality -> build-twice-and-compare -> lab-amd64 + lab-arm64
-> attest (id-token/attestations write) -> draft-release (contents write)
-> approval-protected publish
```

Release jobs have no SSH or production environment. Upload the exact files whose digests passed the lab. Verify tag `v0.1.0`, `VERSION=0.1.0`, archive manifest, and commit agree.

- [ ] **Step 6: Run builder and workflow-structure tests**

```bash
.venv/bin/pytest tests/test_release_build.py -q
make release-candidate VERSION=0.1.0
make verify-release DIST=dist
git diff --check
```

Expected: PASS and two consecutive builds have identical hashes.

- [ ] **Step 7: Commit release tooling**

```bash
git add VERSION release install-bootstrap tests/test_release_build.py .github/workflows/release.yml .github/workflows/test.yml Makefile
git commit -m "ci(release): build and attest installer releases"
```

### Task 17: Complete Russian and English operator documentation

**Files:**
- Modify: `README.md`
- Modify: `README.en.md`
- Modify: `INSTALL.ru.md`
- Modify: `INSTALL.en.md`
- Create: `docs/INSTALLER_REFERENCE.ru.md`
- Create: `docs/INSTALLER_REFERENCE.en.md`
- Modify: `docs/UPGRADING.md`
- Modify: `docs/VALIDATION.md`
- Modify: `docs/README.md`
- Modify: `MIERU.ru.md`
- Modify: `MIERU.en.md`
- Modify: `PANEL.ru.md`
- Modify: `PANEL.en.md`
- Modify: `CHANGELOG.md`
- Create: `tests/test_installer_docs.py`

**Interfaces:**
- Documents only commands and examples exercised by Tasks 1–16.
- `tests/test_installer_docs.py` extracts command blocks marked `installer-check` and runs them against the built release or a no-mutation parser mode.

- [ ] **Step 1: Write failing documentation-contract tests**

```python
def test_every_profile_has_russian_english_example_and_acceptance_section():
    for language in ("ru", "en"):
        text = reference(language)
        for profile in ("core", "core-naive", "core-mieru", "full"):
            assert f"profile = \"{profile}\"" in text
        assert "VLESS Reality TCP" in text
        assert "VLESS Reality XHTTP" in text
        assert "Hysteria2" in text


def test_primary_install_path_verifies_attestation_before_sudo():
    steps = install_steps("ru")
    assert steps.index("gh attestation verify") < steps.index("sudo ./install.sh")
    assert "curl |" not in install_text("ru")
```

- [ ] **Step 2: Run documentation tests and verify RED**

Run: `.venv/bin/pytest tests/test_installer_docs.py -q`

Expected: FAIL because the new reference and release path are absent.

- [ ] **Step 3: Write verified quick-start and screen-by-screen wizard guides**

Cover release/attestation/checksum, profiles, every domain, DNS/CAA, certificates, TCP/UDP, fresh/coexistence, all 3x-ui modes, WARP opt-in, UFW/cloud firewall, plan digest, reports, credential handoff, and acceptance.

- [ ] **Step 4: Write complete config, lifecycle, recovery, and security reference**

Document every TOML field and hard stop, backup generation, interrupted recovery, repair, update planning, separate existing-3x-ui upgrade, rollback, uninstall/purge semantics, Fleet exclusion, and diagnostic-only MSS clamp.

- [ ] **Step 5: Execute documented command blocks against the release candidate parser/lab**

Run: `.venv/bin/pytest tests/test_installer_docs.py -q`

Expected: PASS with no skipped command blocks.

- [ ] **Step 6: Check links and commit documentation**

```bash
python3 scripts/check-doc-links.py
.venv/bin/pytest tests/test_installer_docs.py -q
git add README.md README.en.md INSTALL.ru.md INSTALL.en.md docs MIERU.ru.md MIERU.en.md PANEL.ru.md PANEL.en.md CHANGELOG.md tests/test_installer_docs.py
git commit -m "docs: publish verified interactive installer guide"
```

### Task 18: Full isolated release acceptance and publication readiness

**Files:**
- Modify only when a failing gate exposes a source defect; add a focused regression test beside every fix.
- Produce ignored artifacts: `dist/`, `lab-results/`, and per-architecture sanitized reports.

**Interfaces:**
- Consumes the exact clean release commit and archive from Tasks 1–17.
- Produces reproducible release hashes, amd64/arm64 acceptance reports, JUnit reports, provenance input, and a publication decision.

- [ ] **Step 1: Create a clean isolated execution worktree and build twice**

```bash
git status --short
make release-candidate VERSION=0.1.0
sha256sum dist/proxy-control-v0.1.0.tar.gz > /tmp/proxy-control-first.sha256
rm -rf dist
make release-candidate VERSION=0.1.0
sha256sum -c /tmp/proxy-control-first.sha256
```

Expected: archive checksum matches exactly; only known unrelated untracked user files remain outside release inputs.

- [ ] **Step 2: Run complete repository gates once**

```bash
.venv/bin/ruff check .
.venv/bin/pytest -q
python3 -m unittest -v tests/test_deploy.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
python3 scripts/check-doc-links.py
git diff --check
```

Expected: all commands exit zero.

- [ ] **Step 3: Run full amd64 disposable release lifecycle**

```bash
python3 scripts/lab/qemu_lab.py reset --arch amd64
python3 scripts/lab/qemu_lab.py run --mode release-amd64 --archive dist/proxy-control-v0.1.0.tar.gz --output lab-results/amd64
```

Expected: every required fresh/coexist/profile/3x-ui/failure/reboot/repair/uninstall/protocol scenario is present and PASS.

- [ ] **Step 4: Run full arm64 disposable release lifecycle**

```bash
python3 scripts/lab/qemu_lab.py reset --arch arm64
python3 scripts/lab/qemu_lab.py run --mode release-arm64 --archive dist/proxy-control-v0.1.0.tar.gz --output lab-results/arm64
```

Expected: every required scenario is present and PASS with the arm64 external artifact pins.

- [ ] **Step 5: Verify reports and artifacts contain no test secrets**

Run: `python3 release/verify.py --dist dist --reports lab-results --reject-secrets tests/lab/generated-secret-canary.json`

Expected: checksum, manifest, SPDX, report schemas, scenario completeness, and secret scan PASS.

- [ ] **Step 6: Re-run from Task 1 after any defect correction**

For each failure, add the smallest behavior-level regression test, observe it fail, fix the source, run the focused test, then rebuild the release archive. Re-run the complete affected architecture lifecycle and both architectures before marking publication-ready.

- [ ] **Step 7: Request code and security review**

Review the final clean diff for privilege boundaries, archive extraction, command construction, secret surfaces, ownership, rollback completeness, Nginx routing, UFW SSH preservation, 3x-ui API assumptions, licenses, and workflow permissions. Resolve every blocking finding with a regression test.

- [ ] **Step 8: Create the release-readiness commit**

```bash
git add -u
git commit -m "release: prepare interactive installer v0.1.0"
```

Do not add `dist/`, `lab-results/`, lab disks, credentials, `.env`, or unrelated untracked files. Do not tag or publish until the protected GitHub release workflow and explicit publication action are ready.
