# Isolated Ubuntu 24.04 installer lab

This lab boots an official, checksum-pinned Ubuntu 24.04 cloud image in QEMU. It does not use KVM, TAP, bridges, host firewall rules, host Docker, or production credentials. QEMU always uses TCG, two virtual CPUs, 3 GiB RAM, and a disposable qcow2 overlay. `smoke` uses restricted user-mode networking with no guest outbound access. `full` uses user-mode NAT only after cloud-init installs a fail-closed nftables policy: established SSH replies, slirp DNS, DHCP, and public TCP ports 80/443 are allowed; loopback is available only on the guest loopback interface, while link-local, metadata, carrier-grade NAT, documentation, multicast, RFC1918, and other destinations are rejected. The only inbound mapping in either mode is a checked random loopback TCP port forwarded to guest SSH.

## Prerequisites

Ubuntu host packages: `qemu-system-x86` (and `qemu-system-arm` for `release-arm64`), `qemu-utils`, `cloud-image-utils`, `openssh-client`, `curl`, `shellcheck`, and Python 3. The guest needs outbound package/image access only in `full` mode. No ACME request is made: the full fixture injects a local deterministic Certbot-compatible certificate generator, and DNS is supplied through guest-only `/etc/hosts` entries.

## Commands

```bash
make lab-test       # host helper tests, Bash parse check, ShellCheck
make lab-prepare    # verify/download pinned base; create key, seed, overlay
make lab-start      # boot and wait for cloud-init/SSH readiness
make lab-smoke      # real VM: archive, audit, plan, fixtures, report
make lab-reset      # stop and create a fresh overlay/ephemeral key
make lab-full       # all lifecycle, recovery, coexistence, Docker scenarios
make lab-release RELEASE_ARCHIVE=dist/proxy-control-vX.Y.Z.tar.gz \
                 RELEASE_SHA256=<sha256> [LAB_ARCH=amd64|arm64] \
                 [LAB_SCENARIOS="audit plan"]
make lab-stop
make lab-clean      # remove all lab-created state; retain pinned base cache
```

Direct CLI equivalents are available through `python3 scripts/lab/qemu_lab.py {prepare,start,reset,run,stop,cleanup}`. `start` requires an explicit `--mode`; a disk may not change modes without `reset`. Add `cleanup --purge-cache` to delete the verified base image too. `run --output PATH` writes sanitized `report.json`, JUnit `report.xml`, and `guest.log` outside the guest. A failed full-mode package/network setup emits a named `environment-preflight` failure and marks every unstarted scenario missing. Any missing result, failed guest command, checksum mismatch, readiness timeout, or failed assertion exits nonzero.

## Modes and isolation

`smoke` is intended for TCG CI and normally completes without guest package installation. It copies `git archive HEAD` exactly into the guest, verifies the archive digest, then exercises audit/plan against deterministic Nginx/Xray/DNS/TLS fixtures and proves they remain byte-identical.

`full` installs Nginx, Docker/Compose, and test dependencies inside the disposable VM. It runs audit, plan, install, repair, repeat-install idempotence, uninstall twice, SIGKILL-based interrupted install/uninstall recovery, shared-443/Xray/3x-ui/WARP preservation, local DNS/TLS preflight, Compose image build verification, package/manifest checks, listener checks, and artifact secret scans. It can take well over an hour under TCG. Run `make lab-reset` before an independent full validation.

The base cache is `${XDG_CACHE_HOME:-~/.cache}/mtproxy-installer-lab`. All mutable state and private ephemeral SSH keys are under ignored `.lab-state/`; reports are under ignored `lab-results/`. The private key is never attached as a VM drive and no production secret is embedded.

## Release acceptance

`release-amd64` and `release-arm64` validate one exact release archive rather than the working tree. The controller refuses to start unless `--release-archive` and `--release-sha256` are both given and the archive hashes to that value, and the guest re-verifies the same digest before unpacking. The installer under test is the one inside that archive: the guest drives `python3 -m installer.cli` from the unpacked release, never from the checked-out repository.

Each architecture is pinned separately in `scripts/lab/image.json` (schema 2) with its official image URL, SHA-256, QEMU binary, machine, CPU, and minimum QEMU version. An architecture whose `sha256` is still `null` fails closed with a named error instead of trusting a download; record the official checksum from the `source_checksums` URL before using it. The `arm64` image ships unpinned for exactly this reason.

The release matrix (`qemu_lab.release_scenarios()`) covers fresh full installs with managed 3x-ui, coexistence with an existing 3x-ui and an ambiguous multi-map Nginx, real protocol clients for Telemt, Naive, Mieru, VLESS TCP/XHTTP and Hysteria2, Docker build verification, repair, repeated install idempotence, restart recovery, a crash injected into every durable phase, secret scans, DNS/TLS preflight, uninstall twice, a foreign holder of a fixed identity, interrupted install/uninstall recovery, and final coexistence.

`--scenario NAME` (repeatable, or `LAB_SCENARIOS` through the Makefile) runs a subset. A filtered run is recorded as `filtered_scenarios` in the report and is only valid against what it declared: it can never stand in for a full release report. `qemu_lab.validate_report()` treats any required scenario missing from a full report as a failure even when the guest exits zero.

`report.json` is schema 2 and records the mode, architecture, pinned image, source archive digest, release archive digest, and the plan digest the guest accepted, next to per-scenario results. `report.xml` and the sanitized `guest.log` are written beside it.

## Fixtures

- `tests/lab/fixtures/three-xui-existing.sh` materializes a foreign 3x-ui install - config with clients and a Reality private key, database, binary, and unit - which is hashed before and after the run to prove byte identity.
- `tests/lab/fixtures/nginx-multi-map.conf` provides an ambiguous shared-443 topology with two candidate stream maps; the installer must resolve it or refuse, never guess.
- `tests/lab/clients/compose.yaml` runs each protocol probe in its own read-only, capability-dropped container against the guest's synthetic DNS. Every probe image is a required pinned input, the ephemeral credentials are mounted read-only from the guest overlay, and only a status and a byte count are recorded.
