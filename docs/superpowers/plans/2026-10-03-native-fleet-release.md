# Native Fleet acceptance and release

**Goal:** verify real client and Fleet behavior, update the authorized stands, then publish the verified release on GitHub.

**Architecture:** native installations over SSH on `ams-test` and `AMS_Z`; stock installer and version-agent update paths. Preserve existing Fleet ownership and foreign 3x-ui configuration. Use temporary, attributable test resources and private evidence files.

**Tech stack:** Python, Docker Compose, systemd, Nginx, Xray/3x-ui, Hysteria, Fleet API v2, GitHub Actions.

**Specification:** user authorization on 2026-10-03; `AGENTS.md`, `tests/lab/README.md`, `docs/releases/1.1.1-rc.3-native-acceptance.ru.md`.

**Global constraints:** no QEMU; no credentials in output; rollback points before mutations; one mutation boundary at a time; no cleanup of previously declined test grants; publish only after updating both authorized stands and satisfying the acceptance gates. Actual Telegram application acceptance cannot be replaced by the resPQ probe.

**Review focus:** exact tested archive digest, preservation of live resources, real payload and denial controls, honest distinction between live measurement and synthetic capacity estimates.

- [ ] Inventory both stands, Fleet ownership, client tools and native installation state; retain safe aggregates.
- [ ] Create and verify database/configuration/key backups and image rollback tags on both stands.
- [ ] Exercise VLESS TCP, XHTTP and Hysteria2 with pinned real clients, positive/bad credential/positive controls and server evidence; separately verify managed-new provisioning on the disposable test topology.
- [ ] Exercise real inter-host Fleet delivery, offline recovery and restart recovery using new test objects; measure queue, request and convergence times without disturbing existing ownership.
- [ ] Verify a Telegram application connects through an ephemeral proxy and performs a read request; revoked credential must fail. Remove the ephemeral client configuration afterwards.
- [ ] Resolve discovered defects with narrow failing tests, minimal fixes and corresponding installer/documentation updates.
- [ ] Freeze the release commit, build twice, compare archive and stamped installer, run the full repository gate and native acceptance from those exact bytes.
- [ ] Update both stands through the stock update path, verify all configured services, SQLite integrity, ownership, adjacent routing and real clients.
- [ ] Review the final changes and evidence, integrate the branch, create the annotated release tag with the accepted SHA-256 and verify GitHub release artifacts/provenance.
- [ ] Download the public installer and checksum as an ordinary user on `ams-test`, enter the wizard and quit; retain the pinned-digest and no-changes messages.

Execution continues inline under the user's authorization; any missing real-client prerequisite is recorded explicitly and does not become a claimed pass.
