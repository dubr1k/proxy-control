# Graph Report - audit-hardening  (2026-10-02)

## Corpus Check
- 541 files · ~1,115,140 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 40 file(s) not represented in the graph (top: (none) 14, .service 8, .conf 5)

## Summary
- 12645 nodes · 36274 edges · 386 communities (301 shown, 85 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 3892 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a1c3b966`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CommandRunner
- release.py
- TrafficCollector
- register_fleet_v2_central_routes
- MieruAdapter
- installer/cli.py
- Scenario
- NaiveCredentialManager
- Proxy Control
- NaiveAdapter
- Панель управления Proxy Control
- Action
- Sharing Mieru configurations
- test_installer_mieru.py
- wizard.py
- parse_config
- test_installer_naive.py
- NodeClient
- Interactive release installer
- GrantIntent
- Interactive Release Installer Design
- MemoryMieru
- test_installer_transaction.py
- Управление Mieru / mita 3.35–3.36
- test_installer_nginx.py
- query
- test_naive_manager.py
- test_installer_wizard.py
- firewall.py
- test_installer_credentials.py
- AuditFacts
- Acceptance
- test_xray_router_geodata.py
- RuntimeInstaller
- Proxy Control documentation index
- test_routing_fleet_chains.py
- test_fleet_v2_pusher.py
- Planned File Structure
- test_mieru_manager.py
- naive_manager/egress.py
- test_release_build.py
- vNext v0.2 local control plane implementation plan
- dataclasses
- qemu_lab.py
- test_installer_release.py
- test_installer_docs.py
- PackagesAdapter
- render_config
- TopologyError
- test_installer_fresh_host.py
- Dedicated Proxy-Control-owned xray-router
- bridge.py
- test_mieru_deployment.py
- RoutingService
- CentralProcess
- Unreleased
- CoreError
- RuleMatch
- Troubleshooting Proxy Control
- app.py
- DeployCliTests
- test_fleet_v2_post_merge.py
- MieruManager
- test_users_adapter_ui.py
- VersionAgent
- test_installer_warp_transaction_recovery.py
- esc
- guest-runner.sh
- test_three_xui_api.py
- Матрица негативных и security-тестов vNext (Task 39)
- test_installer_mcp.py
- routing-spike.py
- test_subscription_http.py
- proxyctl.py
- test_proxyctl_transactions.py
- DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)
- test_version_agent_host.py
- document_digest
- CoreAdapter
- test_routing_lanes_routes.py
- resolve_artifacts
- test_version_agent_upstream.py
- prepare-naive-state.py
- exits.py
- test_panel_entrypoint.py
- test_version_agent_server.py
- Store
- 3x-ui mode: managed-new
- register_routing_routes
- MitaCLI
- fleet.js
- CertificateAuthority
- ValidationError
- English
- TransactionStore
- Task 6: Encrypted secret versions and master key
- QuotaEnforcer
- _DefaultCoreRunner
- MemoryTelemt
- WarpAdapter
- common.js
- FleetPusher
- OwnershipError
- test_installer_cli.py
- test_mieru_manager_lanes.py
- main.js
- QemuLabTests
- Panel
- test_mieru_egress.py
- nodes.js
- mcp_server/server.py
- .verify
- Task 2: automatic WARP with selective routing
- test_installer_xray_router.py
- grant.js
- test_version_agent.py
- test_naive_manager_lanes.py
- Continuation prompt for a new Claude Code context
- register_fleet_v2_node_routes
- _PinningStream
- MTProxy acceptance failure: Connection closed
- Proxy Control v0.1.0 Beta
- test_installer_version_agent.py
- curated.py
- XrayRouterManager
- test_mobile_layout.py
- docker_lab.py
- Task 4: Unified DB layer and migrations
- Panel version-agent
- PolicyInput
- sbom.py
- clients.js
- AgentTransportServer
- test_fleet_v2_reconcile.py
- test_mcp_server.py
- renderers/base.py
- 3x-ui mode managed-new: install on clean server, create inbounds
- FakeFleet
- test_naive_manager_egress.py
- ManagerHTTPServer
- test_fleet_acceptance_script.py
- 3. Задачи
- RoutingRule
- Global Constraints
- index.cjs
- TypedCommand
- CorePaths
- create_app
- EgressInvalid
- test_xray_router_mtproxy.py
- Accounting semantics
- api_with
- guest-runner.sh script
- MemoryXrayRouter
- test_qemu_lab.py
- Proxy Control Cover Art
- ReleaseError
- NaiveClient
- run_captured
- Task 1: ADRs and v0.2 architecture record
- install-bootstrap
- ReleaseManifest
- mieru-client/probe.py
- Промпт для продолжения работы в новом контексте
- InstallPlan
- test_ui_browser_findings.py
- test_subscription_renderers.py
- container_cmd
- installer_cmd
- prepare_mieru_token.py
- Task 3: release v0.1.0 through CI
- ProtocolError
- container_setup
- FleetStore
- ProvisioningService
- StubManager
- Rule: verify the open port, not the panel record
- ingress_upgrade.py
- client_probe
- test_mtproxy_respq_probe.py
- test_version_agent_panel.py
- test_acceptance_cleanup_preserves_process_stop_and_reports_other_failures
- check-js-syntax.sh
- BoundedBodyMiddleware
- probe/install.sh
- test_installer_three_xui.py
- Private Vulnerability Reporting Path
- installer/audit.py
- .compose
- upstream
- test_routing_router_service.py
- RuntimeRunner
- MieruClient
- test_agent_client_retries_result_from_durable_outbox_without_reexecution
- XrayRouterClient
- LaneService
- test_installer_reports.py
- English
- InstallerConfig
- mieru-mss-clamp.sh
- ThreeXuiApiError
- test_fleet_v2_ui_contract.py
- _panel_health_diagnosis
- entrypoint.sh
- test_grant_lifecycle.py
- README.md
- Screenshot Sanitization Policy
- telemt-entrypoint.sh
- install.sh
- Database
- Panel dev/test toolchain (pytest, ruff)
- check-deployment.sh
- check-naive-caddy-build.sh
- three-xui-existing.sh
- v0.11 — обновления из upstream и обзор в одну строку
- English
- test_subscription_ui_contract.py
- test_version_agent_artifacts.py
- English
- uninstall.sh
- compose fleet-agent overlay service
- aurora.sky.dubr1kkk.uk (Proxy Control panel, cert: yes)
- comet.sky.dubr1kkk.uk (NaiveProxy, cert: yes)
- nova.sky.dubr1kkk.uk (Hysteria2, cert: yes)
- orion.sky.dubr1kkk.uk (Mieru, cert: no)
- pulsar.sky.dubr1kkk.uk (VLESS Reality XHTTP, cert: no)
- sirius.sky.dubr1kkk.uk (3x-ui panel, cert: yes)
- vega.sky.dubr1kkk.uk (VLESS Reality TCP, cert: no)
- CatalogError
- accepted_sha256
- host-teardown.sh
- XrayError
- v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router
- number
- i18n-strings.py
- status / resume / repair
- CommandRunner
- English
- TelemtError
- TransactionEngine
- ipaddress
- template
- test_access_enforcement.py
- .enabled
- Рабочий протокол для AI-агентов
- test_client_links.py
- English
- BearerGate
- test_telemt_adapter_does_not_leak_secret_in_errors
- safe_extract_zip
- Browser
- .step_05c_chains
- CONTINUE HERE — v0.3 центральная панель
- SecurityHeadersMiddleware
- English
- planner.py
- test_managed_provision_actually_applies_warp_and_subscription
- test_routing_ui_contract.py
- .plan
- Probes
- ManagedInbound
- NginxReloadRecovery
- ThreeXuiClient
- Host
- rejecting
- English
- Check
- TelemtClient
- The Xray-router (v0.5): one dedicated egress router per node
- script
- compile
- _panel_probe
- RuntimePlan
- _await_panel_health
- Xray-router (v0.5): один выделенный egress-роутер на узел
- test_subscription_events.py
- Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext
- TelemtAdapter
- 3. Что v0.6 добавляет
- XrayRouterAdapter
- test_management_ui_contract.py
- service_share_template
- test_fleet.py
- Api
- The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP
- _CaptureBroken
- MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP
- Isolated Ubuntu 24.04 installer lab
- 6. Центр и узлы: привязка панелей
- naive_manager/healthcheck.py
- LabConfigurationsAreValid
- test_dashboard_ui_contract.py
- router_credential_stale
- ingress_credential
- CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)
- xray_router_manager/healthcheck.py
- docker/links.py
- test_mieru_management.py
- English
- ADR 003: One writer per resource
- ImageMetadataTests
- test_xray_router_deployment.py
- Журнал изменений
- test_view_addressing_ui.py
- rotate-xray-router-ingress.sh
- _DefaultXrayRouterRunner
- test_telemt_client_batches_inventory_reads_until_access_changes
- Живая проверка (AMS_Z ↔ ams-test)
- TelemtIndeterminate
- install-release.sh
- prepare-xray-router-state.sh
- v0.10 — клиент на нескольких узлах и подписка под рукой
- test_client_import.py
- Telemt MTProto data plane
- ADR 002: Declarative immutable generations
- AccessGrant
- ._compose_start
- _ScopedClientDouble
- i18n.js
- test_api_key_auth.py
- test_renewal_retries_the_order_not_ready_race_once
- test_a_failed_acceptance_step_carries_what_the_probe_said
- panel
- manifest
- test_download_never_reuses_attacker_link
- exdev_between_directories
- CDP
- ManagerHandler
- pytest
- test_clients_filters_ui.py
- json
- Verification matrix — maintained functions and their proofs
- verification-matrix.py
- English
- test_update_host.py
- CONTINUE HERE — v0.6 сверка функций v0.2–v0.5
- https_probe
- .install
- Protocol acceptance
- Api
- AgentJournal
- test_a_failed_core_command_names_the_command_that_failed
- ADR 004: Client, AccessGrant and subscription as a projection
- v1.1 — маршрутизация MTProxy через Xray-router
- test_a_failed_core_command_never_echoes_a_credential
- ArtifactError
- RelayRunner
- test_docker_lab.py
- Исправления по аудиту v1.1.0
- test_the_release_manifest_pins_x86_64_only
- ADR 005: Secrets travel as references
- test_socks5_stub.py
- English
- test_fetch_reports_the_hop_that_names_the_release
- Interactive Release Installer Implementation Plan
- SecretGenerator
- update-host.sh
- test_rbac_audit.py
- Handler
- test_vnext_characterization.py
- RenderedCore
- FakeClock
- ADR 007: Routing enforcement ownership

## God Nodes (most connected - your core abstractions)
1. `Action` - 234 edges
2. `AuditFacts` - 185 edges
3. `InstallerConfig` - 145 edges
4. `query()` - 143 edges
5. `Proxy Control` - 132 edges
6. `Database` - 122 edges
7. `CoreAdapter` - 117 edges
8. `GrantIntent` - 112 edges
9. `MieruAdapter` - 108 edges
10. `esc()` - 107 edges

## Surprising Connections (you probably didn't know these)
- `7. Установщик: `[egress]` (Task 28)` --references--> `ConfigError`  [INFERRED]
  docs/superpowers/specs/2026-09-14-v0.4-routing-design.md → installer/config.py
- `Коммиты ветки (по порядку)` --references--> `safe_extract_zip()`  [INFERRED]
  docs/superpowers/plans/CONTINUE-HERE-v0.5.md → installer/release.py
- `What not to do` --references--> `client_subscription()`  [INFERRED]
  skills/proxy-control-diagnosing-access/SKILL.md → mcp_server/curated.py
- `Pitfalls` --references--> `audit_tail()`  [INFERRED]
  skills/proxy-control-granting-access/SKILL.md → mcp_server/curated.py
- `Stop rules` --references--> `audit_tail()`  [INFERRED]
  skills/proxy-control-updating-components/SKILL.md → mcp_server/curated.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Fleet command issue → dispatch → journal → upload flow** — fleet_en_command_queue, fleet_en_fleet_ingress, fleet_en_agent_journal_outbox, compose_agent_fleet_agent_service, fleet_en_operation_allowlist [EXTRACTED 1.00]
- **Installer adapters each own one boundary in documented order** — docs_superpowers_plans_2026_09_03_interactive_release_installer_packagesadapter, docs_installer_reference_en_nginx_adapter, docs_installer_reference_en_certificates_adapter, docs_installer_reference_en_firewall_adapter, docs_installer_reference_en_core_adapter, docs_installer_reference_en_naive_adapter, docs_installer_reference_en_mieru_adapter, docs_installer_reference_en_three_xui_adapter [EXTRACTED 1.00]
- **Installer adapters implementing the Adapter protocol** — docs_superpowers_plans_2026_09_03_interactive_release_installer_adapter_protocol, docs_installer_reference_en_nginx_adapter, docs_installer_reference_en_firewall_adapter, docs_superpowers_plans_2026_09_03_interactive_release_installer_packagesadapter, docs_superpowers_plans_2026_09_03_interactive_release_installer_coreadapter, docs_superpowers_plans_2026_09_03_interactive_release_installer_naiveadapter, docs_superpowers_plans_2026_09_03_interactive_release_installer_mieruadapter, docs_superpowers_plans_2026_09_03_interactive_release_installer_threexuiadapter [EXTRACTED 1.00]
- **Lab protocol probes implementing the expect-status contract** — tests_lab_clients_compose_naive_probe, tests_lab_clients_compose_mieru_probe, tests_lab_clients_compose_vless_tcp_probe, tests_lab_clients_compose_vless_xhttp_probe, tests_lab_clients_compose_hysteria2_probe, tests_lab_clients_compose_expect_status_contract [EXTRACTED 1.00]
- **Mieru one-time credential disclosure flow** — docs_mieru_sharing_en_one_time_disclosure, docs_mieru_sharing_en_cache_control_no_store, docs_mieru_sharing_en_ephemeral_dialog, docs_mieru_sharing_en_hashed_password, docs_mieru_sharing_en_new_link_qr_rotation, docs_mieru_sharing_en_qr_security_contract, docs_mieru_sharing_en_dialog_closed_early [EXTRACTED 1.00]
- **Single Compose stack contract across architecture, upgrade, and troubleshooting** — docs_architecture_one_stack_per_node, docs_architecture_compose_file_overlay_set, docs_troubleshooting_en_compose_orphans, docs_upgrading_compose_versions_override, docs_compatibility_frozen_mtproxy_identifiers [EXTRACTED 1.00]
- **Panel master-key and secret-store boundary** — docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_keyring, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_secretstore, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_secrets_v3_migration, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_master_key_file, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_master_key_cli, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_entrypoint_master_key_staging, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_compose_master_key_secret, docs_superpowers_plans_2026_09_10_vnext_v0_2_local_control_plane_installer_master_key_render [EXTRACTED 1.00]
- **Release download and verification chain** — docs_releases_v0_1_0_release_assets_four_files, docs_releases_v0_1_0_sha256sums, docs_releases_v0_1_0_release_manifest_json, docs_releases_v0_1_0_sbom_spdx_json, install_bootstrap, docs_releases_v0_1_0_plan_digest_approval [EXTRACTED 1.00]
- **Selective WARP egress flow (client, proxy port, outbound, rule order, domain list, acceptance)** — docs_plans_2026_09_07_warp_and_final_installation_cloudflare_warp_client, docs_plans_2026_09_07_warp_and_final_installation_warp_proxy_mode_port_40000, docs_plans_2026_09_07_warp_and_final_installation_xray_warp_outbound, docs_plans_2026_09_07_warp_and_final_installation_xray_routing_rules_order, docs_plans_2026_09_07_warp_and_final_installation_warp_domain_list, docs_plans_2026_09_07_warp_and_final_installation_warp_acceptance_external_ip_differs [EXTRACTED 1.00]
- **Nine sky.dubr1kkk.uk domains of the full profile** — docs_plans_2026_09_07_warp_and_final_installation_aurora_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_nebula_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_comet_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_orion_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_sirius_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_vega_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_pulsar_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_nova_sky_dubr1kkk_uk, docs_plans_2026_09_07_warp_and_final_installation_zenith_sky_dubr1kkk_uk [EXTRACTED 1.00]
- **Version-agent update and rollback gate flow** — docs_upgrading_version_agent, docs_upgrading_versions_catalog, docs_upgrading_docker_inspect_fail_closed, docs_upgrading_telemt_update_flow, docs_upgrading_binary_update_flow, docs_upgrading_expected_current_409, docs_upgrading_rollback_failed, docs_upgrading_version_agent_state [EXTRACTED 1.00]
- **vNext target domain model** — docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_client, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_accessgrant, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_clientsubscription, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_node, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_desiredgeneration, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_observedgeneration, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_secretversion, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_routingpolicy, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_egressprovider, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_enforcementbackend, docs_superpowers_specs_2026_09_10_proxy_control_vnext_design_compiledroutinggeneration [EXTRACTED 1.00]
- **Fixed numeric UID/GID isolation contract across services** — compose_mieru_mieru_manager_service, compose_naive_naive_manager_service, compose_panel_service [INFERRED 0.85]
- **One-time credential reveal flow** — panel_en_one_time_reveal, panel_en_naive_client_formats, panel_static_index_access_modal, panel_static_index_mieru_access_modal, panel_static_index_naive_access_modal, mieru_en_users_links_qr, readme_en_first_sign_in [INFERRED 0.85]

## Communities (386 total, 85 thin omitted)

### Community 0 - "CommandRunner"
Cohesion: 0.10
Nodes (41): audit_host(), CommandRunner, audit(), Profile, ThreeXuiMode, test_per_call_timeout_cannot_exceed_runner_limit(), config(), host_responses() (+33 more)

### Community 1 - "release.py"
Cohesion: 0.14
Nodes (28): _best_effort_remove_tree_at(), _copy_regular_member(), _copy_verified_archive(), _create_private_stage(), _decode_bounded_tar(), _destination_identity(), _DestinationAnchor, _digest_open_file() (+20 more)

### Community 2 - "TrafficCollector"
Cohesion: 0.05
Nodes (43): build_manager(), _assert_safe_parent_chain(), _Candidate, _now(), TrafficCollector, collector(), record(), test_active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() (+35 more)

### Community 3 - "register_fleet_v2_central_routes"
Cohesion: 0.04
Nodes (50): Audit event names, Authentication and administrators, Clients, grants and subscriptions, Nodes (central side), Nodes (node side, through the central's key), Global Constraints, Self-review, v0.3 Central Panel Implementation Plan (+42 more)

### Community 4 - "MieruAdapter"
Cohesion: 0.04
Nodes (15): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _decode_transports(), _DefaultMieruRunner, MieruAcceptance, MieruAdapter, MieruError (+7 more)

### Community 5 - "installer/cli.py"
Cohesion: 0.10
Nodes (23): _adopt_legacy_if_needed(), _automated_install(), _bounded_error(), _bounded_text(), CliError, CliServices, _default_services(), plan() (+15 more)

### Community 6 - "Scenario"
Cohesion: 0.11
Nodes (3): describe_artifact(), Scenario, adopted()

### Community 7 - "NaiveCredentialManager"
Cohesion: 0.05
Nodes (19): Task 4: naive-manager — egress API (Task 29a), _assert_regular(), _assert_safe_parent_chain(), _atomic_write(), _durable_mkdir(), _durable_unlink(), _fsync_directory(), lifecycle_synchronized() (+11 more)

### Community 8 - "Proxy Control"
Cohesion: 0.04
Nodes (84): In-lab verification checklist, Documentation contract runs every documented command through the CLI parser, Pinned external artifacts catalog release/external-artifacts.json, Fleet v1 Telemt-only, Profiles and adapters (packages, nginx, certificates, firewall, core, naive, mieru, three_xui), Naive site on port-only address with probe resistance, Per-protocol acceptance with real clients, Release acceptance lab (container and bare metal) (+76 more)

### Community 9 - "NaiveAdapter"
Cohesion: 0.04
Nodes (18): _path_sha256(), _acceptance_value(), _AcceptanceCollision, AcceptanceError, _command_failure(), _DefaultNaiveRunner, relay(), NaiveAcceptance (+10 more)

### Community 10 - "Панель управления Proxy Control"
Cohesion: 0.05
Nodes (72): Synthetic Compose render inputs, Atomic SQLite login-attempt reservation before Argon2, mask service (Caddy cover site), compose mieru-manager overlay service, Compose project mtproxy, mtproxy service (Telemt), compose naive-manager overlay service, panel service (+64 more)

### Community 11 - "Action"
Cohesion: 0.04
Nodes (15): Adapter, ArtifactError, _DefaultThreeXuiRunner, _safe_text(), _tags(), ThreeXuiAdapter, ThreeXuiError, _valid_warp_selector() (+7 more)

### Community 12 - "Sharing Mieru configurations"
Cohesion: 0.06
Nodes (55): Cache-Control: no-store reveal response, Client matrix, Create access flow, Dialog closed too early, Ephemeral reveal dialog, Karing URL scheme documentation, Karing install-config deep link, mieru import config command (+47 more)

### Community 13 - "test_installer_mieru.py"
Cohesion: 0.04
Nodes (81): ArtifactError, MieruPaths, _slot_action(), _slot_config(), SlotRunner, _stage_router(), test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them(), test_mieru_plan_carries_the_slots_and_refuses_a_collision() (+73 more)

### Community 14 - "wizard.py"
Cohesion: 0.09
Nodes (17): locale_from_environment(), parse_locale(), text(), _domain(), EditField, _egress_choice(), _email(), _flatten() (+9 more)

### Community 15 - "parse_config"
Cohesion: 0.06
Nodes (74): _as_dict(), _boolean(), ConfigError, _domain(), _domains(), _enum(), _integer(), _keys() (+66 more)

### Community 16 - "test_installer_naive.py"
Cohesion: 0.06
Nodes (62): _deploy_hook_text(), timeout(), adapter(), applied(), facts_with_uid(), FakeNaiveRunner, _file_writer_options(), host() (+54 more)

### Community 17 - "NodeClient"
Cohesion: 0.02
Nodes (67): Task 7: `NodeClient` — HTTP-клиент центра к узлу, Task 8: Связи с узлами — миграция, `NodeLinkService`, `DesiredStore`, компиляция поколений, 6. Центр, node_fingerprint(), node_link(), fingerprint(), NodeAuthFailed, NodeClient (+59 more)

### Community 18 - "Interactive release installer"
Cohesion: 0.04
Nodes (66): report.json public acceptance report, Installer CLI commands, Commands, Configuration file, credentials/handoff.json, Fleet v1 Telemt-only limit, Hard stops, host_mode (fresh | coexist) (+58 more)

### Community 19 - "GrantIntent"
Cohesion: 0.08
Nodes (34): GrantIntent, MieruOptions, MtproxyOptions, NaiveOptions, _ProtocolOptions, test_local_enforcement_batches_runtime_inventory_per_protocol(), test_an_interrupted_operation_is_resumed_through_the_api(), test_options_are_typed_and_secret_free() (+26 more)

### Community 20 - "Interactive Release Installer Design"
Cohesion: 0.06
Nodes (48): Global Constraints, docs/INSTALLER_REFERENCE.ru.md / .en.md, tests/lab/clients/compose.yaml protocol clients, QEMU lab modes release-amd64 / release-arm64, release/build.py reproducible builder, Release-readiness commit v0.1.0, Required release scenarios, release/verify.py offline verification (+40 more)

### Community 21 - "MemoryMieru"
Cohesion: 0.06
Nodes (11): MemoryMieru, MieruError, anyio_backend(), backend(), test_apply_egress_maps_the_manager_failure_codes(), test_apply_egress_refuses_an_unreachable_provider_and_changes_nothing(), test_apply_egress_returns_the_applied_entry_and_moves_the_target(), test_egress_target_reports_backend_capabilities_and_providers_without_the_url() (+3 more)

### Community 22 - "test_installer_transaction.py"
Cohesion: 0.10
Nodes (42): AcceptedDigestError, import_runtime_v2(), TransactionBusyError, action_for(), engine_for(), installed_runtime_v2(), plan_for(), RecordingAdapter (+34 more)

### Community 23 - "Управление Mieru / mita 3.35–3.36"
Cohesion: 0.09
Nodes (40): Opt-in systemd Mieru TCP MSS clamp, First valid generation before the hardened mita unit, Full-snapshot CAS config transactions with journal v3 HMAC, compose.mieru.yaml overlay, MIERU_MITA_SHA256 executable digest gate, Listener coexistence: no installer or manager silently takes 443, mieru-manager fixed UID/GID 10005, Mieru / mita 3.35–3.36 management (+32 more)

### Community 24 - "test_installer_nginx.py"
Cohesion: 0.09
Nodes (48): ensure_stream_context(), NginxAdapter, HostMode, config(), facts(), FreshExecutor, materialize_route(), RecordingExecutor (+40 more)

### Community 25 - "query"
Cohesion: 0.09
Nodes (47): [0.7.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Исправлено (после v0.6, в ветке до этого тега), 6.1 Модель (`panel/routing/models.py`, схема базы 16), 6.2 Сервис маршрутизации и цели, 6.3 Экран «Маршрутизация и цепи» (+39 more)

### Community 26 - "test_naive_manager.py"
Cohesion: 0.05
Nodes (71): ManagerHTTPServer, ManagerRecoveryError, _bootstrapped(), Hooks, manager(), test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), test_adapted_semantic_drift_makes_health_unready(), test_additional_basic_auth_outside_managed_block_makes_health_unready() (+63 more)

### Community 27 - "test_installer_wizard.py"
Cohesion: 0.09
Nodes (26): Locale, pinned_version(), TerminalIO, WizardSaved, _run_cli_in_pty(), _scripted(), test_a_typed_panel_password_is_saved_privately_and_never_in_the_config(), test_an_invalid_configuration_says_why() (+18 more)

### Community 28 - "firewall.py"
Cohesion: 0.09
Nodes (33): _action_enable(), _action_ipv6_enabled(), _action_rules(), _action_ssh_port(), _assert_foreign_preserved(), _assert_owned_rules_recognized(), _assert_ssh_preserved(), _canonical_source() (+25 more)

### Community 29 - "test_installer_credentials.py"
Cohesion: 0.10
Nodes (24): _anchor(), CredentialError, credentials_path(), discard_staged_credentials(), OperatorCredentials, read_credentials(), stage_credentials(), stage_operator_credentials() (+16 more)

### Community 30 - "AuditFacts"
Cohesion: 0.06
Nodes (44): _encode_transports(), _plain_audit(), _assert_secret_free(), AuditFacts, build_plan(), _canonical_fact_value(), _canonical_json_value(), _freeze() (+36 more)

### Community 31 - "Acceptance"
Cohesion: 0.13
Nodes (3): Task 9b: Браузерный сценарий `ui-acceptance.py` под окно клиента и матрицу, Acceptance, main()

### Community 32 - "test_xray_router_geodata.py"
Cohesion: 0.05
Nodes (42): test_wal_is_enabled_even_while_another_connection_holds_the_database(), hold(), _clocked(), _field(), geodata_file(), _loyal(), _old_meta(), test_a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays() (+34 more)

### Community 33 - "RuntimeInstaller"
Cohesion: 0.11
Nodes (25): RuntimeInstaller, FakeRunner, plan(), runtime_root(), test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(), test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps(), run(), test_failed_install_rollback_is_retried_before_reinstall() (+17 more)

### Community 34 - "Proxy Control documentation index"
Cohesion: 0.07
Nodes (47): Changelog, Transactional release installer with durable journal, 1.0.0 — initial MTProxy release (2026-02-11), 1.1.0 — Fake TLS and hardening (2026-02-21), 1.2.0 — legacy installer fixes (2026-02-22), 1.3.0 — legacy MTProxy installer (2026-08-11), Развёртывание MTProto за Nginx SNI (RU), Backup and restore contract (EN) (+39 more)

### Community 35 - "test_routing_fleet_chains.py"
Cohesion: 0.02
Nodes (97): Task 13: Документация, миграционные заметки, версия, Task 15: Живая проверка AMS_Z ↔ ams-test (разрешение владельца от 2026-09-11), Task 16: Релизный гейт v0.3.0-beta.1, Task 1: Идентичность панели и API-ключи (хранилище), Task 3: Протокол поколений и хранилище узла, Task 6: Fleet API v2 узла и защита ресурсов центра, Структура файлов, Task 9: Fleet v2 — egress в поколении, узел и центр (Task 31) (+89 more)

### Community 36 - "test_fleet_v2_pusher.py"
Cohesion: 0.05
Nodes (45): slow_create(), create_while_the_node_confirms(), _accepts(), _Clock, _converged_after_a_202(), slow_create(), _escrowed(), _failing_alice() (+37 more)

### Community 37 - "Planned File Structure"
Cohesion: 0.05
Nodes (56): AcceptanceReport, adapters_for(config) exact profile selection, audit_host -> AuditFacts, AuditFacts, CommandRunner (bounded, sanitized errors), parse_config / render_config / load_config, examples/installer/*.toml, Full profile order (+48 more)

### Community 38 - "test_mieru_manager.py"
Cohesion: 0.07
Nodes (40): _authenticate_journal(), FakeMita, manager(), MergingMita, RecoveryMita, _service(), _status_cli(), test_a_caller_password_is_validated_and_operations_are_pruned() (+32 more)

### Community 39 - "naive_manager/egress.py"
Cohesion: 0.08
Nodes (38): Task 1: Fix-wave — отложенные замечания v0.4, block_lines(), canonical(), check_reachable(), document_digest(), EgressInvalid, forward_proxy_bounds(), _indent() (+30 more)

### Community 40 - "test_release_build.py"
Cohesion: 0.06
Nodes (48): archive_names(), assert_clean(), build_release(), BuiltRelease, _canonical(), commit_epoch(), _executable(), _external_artifacts() (+40 more)

### Community 41 - "vNext v0.2 local control plane implementation plan"
Cohesion: 0.09
Nodes (35): ADR 004: Client / AccessGrant / subscription, tests/fixtures/vnext-capabilities.json (4 protocols x 23 capabilities), Audit finding 3: uvicorn writes an access log to container stdout, Audit finding 6: Credential re-reveal differs per protocol, Audit finding 10: UI is ES modules without a bundler, Audit finding 11: Fleet tables and the reserved local node, Reserved node local, PANEL_VNEXT_WRITER feature flag (+27 more)

### Community 42 - "dataclasses"
Cohesion: 0.03
Nodes (50): Routing (v0.4), Global Constraints, Self-review, Task 10: Документация выпуска и VERSION, Task 11: Гейт на ams-test и живая проверка AMS_Z → ams-test, Task 2: Escrow при выдаче, гашение при ротации/отзыве, `reveal_token`, Task 4: Подписка выдаётся вместе с клиентом, Task 5: Аудит и документация модели (ADR 004, OPERATIONS) (+42 more)

### Community 43 - "qemu_lab.py"
Cohesion: 0.10
Nodes (29): acceleration(), allocate_port(), _archive(), cleanup(), finalize_results(), full_egress_policy(), guest_remote(), junit_xml() (+21 more)

### Community 44 - "test_installer_release.py"
Cohesion: 0.18
Nodes (33): ArchiveEntry, ArchiveManifest, _manifest_data(), safe_extract_tar(), _stage_paths(), _tar(), test_archive_digest_is_verified_before_tar_processing(), test_archive_path_swap_cannot_change_verified_bytes() (+25 more)

### Community 45 - "test_installer_docs.py"
Cohesion: 0.08
Nodes (27): _parser(), checked_commands(), documented_files(), install_steps(), install_text(), python_requirements(), readme(), reference() (+19 more)

### Community 46 - "PackagesAdapter"
Cohesion: 0.15
Nodes (18): _action_packages(), _assert_added_unchanged(), _assert_preexisting_unchanged(), _checkpoint_packages(), PackageError, PackagesAdapter, _version_mapping(), AptRunner (+10 more)

### Community 47 - "render_config"
Cohesion: 0.11
Nodes (30): test_render_without_an_mtproxy_ingress_is_unchanged(), _intent(), test_generation_digest_changes_with_credentials_and_redact_hides_accounts(), test_redact_masks_relay_and_chain_secrets_too(), test_render_bypass_private_precedes_every_rule_per_tag(), test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous(), test_render_default_egress_warp_needs_warp_url(), test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() (+22 more)

### Community 48 - "TopologyError"
Cohesion: 0.05
Nodes (57): _action_specification(), _address_facts(), _certificate_action(), _certificate_checkpoint(), _certificate_groups(), _certificate_sans(), _certificate_vhost_path(), CertificatePlan (+49 more)

### Community 49 - "test_installer_fresh_host.py"
Cohesion: 0.11
Nodes (48): canonical_ufw(), CertRunner, config(), dns_facts(), firewall_facts(), test_certificate_apply_refuses_lineage_that_appeared_after_prepare(), test_certificate_commands_and_checkpoint_are_secret_free(), test_certificate_owns_http01_vhost_before_certbot_and_removes_only_it() (+40 more)

### Community 50 - "Dedicated Proxy-Control-owned xray-router"
Cohesion: 0.08
Nodes (36): ADR 006: routing policy IR, ADR 007: routing enforcement ownership, Optional WARP outbound, v0.4 acceptance criteria, v0.5 acceptance criteria, CompiledRoutingGeneration (policy_revision, backend_id, compiler/runtime versions, binary/geodata/config digests), EgressProvider (direct | warp | socks | xray-router), EnforcementBackend (native | os-isolation | xray-router; fallback fail-closed | explicitly-approved-direct) (+28 more)

### Community 51 - "bridge.py"
Cohesion: 0.08
Nodes (28): bridge_env(), _credential(), _fake_router(), handle(), _run(), _socks(), test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways(), scenario() (+20 more)

### Community 52 - "test_mieru_deployment.py"
Cohesion: 0.12
Nodes (30): owned_private_file(), render_mieru_compose(), run_state_preparer(), run_token_preparer(), test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(), test_mieru_overlay_has_only_intended_writable_runtime_mounts(), test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access(), test_naive_caddy_identity_cannot_access_mieru_state() (+22 more)

### Community 53 - "RoutingService"
Cohesion: 0.05
Nodes (11): Task 9: Fleet v2 — `companion`, `egress.router.v1`, порядок применения на узле, удалённые attach/detach, CONTINUE HERE — v0.9 (стык фронт/бэк, matches_node, мобильный UI, Xray-router на центре), Сделано, Что дальше, direct_document(), lane_policies(), Compiled, RoutingPolicy (+3 more)

### Community 54 - "CentralProcess"
Cohesion: 0.07
Nodes (6): central_environment(), CentralProcess, NodeB, read_node_credentials(), Stub, _terminate()

### Community 55 - "Unreleased"
Cohesion: 0.07
Nodes (39): Busy buttons: capture event.currentTarget before finally, Client-specific Native/Karing/manual reveals, Host resource card via version-agent GET /v1/host, Generation-specific Karing profile name after rotation, Former host/systemd MTProxy install scripts removed, Complete mieru-client.json in Native reveal, Mieru no longer re-hashes blanked passwords, Pinned mita 3.36.x admitted alongside 3.35.x (+31 more)

### Community 56 - "CoreError"
Cohesion: 0.09
Nodes (7): add(), CoreError, _decode_adjacent_routes(), _read_existing_users(), _valid_master_key_file(), _valid_users_file(), _validate_ownership_mapping()

### Community 57 - "RuleMatch"
Cohesion: 0.06
Nodes (18): ADR 006: Engine-neutral routing policy IR, Amended in v1.1 (2026-10-01): MTProxy through the Xray-router, As shipped in v0.4, Consequences, Context, Decision, Non-goals, _Intent (+10 more)

### Community 58 - "Troubleshooting Proxy Control"
Cohesion: 0.07
Nodes (37): Never claim unavailable accounting precision, Public TCP/443 under host Nginx stream router, caddy adapt --adapter caddyfile --validate, Compose reports orphans, panel.cli create-admin --password-stdin, Initial diagnostics, Login failure, Mieru manager unhealthy (+29 more)

### Community 59 - "app.py"
Cohesion: 0.02
Nodes (139): Task 11: Маршруты центра — связи, импорт пользователей узла, версии, подписки по узлам, Task 2: Bearer-аутентификация, scope-гейты и `/api/keys`, Правила, добытые в этой серии, register_api_key_routes(), create_key(), _ctx(), delete_key(), set_enabled() (+131 more)

### Community 60 - "DeployCliTests"
Cohesion: 0.05
Nodes (3): Task 13: Phase 8 — backup/restore, матрица негативных тестов, замороженные идентификаторы, DeployCliTests, attempt()

### Community 61 - "test_fleet_v2_post_merge.py"
Cohesion: 0.10
Nodes (27): _Answering, _escrowed(), _events(), _link(), _link_row(), test_a_404_heartbeat_answer_is_still_offline(), test_a_429_or_5xx_heartbeat_answer_is_not_offline(), test_a_bare_gateway_5xx_is_offline() (+19 more)

### Community 62 - "MieruManager"
Cohesion: 0.10
Nodes (9): _atomic(), _canonical(), ConfigConflict, _fsync_dir(), _hash(), MieruManager, _pruned_operations(), _read_secure() (+1 more)

### Community 63 - "test_users_adapter_ui.py"
Cohesion: 0.07
Nodes (6): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_busy_buttons_capture_their_target_instead_of_reading_it_after_await(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires(), test_the_domain_writer_adopts_a_user_it_did_not_create(), test_the_domain_writer_records_a_client_and_grant_for_every_protocol(), _writer()

### Community 64 - "VersionAgent"
Cohesion: 0.06
Nodes (13): Global Constraints, Self-review, Task 8: `mita` — обновление закреплённого потребителя вместо отказа, Task 9: Компонент `xray`, v0.11 — обновления из upstream и обзор в одну строку: план реализации, check_upstream(), sha256_bytes(), _atomic_write() (+5 more)

### Community 65 - "test_installer_warp_transaction_recovery.py"
Cohesion: 0.11
Nodes (17): HostCommands, PowerLoss, test_apply_refuses_foreign_state_appearing_after_prepare(), test_apply_waits_for_transient_daemon_status(), test_cleanup_fsyncs_removed_entries_before_engine_completion(), test_egress_probe_overrides_inherited_no_proxy(), test_engine_completes_unpacked_package_on_resume(), test_engine_recovers_sigkill_before_owner_replace() (+9 more)

### Community 66 - "esc"
Cohesion: 0.07
Nodes (94): Task 10: UI «Маршрутизация» — роутер, esc(), queryAll(), attachment(), BACKEND_NAMES, bindRouting(), cardActions(), codeOptions() (+86 more)

### Community 67 - "guest-runner.sh"
Cohesion: 0.06
Nodes (6): CASE_STATUS, dns_tls_fixture(), full_audit(), full_dns_tls(), full_plan(), runtime_cmd()

### Community 68 - "test_three_xui_api.py"
Cohesion: 0.13
Nodes (23): build_managed_clients(), build_managed_inbounds(), warp_routing(), config(), DeterministicSecrets, secret_values(), test_a_hysteria_client_authenticates_with_auth_not_password(), test_acceptance_clients_are_distinct_from_persistent_clients() (+15 more)

### Community 69 - "Матрица негативных и security-тестов vNext (Task 39)"
Cohesion: 0.08
Nodes (39): Матрица негативных и security-тестов vNext (Task 39), Task 4: `xray_router_manager` — рантайм и типизированный менеджер (Task 33), _artifact(), FakeRunner, _lanes_doc(), manager(), _state(), test_apply_conflict_on_stale_revision() (+31 more)

### Community 70 - "test_installer_mcp.py"
Cohesion: 0.07
Nodes (29): _command_failure(), _DefaultMcpRunner, mcp_handoff(), mcp_url(), McpAdapter, McpError, McpPaths, _plaintext_of() (+21 more)

### Community 71 - "routing-spike.py"
Cohesion: 0.04
Nodes (48): ADR 008: Panel-to-panel transport with scoped API keys, Consequences, Context, Decision, Non-goals, 10. Тестирование, 11. Критерии приёмки v0.3, 1. Цель (+40 more)

### Community 72 - "test_subscription_http.py"
Cohesion: 0.09
Nodes (18): Task 3: Ручка `POST /api/clients/{id}/subscription/reveal` и расширенный обзор, _public(), register_subscription_admin_routes(), create(), issue(), overview(), read(), reveal() (+10 more)

### Community 73 - "proxyctl.py"
Cohesion: 0.16
Nodes (19): derive_owned_route_variable(), remove_owned_map_block(), sha256(), _apply_plan_unlocked(), _audit_mapping(), _canonical_route(), _host_path(), InstallerConflict (+11 more)

### Community 74 - "test_proxyctl_transactions.py"
Cohesion: 0.20
Nodes (20): apply_plan(), InstallPlan, repair_installation(), uninstall_installation(), facts_from_root(), host_root(), make_plan(), test_apply_is_transactional_preserves_metadata_and_writes_private_manifest() (+12 more)

### Community 75 - "DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)"
Cohesion: 0.11
Nodes (27): ADR 002: declarative generations, Audit finding 1: Manager tests live in tests/test_naive_manager.py and tests/test_mieru_manager.py, Audit finding 7: Managers generate passwords themselves, Audit finding 8: Telemt list_users allows credential recovery, v0.3 acceptance criteria, DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation), Fleet v2 exchange (/agent/v2/nodes/{node_id}/heartbeat, desired, observed, secrets/resolve, secret-results), ObservedGeneration (applied_generation, bundle_digest, reconcile_state, resource_statuses, safe_drift_summary) (+19 more)

### Community 76 - "test_version_agent_host.py"
Cohesion: 0.11
Nodes (17): _Proc, test_a_stalled_counter_reports_null_rather_than_a_confident_zero(), test_cpu_utilisation_is_a_delta_between_two_samples(), test_disk_reports_space_an_operator_can_actually_write(), test_host_endpoint_is_read_only_and_rejects_writes(), test_memory_counts_reclaimable_cache_as_available(), test_missing_proc_files_degrade_each_section_independently(), test_real_proc_is_parsed_on_linux() (+9 more)

### Community 77 - "document_digest"
Cohesion: 0.12
Nodes (29): Task 8: Routing — сервис и HTTP API (локальный узел), document_digest(), _block(), _link(), _link(), test_identity_reports_router_capability_and_attachment(), test_remote_apply_router_policy_on_node_without_capability_is_422(), test_remote_attach_apply_and_detach_through_generations() (+21 more)

### Community 78 - "CoreAdapter"
Cohesion: 0.09
Nodes (43): CoreAdapter, config(), core_action(), FakeRunner, test_a_generated_password_is_used_when_the_operator_chose_none(), test_absent_filesystem_adoption_refuses_active_fixed_label_resources(), test_acceptance_uses_transaction_unique_name_and_all_configured_credentials(), test_applying_checkpoint_removes_only_probe_and_image_created_after_prepare() (+35 more)

### Community 79 - "test_routing_lanes_routes.py"
Cohesion: 0.22
Nodes (12): _attach(), _csrf(), _grant(), router(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first() (+4 more)

### Community 80 - "resolve_artifacts"
Cohesion: 0.10
Nodes (20): CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой), Сделано, Что дальше, Task 19A — релизный гейт v0.2 на `ams-test` (пройден 2026-09-11), Как проверять (единственный способ), Промпт для продолжения работы в новом контексте, Прочитай сначала, Состояние репозитория (2026-09-11) (+12 more)

### Community 81 - "test_version_agent_upstream.py"
Cohesion: 0.08
Nodes (49): fetcher_from(), fetch(), test_an_older_image_the_registry_does_not_answer_for_is_skipped(), test_an_older_release_without_a_digest_is_skipped_without_a_reason(), test_asset_hosted_outside_the_repository_download_path_is_refused(), test_candidates_are_capped_at_the_six_newest_releases(), test_compare_versions_orders_numerically_and_prereleases_lower(), test_every_published_mita_with_a_digest_is_offered() (+41 more)

### Community 82 - "prepare-naive-state.py"
Cohesion: 0.17
Nodes (17): _assert_directory(), _assert_identities(), _assert_identity_free(), _assert_owned_state(), _assert_safe_parents(), _assert_state_entry(), _create_directory(), _fail() (+9 more)

### Community 83 - "exits.py"
Cohesion: 0.05
Nodes (24): Task 6: Панель — модель политики v3 и миграция 16, _b64(), ExitCredential, ExitInput, ExitInUse, ExitSecurity, ExitStore, ExitTransport (+16 more)

### Community 84 - "test_panel_entrypoint.py"
Cohesion: 0.18
Nodes (21): main(), open_source(), stage(), StageError, validate_source(), verify(), _fake_command(), logged_commands() (+13 more)

### Community 85 - "test_version_agent_server.py"
Cohesion: 0.08
Nodes (18): _Checked, FakeAgent, test_the_automatic_upstream_check_survives_a_failure_and_stops_on_request(), test_the_automatic_upstream_check_waits_for_the_cache_to_age(), test_unix_socket_server_answers_a_panel_update_as_accepted_and_async(), test_unix_socket_server_checks_upstream_on_post(), test_unix_socket_server_preserves_update_contract(), test_unix_socket_server_reports_a_failed_or_disabled_upstream_check() (+10 more)

### Community 86 - "Store"
Cohesion: 0.07
Nodes (9): ConflictError, Store, test_concurrent_login_batch_reserves_attempts_and_bounds_argon2(), test_login_limiter_migrates_existing_reservations(), test_successful_login_preserves_concurrent_failed_reservation(), interleaved_verify(), test_store_startup_uses_valid_policy_matched_precomputed_dummy_hash(), test_unknown_admin_performs_one_argon2_verify_without_logging_password() (+1 more)

### Community 87 - "3x-ui mode: managed-new"
Cohesion: 0.09
Nodes (27): CertificatePlan, release/external-artifacts.json, Managed inbound templates vless_reality_tcp / vless_reality_xhttp / hysteria2_tls, ThreeXuiAdapter.plan_existing_upgrade, safe_extract_tar, Task 12: Existing and staged 3x-ui lifecycle, Task 13: Managed 3x-ui inbounds, clients and optional WARP, Task 5: Release manifest, artifact hashing and safe extraction (+19 more)

### Community 88 - "register_routing_routes"
Cohesion: 0.10
Nodes (24): _outcome(), policy_view(), _refusal(), register_routing_routes(), apply(), attach(), _ctx(), delete_policy() (+16 more)

### Community 89 - "MitaCLI"
Cohesion: 0.13
Nodes (8): MitaCLI, MitaError, _process_running(), test_cli_eof_before_child_exit_is_sanitized_and_reaps_child(), test_cli_passes_complete_config_through_anonymous_fd_and_bounds_output(), test_cli_refuses_unpinned_or_changed_executable_before_launch(), test_cli_success_kills_same_group_descendant_after_direct_child_exits(), test_cli_timeout_kills_descendant_that_inherits_output_pipes()

### Community 90 - "fleet.js"
Cohesion: 0.14
Nodes (24): ACTION_NAMES, applyFilters(), auditBody(), auditMarkup(), auditQuery(), auditRow(), handleAuditClick(), handleAuditSubmit() (+16 more)

### Community 92 - "ValidationError"
Cohesion: 0.16
Nodes (13): _conflict_code(), ManagerHandler, _go_duration_ns(), _object(), _positive_int(), validate_config(), _validate_traffic(), ValidationError (+5 more)

### Community 93 - "English"
Cohesion: 0.12
Nodes (17): English, Gate checklist (lab host `ams-test`), Installing, Live check (the fleet: ams-server → AMS_Z, AMS_Z → ams-test), Screenshots, Upgrading, v0.8.0-beta.1 — свои выходы, таблица правил, geodata, автоимпорт, What the verification found (+9 more)

### Community 94 - "TransactionStore"
Cohesion: 0.13
Nodes (10): _pretty_json(), TransactionStore, test_applied_state_is_durable_before_derived_ownership_journal(), crash_before_derived_journal(), test_operation_lock_rejects_final_symlink_without_chmod_or_flock(), test_operation_lock_rejects_hard_link_before_chmod_or_flock(), test_runtime_v2_import_rejects_change_between_validation_and_capture(), test_store_rejects_symlinked_parent_that_escapes_root() (+2 more)

### Community 95 - "Task 6: Encrypted secret versions and master key"
Cohesion: 0.13
Nodes (21): CoreAdapter / CorePaths / CoreAcceptance, ADR 005: secret references, compose.yaml secret panel-master-key, Pinned cryptography dependency, panel/entrypoint.sh master-key staging, Audit finding 2: Panel vhost is rendered in two places, Audit finding 5: One-time reveal lives only in process memory, Audit finding 9: Panel container is read_only with secrets staged into /run/panel (+13 more)

### Community 97 - "QuotaEnforcer"
Cohesion: 0.10
Nodes (9): caddy_adapt(), command_reload(), command_validate(), main(), QuotaEnforcer, _rewrite_listener(), test_caddy_adapt_unwraps_caddy_211_envelope(), test_private_listener_rewrite_disables_automatic_https_redirects() (+1 more)

### Community 98 - "_DefaultCoreRunner"
Cohesion: 0.07
Nodes (15): _AcceptanceCollision, AcceptanceError, _DefaultCoreRunner, probe_sources_digest(), test_run_suppresses_stdout_preserves_stderr_stdin_and_env(), test_timeout_preserves_stderr_without_exposing_stdout(), test_a_probe_image_built_from_older_sources_is_not_compatible(), test_adjacent_handshake_reads_the_report_not_the_exit_status() (+7 more)

### Community 99 - "MemoryTelemt"
Cohesion: 0.05
Nodes (32): RouterAdapter, attach_document(), router_target_from_identity(), MemoryTelemt, _adapter(), anyio_backend(), Bridge, _item() (+24 more)

### Community 100 - "WarpAdapter"
Cohesion: 0.19
Nodes (5): WarpAdapter, WarpError, test_warp_rollback_checks_all_ownership_before_any_mutation(), test_warp_is_owned_before_consumers_and_requires_real_egress(), test_warp_owned_lifecycle_and_foreign_install_refusal()

### Community 101 - "common.js"
Cohesion: 0.09
Nodes (50): Task 7: Окно клиента: показ ссылки по кнопке, матрица, «Применить», Task 8: «Новый клиент» с матрицей и блок подписки в «Доступы выданы», bindClients(), openClientModal(), proposeUsername(), locale(), OPERATION_MESSAGE, OPERATION_OK (+42 more)

### Community 102 - "FleetPusher"
Cohesion: 0.06
Nodes (9): Центральная панель (fleet_v2 central), Рулинги, принятые за владельца (в итоговый отчёт), NodeRejected, _Backoff, _describe(), FleetPusher, _ImportState, _inventory_digest() (+1 more)

### Community 103 - "OwnershipError"
Cohesion: 0.16
Nodes (8): _assert_contained(), operation_lock(), _owned_path(), OwnershipError, _path_identity(), _root_path(), RuntimeV2Adapter, validate_legacy_runtime_v2()

### Community 104 - "test_installer_cli.py"
Cohesion: 0.15
Nodes (21): load_config(), main(), _plan(), ReturningWizard, _run(), _run_in_pty(), _services(), _state() (+13 more)

### Community 105 - "test_mieru_manager_lanes.py"
Cohesion: 0.09
Nodes (18): empty_config(), LanesInvalid, parse_slots(), Slot, slot_config(), validate_request(), FakeSlot, lane_manager() (+10 more)

### Community 106 - "main.js"
Cohesion: 0.06
Nodes (74): ADR-0008, Task 13: Экран версий — кнопка проверки, пометка источника, карточка Xray, 11. Безопасность, api(), API_REASONS, cookie(), DETAIL_WORTH_SHOWING, problemText() (+66 more)

### Community 109 - "test_mieru_egress.py"
Cohesion: 0.09
Nodes (34): Task 5: naive-manager и mieru-manager — провайдер `router`, canonical(), check_reachable(), _cidr(), document_digest(), _domain(), EgressInvalid, EgressUnreachable (+26 more)

### Community 110 - "nodes.js"
Cohesion: 0.07
Nodes (54): Task 12: UI — API-ключи, «Узлы → Добавить панель», карточка узла, выбор узла в «Клиентах», Task 10: UI «Маршрутизация» (Task 27), refreshCommands(), updateCommandFieldsAfterRender(), actions(), bindLinkDialog(), bindNodes(), certificateLine() (+46 more)

### Community 111 - "mcp_server/server.py"
Cohesion: 0.05
Nodes (11): Task 10: `naive` — пересборка Caddy, Config, _read_secret(), main(), _json_text(), PanelError, build_server(), create_app() (+3 more)

### Community 112 - ".verify"
Cohesion: 0.13
Nodes (5): _acceptance_value(), _compose_publishes_telemt_api(), CoreAcceptance, test_acceptance_dataclass_rejects_inconsistent_counts(), test_panel_client_accepts_a_full_reveal_payload()

### Community 113 - "Task 2: automatic WARP with selective routing"
Cohesion: 0.19
Nodes (15): ams-server production reference server, cloudflare-warp client / warp-svc.service, release/external-artifacts.json (pinned external artifacts), Task 3.2: installer deploys WARP automatically, Task 3.3: selective WARP routing via 3x-ui, three_xui.warp_domains config option, WARP selective domain list (geosite:openai, anthropic, tiktok, reddit, google-gemini, google-play), WARP proxy mode on local SOCKS5 port 40000 (+7 more)

### Community 114 - "test_installer_xray_router.py"
Cohesion: 0.10
Nodes (37): Task 11: Установщик — `[egress] router`, адаптер `xray_router`, секреты, ротация, _relay_config(), test_a_router_action_without_relay_keys_still_applies_and_verifies(), test_router_apply_enables_the_relay_and_verify_proves_its_public_part(), test_router_plan_carries_the_relay_and_refuses_a_claimed_relay_port(), action_for(), adapter(), _agent_state() (+29 more)

### Community 115 - "grant.js"
Cohesion: 0.10
Nodes (34): filename(), jsonConfig(), karingVariant(), mieruNative(), naiveNative(), naiveNekobox(), normaliseAccessPayload(), plainObject() (+26 more)

### Community 116 - "test_version_agent.py"
Cohesion: 0.08
Nodes (42): _agent(), _build_catalog(), test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(), test_archive_member_hash_is_checked_against_the_archive_not_the_file(), test_binary_rollback_restart_is_not_success_without_health(), test_binary_update_records_the_pin_the_unit_check_reads(), test_binary_update_restores_the_previous_pin_when_the_service_fails(), test_binary_update_rolls_back_when_service_restart_fails() (+34 more)

### Community 117 - "test_naive_manager_lanes.py"
Cohesion: 0.11
Nodes (19): handler_lines(), lane_credentials(), lanes_span(), LanesInvalid, outside_lanes(), primary_forward_proxy(), render(), validate_request() (+11 more)

### Community 118 - "Continuation prompt for a new Claude Code context"
Cohesion: 0.12
Nodes (14): ams-test disposable install server, Full install log capture (install.err, docker compose logs, journalctl nginx, container state), full profile with three_xui.mode managed-new, /root/install.toml and /root/install.credentials, Let's Encrypt certificates (four issued), Task 3.1: finish the installation to status active, ams-test disposable server (ssh ams-test, root), Continuation prompt for a new Claude Code context (+6 more)

### Community 119 - "register_fleet_v2_node_routes"
Cohesion: 0.10
Nodes (24): _conflict(), _log_late_outcome(), register_fleet_v2_node_routes(), capture(), _daemon(), _egress_entry(), _enabled(), _geodata() (+16 more)

### Community 120 - "_PinningStream"
Cohesion: 0.11
Nodes (3): _NodeBackend, _NodeTransport, _PinningStream

### Community 121 - "MTProxy acceptance failure: Connection closed"
Cohesion: 0.24
Nodes (7): Fake-TLS handshake, nebula.sky.dubr1kkk.uk (MTProxy, cert: yes), proxy-control-mtproxy container (127.0.0.1:8445), secrets/users.conf MTProxy secret, TDLib MTProto probe (addProxy), proxy-control-mtproxy container, MTProxy / Telemt (Fake-TLS, tg:// access, limits, expiry)

### Community 122 - "Proxy Control v0.1.0 Beta"
Cohesion: 0.13
Nodes (14): Archive SHA-256 checksum for proxy-control-v0.1.0.tar.gz, Mieru (TCP/UDP proxy on explicit public ports), mita local manager for Mieru, NaiveProxy (HTTPS proxy with cover site, users, quotas, completed-tunnel accounting), Proxy Control panel (owner/admin/viewer roles, secret-free audit, one-time credential disclosure), Proxy Control v0.1.0 Beta, Four release assets (archive, SHA256SUMS, release-manifest.json, sbom.spdx.json), sbom.spdx.json SBOM (+6 more)

### Community 123 - "test_installer_version_agent.py"
Cohesion: 0.06
Nodes (36): _command_failure(), _DefaultVersionAgentRunner, _env_key(), _env_values(), VersionAgentAdapter, VersionAgentError, VersionAgentPaths, action_for() (+28 more)

### Community 124 - "curated.py"
Cohesion: 0.18
Nodes (29): Добавлено, Tools, Инструменты, 9a. MCP-сервер `proxy-control-mcp` (решение владельца 2026-09-21: в v0.11, полный набор, доступ с ноутбука через SNI), audit_tail(), client_subscription(), create_client(), CuratedTool (+21 more)

### Community 125 - "XrayRouterManager"
Cohesion: 0.07
Nodes (8): ManagerConflict, ManualInterventionRequired, _now(), revision_of(), _sha256_file(), _test_failure(), XrayRouterManager, run()

### Community 126 - "test_mobile_layout.py"
Cohesion: 0.09
Nodes (13): Task 9: Мобильный аудит окна клиента, _cards_from_real_renderers(), test_mobile_cards_have_semantic_icons_and_quick_settings_align(), _browser(), DevTools, _recv_exact(), _render_at_phone_viewport(), test_access_cards_and_navigation_do_not_collide_on_phone() (+5 more)

### Community 127 - "docker_lab.py"
Cohesion: 0.21
Nodes (10): _architecture(), build_image(), copy_inputs(), DockerLabError, guest_command(), main(), run(), run_acceptance() (+2 more)

### Community 129 - "Task 4: Unified DB layer and migrations"
Cohesion: 0.19
Nodes (17): panel.audit.digest (sha256 of canonical JSON), panel.audit.record(db, ...), panel.audit.scrub (recursive), Migration 2 audit-structured, Migration 1 baseline-v0.1.0, panel.database.Database (WAL, foreign_keys, transaction()), panel.cli db-migrate / db-status, Audit finding 4: Schema is initialised by two processes (+9 more)

### Community 130 - "Panel version-agent"
Cohesion: 0.06
Nodes (37): Bounded log queries, Start of change window, Configuration change procedure, .env secrecy, Incident sequence, Log redaction before sharing, scripts/proxyctl.py repair, Restart and recovery (+29 more)

### Community 131 - "PolicyInput"
Cohesion: 0.07
Nodes (45): Task 7: Routing IR — модели, хранилище, миграция 14, компилятор (Task 26), PolicyInput, PolicyPut, PolicyConflict, PolicyNotFound, RoutingStore, test_a_native_policy_other_than_direct_must_attach_first(), _policy() (+37 more)

### Community 132 - "sbom.py"
Cohesion: 0.26
Nodes (7): build_sbom(), _external_packages(), _identifier(), main(), SbomError, test_sbom_is_deterministic_for_one_commit(), test_sbom_requires_at_least_one_packaged_file()

### Community 133 - "clients.js"
Cohesion: 0.09
Nodes (44): acceptPage(), actions(), adopt(), adoptNote(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT, CLIENT_STATE (+36 more)

### Community 134 - "AgentTransportServer"
Cohesion: 0.19
Nodes (4): main(), required(), serve(), AgentTransportServer

### Community 135 - "test_fleet_v2_reconcile.py"
Cohesion: 0.11
Nodes (26): _accept(), anyio_backend(), _imported(), _push(), _resource(), test_a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user(), test_a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply(), test_a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user() (+18 more)

### Community 136 - "test_mcp_server.py"
Cohesion: 0.07
Nodes (30): _body_schema(), _build(), build_operations(), is_excluded(), is_irreversible(), Operation, resolve_refs(), tool_name() (+22 more)

### Community 137 - "renderers/base.py"
Cohesion: 0.06
Nodes (47): mieru_access(), register_mieru_routes(), escrow(), kept(), kept_share_url(), live_template(), local_only(), mieru_create() (+39 more)

### Community 138 - "3x-ui mode managed-new: install on clean server, create inbounds"
Cohesion: 0.21
Nodes (14): Task 3.4: 3x-ui subscription on ninth domain, zenith.sky.dubr1kkk.uk (reserved: 3x-ui subscription), 3x-ui subscription on zenith.sky.dubr1kkk.uk deferred by owner, Bilingual install wizard, Hysteria2 inbound, Nginx mode coexist: existing Nginx stream keeps TCP/443, Nginx mode fresh: installer installs and configures Nginx, Nine distinct domains for full profile + managed-new + subscription (eight without subscription) (+6 more)

### Community 140 - "test_naive_manager_egress.py"
Cohesion: 0.12
Nodes (28): EgressUnreachable, _block(), EgressHooks, manager(), router_manager(), test_a_failed_reload_restores_the_previous_bytes(), test_a_readback_mismatch_rolls_back_with_its_own_code(), test_apply_conflicts_on_a_stale_revision_without_touching_anything() (+20 more)

### Community 141 - "ManagerHTTPServer"
Cohesion: 0.20
Nodes (5): test_unix_api_exit_test_route(), build_manager(), _env(), main(), ManagerHTTPServer

### Community 142 - "test_fleet_acceptance_script.py"
Cohesion: 0.10
Nodes (5): _run(), test_naive_probe_retries_a_cut_connection_but_not_a_refusal(), test_routing_scenarios_are_opt_in_and_sit_after_the_grants(), test_scenario_report_is_secret_free_and_stops_the_central_on_failure(), test_scenario_runs_all_eleven_steps_on_fakes()

### Community 143 - "3. Задачи"
Cohesion: 0.15
Nodes (12): 1. Где остановились, 2. Как WARP устроен на рабочем сервере (снято с `ams-server`), 3.1 Добить установку, 3.2 Автоматический WARP, 3.3 Выборочная маршрутизация через 3x-ui, 3.4 Подписка 3x-ui (девятый домен), 3.5 Релизная лаборатория, 3. Задачи (+4 more)

### Community 144 - "RoutingRule"
Cohesion: 0.05
Nodes (44): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 11: Лаборатория — сценарии routing и tier `routing`, Task 12: Документация, ADR, CHANGELOG, VERSION, Task 13: Гейт релиза и живая проверка (Task 31A), Task 5: mieru-manager — egress API (Task 29b), v0.4 Routing Implementation Plan (+36 more)

### Community 145 - "Global Constraints"
Cohesion: 0.05
Nodes (38): Chains and per-client lanes spike (v0.7, Task 1), S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user, S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray, S3 — Mieru: a second mita daemon beside the managed one, What v0.7 builds on this, Global Constraints, Task 0: Ветка, спайк, спека, план, Task 10: Установщик — `relay_port`, `lane_slots`, обновление (+30 more)

### Community 146 - "index.cjs"
Cohesion: 0.09
Nodes (22): dependencies, prebuilt-tdlib, tdl, description, engines, node, license, name (+14 more)

### Community 147 - "TypedCommand"
Cohesion: 0.13
Nodes (12): ADR 001: Pull-only node transport, Consequences, Context, Decision, Non-goals, TypedCommand, ExecutionIndeterminate, command() (+4 more)

### Community 149 - "create_app"
Cohesion: 0.02
Nodes (60): Task 5: Reconciler узла, Task 12: Панель — `check()`, компонент `xray`, `/api/versions/check`, relay для узлов, 8.1 API (`panel/routing/routes.py`, owner для мутаций, viewer — чтение), 8.2 Локальный узел, 8.4 UI («Маршрутизация», `panel/static/js/routing.js`), 8. Панель, create_app(), _lifespan() (+52 more)

### Community 150 - "EgressInvalid"
Cohesion: 0.07
Nodes (47): Task 1: Xray-router — intent схемы 2 (полосы, выходы, цепи), test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector(), test_credentials_are_masked_in_the_redacted_intent(), test_exit_outbounds_render_the_way_xray_dials_them(), test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(), test_the_intent_names_exits_and_a_rule_may_leave_through_one(), test_validate_exit_normalises_every_protocol_and_refuses_the_impossible(), _v2() (+39 more)

### Community 151 - "test_xray_router_mtproxy.py"
Cohesion: 0.14
Nodes (15): _inbound(), manager(), SocketRunner, test_a_chain_for_mtproxy_renders_like_any_service(), test_a_malformed_credential_is_a_manual_intervention_not_a_new_one(), test_a_manager_without_the_socket_does_not_know_mtproxy(), test_a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(), test_a_stale_socket_is_removed_before_xray_starts() (+7 more)

### Community 152 - "Accounting semantics"
Cohesion: 0.07
Nodes (24): Pull Request Boundary Checklist, Contribution Architecture Rules, Local Development Gate Commands, Accounting semantics, Mieru rolling session-admission quota, Naive completed-CONNECT byte collector, Telemt total_octets and quota usage counter, Proxy Control architecture (+16 more)

### Community 153 - "api_with"
Cohesion: 0.11
Nodes (23): api_with(), ok(), test_a_panel_certificate_path_must_be_absolute(), test_a_refusal_names_its_kind_but_never_repeats_the_panels_message(), test_api_refuses_a_response_outside_the_contract_schema(), test_api_refuses_an_endpoint_outside_the_pinned_contract(), test_configure_panel_refuses_a_non_loopback_listener(), test_configure_panel_refuses_a_web_path_it_cannot_vouch_for() (+15 more)

### Community 154 - "guest-runner.sh script"
Cohesion: 0.26
Nodes (12): case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), full_environment_preflight(), host_diagnostics(), host_environment_preflight() (+4 more)

### Community 155 - "MemoryXrayRouter"
Cohesion: 0.08
Nodes (13): _csrf(), router(), test_a_linked_panels_geodata_is_driven_through_its_fleet_api(), test_geodata_is_owner_only_to_change_and_needs_a_router(), test_local_geodata_view_settings_update_restore_and_audit(), test_node_geodata_and_exit_routes_answer_the_central_key(), anyio_backend(), test_attach_documents_and_attached_detection() (+5 more)

### Community 156 - "test_qemu_lab.py"
Cohesion: 0.06
Nodes (9): GuestRunnerPreflightScripts, LabDiagnostics, _passing_report(), ReleaseArtifactTests, ReleaseConfigMatchesItsFixture, ReleaseFixtureTests, ReleaseMatrixTests, ReleaseRootLayout (+1 more)

### Community 157 - "Proxy Control Cover Art"
Cohesion: 0.33
Nodes (8): Anime Key-Art Illustration Style, Beam vs Hammer Clash Metaphor, Twin-Tailed Girl Blocking With Stone Hammer, Proxy Control Cover Art, Central Impact Burst Where Beam Meets Hammer, Proxy Control Repository Branding Asset, Night Ruined Colosseum Arena Backdrop, Rearing Unicorn Emitting Magenta Horn Beam

### Community 158 - "ReleaseError"
Cohesion: 0.20
Nodes (17): _DuplicateKeyError, _load_json(), _normalize_archive_path(), _object_without_duplicate_keys(), _parse_artifact(), _parse_members(), _parse_platform_pin(), _reject_json_constant() (+9 more)

### Community 159 - "NaiveClient"
Cohesion: 0.15
Nodes (3): NaiveClient, _optional(), test_naive_adapter_accepts_empty_204_delete_response()

### Community 160 - "run_captured"
Cohesion: 0.21
Nodes (13): full_idempotence(), full_install(), host_idempotence(), host_install(), interrupt_install_recovery(), release_idempotence(), release_install(), release_install_full_xui() (+5 more)

### Community 161 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.20
Nodes (13): ADR 001: pull-only node transport, ADR 003: one writer per resource, Task 1: ADRs and v0.2 architecture record, Task 2: Characterization tests of current boundaries, Task 3: Capability matrix and fixture, Ownership manifest, Fleet v1 Telemt-only command queue, Resource ownership terms: managed | adopted | foreign | drifted | tombstoned (+5 more)

### Community 162 - "install-bootstrap"
Cohesion: 0.23
Nodes (8): sbom.spdx.json, SHA256SUMS, Проверка релиза, release-manifest.json, Primary install path: verified release, Основной путь: проверенный релиз, Step 1: verify the release and extract install-bootstrap, Шаг 1: проверка релиза и install-bootstrap

### Community 163 - "ReleaseManifest"
Cohesion: 0.10
Nodes (21): ExternalArtifact, ReleaseManifest, verify_artifact(), _load_manifest(), main(), _parser(), sha256_file(), stage_xray() (+13 more)

### Community 164 - "mieru-client/probe.py"
Cohesion: 0.36
Nodes (5): _endpoint(), main(), _run(), _socks5_connect(), _status_through()

### Community 165 - "Промпт для продолжения работы в новом контексте"
Cohesion: 0.22
Nodes (8): Задача 1: добить установку, Задача 2: автоматический WARP, Задача 3: релиз, Отложено владельцем, Правила, добытые дорогой ценой, Промпт для продолжения работы в новом контексте, Прочитай сначала, Что уже сделано

### Community 166 - "InstallPlan"
Cohesion: 0.19
Nodes (4): InstallPlan, TransactionState, RecordingEngine, RecordingStore

### Community 167 - "test_ui_browser_findings.py"
Cohesion: 0.11
Nodes (8): test_an_audit_row_stacks_its_main_line_and_its_details(), test_every_documented_audit_action_has_a_journal_label(), test_no_module_renders_an_inline_style_attribute(), test_the_brand_mark_is_the_product_artwork_that_actually_ships(), test_the_grant_dialog_body_issues_a_mieru_grant(), test_the_grant_dialog_reads_only_its_own_protocol_boxes(), test_the_login_form_shows_a_refusal_instead_of_reloading(), test_the_profile_button_opens_a_menu_instead_of_a_toast()

### Community 168 - "test_subscription_renderers.py"
Cohesion: 0.12
Nodes (5): artifacts(), _database_bytes(), manifest_with_canary(), test_rendering_leaves_no_secret_in_database_logs_or_errors(), test_the_official_singbox_variant_carries_naive_only()

### Community 169 - "container_cmd"
Cohesion: 0.22
Nodes (9): container_audit(), container_cmd(), container_nginx_multi_map(), container_uninstall_foreign_identity(), host_crash_every_phase(), host_reboot_recovery(), host_repair(), host_report() (+1 more)

### Community 170 - "installer_cmd"
Cohesion: 0.22
Nodes (9): installer_cmd(), release_audit(), release_coexist_existing_xui(), release_crash_every_phase(), release_nginx_multi_map(), release_reboot_recovery(), release_repair(), release_uninstall() (+1 more)

### Community 171 - "prepare_mieru_token.py"
Cohesion: 0.36
Nodes (6): fail(), main(), prepare_or_verify(), TokenError, validate_path(), validate_source()

### Community 172 - "Task 3: release v0.1.0 through CI"
Cohesion: 0.27
Nodes (6): lab-amd64 CI release lab, Task 3.5: release lab lab-amd64, gh workflow run Release -f version=0.1.0 --ref main, lab-amd64 CI lab (red), Task 3: release v0.1.0 through CI, Verified: exact-archive lifecycle on isolated amd64 VPS (install, repair, idempotence, reboot/crash recovery, uninstall, coexistence)

### Community 173 - "ProtocolError"
Cohesion: 0.22
Nodes (5): main(), run(), ProtocolError, AgentTransportClient, NodeAgent

### Community 174 - "container_setup"
Cohesion: 0.33
Nodes (7): add_hosts(), container_setup(), container_write_configs(), host_ip(), host_setup(), setup_full_host(), write_fake_certbot()

### Community 175 - "FleetStore"
Cohesion: 0.26
Nodes (5): _canonical(), CommandConflict, FleetStore, test_fleet_store_assigns_monotonic_sequences_and_enforces_idempotency(), test_result_upload_retry_is_idempotent_but_conflicting_replay_is_rejected()

### Community 176 - "ProvisioningService"
Cohesion: 0.06
Nodes (15): Task 1: Fix-wave — отложенные замечания v0.3, OperationResult, ProvisioningService, StepResult, anyio_backend(), backends(), _grants(), _intent() (+7 more)

### Community 178 - "Rule: verify the open port, not the panel record"
Cohesion: 0.25
Nodes (3): three_xui managed-new mode completed, 3x-ui 3.7.0 (pinned), 3x-ui mode existing: adopt installed 3x-ui without changing its files

### Community 179 - "ingress_upgrade.py"
Cohesion: 0.08
Nodes (34): CONTINUE HERE — v0.4 маршрутизация, Где мы, Гейт (Task 13) — итог, Известные ограничения/решения (для ревью и v0.5), Коммиты ветки (по порядку), Публикация (по поручению владельца 2026-09-14), Что дальше (владелец), _mcp_vhost_text() (+26 more)

### Community 180 - "client_probe"
Cohesion: 0.29
Nodes (7): client_probe(), release_hysteria_client(), release_mieru_client(), release_naive_client(), release_telemt_client(), release_vless_tcp_client(), release_vless_xhttp_client()

### Community 181 - "test_mtproxy_respq_probe.py"
Cohesion: 0.57
Nodes (4): run_wrapper(), test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(), test_wrapper_rejects_invalid_arguments_without_starting_docker(), test_wrapper_requires_root()

### Community 182 - "test_version_agent_panel.py"
Cohesion: 0.11
Nodes (29): _mutations(), _panel_archive(), _PanelHost, _release_tar(), _state(), test_a_second_panel_update_is_refused_while_one_is_running(), test_a_version_file_ahead_of_the_running_panel_does_not_hide_the_update(), test_panel_current_falls_back_to_the_version_file_without_a_container() (+21 more)

### Community 183 - "test_acceptance_cleanup_preserves_process_stop_and_reports_other_failures"
Cohesion: 0.15
Nodes (10): _alive(), test_acceptance_cleanup_preserves_process_stop_and_reports_other_failures(), logout(), request(), unlink(), test_interrupt_stops_the_process_group(), test_timeout_drain_is_bounded_when_a_daemon_escapes_the_group(), test_timeout_stops_term_ignoring_child_before_rollback() (+2 more)

### Community 185 - "BoundedBodyMiddleware"
Cohesion: 0.33
Nodes (3): receive(), BoundedBodyMiddleware, replay()

### Community 186 - "probe/install.sh"
Cohesion: 0.33
Nodes (5): DESTINATION, IMAGE, install.sh script, TDL_VERSION, TDLIB_VERSION

### Community 188 - "test_installer_three_xui.py"
Cohesion: 0.03
Nodes (75): AcceptanceError, parse_reality_keypair(), ThreeXuiAudit, ThreeXuiConfig, SystemSecrets, adapter(), build_release(), config_with_clients_and_reality_secret() (+67 more)

### Community 189 - "Private Vulnerability Reporting Path"
Cohesion: 0.40
Nodes (5): Sanitized Bug Report Template, Issue Template Config (blank issues disabled), Security Reporting Guidance Template, Code of Conduct, Private Vulnerability Reporting Path

### Community 190 - "installer/audit.py"
Cohesion: 0.05
Nodes (64): patch_owned_map(), _applicable_caa(), _audit_host(), AuditError, AuditFacts, _bounded_execute(), _bounded_resolve(), _caa_compatible() (+56 more)

### Community 191 - ".compose"
Cohesion: 0.20
Nodes (8): CONTINUE HERE — v0.5 Xray egress-router, Где мы, Гейт (Task 15) — итог, Коммиты ветки (по порядку), Что дальше (владелец), Drill, main(), sha256()

### Community 192 - "upstream"
Cohesion: 0.04
Nodes (63): [0.5.0-beta.1] - 2026-09-16, Безопасность, Добавлено, Изменено, Отложено (дорожная карта), Consequences, END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`, Non-goals (+55 more)

### Community 193 - "test_routing_router_service.py"
Cohesion: 0.17
Nodes (22): Task 8: RoutingService — targets с роутером, attach/detach, apply/rollback через роутер (локально), anyio_backend(), _audits(), _block(), _item(), _rules(), test_apply_native_policy_on_attached_service_is_422(), test_apply_router_failure_marks_failed_and_maps_codes() (+14 more)

### Community 194 - "RuntimeRunner"
Cohesion: 0.15
Nodes (3): InjectedCrash, RuntimeRunner, crash_after_started()

### Community 195 - "MieruClient"
Cohesion: 0.12
Nodes (5): MieruClient, test_mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body(), test_mieru_client_rotate_sends_the_caller_credential_and_operation_id(), test_mieru_client_sanitizes_manager_errors(), handler()

### Community 196 - "test_agent_client_retries_result_from_durable_outbox_without_reexecution"
Cohesion: 0.31
Nodes (7): issue_fixture(), mtls_context(), start_server(), test_agent_client_retries_result_from_durable_outbox_without_reexecution(), test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(), test_revocation_and_request_body_bound_fail_closed(), test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node()

### Community 197 - "XrayRouterClient"
Cohesion: 0.13
Nodes (5): 9.1 API (`panel/routing/routes.py`; owner для мутаций, viewer — чтение), 9.2 Локальный узел, 9.4 UI («Маршрутизация», `panel/static/js/routing.js`), 9. Панель, XrayRouterClient

### Community 199 - "test_installer_reports.py"
Cohesion: 0.12
Nodes (17): AcceptanceReport, _assert_public(), CredentialHandoff, _encode(), ReportError, ReportWriter, handoff_with_secrets(), public_report_values() (+9 more)

### Community 200 - "English"
Cohesion: 0.40
Nodes (5): Domains and shared port 443, English, Included, Installation, Verified for this release

### Community 201 - "InstallerConfig"
Cohesion: 0.07
Nodes (30): Task 3: Установщик — секция `[egress]` (Task 28), WizardRunner, _canonical_dataclass(), DomainConfig, EgressConfig, FirewallConfig, InstallerConfig, MieruConfig (+22 more)

### Community 202 - "mieru-mss-clamp.sh"
Cohesion: 0.83
Nodes (3): check_rule(), mieru-mss-clamp.sh script, usage()

### Community 203 - "ThreeXuiApiError"
Cohesion: 0.12
Nodes (6): _form_value(), parse_csrf_token(), ThreeXuiApi, ThreeXuiApiError, test_a_page_without_a_usable_csrf_token_fails_closed(), test_csrf_token_is_read_from_the_page_the_panel_serves()

### Community 205 - "_panel_health_diagnosis"
Cohesion: 0.11
Nodes (8): _as_text(), _command_failure(), _panel_health_diagnosis(), _sanitize_diagnostic(), _without_health_polling(), test_a_failed_panel_health_check_says_what_the_containers_were_doing(), test_the_panel_diagnosis_drops_its_own_health_polling(), test_the_panel_diagnosis_never_lets_a_diagnostic_failure_mask_the_real_one()

### Community 208 - "test_grant_lifecycle.py"
Cohesion: 0.16
Nodes (22): _actions(), _generation(), _grant(), _node_users(), _remote(), _secret_states(), test_a_deleted_or_unknown_grant_is_refused(), test_bundle_never_renders_a_withdrawn_or_deleted_grant() (+14 more)

### Community 209 - "README.md"
Cohesion: 0.08
Nodes (18): Changing routing, Steps, `unsupported` reasons and what to do, What to tell the owner, Diagnosing a client's access, Report to the owner, Steps, Symptom → likely cause (+10 more)

### Community 214 - "Database"
Cohesion: 0.02
Nodes (84): Live check (AMS_Z ↔ ams-test), Task 1: Миграция 20 и `secret_ref` у подписки, ApiKeyService, _hash(), main(), Connection, Database, DatabaseError (+76 more)

### Community 219 - "v0.11 — обновления из upstream и обзор в одну строку"
Cohesion: 0.20
Nodes (9): 10. Тесты и проверка, 1. Цель, 5. Компонент `xray`, 6. Компонент `mita` и закреплённый потребитель, 7. Компонент `naive` — пересборка Caddy, 8. API и данные, 9. Ошибки, v0.11 — обновления из upstream и обзор в одну строку (+1 more)

### Community 220 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v1.0.2, v1.0.3 — скрипт установки в каждом выпуске, исправленный мастер установки, Добавлено, Исправлено, Обновление с v1.0.2 (+1 more)

### Community 222 - "test_version_agent_artifacts.py"
Cohesion: 0.25
Nodes (12): _targz(), test_escaping_members_unknown_formats_and_garbage_are_refused(), test_missing_member_symlink_and_oversize_are_refused(), test_tar_member_may_sit_under_a_directory(), test_tar_member_written_with_a_dot_slash_prefix_is_still_found(), test_zip_member_is_returned_by_exact_name(), _zip(), ArtifactError (+4 more)

### Community 223 - "English"
Cohesion: 0.12
Nodes (17): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z → ams-test), Proxy Control v0.7.0-beta.1, Screenshots, Upgrading, What the verification found (+9 more)

### Community 225 - "compose fleet-agent overlay service"
Cohesion: 0.20
Nodes (6): compose fleet-agent overlay service, compose fleet-ingress overlay service, Typed per-node command queue, Fleet central mTLS ingress, Outbound mTLS fleet transport v1, panel.cli fleet CA/enrollment commands

### Community 233 - "CatalogError"
Cohesion: 0.11
Nodes (23): Task 11: Сервер агента — `POST /v1/upstream/check`, долгий таймаут для сборки, Task 14: Установщик принимает версии из `state.json` агента, Task 15: Документация и changelog, Task 16: Гейт на ams-test и живая проверка на AMS_Z, Task 1: Обзор — без «Application bytes», ресурсы одной строкой, три карточки, Task 4: Каталог — `xray`, `source`, `archive`, `kind: build`, Task 5: Извлечение member из архива, Task 6: Опрос upstream — GitHub Releases, ghcr.io, Docker Hub (+15 more)

### Community 234 - "accepted_sha256"
Cohesion: 0.28
Nodes (7): accepted_caddy_pins(), accepted_sha256(), agent_component(), _state(), test_invalid_state_yields_only_the_pin(), test_missing_or_failed_state_yields_only_the_pin(), test_state_adds_the_agent_installed_hashes()

### Community 238 - "XrayError"
Cohesion: 0.07
Nodes (11): test_a_router_that_does_not_come_back_after_the_swap_is_recorded(), broken_start(), _atomic_write(), check_hop_reachable(), _free_port(), _fsync_directory(), _port_open(), _socket_open() (+3 more)

### Community 239 - "v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router"
Cohesion: 0.10
Nodes (24): Custom exits, quick settings and geodata (v0.8), Свои выходы, быстрые настройки и geodata (v0.8), 10. Лаборатория и гейт, 11. План работ (оценка), 12. Вопросы владельцу, 1. Цель, 2. Словарь, 3. Архитектурные решения (+16 more)

### Community 240 - "number"
Cohesion: 0.10
Nodes (45): Task 2: Счётчик клиентов в навигации, 2. Обзор и навигация (панель, только фронт), issueOnNode(), bytes(), localDateTime(), number(), paintClientsCount(), clientsCount() (+37 more)

### Community 241 - "i18n-strings.py"
Cohesion: 0.26
Nodes (7): _clean(), fragments(), main(), _read_string(), _read_template(), _scan_code(), _skip_comment()

### Community 242 - "status / resume / repair"
Cohesion: 0.33
Nodes (7): Ownership journal /var/lib/proxy-control/installer/state.json, status / resume / repair, uninstall and --purge-data, Журнал владения state.json, uninstall и --purge-data, Uninstalling, Удаление

### Community 243 - "CommandRunner"
Cohesion: 0.15
Nodes (4): CommandRunner, test_command_runner_reports_captured_stderr_for_failed_command(), test_compose_discovery_reports_unavailable_when_docker_is_not_installed(), test_compose_reconciliation_uses_declared_project_identity()

### Community 244 - "English"
Cohesion: 0.20
Nodes (9): Changes, Deployment and rollback, English, v0.14.0-beta.1 — совместное использование 443 и приёмка Naive, Validation scope, Изменения, Развёртывание и откат, Русский (+1 more)

### Community 245 - "TelemtError"
Cohesion: 0.07
Nodes (37): Где мы, confirm(), _existing(), ImportDecision, ImportResult, _integer(), inventory(), InventoryItem (+29 more)

### Community 246 - "TransactionEngine"
Cohesion: 0.15
Nodes (11): _canonical_json(), _checkpoint_data(), _evidence_to_dict(), _freeze(), _freeze_mapping(), _thaw(), TransactionCheckpoint, TransactionEngine (+3 more)

### Community 247 - "ipaddress"
Cohesion: 0.19
Nodes (5): _main(), _pump(), _read_target(), _reply(), Stub

### Community 248 - "template"
Cohesion: 0.33
Nodes (9): client(), failing_api(), sensitive_values(), template(), test_add_inbound_posts_the_pinned_contract_path_and_returns_the_id(), test_add_inbound_rejects_a_response_without_an_identifier(), test_api_failure_chain_never_carries_the_response_body(), test_api_failure_log_contains_no_cookie_uuid_password_or_private_key() (+1 more)

### Community 249 - "test_access_enforcement.py"
Cohesion: 0.18
Nodes (19): _drifted_report(), _enabled(), _local(), test_background_timer_expires_access_without_a_request(), test_drift_report_does_not_infer_node_runtime_from_central_clock(), test_lifespan_enforces_expired_local_access_before_serving(), test_local_clock_transition_enables_then_expires_without_request(), test_local_enable_cannot_bypass_suspension_or_expiry() (+11 more)

### Community 250 - ".enabled"
Cohesion: 0.05
Nodes (45): ADR 009: Lanes per client and chains through the fleet's relays, Consequences, Context, Decision, 10.1 Парк с нуля (центр + два узла), 10.2 Добавить узел в существующий парк, 10.3 Выдать доступ клиенту на другом узле, 10.4 Включить WARP для сервиса на узле (+37 more)

### Community 251 - "Рабочий протокол для AI-агентов"
Cohesion: 0.22
Nodes (9): Главное правило, Изолированная установка и реальные проверки, Обязательные проверки репозитория, Перед изменением, Правила, которые уже спасали от ложных отчётов, Правила отчёта, Проверка всех Compose-моделей и образов, Рабочий протокол для AI-агентов (+1 more)

### Community 252 - "test_client_links.py"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 253 - "English"
Cohesion: 0.18
Nodes (11): Added, Changed, English, Fixed, Upgrading from v1.0.0, v1.0.1 — любые версии компонентов, региональные geodata с автообновлением, Добавлено, Изменено (+3 more)

### Community 255 - "test_telemt_adapter_does_not_leak_secret_in_errors"
Cohesion: 0.25
Nodes (6): test_telemt_adapter_does_not_leak_secret_in_errors(), handler(), test_telemt_adapter_patches_limits_and_resets_quota(), handler(), test_telemt_adapter_reads_3425_quota_stats_route(), test_telemt_adapter_sends_auth_and_maps_envelope()

### Community 256 - "safe_extract_zip"
Cohesion: 0.25
Nodes (15): Task 2: Артефакт Xray в каталоге релиза и `safe_extract_zip`, _copy_zip_member(), MemberPin, safe_extract_zip(), _validate_zip_members(), _pins(), _sha(), test_safe_extract_zip_extracts_named_members_only() (+7 more)

### Community 257 - "Browser"
Cohesion: 0.15
Nodes (3): Task 3: Браузерный шаг «обзор на телефоне» в lab, test_overlapping_ticks_share_a_global_concurrency_limit_and_visit_every_node(), Browser

### Community 258 - ".step_05c_chains"
Cohesion: 0.12
Nodes (9): Task 12: Лаборатория — staging, `lab-host` с роутером, сценарии `router-*`, tier `router`, redact(), lane_built(), slot_learned(), warp_reachable(), settled(), settled(), settled() (+1 more)

### Community 259 - "CONTINUE HERE — v0.3 центральная панель"
Cohesion: 0.29
Nodes (6): CONTINUE HERE — v0.3 центральная панель, Гейт v0.3.0-beta.1 (2026-09-14 11:42–11:59 UTC, дерево `ade7fcc`, чистое — после трёх раундов фикс-волны), Действия владельца, Отложенные minor и out-of-scope наблюдения, Точка продолжения, Что дальше по ветке

### Community 260 - "SecurityHeadersMiddleware"
Cohesion: 0.33
Nodes (3): send(), SecurityHeadersMiddleware, secured_send()

### Community 261 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`, tree `841a086`, 2026-09-14), Installing, Live check (AMS_Z), Proxy Control v0.4.0-beta.1, Screenshots, Upgrading, What's new (+7 more)

### Community 262 - "planner.py"
Cohesion: 0.07
Nodes (22): _file_sha256(), _client_config_for(), _command_failure(), _download(), ensure_pinned_package(), _identity_from_entry(), NaivePaths, _sanitize_diagnostic() (+14 more)

### Community 264 - "test_routing_ui_contract.py"
Cohesion: 0.08
Nodes (9): _interpolations(), test_every_interpolated_value_from_the_api_is_escaped(), test_routing_card_forgets_the_previous_policy_before_it_paints(), test_routing_js_seam_fixes_of_v09(), test_routing_js_speaks_lanes_chains_and_the_relay(), test_routing_js_speaks_presets_exits_and_geodata(), test_routing_js_speaks_the_router(), test_routing_js_tells_the_operator_when_the_node_already_runs_the_policy() (+1 more)

### Community 266 - ".plan"
Cohesion: 0.33
Nodes (3): _encode_adjacent_routes(), _valid_adjacent_backend(), _validate_users()

### Community 269 - "NginxReloadRecovery"
Cohesion: 0.29
Nodes (3): NginxReloadRecovery, run(), test_a_reload_that_kills_nginx_is_recovered_and_reported()

### Community 270 - "ThreeXuiClient"
Cohesion: 0.13
Nodes (5): _default_api_factory(), _Sanitized, ThreeXuiClient, test_api_refuses_a_non_loopback_endpoint(), test_panel_client_uses_tls_and_pins_certificate_before_credentials()

### Community 271 - "Host"
Cohesion: 0.08
Nodes (10): Decision, Results — Mieru via the router (`mieru` ingress), Results — NaiveProxy via the router (`naive` ingress), Results — the router itself, Xray egress-router spike (v0.5, Task 32), Docker, Host, main() (+2 more)

### Community 273 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.14, v0.15.0-beta.1 — версия панели и обновления узлов из центра, Добавлено, Исправлено, Обновление с v0.12–v0.14 (+1 more)

### Community 274 - "Check"
Cohesion: 0.14
Nodes (9): UI, v0.3 — задачи после слияния (post-merge issues), Спека (follow-ups, не дефекты реализации), Стенд и приёмка, assert_secret_free(), walk(), mtproxy_secret(), Check (+1 more)

### Community 276 - "The Xray-router (v0.5): one dedicated egress router per node"
Cohesion: 0.18
Nodes (11): A third ingress: MTProxy (v1.1), Credentials and rotation, DNS and private destinations, Lanes, chains and the relay (v0.7), Limits and what is deferred, Operations, The runtime, The transaction (+3 more)

### Community 277 - "script"
Cohesion: 0.11
Nodes (11): script(), FakeConnection, FakeResponse, _panel(), serve(), test_api_refuses_an_oversized_response(), script(), test_login_fetches_a_csrf_token_and_sends_it() (+3 more)

### Community 278 - "compile"
Cohesion: 0.11
Nodes (42): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 14: Документация, ADR 007, CHANGELOG, VERSION, релизная заметка, Task 15: Гейт релиза на `ams-test` и точка продолжения, Task 3: Spike — Xray как egress-router на стенде (Task 32), Task 6: Панель — клиент роутера, `RouterTarget`, адаптер, wiring, Task 7: Routing IR — backend `xray_router`, `geosites/geoips`, миграция 15, компилятор (+34 more)

### Community 279 - "_panel_probe"
Cohesion: 0.25
Nodes (3): _panel_probe(), test_a_panel_that_answers_with_an_error_code_reports_that_code(), test_a_panel_that_cannot_be_reached_still_raises()

### Community 281 - "_await_panel_health"
Cohesion: 0.29
Nodes (3): _await_panel_health(), test_panel_acceptance_gives_up_and_reports_the_last_refusal(), test_panel_acceptance_waits_for_the_panel_instead_of_racing_it()

### Community 282 - "Xray-router (v0.5): один выделенный egress-роутер на узел"
Cohesion: 0.18
Nodes (11): DNS и приватные адреса, Xray-router (v0.5): один выделенный egress-роутер на узел, Ключи и ротация, Ограничения и что отложено, Полосы, цепи и relay (v0.7), Рантайм, Транзакция, Третий вход: MTProxy (v1.1) (+3 more)

### Community 283 - "test_subscription_events.py"
Cohesion: 0.12
Nodes (14): [1.0.3] - 2026-10-01, _events(), test_fetches_emit_with_their_status_and_misses_emit_nothing(), test_generation_change_emits_inside_the_transaction_or_not_at_all(), test_no_event_carries_a_token_a_link_or_a_delivery_claim(), test_revocation_and_rotation_emit_revoked_for_the_old_url(), test_the_bus_refuses_unknown_names_and_scrubs_payloads(), client_id() (+6 more)

### Community 284 - "Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext"
Cohesion: 0.14
Nodes (14): 10. Spike (Task 32) — что проверяется на стенде, 12. Backup/restore и матрица негативных тестов (Tasks 37, 39), 13. Лаборатория и гейт (Tasks 36, 40), 14. Документация и релиз (Task 41), 15. Отклонения от спеки vNext и решения, принятые за владельца, 1. Цель, 2. Паритет с 3x-ui, 3. Архитектурные решения (+6 more)

### Community 285 - "TelemtAdapter"
Cohesion: 0.02
Nodes (66): Runtime users (protocol routes), Task 4: Адаптеры — caller-supplied secret для Telemt и `update_options`, Task 6: Панель — клиенты менеджеров и адаптеры egress, AccessArtifact, AdapterError, applied_egress_from_view(), AppliedEgress, AppliedGrant (+58 more)

### Community 286 - "3. Что v0.6 добавляет"
Cohesion: 0.14
Nodes (11): 1. Цель, 2. Что уже доказано (не переделывается), 3.1 Матрица сверки — `docs/VERIFICATION_MATRIX.md` + `tests/fixtures/verification-matrix.json`, 3.2 Аудит маршрутов — `scripts/dev/route-coverage.py`, 3.3 Tier `ui` — `scripts/lab/ui-acceptance.py` (+ `remote-gate.sh ui`), 3.4 Бэкенд: дыры в лабораторном покрытии, 3.5 Живая проверка на AMS_Z (по разрешению владельца), 3. Что v0.6 добавляет (+3 more)

### Community 287 - "XrayRouterAdapter"
Cohesion: 0.11
Nodes (3): _command_failure(), XrayRouterAdapter, XrayRouterError

### Community 289 - "service_share_template"
Cohesion: 0.50
Nodes (3): 7. Fleet v2, _host(), service_share_template()

### Community 290 - "test_fleet.py"
Cohesion: 0.13
Nodes (15): Task 0: Spike — принимает ли пиннутый Telemt-форк caller-supplied `secret`, 12. Отклонения от Phase 5 спеки vNext, 3. Архитектурные решения, build_executor(), required(), secret(), LocalTelemtExecutor, RoutingExecutor (+7 more)

### Community 292 - "The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP"
Cohesion: 0.22
Nodes (9): Connecting, How to enable, Rotating the token and the key, Skills, The `confirm` rule, The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP, Turning it off, Verification (+1 more)

### Community 294 - "MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP"
Cohesion: 0.22
Nodes (9): MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP, Выключить, Как включить, Подключение, Правило `confirm`, Проверка, Ротация токена и ключа, Скиллы (+1 more)

### Community 295 - "Isolated Ubuntu 24.04 installer lab"
Cohesion: 0.04
Nodes (66): attest job, build-twice-and-compare job, draft-release job, lab-amd64 job, publish job, quality job, Release workflow, Tag, VERSION and manifest agreement check (+58 more)

### Community 296 - "6. Центр и узлы: привязка панелей"
Cohesion: 0.12
Nodes (15): 6.1 Порядок раскатки парка, 6.2 Подготовка узла, 6.3 Привязка: три действия на центре, 6.4 Импорт существующих пользователей узла, 6.5 Карточка узла и ежедневная проверка, 6.6 Отвязка, удаление, ротация ключа, 6. Центр и узлы: привязка панелей, CONTINUE HERE — v0.7 (цепи и полосы) (+7 more)

### Community 299 - "test_dashboard_ui_contract.py"
Cohesion: 0.14
Nodes (3): test_host_card_follows_the_host_while_the_overview_is_open(), test_overview_placeholder_has_the_overviews_own_shape(), test_panel_version_is_on_screen_for_every_role_and_on_a_phone()

### Community 300 - "router_credential_stale"
Cohesion: 0.12
Nodes (16): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.5.0-beta.1, Screenshots, Upgrading, What's new (+8 more)

### Community 302 - "CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)"
Cohesion: 0.40
Nodes (4): CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт), Сделано, Что дальше, Что оставлено на хостах

### Community 303 - "xray_router_manager/healthcheck.py"
Cohesion: 0.20
Nodes (8): test_healthcheck_relay_flags_post_and_get(), test_healthcheck_status_flag_prints_the_manager_status(), check(), main(), relay(), relay_enable(), _request(), status()

### Community 305 - "test_mieru_management.py"
Cohesion: 0.08
Nodes (12): check(), main(), main(), ManagerHTTPServer, _password(), request(), test_deleting_on_the_protocol_pages_takes_the_kept_grant_with_it(), test_manager_healthcheck_uses_authenticated_unix_health_endpoint() (+4 more)

### Community 306 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.15, v1.0.0 — первый стабильный выпуск: понятная маршрутизация, английский интерфейс, сохранённые ключи Mieru, Добавлено, Исправлено, Обновление с v0.12–v0.15 (+1 more)

### Community 307 - "ADR 003: One writer per resource"
Cohesion: 0.50
Nodes (4): ADR 003: One writer per resource, Consequences, Decision, Non-goals

### Community 309 - "test_xray_router_deployment.py"
Cohesion: 0.22
Nodes (7): render_compose(), run_state_preparer(), test_prepare_and_verify_state_directory(), test_router_overlay_gives_managers_their_ingress_and_the_panel_its_socket(), test_router_overlay_is_loopback_only_read_only_and_pinned(), test_router_overlay_without_mieru_still_renders(), test_state_preparer_refuses_bad_paths()

### Community 310 - "Журнал изменений"
Cohesion: 0.06
Nodes (34): [0.10.0-beta.1] - 2026-09-21, [0.11.0-beta.1] - 2026-09-22, [0.12.0-beta.1] - 2026-09-22, [0.13.0-beta.1] - 2026-09-23, [0.14.0-beta.1] - 2026-09-23, [0.15.0-beta.1] - 2026-09-23, [0.4.0-beta.1] - 2026-09-14, [0.6.0-beta.1] - 2026-09-17 (+26 more)

### Community 311 - "test_view_addressing_ui.py"
Cohesion: 0.21
Nodes (7): index_html(), main_js(), test_an_unknown_or_forbidden_view_falls_back_to_the_overview(), test_back_and_forward_move_between_views(), test_boot_opens_the_view_the_address_names(), test_every_menu_item_has_an_address(), test_navigation_writes_the_view_into_the_address()

### Community 312 - "rotate-xray-router-ingress.sh"
Cohesion: 0.27
Nodes (10): compose(), fail(), MIERU_MANAGER_UID, NAIVE_MANAGER_GID, NAIVE_MANAGER_UID, random_hex(), random_password(), ROUTER_GID (+2 more)

### Community 315 - "_DefaultXrayRouterRunner"
Cohesion: 0.07
Nodes (5): 3.6 Исправления, _DefaultXrayRouterRunner, XrayRouterPaths, test_the_real_runner_fetches_over_https_only(), test_the_real_runner_sees_only_the_router_compose_service()

### Community 317 - "Живая проверка (AMS_Z ↔ ams-test)"
Cohesion: 0.14
Nodes (14): English, Gate checklist (lab host `ams-test`, tree `ade7fcc`, 2026-09-14 — after the three rounds of the final-review fix wave), Installing, Proxy Control v0.3.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z ↔ ams-test) (+6 more)

### Community 319 - "TelemtIndeterminate"
Cohesion: 0.15
Nodes (13): TelemtIndeterminate, blocked_rotate(), test_create_double_indeterminate_propagates_raw_not_adapter_error(), create_user(), rotate(), anyio_backend(), _client(), telemt() (+5 more)

### Community 320 - "install-release.sh"
Cohesion: 0.52
Nodes (6): check_manifest(), fail(), requirements(), say(), install-release.sh script, usage()

### Community 321 - "prepare-xray-router-state.sh"
Cohesion: 0.43
Nodes (6): fail(), ROUTER_GID, ROUTER_MODE, ROUTER_UID, prepare-xray-router-state.sh script, verify_regular_file()

### Community 322 - "v0.10 — клиент на нескольких узлах и подписка под рукой"
Cohesion: 0.15
Nodes (13): 1. Цель, 3. API, 4. Реестр аудита и события, 5.1 Окно клиента, 5.2 Диалог «Новый клиент», 5.3 Диалог «Выдать доступ», 5.4 Экраны MTProxy / NaiveProxy / Mieru, 5. Интерфейс (+5 more)

### Community 323 - "test_client_import.py"
Cohesion: 0.18
Nodes (12): _render(), _seed(), test_a_locally_imported_mtproxy_user_renders_with_telemts_link_host(), test_a_username_the_runtime_already_uses_is_refused_before_anything_is_written(), test_adopt_batch_reports_what_it_could_not_take(), test_adopting_an_imported_grant_makes_it_renderable(), test_import_can_attach_to_an_existing_client(), test_import_is_idempotent_and_makes_no_manager_mutation() (+4 more)

### Community 324 - "Telemt MTProto data plane"
Cohesion: 0.40
Nodes (3): Private-network Caddy mask / cover site, Host Nginx stream/SNI router, Telemt MTProto data plane

### Community 325 - "ADR 002: Declarative immutable generations"
Cohesion: 0.40
Nodes (5): ADR 002: Declarative immutable generations, Consequences, Context, Decision, Non-goals

### Community 326 - "AccessGrant"
Cohesion: 0.03
Nodes (48): Context, Decision, Task 10: Lifecycle грантов (enable/disable/rotate/delete) для local и remote, Task 9: Pusher — heartbeat и доставка поколений, Узел (fleet_v2 node, local lifecycle), Что уже сделано (Tasks 0–14), Decision records, Goal of v0.2 (+40 more)

### Community 329 - "i18n.js"
Cohesion: 0.09
Nodes (30): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.6.0-beta.1, Screenshots, Upgrading, What the verification found (+22 more)

### Community 330 - "test_api_key_auth.py"
Cohesion: 0.46
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 335 - "panel"
Cohesion: 0.04
Nodes (45): English, Fresh install, Upgrading from v0.9 or v0.10, v0.11.0-beta.1 — обновления из upstream, What changed for you, Обновление с v0.9 или v0.10, Русский, Установка с нуля (+37 more)

### Community 336 - "manifest"
Cohesion: 0.17
Nodes (13): English, Installer fixes, Installing, Proxy Control v0.2.0-beta.1, Verified for this release (on the lab host), What is new, Исправлено в установщике, Проверено для этого выпуска (на стенде) (+5 more)

### Community 341 - "CDP"
Cohesion: 0.12
Nodes (12): Global Constraints, Task 0: Ветка, спека, план, Task 1: Инвентарь функций и матрица сверки (TDD: тест-страж первым), Task 2: Tier `ui` — драйвер и view без второй панели, Task 3: Tier `ui` — центр (вторая панель) и Fleet-экраны, Task 4: Дыры бэкенда, Task 5: Живая проверка AMS_Z, Task 6: Релиз (+4 more)

### Community 345 - "pytest"
Cohesion: 0.06
Nodes (15): test_fingerprint_private_address_requires_explicit_opt_in(), test_fingerprint_request_deadline_also_bounds_slow_system_dns(), test_link_rejects_bad_key_private_url_and_self(), run(), test_diff_creates_enables_and_disables_from_ticks(), test_render_marks_cells_and_disables_what_cannot_change(), test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants(), test_settling_is_true_while_a_node_has_not_confirmed_and_ignores_deleted_grants() (+7 more)

### Community 346 - "test_clients_filters_ui.py"
Cohesion: 0.39
Nodes (5): _node(), test_import_still_offers_clients_outside_the_current_page(), test_paging_and_server_search_keep_the_dom_bounded_and_discard_stale_responses(), test_search_and_filters_select_the_right_clients(), test_the_card_lists_clickable_grant_rows_and_escapes_names()

### Community 347 - "json"
Cohesion: 0.05
Nodes (9): check(), main(), account_url(), ManagerNotFound, leaf_fingerprint(), rows(), test_no_gap_survives_the_release_gate(), probe_trace() (+1 more)

### Community 348 - "Verification matrix — maintained functions and their proofs"
Cohesion: 0.22
Nodes (9): backend, clients, fleet, installer, release, router, routing, ui (+1 more)

### Community 349 - "verification-matrix.py"
Cohesion: 0.43
Nodes (4): load(), main(), proof_problem(), render()

### Community 350 - "English"
Cohesion: 0.18
Nodes (11): Added, Changed, English, Fixed, Upgrading from v1.0.1, v1.0.2 — окно доступа, поиск и фильтры клиентов, аккуратная вёрстка, Добавлено, Изменено (+3 more)

### Community 351 - "test_update_host.py"
Cohesion: 0.14
Nodes (18): Agent, host(), _run(), _serve(), _answer(), do_GET(), do_POST(), get_request() (+10 more)

### Community 352 - "CONTINUE HERE — v0.6 сверка функций v0.2–v0.5"
Cohesion: 0.22
Nodes (8): CONTINUE HERE — v0.6 сверка функций v0.2–v0.5, Где мы, Гейт (финальное дерево) и живая проверка, Известные ограничения/решения, Публикация (сделано 2026-09-17 11:18–11:30 UTC), Что дальше (владелец), Что сделано (коммиты по порядку), test_every_route_and_every_view_has_a_row()

### Community 357 - ".install"
Cohesion: 0.10
Nodes (10): 4.1 Требования к хосту, 4.2 Скачать и проверить релиз (без root), 4.3 Мастер: вопросы по порядку, 4.4 План и digest, 4.6 Приёмка, отчёты, где пароли, 4.7 Первые действия в панели, 4.8 Повторный запуск, resume, repair, uninstall, 4. Автоматическое развёртывание узла (+2 more)

### Community 358 - "Protocol acceptance"
Cohesion: 0.08
Nodes (40): Acceptance per protocol, certificates adapter, Core acceptance evidence, core adapter, firewall adapter, Mieru acceptance evidence, mieru adapter, NaiveProxy acceptance evidence (+32 more)

### Community 370 - "AgentJournal"
Cohesion: 0.12
Nodes (7): Executor, AgentJournal, command_envelope(), test_agent_journal_prevents_reexecution_after_restart_and_rejects_sequence_gap(), test_concurrent_duplicate_does_not_corrupt_inflight_execution(), test_expired_command_advances_node_sequence_without_executing_mutation(), test_node_journal_does_not_retry_removed_mieru_outbox()

### Community 376 - "ADR 004: Client, AccessGrant and subscription as a projection"
Cohesion: 0.50
Nodes (4): ADR 004: Client, AccessGrant and subscription as a projection, Consequences, Context, Non-goals

### Community 377 - "v1.1 — маршрутизация MTProxy через Xray-router"
Cohesion: 0.15
Nodes (12): 1. Цель, 2. Что доказано на стенде (ams-test, 2026-10-01), 3. Топология, 4. Xray-router (менеджер), 5. Мост `xray-router-ingress`, 6. Панель, 7. Установщик, 7a. Обновление одной командой (добавлено владельцем 2026-10-01) (+4 more)

### Community 389 - "test_docker_lab.py"
Cohesion: 0.07
Nodes (5): ContainerImageTests, ContainerInputTests, ContainerScenarioTests, DockerAvailableTests, RecordedRunTests

### Community 394 - "Исправления по аудиту v1.1.0"
Cohesion: 0.25
Nodes (7): Исправления по аудиту v1.1.0, Исходные доказательства, Контрольная точка кандидата (2026-10-02), Незавершённые проверки и ограничения, Последовательность, Следующие улучшения за пределами исправлений, Соответствие исходным находкам

### Community 400 - "ADR 005: Secrets travel as references"
Cohesion: 0.40
Nodes (5): ADR 005: Secrets travel as references, Consequences, Context, Decision, Non-goals

### Community 405 - "test_socks5_stub.py"
Cohesion: 0.11
Nodes (15): Task 14: Лаборатория на стенде — `fleet-acceptance.py` и tier `fleet`, Task 2: Spike — нативные возможности Caddy forwardproxy и mita (Task 30), core_checks(), fetch(), _ip_through(), main(), _run(), _socks5_udp_dns() (+7 more)

### Community 411 - "English"
Cohesion: 0.22
Nodes (9): Added, Changed, English, Upgrading from v1.0.3, v1.1.0 — маршрутизация MTProxy через Xray-router, Добавлено, Изменено, Обновление с v1.0.3 (+1 more)

### Community 412 - "test_fetch_reports_the_hop_that_names_the_release"
Cohesion: 0.20
Nodes (4): test_fetch_reports_the_hop_that_names_the_release(), build_opener(), fetch(), redirect_request()

### Community 413 - "Interactive Release Installer Implementation Plan"
Cohesion: 0.10
Nodes (19): README dependency surface list, Interactive Release Installer Implementation Plan, MieruAdapter / MieruPaths / MieruAcceptance, Operator requirements recorded 2026-09-04, release/sbom.py SPDX generation, ReleaseManifest / ExternalArtifact.for_platform, Optional warp_routing action, WARP SOCKS5 endpoint 127.0.0.1:45000 (+11 more)

### Community 421 - "update-host.sh"
Cohesion: 0.46
Nodes (7): agent(), fail(), has(), health(), json(), say(), update-host.sh script

### Community 430 - "test_vnext_characterization.py"
Cohesion: 0.23
Nodes (10): validate_inventory(), validate_payload(), validate_result(), _walk_secret_free(), _csrf(), test_every_protocol_access_is_re_revealable(), test_fleet_v1_rejects_secret_bearing_payload(), test_fleet_v1_rejects_secret_bearing_result() (+2 more)

### Community 435 - "ADR 007: Routing enforcement ownership"
Cohesion: 0.67
Nodes (3): ADR 007: Routing enforcement ownership, Context, Decision

## Ambiguous Edges - Review These
- `Beam vs Hammer Clash Metaphor` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: rationale_for
- `Proxy Control Repository Branding Asset` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: conceptually_related_to
- `WARP as one loopback SOCKS5 endpoint` → `WARP as one SOCKS5 endpoint 127.0.0.1:40000`  [AMBIGUOUS]
  CHANGELOG.md · relation: semantically_similar_to

## Knowledge Gaps
- **674 isolated node(s):** `telemt-entrypoint.sh script`, `install.sh script`, `entrypoint.sh script`, `TELEMT_API_TOKEN_FILE`, `API_REASONS` (+669 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 3574 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **85 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Beam vs Hammer Clash Metaphor` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: rationale_for) - confidence is low._
- **What is the exact relationship between `Proxy Control Repository Branding Asset` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `WARP as one loopback SOCKS5 endpoint` and `WARP as one SOCKS5 endpoint 127.0.0.1:40000`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **Why does `Proxy Control documentation index` connect `Proxy Control documentation index` to `Panel version-agent`, `Troubleshooting Proxy Control`, `Proxy Control`, `Панель управления Proxy Control`, `Sharing Mieru configurations`, `Interactive release installer`, `Управление Mieru / mita 3.35–3.36`, `Accounting semantics`, `Proxy Control v0.1.0 Beta`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `vNext architecture (v0.2 and v0.3)` connect `AccessGrant` to `manifest`, `Proxy Control documentation index`, `test_routing_fleet_chains.py`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `Матрица негативных и security-тестов vNext (Task 39)` connect `Матрица негативных и security-тестов vNext (Task 39)` to `safe_extract_zip`, `PolicyInput`, `Scenario`, `test_fleet_v2_reconcile.py`, `test_naive_manager_egress.py`, `test_fleet_acceptance_script.py`, `NodeClient`, `TypedCommand`, `script`, `compile`, `test_installer_transaction.py`, `EgressInvalid`, `Proxy Control documentation index`, `test_routing_fleet_chains.py`, `test_fleet_v2_pusher.py`, `ReleaseManifest`, `test_rbac_audit.py`, `test_mieru_manager.py`, `test_subscription_renderers.py`, `naive_manager/egress.py`, `test_installer_release.py`, `FleetStore`, `render_config`, `DeployCliTests`, `test_fleet_v2_post_merge.py`, `test_users_adapter_ui.py`, `test_routing_router_service.py`, `test_agent_client_retries_result_from_durable_outbox_without_reexecution`, `test_subscription_http.py`, `document_digest`, `test_grant_lifecycle.py`, `Database`, `pytest`, `test_mieru_egress.py`, `test_installer_xray_router.py`, `TelemtError`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `Action` (e.g. with `Adapter` and `CoreAdapter`) actually correct?**
  _`Action` has 38 INFERRED edges - model-reasoned connections that need verification._