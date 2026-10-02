# Graph Report - audit-hardening  (2026-10-02)

## Corpus Check
- 540 files · ~1,112,600 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 40 file(s) not represented in the graph (top: (none) 14, .service 8, .conf 5)

## Summary
- 12621 nodes · 36212 edges · 417 communities (305 shown, 112 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 3882 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `361072e3`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CommandRunner
- release.py
- TrafficCollector
- _DefaultMieruRunner
- MieruAdapter
- installer/cli.py
- Scenario
- NaiveCredentialManager
- Proxy Control
- NaiveAdapter
- Панель управления Proxy Control
- ThreeXuiAdapter
- Sharing Mieru configurations
- test_installer_mieru.py
- TerminalWizard
- parse_config
- test_installer_naive.py
- test_fleet_v2_post_merge.py
- install-bootstrap
- .stage
- Task 16: Reproducible release builder and GitHub workflow
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
- test_proxyctl_runtime.py
- Proxy Control documentation index
- test_routing_fleet_chains.py
- GrantIntent
- Planned File Structure
- test_mieru_manager.py
- naive_manager/egress.py
- test_release_build.py
- vNext v0.2 local control plane implementation plan
- Keyring
- qemu_lab.py
- test_installer_release.py
- test_installer_docs.py
- Action
- render_config
- TopologyError
- test_installer_fresh_host.py
- Dedicated Proxy-Control-owned xray-router
- bridge.py
- test_mieru_deployment.py
- RoutingService
- CentralProcess
- build.py
- CoreError
- test_naive_acceptance_tunnels_a_real_inner_tls_session
- Troubleshooting Proxy Control
- app.py
- DeployCliTests
- _DefaultNaiveRunner
- MieruManager
- test_users_adapter_ui.py
- VersionAgent
- test_installer_warp_transaction_recovery.py
- esc
- guest-runner.sh
- config
- Матрица негативных и security-тестов vNext (Task 39)
- test_installer_mcp.py
- routing-spike.py
- GeodataStore
- proxyctl.py
- test_proxyctl_transactions.py
- DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)
- test_naive_management.py
- test_routing_service.py
- CoreAdapter
- test_routing_lanes_routes.py
- full_config
- test_version_agent_upstream.py
- prepare-naive-state.py
- routing/service.py
- test_panel_entrypoint.py
- test_version_agent_server.py
- Store
- 3x-ui mode: managed-new
- register_routing_routes
- test_dns_is_checked_again_for_each_connection_and_only_numeric_ip_is_dialed
- core_checks
- CertificateAuthority
- compile
- panel
- test_fleet_v2_client.py
- Task 6: Encrypted secret versions and master key
- QuotaEnforcer
- _DefaultCoreRunner
- MemoryTelemt
- WarpAdapter
- createSubscriptionDialog
- FleetPusher
- Path
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
- access.js
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
- Interactive Release Installer Design
- CorePaths
- create_app
- EgressInvalid
- test_xray_router_mtproxy.py
- Trust Boundaries
- test_three_xui_api.py
- guest-runner.sh script
- MemoryXrayRouter
- ReleaseMatrixTests
- Proxy Control Cover Art
- route-coverage.py
- NaiveClient
- run_captured
- Task 1: ADRs and v0.2 architecture record
- Proxy Control v0.3 — центральная панель и подключённые панели
- ReleaseManifest
- mieru-client/probe.py
- Промпт для продолжения работы в новом контексте
- test_ui_browser_findings.py
- test_route_coverage.py
- container_cmd
- installer_cmd
- prepare_mieru_token.py
- Task 3: release v0.1.0 through CI
- Карта файлов
- container_setup
- FleetStore
- ProvisioningService
- tools.py
- Rule: verify the open port, not the panel record
- ingress_upgrade.py
- client_probe
- test_mtproxy_respq_probe.py
- test_version_agent_panel.py
- 4. Автоматическое развёртывание узла
- check-js-syntax.sh
- BoundedBodyMiddleware
- probe/install.sh
- test_installer_three_xui.py
- Private Vulnerability Reporting Path
- test_proxyctl.py
- .compose
- upstream
- test_routing_router_service.py
- RuntimeRunner
- MieruClient
- MemoryNaive
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
- Diagnosing a client's access
- Screenshot Sanitization Policy
- telemt-entrypoint.sh
- install.sh
- Database
- Panel dev/test toolchain (pytest, ruff)
- check-deployment.sh
- check-naive-caddy-build.sh
- three-xui-existing.sh
- UpdateError
- test_installer_chains.py
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
- common.js
- i18n-strings.py
- routes.py
- CommandRunner
- English
- test_fleet_v2_node_api.py
- InstallPlan
- ipaddress
- Xray egress-router spike (v0.5, Task 32)
- test_access_enforcement.py
- Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация
- Рабочий протокол для AI-агентов
- test_client_links.py
- English
- SequentialSecrets
- ArtifactPin
- safe_extract_zip
- Browser
- .step_05c_chains
- EgressConfig
- SecurityHeadersMiddleware
- English
- NaivePaths
- test_managed_provision_actually_applies_warp_and_subscription
- test_routing_ui_contract.py
- ThreeXuiPaths
- ADR 008: Panel-to-panel transport with scoped API keys
- ManagedClient
- 8.2 Локальный узел
- ThreeXuiClient
- Host
- register_node_routes
- English
- Check
- TelemtClient
- The Xray-router (v0.5): one dedicated egress router per node
- script
- test_xray_routing_compiler.py
- _panel_probe
- Ownership boundaries and adapter order
- _await_panel_health
- Xray-router (v0.5): один выделенный egress-роутер на узел
- test_subscription_http.py
- Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext
- TelemtAdapter
- dashboard
- XrayRouterAdapter
- test_management_ui_contract.py
- proxy-control-lab-clients Compose project
- test_fleet.py
- Api
- The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP
- vNext capability matrix
- MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP
- Isolated Ubuntu 24.04 installer lab
- 6. Центр и узлы: привязка панелей
- naive_manager/healthcheck.py
- .__init__
- test_dashboard_ui_contract.py
- English
- Granting access to a client
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
- _preparer
- Живая проверка (AMS_Z ↔ ams-test)
- test_telemt_recovery.py
- install-release.sh
- prepare-xray-router-state.sh
- v0.10 — клиент на нескольких узлах и подписка под рукой
- test_client_import.py
- Telemt MTProto data plane
- ADR 002: Declarative immutable generations
- AccessGrant
- ._compose_start
- test_compose_runs_to_completion_not_through_diagnostic_capture
- i18n.js
- test_api_key_auth.py
- test_fleet_v2_central_routes.py
- English
- English
- .view_central
- test_mieru_replanning_accepts_ports_its_own_server_already_holds
- Структура файлов
- ManagerHandler
- English
- test_placement_ui_contract.py
- test_clients_filters_ui.py
- json
- Verification matrix — maintained functions and their proofs
- verification-matrix.py
- English
- test_update_host.py
- CONTINUE HERE — v0.6 сверка функций v0.2–v0.5
- https_probe
- ReleaseFixtureTests
- RuntimeInstaller
- Accounting semantics
- test_a_download_that_does_not_match_its_pin_is_discarded
- Api
- ContainerImageTests
- DockerAvailableTests
- GuestRunnerPreflightScripts
- ReleaseRootLayout
- ReleaseConfigMatchesItsFixture
- ContainerInputTests
- RecordedRunTests
- CDP
- AgentJournal
- LabDiagnostics
- ReleaseArtifactTests
- test_routing_routes.py
- test_a_failed_core_command_names_the_command_that_failed
- ADR 004: Client, AccessGrant and subscription as a projection
- v1.1 — маршрутизация MTProxy через Xray-router
- test_a_failed_core_command_never_echoes_a_credential
- _deploy_hook_text
- test_compose_builds_the_images_from_the_release_it_installs
- ArtifactError
- _command_failure
- test_naive_bootstrap_log_matches_the_manager_accounting_writer
- config
- test_the_shared_core_project_is_not_mistaken_for_naive_resources
- ContainerScenarioTests
- test_mieru_acceptance_deletes_with_a_compare_and_set_revision
- _sanitize_diagnostic
- ADR 009: Lanes per client and chains through the fleet's relays
- Исправления по аудиту v1.1.0
- test_the_release_manifest_pins_x86_64_only
- test_a_failed_identity_lookup_is_not_a_collision
- ADR 005: Secrets travel as references
- RenderedNaive
- test_socks5_stub.py
- English
- test_fetch_reports_the_hop_that_names_the_release
- remote-gate.sh
- SecretGenerator
- FakePanel
- update-host.sh
- test_rbac_audit.py
- Handler
- warp_routing
- ProtocolError
- RenderedCore
- FakeClock
- ADR 007: Routing enforcement ownership
- full_config

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

## Communities (417 total, 112 thin omitted)

### Community 0 - "CommandRunner"
Cohesion: 0.05
Nodes (74): _applicable_caa(), audit_host(), _audit_host(), AuditError, _bounded_execute(), _bounded_resolve(), _caa_compatible(), _certificate_fact() (+66 more)

### Community 1 - "release.py"
Cohesion: 0.10
Nodes (47): _best_effort_remove_tree_at(), _copy_regular_member(), _copy_verified_archive(), _create_private_stage(), _decode_bounded_tar(), _destination_identity(), _DestinationAnchor, _digest_open_file() (+39 more)

### Community 2 - "TrafficCollector"
Cohesion: 0.05
Nodes (43): build_manager(), _assert_safe_parent_chain(), _Candidate, _now(), TrafficCollector, collector(), record(), test_active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() (+35 more)

### Community 3 - "_DefaultMieruRunner"
Cohesion: 0.07
Nodes (9): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _client_config_for(), _DefaultMieruRunner, MieruAcceptance, _require_acceptance(), test_real_mieru_runner_recognizes_existing_named_system_group() (+1 more)

### Community 4 - "MieruAdapter"
Cohesion: 0.07
Nodes (6): _command_failure(), _decode_transports(), MieruAdapter, MieruError, _validate_ownership_mapping(), test_compose_failure_retains_bounded_sanitized_diagnostics()

### Community 5 - "installer/cli.py"
Cohesion: 0.08
Nodes (28): _adopt_legacy_if_needed(), _automated_install(), _bounded_error(), _bounded_text(), CliError, plan(), main(), _plan_from_path() (+20 more)

### Community 6 - "Scenario"
Cohesion: 0.12
Nodes (3): describe_artifact(), Scenario, adopted()

### Community 7 - "NaiveCredentialManager"
Cohesion: 0.05
Nodes (20): Task 4: naive-manager — egress API (Task 29a), 6. Egress API менеджеров (Task 29), _assert_regular(), _assert_safe_parent_chain(), _atomic_write(), _durable_mkdir(), _durable_unlink(), _fsync_directory() (+12 more)

### Community 8 - "Proxy Control"
Cohesion: 0.04
Nodes (83): In-lab verification checklist, Documentation contract runs every documented command through the CLI parser, Pinned external artifacts catalog release/external-artifacts.json, Fleet v1 Telemt-only, Profiles and adapters (packages, nginx, certificates, firewall, core, naive, mieru, three_xui), Naive site on port-only address with probe resistance, Per-protocol acceptance with real clients, Release acceptance lab (container and bare metal) (+75 more)

### Community 9 - "NaiveAdapter"
Cohesion: 0.08
Nodes (3): NaiveAdapter, NaiveError, _validate_ownership_mapping()

### Community 10 - "Панель управления Proxy Control"
Cohesion: 0.04
Nodes (104): Synthetic Compose render inputs, Busy buttons: capture event.currentTarget before finally, Client-specific Native/Karing/manual reveals, Host resource card via version-agent GET /v1/host, Generation-specific Karing profile name after rotation, Former host/systemd MTProxy install scripts removed, Atomic SQLite login-attempt reservation before Argon2, Complete mieru-client.json in Native reveal (+96 more)

### Community 11 - "ThreeXuiAdapter"
Cohesion: 0.04
Nodes (14): ArtifactError, _client_count(), _DefaultThreeXuiRunner, _plain_audit(), _safe_text(), _tags(), ThreeXuiAdapter, ThreeXuiAudit (+6 more)

### Community 12 - "Sharing Mieru configurations"
Cohesion: 0.06
Nodes (55): Cache-Control: no-store reveal response, Client matrix, Create access flow, Dialog closed too early, Ephemeral reveal dialog, Karing URL scheme documentation, Karing install-config deep link, mieru import config command (+47 more)

### Community 13 - "test_installer_mieru.py"
Cohesion: 0.08
Nodes (51): ArtifactError, adapter(), applied(), artifact_action(), fake_deb(), FakeMieruRunner, host(), stage_client_package() (+43 more)

### Community 14 - "TerminalWizard"
Cohesion: 0.09
Nodes (15): text(), _domain(), EditField, _email(), _optional(), pinned_version(), PromptValidationError, ReviewAction (+7 more)

### Community 15 - "parse_config"
Cohesion: 0.06
Nodes (76): _as_dict(), _boolean(), ConfigError, _domain(), _domains(), _enum(), _integer(), _keys() (+68 more)

### Community 16 - "test_installer_naive.py"
Cohesion: 0.11
Nodes (42): adapter(), applied(), FakeNaiveRunner, host(), naive_action(), _router_config(), _stage_router_secret(), test_naive_acceptance_requires_closed_connect_accounting() (+34 more)

### Community 17 - "test_fleet_v2_post_merge.py"
Cohesion: 0.02
Nodes (88): 6.5 Карточка узла и ежедневная проверка, Task 8: Связи с узлами — миграция, `NodeLinkService`, `DesiredStore`, компиляция поколений, 6. Центр, _refusal(), register_fleet_v2_central_routes(), _linked(), node_auth_failed(), node_fingerprint() (+80 more)

### Community 18 - "install-bootstrap"
Cohesion: 0.04
Nodes (74): report.json public acceptance report, Installer CLI commands, Commands, Configuration file, credentials/handoff.json, Fleet v1 Telemt-only limit, Hard stops, host_mode (fresh | coexist) (+66 more)

### Community 20 - "Task 16: Reproducible release builder and GitHub workflow"
Cohesion: 0.09
Nodes (37): README dependency surface list, Global Constraints, docs/INSTALLER_REFERENCE.ru.md / .en.md, tests/lab/clients/compose.yaml protocol clients, Operator requirements recorded 2026-09-04, QEMU lab modes release-amd64 / release-arm64, release/build.py reproducible builder, Release-readiness commit v0.1.0 (+29 more)

### Community 21 - "MemoryMieru"
Cohesion: 0.13
Nodes (3): MemoryMieru, MieruError, test_memory_mieru_replays_a_caller_credential_and_refuses_a_generated_one()

### Community 22 - "test_installer_transaction.py"
Cohesion: 0.08
Nodes (50): import_runtime_v2(), OwnershipError, TransactionBusyError, TransactionStore, RuntimePlan, action_for(), engine_for(), InjectedCrash (+42 more)

### Community 23 - "Управление Mieru / mita 3.35–3.36"
Cohesion: 0.07
Nodes (45): Opt-in systemd Mieru TCP MSS clamp, Pinned mita 3.36.x admitted alongside 3.35.x, Next integrations: Panel/Naive, Mieru, Fleet, Следующие интеграции, First valid generation before the hardened mita unit, Full-snapshot CAS config transactions with journal v3 HMAC, compose.mieru.yaml overlay, MIERU_MITA_SHA256 executable digest gate (+37 more)

### Community 24 - "test_installer_nginx.py"
Cohesion: 0.08
Nodes (52): _certificate_groups(), ensure_stream_context(), NginxAdapter, DomainConfig, HostMode, config(), facts(), FreshExecutor (+44 more)

### Community 25 - "query"
Cohesion: 0.09
Nodes (50): [0.7.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Исправлено (после v0.6, в ветке до этого тега), 6.1 Модель (`panel/routing/models.py`, схема базы 16), 6.2 Сервис маршрутизации и цели, 6.3 Экран «Маршрутизация и цепи» (+42 more)

### Community 26 - "test_naive_manager.py"
Cohesion: 0.05
Nodes (71): ManagerHTTPServer, ManagerRecoveryError, _bootstrapped(), Hooks, manager(), test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), test_adapted_semantic_drift_makes_health_unready(), test_additional_basic_auth_outside_managed_block_makes_health_unready() (+63 more)

### Community 27 - "test_installer_wizard.py"
Cohesion: 0.10
Nodes (24): load_config(), TerminalIO, WizardSaved, _run_cli_in_pty(), _scripted(), test_a_typed_panel_password_is_saved_privately_and_never_in_the_config(), test_an_invalid_configuration_says_why(), test_blank_passwords_leave_no_credentials_file_behind() (+16 more)

### Community 28 - "firewall.py"
Cohesion: 0.12
Nodes (30): _action_enable(), _action_ipv6_enabled(), _action_rules(), _action_ssh_port(), _assert_foreign_preserved(), _assert_owned_rules_recognized(), _assert_ssh_preserved(), _canonical_source() (+22 more)

### Community 29 - "test_installer_credentials.py"
Cohesion: 0.10
Nodes (23): _anchor(), CredentialError, credentials_path(), discard_staged_credentials(), OperatorCredentials, read_credentials(), stage_credentials(), stage_operator_credentials() (+15 more)

### Community 30 - "AuditFacts"
Cohesion: 0.09
Nodes (39): _encode_transports(), _assert_secret_free(), AuditFacts, build_plan(), _canonical_fact_value(), _canonical_json_value(), _freeze(), _nonempty() (+31 more)

### Community 32 - "test_xray_router_geodata.py"
Cohesion: 0.08
Nodes (34): _clocked(), _field(), geodata_file(), _loyal(), _old_meta(), test_a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays(), test_automatic_updates_run_at_the_interval_from_the_watchdog(), test_block_document_still_applies_after_an_update() (+26 more)

### Community 33 - "test_proxyctl_runtime.py"
Cohesion: 0.10
Nodes (24): FakeRunner, plan(), runtime_root(), test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(), test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps(), run(), test_failed_install_rollback_is_retried_before_reinstall(), test_generated_acme_and_panel_sites_pass_native_nginx_syntax_check() (+16 more)

### Community 34 - "Proxy Control documentation index"
Cohesion: 0.06
Nodes (51): Changelog, Transactional release installer with durable journal, 1.0.0 — initial MTProxy release (2026-02-11), 1.1.0 — Fake TLS and hardening (2026-02-21), 1.2.0 — legacy installer fixes (2026-02-22), 1.3.0 — legacy MTProxy installer (2026-08-11), Развёртывание MTProto за Nginx SNI (RU), Backup and restore contract (EN) (+43 more)

### Community 35 - "test_routing_fleet_chains.py"
Cohesion: 0.02
Nodes (115): Task 13: Документация, миграционные заметки, версия, Task 15: Живая проверка AMS_Z ↔ ams-test (разрешение владельца от 2026-09-11), Task 16: Релизный гейт v0.3.0-beta.1, Task 1: Идентичность панели и API-ключи (хранилище), Task 3: Протокол поколений и хранилище узла, Task 5: Reconciler узла, Task 6: Fleet API v2 узла и защита ресурсов центра, Task 7: `NodeClient` — HTTP-клиент центра к узлу (+107 more)

### Community 36 - "GrantIntent"
Cohesion: 0.02
Nodes (133): confirm(), _existing(), ImportDecision, ImportResult, _integer(), inventory(), InventoryItem, _mieru_options() (+125 more)

### Community 37 - "Planned File Structure"
Cohesion: 0.08
Nodes (38): audit_host -> AuditFacts, AuditFacts, parse_config / render_config / load_config, examples/installer/*.toml, Full profile order, import_runtime_v2 legacy importer, installer.cli main (wizard/plan/install/status/repair/uninstall/upgrade), InstallerConfig (frozen dataclass) (+30 more)

### Community 38 - "test_mieru_manager.py"
Cohesion: 0.07
Nodes (45): _authenticate_journal(), FakeMita, manager(), MergingMita, _process_running(), RecoveryMita, _service(), _status_cli() (+37 more)

### Community 39 - "naive_manager/egress.py"
Cohesion: 0.07
Nodes (39): Task 1: Fix-wave — отложенные замечания v0.4, block_lines(), canonical(), check_reachable(), document_digest(), EgressInvalid, forward_proxy_bounds(), _indent() (+31 more)

### Community 40 - "test_release_build.py"
Cohesion: 0.10
Nodes (28): build(), checkout_with_private_files(), clean_checkout(), git(), gzip_rewrap(), _run_published_script(), sha256(), tar_names() (+20 more)

### Community 41 - "vNext v0.2 local control plane implementation plan"
Cohesion: 0.08
Nodes (38): ADR 004: Client / AccessGrant / subscription, Disposable lab host ams-test, tests/fixtures/vnext-capabilities.json (4 protocols x 23 capabilities), Audit finding 2: Panel vhost is rendered in two places, Audit finding 3: uvicorn writes an access log to container stdout, Audit finding 6: Credential re-reveal differs per protocol, Audit finding 10: UI is ES modules without a bundler, Audit finding 11: Fleet tables and the reserved local node (+30 more)

### Community 42 - "Keyring"
Cohesion: 0.03
Nodes (60): Task 9: Fleet v2 — возможности, секция `relay`, полосы в поколении, Global Constraints, Self-review, Task 10: Документация выпуска и VERSION, Task 11: Гейт на ams-test и живая проверка AMS_Z → ams-test, Task 2: Escrow при выдаче, гашение при ротации/отзыве, `reveal_token`, Task 4: Подписка выдаётся вместе с клиентом, Task 5: Аудит и документация модели (ADR 004, OPERATIONS) (+52 more)

### Community 43 - "qemu_lab.py"
Cohesion: 0.10
Nodes (29): acceleration(), allocate_port(), _archive(), cleanup(), finalize_results(), full_egress_policy(), guest_remote(), junit_xml() (+21 more)

### Community 44 - "test_installer_release.py"
Cohesion: 0.17
Nodes (33): ArchiveEntry, ArchiveManifest, _manifest_data(), safe_extract_tar(), _stage_paths(), _tar(), test_archive_digest_is_verified_before_tar_processing(), test_archive_path_swap_cannot_change_verified_bytes() (+25 more)

### Community 45 - "test_installer_docs.py"
Cohesion: 0.08
Nodes (27): _parser(), checked_commands(), documented_files(), install_steps(), install_text(), python_requirements(), readme(), reference() (+19 more)

### Community 46 - "Action"
Cohesion: 0.06
Nodes (28): Adapter, _action_packages(), _assert_added_unchanged(), _assert_preexisting_unchanged(), _checkpoint_packages(), PackageError, PackagesAdapter, _version_mapping() (+20 more)

### Community 47 - "render_config"
Cohesion: 0.10
Nodes (31): test_render_without_an_mtproxy_ingress_is_unchanged(), _intent(), test_generation_digest_changes_with_credentials_and_redact_hides_accounts(), test_redact_masks_relay_and_chain_secrets_too(), test_render_bypass_private_precedes_every_rule_per_tag(), test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous(), test_render_default_egress_warp_needs_warp_url(), test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() (+23 more)

### Community 48 - "TopologyError"
Cohesion: 0.05
Nodes (57): _action_specification(), _address_facts(), _certificate_action(), _certificate_checkpoint(), _certificate_sans(), _certificate_vhost_path(), _checkpoint_identity(), _client_ip_backend() (+49 more)

### Community 49 - "test_installer_fresh_host.py"
Cohesion: 0.09
Nodes (54): FirewallAdapter, CertificatePlan, test_renewal_does_not_retry_a_real_acme_failure(), test_renewal_retries_deactivated_authorization_race_without_hiding_errors(), test_renewal_retries_the_order_not_ready_race_once(), test_renewal_reuses_only_same_process_same_lineage_evidence(), canonical_ufw(), CertRunner (+46 more)

### Community 50 - "Dedicated Proxy-Control-owned xray-router"
Cohesion: 0.09
Nodes (35): ADR 006: routing policy IR, ADR 007: routing enforcement ownership, v0.4 acceptance criteria, v0.5 acceptance criteria, CompiledRoutingGeneration (policy_revision, backend_id, compiler/runtime versions, binary/geodata/config digests), EgressProvider (direct | warp | socks | xray-router), EnforcementBackend (native | os-isolation | xray-router; fallback fail-closed | explicitly-approved-direct), Immutable management/control bypass (+27 more)

### Community 51 - "bridge.py"
Cohesion: 0.08
Nodes (28): bridge_env(), _credential(), _fake_router(), handle(), _run(), _socks(), test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways(), scenario() (+20 more)

### Community 52 - "test_mieru_deployment.py"
Cohesion: 0.12
Nodes (30): owned_private_file(), render_mieru_compose(), run_state_preparer(), run_token_preparer(), test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(), test_mieru_overlay_has_only_intended_writable_runtime_mounts(), test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access(), test_naive_caddy_identity_cannot_access_mieru_state() (+22 more)

### Community 53 - "RoutingService"
Cohesion: 0.05
Nodes (9): CONTINUE HERE — v0.9 (стык фронт/бэк, matches_node, мобильный UI, Xray-router на центре), Сделано, Что дальше, direct_document(), lane_policies(), Compiled, RoutingPolicy, RoutingError (+1 more)

### Community 54 - "CentralProcess"
Cohesion: 0.11
Nodes (4): central_environment(), CentralProcess, Stub, _terminate()

### Community 55 - "build.py"
Cohesion: 0.11
Nodes (20): archive_names(), assert_clean(), build_release(), BuiltRelease, _canonical(), commit_epoch(), _executable(), _external_artifacts() (+12 more)

### Community 56 - "CoreError"
Cohesion: 0.08
Nodes (9): add(), CoreError, _encode_adjacent_routes(), _file_sha256(), _path_sha256(), _read_existing_users(), _valid_master_key_file(), _validate_ownership_mapping() (+1 more)

### Community 58 - "Troubleshooting Proxy Control"
Cohesion: 0.04
Nodes (57): Bounded log queries, Start of change window, Configuration change procedure, .env secrecy, Incident sequence, Log redaction before sharing, scripts/proxyctl.py repair, Restart and recovery (+49 more)

### Community 59 - "app.py"
Cohesion: 0.02
Nodes (140): What is new, Что нового, Task 11: Маршруты центра — связи, импорт пользователей узла, версии, подписки по узлам, Subscription client compatibility, register_api_key_routes(), create_key(), _ctx(), delete_key() (+132 more)

### Community 60 - "DeployCliTests"
Cohesion: 0.05
Nodes (3): Task 13: Phase 8 — backup/restore, матрица негативных тестов, замороженные идентификаторы, DeployCliTests, attempt()

### Community 61 - "_DefaultNaiveRunner"
Cohesion: 0.06
Nodes (13): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _DefaultNaiveRunner, relay(), NaiveAcceptance, _require_acceptance(), test_h2_curl_failure_exposes_only_allowlisted_tls_reason() (+5 more)

### Community 62 - "MieruManager"
Cohesion: 0.06
Nodes (23): _atomic(), _canonical(), ConfigConflict, _fsync_dir(), _go_duration_ns(), _hash(), MieruManager, MitaCLI (+15 more)

### Community 63 - "test_users_adapter_ui.py"
Cohesion: 0.06
Nodes (12): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_busy_buttons_capture_their_target_instead_of_reading_it_after_await(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires(), test_telemt_adapter_does_not_leak_secret_in_errors(), handler(), test_telemt_adapter_patches_limits_and_resets_quota(), handler(), test_telemt_adapter_reads_3425_quota_stats_route() (+4 more)

### Community 64 - "VersionAgent"
Cohesion: 0.07
Nodes (12): Task 7: Агент — `check_upstream`, кэш в `state.json`, выбор версии из upstream, Task 8: `mita` — обновление закреплённого потребителя вместо отказа, Task 9: Компонент `xray`, 3.1. Артефакты внутри архивов, CatalogEntry, sha256_bytes(), agent_from_env(), _atomic_write() (+4 more)

### Community 65 - "test_installer_warp_transaction_recovery.py"
Cohesion: 0.10
Nodes (20): HostCommands, PowerLoss, test_apply_refuses_foreign_state_appearing_after_prepare(), test_apply_waits_for_transient_daemon_status(), test_cleanup_fsyncs_removed_entries_before_engine_completion(), test_egress_probe_overrides_inherited_no_proxy(), test_engine_completes_unpacked_package_on_resume(), test_engine_recovers_sigkill_before_owner_replace() (+12 more)

### Community 66 - "esc"
Cohesion: 0.07
Nodes (97): Task 10: UI «Маршрутизация» (Task 27), Task 10: UI «Маршрутизация» — роутер, esc(), number(), queryAll(), attachment(), BACKEND_NAMES, bindRouting() (+89 more)

### Community 67 - "guest-runner.sh"
Cohesion: 0.06
Nodes (6): CASE_STATUS, dns_tls_fixture(), full_audit(), full_dns_tls(), full_plan(), runtime_cmd()

### Community 68 - "config"
Cohesion: 0.13
Nodes (18): build_managed_clients(), build_managed_inbounds(), ManagedInbound, config(), DeterministicSecrets, test_a_hysteria_client_authenticates_with_auth_not_password(), test_acceptance_clients_are_distinct_from_persistent_clients(), test_hysteria_matches_the_shape_a_running_server_actually_serves() (+10 more)

### Community 69 - "Матрица негативных и security-тестов vNext (Task 39)"
Cohesion: 0.07
Nodes (40): Матрица негативных и security-тестов vNext (Task 39), Task 4: `xray_router_manager` — рантайм и типизированный менеджер (Task 33), test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(), _artifact(), FakeRunner, _lanes_doc(), manager(), _state() (+32 more)

### Community 70 - "test_installer_mcp.py"
Cohesion: 0.07
Nodes (29): _command_failure(), _DefaultMcpRunner, mcp_handoff(), mcp_url(), McpAdapter, McpError, McpPaths, _plaintext_of() (+21 more)

### Community 71 - "routing-spike.py"
Cohesion: 0.06
Nodes (30): adapt(), admin(), curl_socks(), forward_proxy_handler(), walk(), load(), main(), apply_mita() (+22 more)

### Community 72 - "GeodataStore"
Cohesion: 0.13
Nodes (8): test_wal_is_enabled_even_while_another_connection_holds_the_database(), hold(), _atomic_write(), _fsync_directory(), GeodataStore, _now(), _sha256(), _sha256_path()

### Community 73 - "proxyctl.py"
Cohesion: 0.19
Nodes (17): sha256(), _apply_plan_unlocked(), _audit_mapping(), _canonical_route(), _host_path(), InstallerConflict, _load_state(), _owned_route_marker() (+9 more)

### Community 74 - "test_proxyctl_transactions.py"
Cohesion: 0.17
Nodes (20): AuditFacts, apply_plan(), InstallPlan, repair_installation(), facts_from_root(), host_root(), make_plan(), test_apply_is_transactional_preserves_metadata_and_writes_private_manifest() (+12 more)

### Community 75 - "DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)"
Cohesion: 0.11
Nodes (27): ADR 002: declarative generations, Audit finding 1: Manager tests live in tests/test_naive_manager.py and tests/test_mieru_manager.py, Audit finding 7: Managers generate passwords themselves, Audit finding 8: Telemt list_users allows credential recovery, v0.3 acceptance criteria, DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation), Fleet v2 exchange (/agent/v2/nodes/{node_id}/heartbeat, desired, observed, secrets/resolve, secret-results), ObservedGeneration (applied_generation, bundle_digest, reconcile_state, resource_statuses, safe_drift_summary) (+19 more)

### Community 76 - "test_naive_management.py"
Cohesion: 0.10
Nodes (5): test_enabling_an_exhausted_user_reports_the_quota_reason_not_an_outage(), test_memory_naive_replays_an_operation_and_can_lose_a_response(), test_naive_adapter_accepts_empty_204_delete_response(), test_naive_feature_is_hidden_and_routes_fail_closed_when_disabled(), test_naive_rotation_on_its_page_replaces_the_kept_credential()

### Community 77 - "test_routing_service.py"
Cohesion: 0.22
Nodes (14): Task 8: Routing — сервис и HTTP API (локальный узел), anyio_backend(), _audits(), _block(), test_apply_io_outside_transaction(), test_apply_local_calls_manager_and_records_applied(), test_apply_manager_conflict_marks_failed(), test_apply_unreachable_provider_leaves_policy_unchanged() (+6 more)

### Community 78 - "CoreAdapter"
Cohesion: 0.09
Nodes (42): CoreAdapter, config(), core_action(), FakeRunner, test_a_generated_password_is_used_when_the_operator_chose_none(), test_absent_filesystem_adoption_refuses_active_fixed_label_resources(), test_acceptance_uses_transaction_unique_name_and_all_configured_credentials(), test_applying_checkpoint_removes_only_probe_and_image_created_after_prepare() (+34 more)

### Community 79 - "test_routing_lanes_routes.py"
Cohesion: 0.22
Nodes (12): _attach(), _csrf(), _grant(), router(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first() (+4 more)

### Community 80 - "full_config"
Cohesion: 0.16
Nodes (17): clean_facts(), config_without_initial_user(), full_config(), mieru_action(), test_recovery_verifies_nonempty_manager_state_and_new_token_is_32_bytes(), _router_config(), test_generated_manager_token_is_valid_http_text(), test_mieru_bootstrap_config_proxies_all_traffic_with_warp() (+9 more)

### Community 81 - "test_version_agent_upstream.py"
Cohesion: 0.06
Nodes (61): 2026-09-22 — окно клиента, гейт, раскатка, CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22, MCP-сервер (решение владельца: в v0.11, полный набор, с ноутбука через SNI, только на центре), WARP на парке единообразно (2026-09-22, по слову владельца), ВЫПУЩЕНО 2026-09-22 (по слову владельца), Обновление компонентов на парке (2026-09-22, по слову владельца «обнови»), Открытые мелочи, Проверено живьём на ams-test (настоящая установка `aurora.sky.dubr1kkk.uk`) (+53 more)

### Community 82 - "prepare-naive-state.py"
Cohesion: 0.17
Nodes (17): _assert_directory(), _assert_identities(), _assert_identity_free(), _assert_owned_state(), _assert_safe_parents(), _assert_state_entry(), _create_directory(), _fail() (+9 more)

### Community 83 - "routing/service.py"
Cohesion: 0.05
Nodes (25): Task 6: Панель — модель политики v3 и миграция 16, _b64(), ExitCredential, ExitInput, ExitInUse, ExitSecurity, ExitStore, ExitTransport (+17 more)

### Community 84 - "test_panel_entrypoint.py"
Cohesion: 0.18
Nodes (21): main(), open_source(), stage(), StageError, validate_source(), verify(), _fake_command(), logged_commands() (+13 more)

### Community 85 - "test_version_agent_server.py"
Cohesion: 0.05
Nodes (32): _Proc, test_a_stalled_counter_reports_null_rather_than_a_confident_zero(), test_cpu_utilisation_is_a_delta_between_two_samples(), test_disk_reports_space_an_operator_can_actually_write(), test_host_endpoint_is_read_only_and_rejects_writes(), test_memory_counts_reclaimable_cache_as_available(), test_missing_proc_files_degrade_each_section_independently(), test_real_proc_is_parsed_on_linux() (+24 more)

### Community 86 - "Store"
Cohesion: 0.07
Nodes (9): ConflictError, Store, test_concurrent_login_batch_reserves_attempts_and_bounds_argon2(), test_login_limiter_migrates_existing_reservations(), test_successful_login_preserves_concurrent_failed_reservation(), interleaved_verify(), test_store_startup_uses_valid_policy_matched_precomputed_dummy_hash(), test_unknown_admin_performs_one_argon2_verify_without_logging_password() (+1 more)

### Community 87 - "3x-ui mode: managed-new"
Cohesion: 0.10
Nodes (21): release/external-artifacts.json, Interactive Release Installer Implementation Plan, Managed inbound templates vless_reality_tcp / vless_reality_xhttp / hysteria2_tls, ThreeXuiAdapter.plan_existing_upgrade, ReleaseManifest / ExternalArtifact.for_platform, safe_extract_tar, Task 12: Existing and staged 3x-ui lifecycle, Task 13: Managed 3x-ui inbounds, clients and optional WARP (+13 more)

### Community 88 - "register_routing_routes"
Cohesion: 0.10
Nodes (23): _outcome(), policy_view(), _refusal(), register_routing_routes(), apply(), attach(), _ctx(), delete_policy() (+15 more)

### Community 89 - "test_dns_is_checked_again_for_each_connection_and_only_numeric_ip_is_dialed"
Cohesion: 0.12
Nodes (8): test_dns_is_checked_again_for_each_connection_and_only_numeric_ip_is_dialed(), test_dns_private_addresses_are_refused_before_connect(), connect(), resolve(), test_dns_timeout_is_bounded_and_typed(), test_explicit_private_opt_in_reaches_loopback(), test_fingerprint_dns_private_answer_is_refused_before_connect(), test_public_ipv6_failure_falls_back_to_validated_ipv4()

### Community 90 - "core_checks"
Cohesion: 0.18
Nodes (7): Task 14: Лаборатория на стенде — `fleet-acceptance.py` и tier `fleet`, core_checks(), fetch(), _ip_through(), main(), _run(), _socks5_udp_dns()

### Community 91 - "CertificateAuthority"
Cohesion: 0.17
Nodes (8): CertificateAuthority, issue_fixture(), mtls_context(), start_server(), test_agent_client_retries_result_from_durable_outbox_without_reexecution(), test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(), test_revocation_and_request_body_bound_fail_closed(), test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node()

### Community 92 - "compile"
Cohesion: 0.23
Nodes (31): Task 7: Routing IR — модели, хранилище, миграция 14, компилятор (Task 26), compile(), _policy(), _rule(), _target(), test_compile_capability_missing_from_target(), test_compile_diff_against_applied(), test_compile_digest_is_canonical() (+23 more)

### Community 93 - "panel"
Cohesion: 0.06
Nodes (33): English, Fixed, Upgrading from v0.12, v0.13.0-beta.1 — мобильные карточки и быстрые настройки, Verification and rollout scope, Исправлено, Обновление с v0.12, Русский (+25 more)

### Community 94 - "test_fleet_v2_client.py"
Cohesion: 0.07
Nodes (26): _client(), _EmptyHandler, _OneShotTLSServer, _start_tls_server(), test_api_key_never_appears_in_the_unreachable_exception(), test_capture_sends_bounded_resource_list_and_returns_body_verbatim(), test_client_scope_closes_after_transport_failure(), test_explicit_client_scope_reuses_http_client_and_closes_once() (+18 more)

### Community 95 - "Task 6: Encrypted secret versions and master key"
Cohesion: 0.15
Nodes (17): ADR 005: secret references, compose.yaml secret panel-master-key, Pinned cryptography dependency, panel/entrypoint.sh master-key staging, Installer renders secrets/panel-master-key, panel.keyring.Keyring (load/generate/save/rotate/retire_all_but_active), panel.cli master-key-init / master-key-rotate / master-key-verify, Master key documentation (BACKUP_RESTORE, UPGRADING, PANEL) (+9 more)

### Community 97 - "QuotaEnforcer"
Cohesion: 0.10
Nodes (9): caddy_adapt(), command_reload(), command_validate(), main(), QuotaEnforcer, _rewrite_listener(), test_caddy_adapt_unwraps_caddy_211_envelope(), test_private_listener_rewrite_disables_automatic_https_redirects() (+1 more)

### Community 98 - "_DefaultCoreRunner"
Cohesion: 0.06
Nodes (16): _AcceptanceCollision, AcceptanceError, _DefaultCoreRunner, probe_sources_digest(), _valid_users_file(), test_a_failed_acceptance_step_carries_what_the_probe_said(), test_a_probe_image_built_from_older_sources_is_not_compatible(), test_adjacent_handshake_reads_the_report_not_the_exit_status() (+8 more)

### Community 99 - "MemoryTelemt"
Cohesion: 0.05
Nodes (33): RouterAdapter, attach_document(), router_target_from_identity(), MemoryTelemt, _adapter(), anyio_backend(), Bridge, _item() (+25 more)

### Community 100 - "WarpAdapter"
Cohesion: 0.15
Nodes (6): WarpAdapter, WarpError, test_warp_rollback_checks_all_ownership_before_any_mutation(), test_download_never_reuses_attacker_link(), test_warp_is_owned_before_consumers_and_requires_real_egress(), test_warp_owned_lifecycle_and_foreign_install_refusal()

### Community 101 - "createSubscriptionDialog"
Cohesion: 0.08
Nodes (53): Task 7: Окно клиента: показ ссылки по кнопке, матрица, «Применить», Task 8: «Новый клиент» с матрицей и блок подписки в «Доступы выданы», CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой), Сделано, Что дальше, bindClients(), openClientModal(), proposeUsername() (+45 more)

### Community 102 - "FleetPusher"
Cohesion: 0.03
Nodes (32): Audit event names, Authentication and administrators, Clients, grants and subscriptions, Nodes (central side), Nodes (node side, through the central's key), Routing (v0.4), Global Constraints, Self-review (+24 more)

### Community 103 - "Path"
Cohesion: 0.19
Nodes (8): _assert_contained(), fsync_file(), fsync_tree(), operation_lock(), _owned_path(), _path_identity(), _root_path(), validate_legacy_runtime_v2()

### Community 104 - "test_installer_cli.py"
Cohesion: 0.12
Nodes (22): CliServices, _default_services(), adapter_factories(), _plan(), RecordingStore, ReturningWizard, _run(), _run_in_pty() (+14 more)

### Community 105 - "test_mieru_manager_lanes.py"
Cohesion: 0.06
Nodes (23): account_url(), empty_config(), LanesInvalid, parse_slots(), Slot, slot_config(), validate_request(), main() (+15 more)

### Community 106 - "main.js"
Cohesion: 0.06
Nodes (63): ADR-0008, Task 13: Экран версий — кнопка проверки, пометка источника, карточка Xray, api(), API_REASONS, cookie(), DETAIL_WORTH_SHOWING, problemText(), registerReasons() (+55 more)

### Community 109 - "test_mieru_egress.py"
Cohesion: 0.09
Nodes (35): Task 5: naive-manager и mieru-manager — провайдер `router`, canonical(), check_reachable(), _cidr(), document_digest(), _domain(), EgressInvalid, EgressUnreachable (+27 more)

### Community 110 - "nodes.js"
Cohesion: 0.05
Nodes (70): Task 12: UI — API-ключи, «Узлы → Добавить панель», карточка узла, выбор узла в «Клиентах», date(), commandForm(), commandPayload(), commandRow(), commandStatus(), FLEET_OPERATIONS, handleFleetChange() (+62 more)

### Community 111 - "mcp_server/server.py"
Cohesion: 0.05
Nodes (8): Config, _read_secret(), main(), BearerGate, build_server(), create_app(), test_a_host_outside_the_allowlist_is_refused(), test_config_reads_secrets_from_files_and_requires_allowed_hosts()

### Community 112 - ".verify"
Cohesion: 0.18
Nodes (4): _acceptance_value(), _compose_publishes_telemt_api(), CoreAcceptance, test_acceptance_dataclass_rejects_inconsistent_counts()

### Community 113 - "Task 2: automatic WARP with selective routing"
Cohesion: 0.19
Nodes (15): ams-server production reference server, cloudflare-warp client / warp-svc.service, release/external-artifacts.json (pinned external artifacts), Task 3.2: installer deploys WARP automatically, Task 3.3: selective WARP routing via 3x-ui, three_xui.warp_domains config option, WARP selective domain list (geosite:openai, anthropic, tiktok, reddit, google-gemini, google-play), WARP proxy mode on local SOCKS5 port 40000 (+7 more)

### Community 114 - "test_installer_xray_router.py"
Cohesion: 0.10
Nodes (34): Task 11: Установщик — `[egress] router`, адаптер `xray_router`, секреты, ротация, ingress_credential(), action_for(), adapter(), _agent_state(), _applied(), _archive_bytes(), FakeRunner (+26 more)

### Community 115 - "access.js"
Cohesion: 0.13
Nodes (30): createAccessDialogs(), bind(), bindClientDialog(), clearBundleSubscription(), clearClientDialog(), openOperationBundle(), renderVariant(), revealMieruToken() (+22 more)

### Community 116 - "test_version_agent.py"
Cohesion: 0.09
Nodes (35): _agent(), _build_catalog(), test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(), test_archive_member_hash_is_checked_against_the_archive_not_the_file(), test_binary_rollback_restart_is_not_success_without_health(), test_binary_update_records_the_pin_the_unit_check_reads(), test_binary_update_restores_the_previous_pin_when_the_service_fails(), test_binary_update_rolls_back_when_service_restart_fails() (+27 more)

### Community 117 - "test_naive_manager_lanes.py"
Cohesion: 0.12
Nodes (18): handler_lines(), lane_credentials(), lanes_span(), LanesInvalid, primary_forward_proxy(), render(), validate_request(), lane_manager() (+10 more)

### Community 118 - "Continuation prompt for a new Claude Code context"
Cohesion: 0.18
Nodes (7): ams-test disposable install server, full profile with three_xui.mode managed-new, /root/install.toml and /root/install.credentials, Let's Encrypt certificates (four issued), ams-test disposable server (ssh ams-test, root), Continuation prompt for a new Claude Code context, Referenced plan: docs/plans/2026-09-07-warp-and-final-installation.md

### Community 119 - "register_fleet_v2_node_routes"
Cohesion: 0.10
Nodes (24): _conflict(), _log_late_outcome(), register_fleet_v2_node_routes(), capture(), _daemon(), _egress_entry(), _enabled(), _geodata() (+16 more)

### Community 120 - "_PinningStream"
Cohesion: 0.10
Nodes (4): _NodeBackend, _NodeTransport, _PinningStream, _public_address()

### Community 121 - "MTProxy acceptance failure: Connection closed"
Cohesion: 0.15
Nodes (14): Fake-TLS handshake, Full install log capture (install.err, docker compose logs, journalctl nginx, container state), nebula.sky.dubr1kkk.uk (MTProxy, cert: yes), proxy-control-mtproxy container (127.0.0.1:8445), secrets/users.conf MTProxy secret, Task 3.1: finish the installation to status active, TDLib MTProto probe (addProxy), External verification after status active (+6 more)

### Community 122 - "Proxy Control v0.1.0 Beta"
Cohesion: 0.13
Nodes (14): Archive SHA-256 checksum for proxy-control-v0.1.0.tar.gz, Mieru (TCP/UDP proxy on explicit public ports), mita local manager for Mieru, NaiveProxy (HTTPS proxy with cover site, users, quotas, completed-tunnel accounting), Proxy Control panel (owner/admin/viewer roles, secret-free audit, one-time credential disclosure), Proxy Control v0.1.0 Beta, Four release assets (archive, SHA256SUMS, release-manifest.json, sbom.spdx.json), sbom.spdx.json SBOM (+6 more)

### Community 123 - "test_installer_version_agent.py"
Cohesion: 0.06
Nodes (36): _command_failure(), _DefaultVersionAgentRunner, _env_key(), _env_values(), VersionAgentAdapter, VersionAgentError, VersionAgentPaths, action_for() (+28 more)

### Community 124 - "curated.py"
Cohesion: 0.15
Nodes (28): Добавлено, Tools, Инструменты, 9a. MCP-сервер `proxy-control-mcp` (решение владельца 2026-09-21: в v0.11, полный набор, доступ с ноутбука через SNI), audit_tail(), client_subscription(), create_client(), CuratedTool (+20 more)

### Community 125 - "XrayRouterManager"
Cohesion: 0.07
Nodes (9): _atomic_write(), _free_port(), ManagerConflict, ManualInterventionRequired, _now(), revision_of(), _test_failure(), XrayRouterManager (+1 more)

### Community 126 - "test_mobile_layout.py"
Cohesion: 0.09
Nodes (13): Task 9: Мобильный аудит окна клиента, _cards_from_real_renderers(), test_mobile_cards_have_semantic_icons_and_quick_settings_align(), _browser(), DevTools, _recv_exact(), _render_at_phone_viewport(), test_access_cards_and_navigation_do_not_collide_on_phone() (+5 more)

### Community 127 - "docker_lab.py"
Cohesion: 0.21
Nodes (10): _architecture(), build_image(), copy_inputs(), DockerLabError, guest_command(), main(), run(), run_acceptance() (+2 more)

### Community 129 - "Task 4: Unified DB layer and migrations"
Cohesion: 0.16
Nodes (19): CommandRunner (bounded, sanitized errors), panel.audit.digest (sha256 of canonical JSON), panel.audit.record(db, ...), panel.audit.scrub (recursive), Migration 2 audit-structured, Migration 1 baseline-v0.1.0, panel.database.Database (WAL, foreign_keys, transaction()), panel.cli db-migrate / db-status (+11 more)

### Community 130 - "Panel version-agent"
Cohesion: 0.15
Nodes (14): Обновление существующего 3x-ui, Back up a complete generation before changing runtime, state, identities, ports or routes, NaiveProxy/Caddy and Mieru/mita binary update flow, Caddyfile and module checker validation, version-overrides/compose.versions.yaml, Single-generation backup, Обновление бинарников Caddy и mita, Проверка Caddyfile и module checker (+6 more)

### Community 131 - "PolicyInput"
Cohesion: 0.08
Nodes (19): Известные ограничения/решения (для ревью и после v0.5), backends_for(), normalise_lane(), PolicyInput, PolicyPut, PolicyConflict, PolicyNotFound, RoutingStore (+11 more)

### Community 132 - "sbom.py"
Cohesion: 0.26
Nodes (7): build_sbom(), _external_packages(), _identifier(), main(), SbomError, test_sbom_is_deterministic_for_one_commit(), test_sbom_requires_at_least_one_packaged_file()

### Community 133 - "clients.js"
Cohesion: 0.06
Nodes (61): proxyLink(), actions(), adopt(), adoptNote(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT, CLIENT_STATE (+53 more)

### Community 134 - "AgentTransportServer"
Cohesion: 0.19
Nodes (4): main(), required(), serve(), AgentTransportServer

### Community 135 - "test_fleet_v2_reconcile.py"
Cohesion: 0.11
Nodes (26): _accept(), anyio_backend(), _imported(), _push(), _resource(), test_a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user(), test_a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply(), test_a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user() (+18 more)

### Community 136 - "test_mcp_server.py"
Cohesion: 0.09
Nodes (22): tool_name(), anyio_backend(), config(), fake(), FakePanel, registry(), _rpc(), test_a_confirmed_call_reaches_the_panel_and_its_error_comes_back_as_tool_text() (+14 more)

### Community 137 - "renderers/base.py"
Cohesion: 0.05
Nodes (49): mieru_access(), register_mieru_routes(), escrow(), kept(), kept_share_url(), live_template(), local_only(), mieru_create() (+41 more)

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
Cohesion: 0.03
Nodes (55): ADR 006: Engine-neutral routing policy IR, Amended in v1.1 (2026-10-01): MTProxy through the Xray-router, As shipped in v0.4, Consequences, Context, Decision, Non-goals, Task 7: Панель — компилятор v3 (полосы, цепи, причины) (+47 more)

### Community 145 - "Global Constraints"
Cohesion: 0.05
Nodes (41): Chains and per-client lanes spike (v0.7, Task 1), S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user, S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray, S3 — Mieru: a second mita daemon beside the managed one, What v0.7 builds on this, Global Constraints, Task 0: Ветка, спайк, спека, план, Task 10: Установщик — `relay_port`, `lane_slots`, обновление (+33 more)

### Community 146 - "index.cjs"
Cohesion: 0.09
Nodes (22): dependencies, prebuilt-tdlib, tdl, description, engines, node, license, name (+14 more)

### Community 147 - "Interactive Release Installer Design"
Cohesion: 0.08
Nodes (29): CertificatePlan, parse_effective_nginx / select_route_target, Task 7: Effective Nginx shared-443 topology and owned routes, Task 8: Fresh-host packages, certificates and UFW ownership, 3x-ui modes, Artifact policy, Coexistence behavior, Configuration file (+21 more)

### Community 149 - "create_app"
Cohesion: 0.04
Nodes (42): Task 2: Bearer-аутентификация, scope-гейты и `/api/keys`, Task 9: Pusher — heartbeat и доставка поколений, Task 12: Панель — `check()`, компонент `xray`, `/api/versions/check`, relay для узлов, Task 19A — релизный гейт v0.2 на `ams-test` (пройден 2026-09-11), Как проверять (единственный способ), Правила, добытые в этой серии, Промпт для продолжения работы в новом контексте, Прочитай сначала (+34 more)

### Community 150 - "EgressInvalid"
Cohesion: 0.08
Nodes (45): Task 1: Xray-router — intent схемы 2 (полосы, выходы, цепи), test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector(), test_credentials_are_masked_in_the_redacted_intent(), test_exit_outbounds_render_the_way_xray_dials_them(), test_the_intent_names_exits_and_a_rule_may_leave_through_one(), test_validate_exit_normalises_every_protocol_and_refuses_the_impossible(), _v2(), _doc() (+37 more)

### Community 151 - "test_xray_router_mtproxy.py"
Cohesion: 0.14
Nodes (15): _inbound(), manager(), SocketRunner, test_a_chain_for_mtproxy_renders_like_any_service(), test_a_malformed_credential_is_a_manual_intervention_not_a_new_one(), test_a_manager_without_the_socket_does_not_know_mtproxy(), test_a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(), test_a_stale_socket_is_removed_before_xray_starts() (+7 more)

### Community 152 - "Trust Boundaries"
Cohesion: 0.20
Nodes (6): Pull Request Boundary Checklist, Contribution Architecture Rules, Local Development Gate Commands, Trust Boundaries, Caddy Builder Digest and forwardproxy Commit Pin, Third-Party License Boundary Summary

### Community 153 - "test_three_xui_api.py"
Cohesion: 0.11
Nodes (33): api_with(), client(), failing_api(), ok(), _panel(), secret_values(), sensitive_values(), template() (+25 more)

### Community 154 - "guest-runner.sh script"
Cohesion: 0.26
Nodes (12): case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), full_environment_preflight(), host_diagnostics(), host_environment_preflight() (+4 more)

### Community 155 - "MemoryXrayRouter"
Cohesion: 0.09
Nodes (10): _csrf(), router(), test_a_linked_panels_geodata_is_driven_through_its_fleet_api(), test_geodata_is_owner_only_to_change_and_needs_a_router(), test_local_geodata_view_settings_update_restore_and_audit(), test_node_geodata_and_exit_routes_answer_the_central_key(), test_memory_router_behaves_like_the_manager(), test_router_adapter_maps_codes_and_targets() (+2 more)

### Community 156 - "ReleaseMatrixTests"
Cohesion: 0.24
Nodes (3): _passing_report(), ReleaseMatrixTests, report_without()

### Community 157 - "Proxy Control Cover Art"
Cohesion: 0.33
Nodes (8): Anime Key-Art Illustration Style, Beam vs Hammer Clash Metaphor, Twin-Tailed Girl Blocking With Stone Hammer, Proxy Control Cover Art, Central Impact Burst Where Beam Meets Hammer, Proxy Control Repository Branding Asset, Night Ruined Colosseum Arena Backdrop, Rearing Unicorn Emitting Magenta Horn Beam

### Community 158 - "route-coverage.py"
Cohesion: 0.33
Nodes (7): build_app(), collect_routes(), gate_problems(), _gates(), main(), _pattern(), unmentioned()

### Community 160 - "run_captured"
Cohesion: 0.21
Nodes (13): full_idempotence(), full_install(), host_idempotence(), host_install(), interrupt_install_recovery(), release_idempotence(), release_install(), release_install_full_xui() (+5 more)

### Community 161 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.22
Nodes (12): ADR 001: pull-only node transport, ADR 003: one writer per resource, Task 1: ADRs and v0.2 architecture record, Task 2: Characterization tests of current boundaries, Ownership manifest, Fleet v1 Telemt-only command queue, Resource ownership terms: managed | adopted | foreign | drifted | tombstoned, Phase 0: Contract freeze and decision records (+4 more)

### Community 162 - "Proxy Control v0.3 — центральная панель и подключённые панели"
Cohesion: 0.15
Nodes (13): Task 0: Spike — принимает ли пиннутый Telemt-форк caller-supplied `secret`, 10. Тестирование, 11. Критерии приёмки v0.3, 12. Отклонения от Phase 5 спеки vNext, 1. Цель, 2. Паритет с 3x-ui, 3. Архитектурные решения, 7. UI (+5 more)

### Community 163 - "ReleaseManifest"
Cohesion: 0.14
Nodes (18): ReleaseManifest, _load_manifest(), main(), _parser(), sha256_file(), stage_xray(), _manifest_bytes(), test_an_architecture_this_release_does_not_build_for_is_refused() (+10 more)

### Community 164 - "mieru-client/probe.py"
Cohesion: 0.36
Nodes (5): _endpoint(), main(), _run(), _socks5_connect(), _status_through()

### Community 165 - "Промпт для продолжения работы в новом контексте"
Cohesion: 0.22
Nodes (8): Задача 1: добить установку, Задача 2: автоматический WARP, Задача 3: релиз, Отложено владельцем, Правила, добытые дорогой ценой, Промпт для продолжения работы в новом контексте, Прочитай сначала, Что уже сделано

### Community 167 - "test_ui_browser_findings.py"
Cohesion: 0.11
Nodes (8): test_an_audit_row_stacks_its_main_line_and_its_details(), test_every_documented_audit_action_has_a_journal_label(), test_no_module_renders_an_inline_style_attribute(), test_the_brand_mark_is_the_product_artwork_that_actually_ships(), test_the_grant_dialog_body_issues_a_mieru_grant(), test_the_grant_dialog_reads_only_its_own_protocol_boxes(), test_the_login_form_shows_a_refusal_instead_of_reloading(), test_the_profile_button_opens_a_menu_instead_of_a_toast()

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

### Community 173 - "Карта файлов"
Cohesion: 0.13
Nodes (14): Global Constraints, Task 10: `naive` — пересборка Caddy, Task 11: Сервер агента — `POST /v1/upstream/check`, долгий таймаут для сборки, Task 14: Установщик принимает версии из `state.json` агента, Task 15: Документация и changelog, Task 16: Гейт на ams-test и живая проверка на AMS_Z, Task 1: Обзор — без «Application bytes», ресурсы одной строкой, три карточки, Task 4: Каталог — `xray`, `source`, `archive`, `kind: build` (+6 more)

### Community 174 - "container_setup"
Cohesion: 0.33
Nodes (7): add_hosts(), container_setup(), container_write_configs(), host_ip(), host_setup(), setup_full_host(), write_fake_certbot()

### Community 175 - "FleetStore"
Cohesion: 0.26
Nodes (5): _canonical(), FleetStore, test_fleet_inventory_and_results_are_recursively_secret_free(), test_fleet_v1_hides_and_retires_legacy_mieru_state(), test_fleet_v1_rejects_mieru_inventory_advertisement()

### Community 176 - "ProvisioningService"
Cohesion: 0.08
Nodes (4): Task 1: Fix-wave — отложенные замечания v0.3, OperationResult, ProvisioningService, StepResult

### Community 177 - "tools.py"
Cohesion: 0.15
Nodes (12): PanelError, _body_schema(), _build(), build_operations(), is_excluded(), is_irreversible(), Operation, refusal() (+4 more)

### Community 178 - "Rule: verify the open port, not the panel record"
Cohesion: 0.25
Nodes (3): three_xui managed-new mode completed, 3x-ui 3.7.0 (pinned), 3x-ui mode existing: adopt installed 3x-ui without changing its files

### Community 179 - "ingress_upgrade.py"
Cohesion: 0.07
Nodes (34): CONTINUE HERE — v0.4 маршрутизация, Где мы, Гейт (Task 13) — итог, Известные ограничения/решения (для ревью и v0.5), Коммиты ветки (по порядку), Публикация (по поручению владельца 2026-09-14), Что дальше (владелец), _mcp_vhost_text() (+26 more)

### Community 180 - "client_probe"
Cohesion: 0.29
Nodes (7): client_probe(), release_hysteria_client(), release_mieru_client(), release_naive_client(), release_telemt_client(), release_vless_tcp_client(), release_vless_xhttp_client()

### Community 181 - "test_mtproxy_respq_probe.py"
Cohesion: 0.57
Nodes (4): run_wrapper(), test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(), test_wrapper_rejects_invalid_arguments_without_starting_docker(), test_wrapper_requires_root()

### Community 182 - "test_version_agent_panel.py"
Cohesion: 0.11
Nodes (28): _mutations(), _panel_archive(), _PanelHost, _release_tar(), _state(), test_a_second_panel_update_is_refused_while_one_is_running(), test_a_version_file_ahead_of_the_running_panel_does_not_hide_the_update(), test_panel_current_falls_back_to_the_version_file_without_a_container() (+20 more)

### Community 183 - "4. Автоматическое развёртывание узла"
Cohesion: 0.25
Nodes (8): 4.1 Требования к хосту, 4.2 Скачать и проверить релиз (без root), 4.3 Мастер: вопросы по порядку, 4.4 План и digest, 4.6 Приёмка, отчёты, где пароли, 4.7 Первые действия в панели, 4.8 Повторный запуск, resume, repair, uninstall, 4. Автоматическое развёртывание узла

### Community 185 - "BoundedBodyMiddleware"
Cohesion: 0.33
Nodes (3): receive(), BoundedBodyMiddleware, replay()

### Community 186 - "probe/install.sh"
Cohesion: 0.33
Nodes (5): DESTINATION, IMAGE, install.sh script, TDL_VERSION, TDLIB_VERSION

### Community 188 - "test_installer_three_xui.py"
Cohesion: 0.04
Nodes (72): AcceptanceError, parse_reality_keypair(), ThreeXuiConfig, SystemSecrets, adapter(), build_release(), config_with_clients_and_reality_secret(), existing_config() (+64 more)

### Community 189 - "Private Vulnerability Reporting Path"
Cohesion: 0.40
Nodes (5): Sanitized Bug Report Template, Issue Template Config (blank issues disabled), Security Reporting Guidance Template, Code of Conduct, Private Vulnerability Reporting Path

### Community 190 - "test_proxyctl.py"
Cohesion: 0.17
Nodes (15): _canonical_caa_record(), _parse_caa_answer(), parse_http_domains(), parse_nginx_observation(), parse_xray_inbounds(), validate_domain(), test_audit_collision_routes_come_only_from_selected_active_map(), facts_from_root() (+7 more)

### Community 191 - ".compose"
Cohesion: 0.20
Nodes (8): CONTINUE HERE — v0.5 Xray egress-router, Где мы, Гейт (Task 15) — итог, Коммиты ветки (по порядку), Что дальше (владелец), Drill, main(), sha256()

### Community 192 - "upstream"
Cohesion: 0.03
Nodes (66): [0.5.0-beta.1] - 2026-09-16, Безопасность, Добавлено, Изменено, Отложено (дорожная карта), Consequences, END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`, Non-goals (+58 more)

### Community 193 - "test_routing_router_service.py"
Cohesion: 0.17
Nodes (22): Task 8: RoutingService — targets с роутером, attach/detach, apply/rollback через роутер (локально), anyio_backend(), _audits(), _block(), _item(), _rules(), test_apply_native_policy_on_attached_service_is_422(), test_apply_router_failure_marks_failed_and_maps_codes() (+14 more)

### Community 195 - "MieruClient"
Cohesion: 0.12
Nodes (5): MieruClient, test_mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body(), test_mieru_client_rotate_sends_the_caller_credential_and_operation_id(), test_mieru_client_sanitizes_manager_errors(), handler()

### Community 196 - "MemoryNaive"
Cohesion: 0.11
Nodes (6): MemoryNaive, NaiveError, canonical(), test_dashboard_stays_available_when_enabled_naive_manager_is_degraded(), health(), list_users()

### Community 197 - "XrayRouterClient"
Cohesion: 0.08
Nodes (12): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 14: Документация, ADR 007, CHANGELOG, VERSION, релизная заметка, Task 15: Гейт релиза на `ams-test` и точка продолжения, Task 3: Spike — Xray как egress-router на стенде (Task 32), Task 6: Панель — клиент роутера, `RouterTarget`, адаптер, wiring, v0.5 Xray Router Implementation Plan (+4 more)

### Community 199 - "test_installer_reports.py"
Cohesion: 0.12
Nodes (17): AcceptanceReport, _assert_public(), CredentialHandoff, _encode(), ReportError, ReportWriter, handoff_with_secrets(), public_report_values() (+9 more)

### Community 200 - "English"
Cohesion: 0.40
Nodes (5): Domains and shared port 443, English, Included, Installation, Verified for this release

### Community 201 - "InstallerConfig"
Cohesion: 0.09
Nodes (24): WizardRunner, _canonical_dataclass(), FirewallConfig, InstallerConfig, Profile, adapters_for(), compose_file_list(), LabConfigurationsAreValid (+16 more)

### Community 202 - "mieru-mss-clamp.sh"
Cohesion: 0.83
Nodes (3): check_rule(), mieru-mss-clamp.sh script, usage()

### Community 203 - "ThreeXuiApiError"
Cohesion: 0.11
Nodes (6): _form_value(), parse_csrf_token(), ThreeXuiApi, ThreeXuiApiError, test_a_page_without_a_usable_csrf_token_fails_closed(), test_csrf_token_is_read_from_the_page_the_panel_serves()

### Community 205 - "_panel_health_diagnosis"
Cohesion: 0.11
Nodes (8): _as_text(), _command_failure(), _panel_health_diagnosis(), _sanitize_diagnostic(), _without_health_polling(), test_a_failed_panel_health_check_says_what_the_containers_were_doing(), test_the_panel_diagnosis_drops_its_own_health_polling(), test_the_panel_diagnosis_never_lets_a_diagnostic_failure_mask_the_real_one()

### Community 208 - "test_grant_lifecycle.py"
Cohesion: 0.15
Nodes (23): _actions(), _generation(), _grant(), _node_users(), _remote(), _secret_states(), test_a_deleted_or_unknown_grant_is_refused(), test_bundle_never_renders_a_withdrawn_or_deleted_grant() (+15 more)

### Community 209 - "Diagnosing a client's access"
Cohesion: 0.33
Nodes (5): Diagnosing a client's access, Report to the owner, Steps, Symptom → likely cause, What not to do

### Community 214 - "Database"
Cohesion: 0.02
Nodes (87): Live check (AMS_Z ↔ ams-test), Task 1: Миграция 20 и `secret_ref` у подписки, 5.1 API-ключи, 5.2 Эндпоинты `/api/fleet/v2/*` (scope `node-sync` или `admin`), 5.3 Reconcile на узле (`panel/fleet_v2/reconcile.py`), 5. Узел: API-ключи и Fleet API v2, ApiKeyService, _hash() (+79 more)

### Community 219 - "UpdateError"
Cohesion: 0.09
Nodes (14): 10. Тесты и проверка, 1. Цель, 3. Источники upstream (version-agent), 5. Компонент `xray`, 6. Компонент `mita` и закреплённый потребитель, 7. Компонент `naive` — пересборка Caddy, 9. Ошибки, v0.11 — обновления из upstream и обзор в одну строку (+6 more)

### Community 220 - "test_installer_chains.py"
Cohesion: 0.13
Nodes (9): MieruPaths, _slot_action(), _slot_config(), SlotRunner, _stage_router(), test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them(), test_mieru_plan_carries_the_slots_and_refuses_a_collision(), test_mieru_without_slots_starts_none_and_a_slotted_action_needs_the_router() (+1 more)

### Community 222 - "test_version_agent_artifacts.py"
Cohesion: 0.25
Nodes (12): _targz(), test_escaping_members_unknown_formats_and_garbage_are_refused(), test_missing_member_symlink_and_oversize_are_refused(), test_tar_member_may_sit_under_a_directory(), test_tar_member_written_with_a_dot_slash_prefix_is_still_found(), test_zip_member_is_returned_by_exact_name(), _zip(), ArtifactError (+4 more)

### Community 223 - "English"
Cohesion: 0.12
Nodes (16): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z → ams-test), Proxy Control v0.7.0-beta.1, Screenshots, Upgrading, What the verification found (+8 more)

### Community 225 - "compose fleet-agent overlay service"
Cohesion: 0.20
Nodes (6): compose fleet-agent overlay service, compose fleet-ingress overlay service, Typed per-node command queue, Fleet central mTLS ingress, Outbound mTLS fleet transport v1, panel.cli fleet CA/enrollment commands

### Community 233 - "CatalogError"
Cohesion: 0.16
Nodes (16): Self-review, test_catalog_accepts_a_caddy_build_entry(), test_catalog_accepts_a_panel_release_entry_and_refuses_it_elsewhere(), test_catalog_rejects_archive_members_that_escape(), test_catalog_rejects_non_https_binary_sources(), test_catalog_requires_immutable_artifacts(), test_catalog_requires_the_xray_member_set_and_a_single_member_elsewhere(), _archive() (+8 more)

### Community 234 - "accepted_sha256"
Cohesion: 0.28
Nodes (7): accepted_caddy_pins(), accepted_sha256(), agent_component(), _state(), test_invalid_state_yields_only_the_pin(), test_missing_or_failed_state_yields_only_the_pin(), test_state_adds_the_agent_installed_hashes()

### Community 238 - "XrayError"
Cohesion: 0.07
Nodes (10): test_a_router_that_does_not_come_back_after_the_swap_is_recorded(), broken_start(), check_hop_reachable(), _fsync_directory(), _port_open(), _sha256_file(), _socket_open(), SubprocessXrayRunner (+2 more)

### Community 239 - "v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router"
Cohesion: 0.12
Nodes (23): Custom exits, quick settings and geodata (v0.8), Свои выходы, быстрые настройки и geodata (v0.8), 10. Лаборатория и гейт, 11. План работ (оценка), 12. Вопросы владельцу, 1. Цель, 2. Словарь, 3. Архитектурные решения (+15 more)

### Community 240 - "common.js"
Cohesion: 0.10
Nodes (44): Task 2: Счётчик клиентов в навигации, 2. Обзор и навигация (панель, только фронт), acceptPage(), loadPage(), pageUrl(), renderClients(), bytes(), icon() (+36 more)

### Community 241 - "i18n-strings.py"
Cohesion: 0.26
Nodes (7): _clean(), fragments(), main(), _read_string(), _read_template(), _scan_code(), _skip_comment()

### Community 242 - "routes.py"
Cohesion: 0.15
Nodes (9): redact_document(), ExitImportBody, ExplainBody, GeodataSettingsBody, GeodataSourceBody, LaneModeBody, history(), RelayEnableBody (+1 more)

### Community 243 - "CommandRunner"
Cohesion: 0.15
Nodes (4): CommandRunner, test_command_runner_reports_captured_stderr_for_failed_command(), test_compose_discovery_reports_unavailable_when_docker_is_not_installed(), test_compose_reconciliation_uses_declared_project_identity()

### Community 244 - "English"
Cohesion: 0.20
Nodes (9): Changes, Deployment and rollback, English, v0.14.0-beta.1 — совместное использование 443 и приёмка Naive, Validation scope, Изменения, Развёртывание и откат, Русский (+1 more)

### Community 245 - "test_fleet_v2_node_api.py"
Cohesion: 0.16
Nodes (17): _doc(), _node_key(), _push(), test_a_push_landing_during_unlink_cannot_resurrect_managed_rows(), test_capture_answers_null_not_500_while_telemt_is_down(), down(), test_capture_unlink_and_versions_update(), test_central_owned_users_refuse_local_mutation_and_leave_local_inventory() (+9 more)

### Community 246 - "InstallPlan"
Cohesion: 0.07
Nodes (19): InstallPlan, AcceptedDigestError, _canonical_json(), _checkpoint_data(), _evidence_to_dict(), _freeze(), _freeze_mapping(), _plan_from_dict() (+11 more)

### Community 247 - "ipaddress"
Cohesion: 0.18
Nodes (5): _main(), _pump(), _read_target(), _reply(), Stub

### Community 248 - "Xray egress-router spike (v0.5, Task 32)"
Cohesion: 0.33
Nodes (5): Decision, Results — Mieru via the router (`mieru` ingress), Results — NaiveProxy via the router (`naive` ingress), Results — the router itself, Xray egress-router spike (v0.5, Task 32)

### Community 249 - "test_access_enforcement.py"
Cohesion: 0.17
Nodes (20): _drifted_report(), _enabled(), _local(), test_background_timer_expires_access_without_a_request(), test_drift_report_does_not_infer_node_runtime_from_central_clock(), test_lifespan_enforces_expired_local_access_before_serving(), test_local_clock_transition_enables_then_expires_without_request(), test_local_enable_cannot_bypass_suspension_or_expiry() (+12 more)

### Community 250 - "Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация"
Cohesion: 0.07
Nodes (29): 10.1 Парк с нуля (центр + два узла), 10.2 Добавить узел в существующий парк, 10.3 Выдать доступ клиенту на другом узле, 10.4 Включить WARP для сервиса на узле, 10.5 Вывести узел из парка, 10. Сквозные чек-листы, 1. Термины, 2.1 Один узел: что на нём работает (+21 more)

### Community 251 - "Рабочий протокол для AI-агентов"
Cohesion: 0.22
Nodes (9): Главное правило, Изолированная установка и реальные проверки, Обязательные проверки репозитория, Перед изменением, Правила, которые уже спасали от ложных отчётов, Правила отчёта, Проверка всех Compose-моделей и образов, Рабочий протокол для AI-агентов (+1 more)

### Community 252 - "test_client_links.py"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 253 - "English"
Cohesion: 0.18
Nodes (11): Added, Changed, English, Fixed, Upgrading from v1.0.0, v1.0.1 — любые версии компонентов, региональные geodata с автообновлением, Добавлено, Изменено (+3 more)

### Community 256 - "safe_extract_zip"
Cohesion: 0.25
Nodes (15): Task 2: Артефакт Xray в каталоге релиза и `safe_extract_zip`, _copy_zip_member(), MemberPin, safe_extract_zip(), _validate_zip_members(), _pins(), _sha(), test_safe_extract_zip_extracts_named_members_only() (+7 more)

### Community 258 - ".step_05c_chains"
Cohesion: 0.10
Nodes (9): Task 12: Лаборатория — staging, `lab-host` с роутером, сценарии `router-*`, tier `router`, redact(), lane_built(), slot_learned(), warp_reachable(), settled(), settled(), settled() (+1 more)

### Community 259 - "EgressConfig"
Cohesion: 0.16
Nodes (8): Task 0: Ветка, спека, план, Task 11: Лаборатория — сценарии routing и tier `routing`, Task 12: Документация, ADR, CHANGELOG, VERSION, Task 13: Гейт релиза и живая проверка (Task 31A), Task 3: Установщик — секция `[egress]` (Task 28), Task 5: mieru-manager — egress API (Task 29b), Структура файлов, EgressConfig

### Community 260 - "SecurityHeadersMiddleware"
Cohesion: 0.33
Nodes (3): send(), SecurityHeadersMiddleware, secured_send()

### Community 261 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`, tree `841a086`, 2026-09-14), Installing, Live check (AMS_Z), Proxy Control v0.4.0-beta.1, Screenshots, Upgrading, What's new (+7 more)

### Community 264 - "test_routing_ui_contract.py"
Cohesion: 0.08
Nodes (9): _interpolations(), test_every_interpolated_value_from_the_api_is_escaped(), test_routing_card_forgets_the_previous_policy_before_it_paints(), test_routing_js_seam_fixes_of_v09(), test_routing_js_speaks_lanes_chains_and_the_relay(), test_routing_js_speaks_presets_exits_and_geodata(), test_routing_js_speaks_the_router(), test_routing_js_tells_the_operator_when_the_node_already_runs_the_policy() (+1 more)

### Community 267 - "ADR 008: Panel-to-panel transport with scoped API keys"
Cohesion: 0.40
Nodes (5): ADR 008: Panel-to-panel transport with scoped API keys, Consequences, Context, Decision, Non-goals

### Community 269 - "8.2 Локальный узел"
Cohesion: 0.40
Nodes (5): 8.1 API (`panel/routing/routes.py`, owner для мутаций, viewer — чтение), 8.2 Локальный узел, 8.3 Подключённые панели (Fleet v2), 8.4 UI («Маршрутизация», `panel/static/js/routing.js`), 8. Панель

### Community 270 - "ThreeXuiClient"
Cohesion: 0.13
Nodes (5): _default_api_factory(), _Sanitized, ThreeXuiClient, test_api_refuses_a_non_loopback_endpoint(), test_panel_client_uses_tls_and_pins_certificate_before_credentials()

### Community 271 - "Host"
Cohesion: 0.10
Nodes (5): Docker, Host, main(), parse_args(), RoutingProbes

### Community 272 - "register_node_routes"
Cohesion: 0.17
Nodes (16): _local_identity(), _local_services(), _probe(), register_node_routes(), _context(), disable(), enable(), node() (+8 more)

### Community 273 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.14, v0.15.0-beta.1 — версия панели и обновления узлов из центра, Добавлено, Исправлено, Обновление с v0.12–v0.14 (+1 more)

### Community 274 - "Check"
Cohesion: 0.11
Nodes (10): UI, v0.3 — задачи после слияния (post-merge issues), Спека (follow-ups, не дефекты реализации), Стенд и приёмка, assert_secret_free(), walk(), mtproxy_secret(), NodeB (+2 more)

### Community 276 - "The Xray-router (v0.5): one dedicated egress router per node"
Cohesion: 0.18
Nodes (11): A third ingress: MTProxy (v1.1), Credentials and rotation, DNS and private destinations, Lanes, chains and the relay (v0.7), Limits and what is deferred, Operations, The runtime, The transaction (+3 more)

### Community 277 - "script"
Cohesion: 0.11
Nodes (12): script(), FakeConnection, FakeResponse, serve(), test_api_refuses_an_oversized_response(), script(), test_login_fetches_a_csrf_token_and_sends_it(), script() (+4 more)

### Community 278 - "test_xray_routing_compiler.py"
Cohesion: 0.23
Nodes (27): Task 7: Routing IR — backend `xray_router`, `geosites/geoips`, миграция 15, компилятор, _lane(), Resolver, test_a_service_without_lanes_or_node_exits_still_compiles_to_schema_1(), test_compiling_a_lane_policy_folds_the_service_and_the_other_lanes(), test_explain_walks_a_lanes_rules_for_a_destination(), test_lanes_and_node_exits_need_the_router_and_the_attachment(), test_lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains() (+19 more)

### Community 279 - "_panel_probe"
Cohesion: 0.25
Nodes (3): _panel_probe(), test_a_panel_that_answers_with_an_error_code_reports_that_code(), test_a_panel_that_cannot_be_reached_still_raises()

### Community 280 - "Ownership boundaries and adapter order"
Cohesion: 0.08
Nodes (34): certificates adapter, firewall adapter, naive adapter, nginx adapter, 3x-ui acceptance evidence, three_xui adapter, Адаптер certificates, Адаптер firewall (+26 more)

### Community 281 - "_await_panel_health"
Cohesion: 0.29
Nodes (3): _await_panel_health(), test_panel_acceptance_gives_up_and_reports_the_last_refusal(), test_panel_acceptance_waits_for_the_panel_instead_of_racing_it()

### Community 282 - "Xray-router (v0.5): один выделенный egress-роутер на узел"
Cohesion: 0.18
Nodes (11): DNS и приватные адреса, Xray-router (v0.5): один выделенный egress-роутер на узел, Ключи и ротация, Ограничения и что отложено, Полосы, цепи и relay (v0.7), Рантайм, Транзакция, Третий вход: MTProxy (v1.1) (+3 more)

### Community 283 - "test_subscription_http.py"
Cohesion: 0.06
Nodes (29): [1.0.3] - 2026-10-01, Added, English, Fixed, Upgrading from v1.0.2, v1.0.3 — скрипт установки в каждом выпуске, исправленный мастер установки, Добавлено, Исправлено (+21 more)

### Community 284 - "Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext"
Cohesion: 0.07
Nodes (28): The policy, Политика, 10. Spike (Task 32) — что проверяется на стенде, 11. Безопасность, 12. Backup/restore и матрица негативных тестов (Tasks 37, 39), 13. Лаборатория и гейт (Tasks 36, 40), 14. Документация и релиз (Task 41), 15. Отклонения от спеки vNext и решения, принятые за владельца (+20 more)

### Community 285 - "TelemtAdapter"
Cohesion: 0.02
Nodes (64): Runtime users (protocol routes), Task 4: Адаптеры — caller-supplied secret для Telemt и `update_options`, Task 6: Панель — клиенты менеджеров и адаптеры egress, AccessArtifact, AdapterError, applied_egress_from_view(), AppliedEgress, AppliedGrant (+56 more)

### Community 286 - "dashboard"
Cohesion: 0.10
Nodes (17): Task 2: Tier `ui` — драйвер и view без второй панели, 1. Цель, 2. Что уже доказано (не переделывается), 3.1 Матрица сверки — `docs/VERIFICATION_MATRIX.md` + `tests/fixtures/verification-matrix.json`, 3.2 Аудит маршрутов — `scripts/dev/route-coverage.py`, 3.3 Tier `ui` — `scripts/lab/ui-acceptance.py` (+ `remote-gate.sh ui`), 3.4 Бэкенд: дыры в лабораторном покрытии, 3.5 Живая проверка на AMS_Z (по разрешению владельца) (+9 more)

### Community 287 - "XrayRouterAdapter"
Cohesion: 0.10
Nodes (3): _command_failure(), XrayRouterAdapter, XrayRouterError

### Community 289 - "proxy-control-lab-clients Compose project"
Cohesion: 0.23
Nodes (16): Post-install acceptance checks, Installer transaction steps 1–7, External MTProto probe (TDLib addProxy/pingProxy), Приёмка после установки, Шаги транзакции установщика 1–7, Внешняя проба MTProto (TDLib), --config … --expect-status probe contract, https-cover curl probe (+8 more)

### Community 290 - "test_fleet.py"
Cohesion: 0.08
Nodes (24): Executor, build_executor(), main(), required(), run(), CommandConflict, ExecutionIndeterminate, LocalTelemtExecutor (+16 more)

### Community 292 - "The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP"
Cohesion: 0.22
Nodes (9): Connecting, How to enable, Rotating the token and the key, Skills, The `confirm` rule, The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP, Turning it off, Verification (+1 more)

### Community 293 - "vNext capability matrix"
Cohesion: 0.40
Nodes (5): Control-plane access enforcement, Protocols and the Fleet v1 transport, Spike plan before any routing claim, Subscription clients, vNext capability matrix

### Community 294 - "MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP"
Cohesion: 0.22
Nodes (9): MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP, Выключить, Как включить, Подключение, Правило `confirm`, Проверка, Ротация токена и ключа, Скиллы (+1 more)

### Community 295 - "Isolated Ubuntu 24.04 installer lab"
Cohesion: 0.05
Nodes (56): attest job, build-twice-and-compare job, draft-release job, lab-amd64 job, publish job, quality job, Release workflow, Tag, VERSION and manifest agreement check (+48 more)

### Community 296 - "6. Центр и узлы: привязка панелей"
Cohesion: 0.14
Nodes (13): 6.1 Порядок раскатки парка, 6.2 Подготовка узла, 6.3 Привязка: три действия на центре, 6.4 Импорт существующих пользователей узла, 6.6 Отвязка, удаление, ротация ключа, 6. Центр и узлы: привязка панелей, CONTINUE HERE — v0.7 (цепи и полосы), Выпуск (сделано 2026-09-18 10:16–12:50 UTC) (+5 more)

### Community 299 - "test_dashboard_ui_contract.py"
Cohesion: 0.14
Nodes (3): test_host_card_follows_the_host_while_the_overview_is_open(), test_overview_placeholder_has_the_overviews_own_shape(), test_panel_version_is_on_screen_for_every_role_and_on_a_phone()

### Community 300 - "English"
Cohesion: 0.14
Nodes (14): English, Installing, Live check (AMS_Z), Proxy Control v0.5.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z) (+6 more)

### Community 301 - "Granting access to a client"
Cohesion: 0.40
Nodes (4): Granting access to a client, Link variants (`subscription.variants`), Pitfalls, Report to the owner

### Community 302 - "CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)"
Cohesion: 0.40
Nodes (4): CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт), Сделано, Что дальше, Что оставлено на хостах

### Community 303 - "xray_router_manager/healthcheck.py"
Cohesion: 0.20
Nodes (8): test_healthcheck_relay_flags_post_and_get(), test_healthcheck_status_flag_prints_the_manager_status(), check(), main(), relay(), relay_enable(), _request(), status()

### Community 305 - "test_mieru_management.py"
Cohesion: 0.05
Nodes (12): check(), main(), _password(), request(), StubManager, test_deleting_on_the_protocol_pages_takes_the_kept_grant_with_it(), test_manager_healthcheck_uses_authenticated_unix_health_endpoint(), test_manager_unix_api_is_authenticated_bounded_and_no_store() (+4 more)

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
Nodes (33): [0.10.0-beta.1] - 2026-09-21, [0.11.0-beta.1] - 2026-09-22, [0.12.0-beta.1] - 2026-09-22, [0.13.0-beta.1] - 2026-09-23, [0.14.0-beta.1] - 2026-09-23, [0.15.0-beta.1] - 2026-09-23, [0.4.0-beta.1] - 2026-09-14, [0.6.0-beta.1] - 2026-09-17 (+25 more)

### Community 311 - "test_view_addressing_ui.py"
Cohesion: 0.21
Nodes (7): index_html(), main_js(), test_an_unknown_or_forbidden_view_falls_back_to_the_overview(), test_back_and_forward_move_between_views(), test_boot_opens_the_view_the_address_names(), test_every_menu_item_has_an_address(), test_navigation_writes_the_view_into_the_address()

### Community 312 - "rotate-xray-router-ingress.sh"
Cohesion: 0.27
Nodes (10): compose(), fail(), MIERU_MANAGER_UID, NAIVE_MANAGER_GID, NAIVE_MANAGER_UID, random_hex(), random_password(), ROUTER_GID (+2 more)

### Community 315 - "_DefaultXrayRouterRunner"
Cohesion: 0.11
Nodes (4): 3.6 Исправления, _DefaultXrayRouterRunner, test_the_real_runner_fetches_over_https_only(), test_the_real_runner_sees_only_the_router_compose_service()

### Community 316 - "_preparer"
Cohesion: 0.40
Nodes (4): _preparer(), test_state_preparer_refuses_a_symlinked_boundary(), test_state_preparer_refuses_unnormalized_and_relative_paths(), test_state_preparer_requires_root()

### Community 317 - "Живая проверка (AMS_Z ↔ ams-test)"
Cohesion: 0.14
Nodes (14): English, Gate checklist (lab host `ams-test`, tree `ade7fcc`, 2026-09-14 — after the three rounds of the final-review fix wave), Installing, Proxy Control v0.3.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z ↔ ams-test) (+6 more)

### Community 319 - "test_telemt_recovery.py"
Cohesion: 0.19
Nodes (10): anyio_backend(), _client(), telemt(), test_a_reply_lost_after_the_request_was_sent_is_indeterminate(), timeout(), test_a_request_that_never_left_is_a_plain_failure_not_indeterminate(), test_current_access_reads_the_live_link_from_the_user_listing(), listing() (+2 more)

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
Cohesion: 0.16
Nodes (13): _render(), _seed(), test_a_locally_imported_mtproxy_user_renders_with_telemts_link_host(), test_a_remotely_imported_mtproxy_user_renders_with_the_nodes_telemt_link_host(), test_a_username_the_runtime_already_uses_is_refused_before_anything_is_written(), test_adopt_batch_reports_what_it_could_not_take(), test_adopting_an_imported_grant_makes_it_renderable(), test_import_can_attach_to_an_existing_client() (+5 more)

### Community 324 - "Telemt MTProto data plane"
Cohesion: 0.40
Nodes (3): Private-network Caddy mask / cover site, Host Nginx stream/SNI router, Telemt MTProto data plane

### Community 325 - "ADR 002: Declarative immutable generations"
Cohesion: 0.40
Nodes (5): ADR 002: Declarative immutable generations, Consequences, Context, Decision, Non-goals

### Community 326 - "AccessGrant"
Cohesion: 0.03
Nodes (40): Context, Decision, Task 10: Lifecycle грантов (enable/disable/rotate/delete) для local и remote, Узел (fleet_v2 node, local lifecycle), Что уже сделано (Tasks 0–14), Decision records, Goal of v0.2, Release train (+32 more)

### Community 329 - "i18n.js"
Cohesion: 0.09
Nodes (32): Gate checklist (lab host `ams-test`), English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.6.0-beta.1, Screenshots, Upgrading (+24 more)

### Community 330 - "test_api_key_auth.py"
Cohesion: 0.46
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 331 - "test_fleet_v2_central_routes.py"
Cohesion: 0.15
Nodes (5): central_http(), test_fingerprint_private_address_requires_explicit_opt_in(), test_fingerprint_request_deadline_also_bounds_slow_system_dns(), test_link_rejects_bad_key_private_url_and_self(), test_node_version_update_is_relayed_to_the_node_and_audited_on_both_sides()

### Community 335 - "English"
Cohesion: 0.22
Nodes (9): English, Fresh install, Upgrading from v0.9 or v0.10, v0.11.0-beta.1 — обновления из upstream, What changed for you, Обновление с v0.9 или v0.10, Русский, Установка с нуля (+1 more)

### Community 336 - "English"
Cohesion: 0.22
Nodes (9): English, Installer fixes, Installing, Proxy Control v0.2.0-beta.1, Verified for this release (on the lab host), Исправлено в установщике, Проверено для этого выпуска (на стенде), Русский (+1 more)

### Community 341 - "Структура файлов"
Cohesion: 0.20
Nodes (9): Global Constraints, Task 0: Ветка, спека, план, Task 1: Инвентарь функций и матрица сверки (TDD: тест-страж первым), Task 3: Tier `ui` — центр (вторая панель) и Fleet-экраны, Task 4: Дыры бэкенда, Task 5: Живая проверка AMS_Z, Task 6: Релиз, v0.6 Verification Implementation Plan (+1 more)

### Community 343 - "English"
Cohesion: 0.22
Nodes (9): English, Installing, Upgrading from v0.11, v0.12.0-beta.1 — адрес у каждого раздела, ссылки MTProxy в карточке клиента, What changed for you, Обновление с v0.11, Русский, Установка с нуля (+1 more)

### Community 345 - "test_placement_ui_contract.py"
Cohesion: 0.30
Nodes (6): run(), test_diff_creates_enables_and_disables_from_ticks(), test_render_marks_cells_and_disables_what_cannot_change(), test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants(), test_settling_is_true_while_a_node_has_not_confirmed_and_ignores_deleted_grants(), test_unoffered_rows_are_never_part_of_the_diff()

### Community 346 - "test_clients_filters_ui.py"
Cohesion: 0.39
Nodes (5): _node(), test_import_still_offers_clients_outside_the_current_page(), test_paging_and_server_search_keep_the_dom_bounded_and_discard_stale_responses(), test_search_and_filters_select_the_right_clients(), test_the_card_lists_clickable_grant_rows_and_escapes_names()

### Community 347 - "json"
Cohesion: 0.04
Nodes (30): _decode_adjacent_routes(), _valid_adjacent_backend(), _download(), ensure_pinned_package(), _identity_from_entry(), _sanitize_diagnostic(), _canonical_ip(), _environment_secret_values() (+22 more)

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

### Community 357 - "RuntimeInstaller"
Cohesion: 0.16
Nodes (3): RuntimeInstaller, operation(), operation()

### Community 358 - "Accounting semantics"
Cohesion: 0.05
Nodes (47): Accounting semantics, Mieru rolling session-admission quota, Naive completed-CONNECT byte collector, Telemt total_octets and quota usage counter, Proxy Control architecture, Caddy/NaiveProxy runtime and manager, Complete COMPOSE_FILE overlay set, FastAPI panel on loopback (+39 more)

### Community 359 - "test_a_download_that_does_not_match_its_pin_is_discarded"
Cohesion: 0.25
Nodes (4): test_a_download_that_does_not_match_its_pin_is_discarded(), test_a_missing_package_is_fetched_from_its_pin(), fetch(), test_a_package_that_is_already_staged_is_not_fetched_again()

### Community 370 - "AgentJournal"
Cohesion: 0.14
Nodes (8): ADR 001: Pull-only node transport, Consequences, Context, Decision, Non-goals, TypedCommand, AgentJournal, test_node_journal_does_not_retry_removed_mieru_outbox()

### Community 373 - "test_routing_routes.py"
Cohesion: 0.48
Nodes (5): _csrf(), test_apply_rollback_delete_and_history(), test_preview_of_a_draft_does_not_save(), test_put_upserts_with_expected_revision_and_keeps_rule_ids(), test_viewer_reads_and_previews_but_never_mutates()

### Community 376 - "ADR 004: Client, AccessGrant and subscription as a projection"
Cohesion: 0.50
Nodes (4): ADR 004: Client, AccessGrant and subscription as a projection, Consequences, Context, Non-goals

### Community 377 - "v1.1 — маршрутизация MTProxy через Xray-router"
Cohesion: 0.15
Nodes (12): 1. Цель, 2. Что доказано на стенде (ams-test, 2026-10-01), 3. Топология, 4. Xray-router (менеджер), 5. Мост `xray-router-ingress`, 6. Панель, 7. Установщик, 7a. Обновление одной командой (добавлено владельцем 2026-10-01) (+4 more)

### Community 386 - "config"
Cohesion: 0.20
Nodes (6): _relay_config(), RelayRunner, test_a_router_action_without_relay_keys_still_applies_and_verifies(), test_router_apply_enables_the_relay_and_verify_proves_its_public_part(), test_router_plan_carries_the_relay_and_refuses_a_claimed_relay_port(), config()

### Community 393 - "ADR 009: Lanes per client and chains through the fleet's relays"
Cohesion: 0.50
Nodes (4): ADR 009: Lanes per client and chains through the fleet's relays, Consequences, Context, Decision

### Community 394 - "Исправления по аудиту v1.1.0"
Cohesion: 0.50
Nodes (3): Исправления по аудиту v1.1.0, Исходные доказательства, Последовательность

### Community 400 - "ADR 005: Secrets travel as references"
Cohesion: 0.40
Nodes (5): ADR 005: Secrets travel as references, Consequences, Context, Decision, Non-goals

### Community 405 - "test_socks5_stub.py"
Cohesion: 0.14
Nodes (9): Task 2: Spike — нативные возможности Caddy forwardproxy и mita (Task 30), Probes, _connect_through(), _echo(), _load(), _refuses(), _relays(), test_stub_logs_connect_target_and_relays() (+1 more)

### Community 411 - "English"
Cohesion: 0.22
Nodes (9): Added, Changed, English, Upgrading from v1.0.3, v1.1.0 — маршрутизация MTProxy через Xray-router, Добавлено, Изменено, Обновление с v1.0.3 (+1 more)

### Community 412 - "test_fetch_reports_the_hop_that_names_the_release"
Cohesion: 0.20
Nodes (4): test_fetch_reports_the_hop_that_names_the_release(), build_opener(), fetch(), redirect_request()

### Community 413 - "remote-gate.sh"
Cohesion: 0.36
Nodes (7): Baseline main@8c787c5 (2026-09-10), Audit finding 15: Baseline on ams-test, Verification levels A-F (quick, full, compose, lab-container, lab-host, real install), Task 0: ams-test stand and baseline, remote(), remote-gate.sh script, sync_tree()

### Community 421 - "update-host.sh"
Cohesion: 0.46
Nodes (7): agent(), fail(), has(), health(), json(), say(), update-host.sh script

### Community 426 - "warp_routing"
Cohesion: 0.40
Nodes (4): warp_routing(), test_warp_appends_rules_without_replacing_the_final_policy(), test_warp_emits_nothing_when_disabled(), test_warp_requires_operator_confirmed_domains()

### Community 430 - "ProtocolError"
Cohesion: 0.13
Nodes (13): ProtocolError, validate_inventory(), validate_payload(), validate_result(), _walk_secret_free(), AgentTransportClient, test_typed_protocol_rejects_generic_commands_and_unknown_payload_fields(), _csrf() (+5 more)

### Community 435 - "ADR 007: Routing enforcement ownership"
Cohesion: 0.67
Nodes (3): ADR 007: Routing enforcement ownership, Context, Decision

### Community 444 - "full_config"
Cohesion: 0.28
Nodes (8): facts_with_uid(), full_config(), test_naive_plan_adopts_its_own_reserved_identities(), test_naive_plan_is_empty_without_the_naive_profile(), test_naive_plan_keeps_only_audited_adjacent_routes(), test_naive_plan_stops_on_fixed_accounting_group_collision(), test_naive_plan_stops_on_fixed_identity_collision(), test_naive_sends_every_tunnel_through_warp_when_it_is_enabled()

## Ambiguous Edges - Review These
- `Beam vs Hammer Clash Metaphor` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: rationale_for
- `Proxy Control Repository Branding Asset` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: conceptually_related_to
- `WARP as one loopback SOCKS5 endpoint` → `WARP as one SOCKS5 endpoint 127.0.0.1:40000`  [AMBIGUOUS]
  CHANGELOG.md · relation: semantically_similar_to

## Knowledge Gaps
- **670 isolated node(s):** `telemt-entrypoint.sh script`, `install.sh script`, `entrypoint.sh script`, `TELEMT_API_TOKEN_FILE`, `API_REASONS` (+665 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 3568 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **112 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Beam vs Hammer Clash Metaphor` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: rationale_for) - confidence is low._
- **What is the exact relationship between `Proxy Control Repository Branding Asset` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `WARP as one loopback SOCKS5 endpoint` and `WARP as one SOCKS5 endpoint 127.0.0.1:40000`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **Why does `vNext architecture (v0.2 and v0.3)` connect `AccessGrant` to `test_routing_fleet_chains.py`, `Proxy Control documentation index`, `app.py`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Why does `Матрица негативных и security-тестов vNext (Task 39)` connect `Матрица негативных и security-тестов vNext (Task 39)` to `safe_extract_zip`, `PolicyInput`, `Scenario`, `test_fleet_v2_reconcile.py`, `test_naive_manager_egress.py`, `test_fleet_acceptance_script.py`, `test_fleet_v2_post_merge.py`, `script`, `test_xray_routing_compiler.py`, `test_installer_transaction.py`, `EgressInvalid`, `test_subscription_http.py`, `Proxy Control documentation index`, `test_fleet.py`, `test_routing_fleet_chains.py`, `GrantIntent`, `test_rbac_audit.py`, `ReleaseManifest`, `test_mieru_manager.py`, `naive_manager/egress.py`, `test_installer_release.py`, `render_config`, `DeployCliTests`, `test_users_adapter_ui.py`, `test_routing_router_service.py`, `AccessGrant`, `test_fleet_v2_central_routes.py`, `test_routing_service.py`, `test_grant_lifecycle.py`, `Database`, `CertificateAuthority`, `test_mieru_egress.py`, `test_installer_xray_router.py`, `test_fleet_v2_node_api.py`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Why does `Proxy Control documentation index` connect `Proxy Control documentation index` to `Accounting semantics`, `Proxy Control v0.1.0 Beta`, `Proxy Control`, `Панель управления Proxy Control`, `Sharing Mieru configurations`, `install-bootstrap`, `Управление Mieru / mita 3.35–3.36`, `Troubleshooting Proxy Control`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `Action` (e.g. with `Adapter` and `CoreAdapter`) actually correct?**
  _`Action` has 38 INFERRED edges - model-reasoned connections that need verification._