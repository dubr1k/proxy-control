# Graph Report - proxy-control-rc2-hardening  (2026-10-03)

## Corpus Check
- 552 files · ~1,128,413 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 40 file(s) not represented in the graph (top: (none) 14, .service 8, .conf 5)

## Summary
- 12877 nodes · 36759 edges · 452 communities (329 shown, 123 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 3832 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `485183b6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_routing_fleet_router.py
- AccessGrant
- Database
- json
- GrantRef
- test_installer_wizard.py
- GrantIntent
- test_installer_three_xui.py
- MemoryXrayRouter
- NaiveCredentialManager
- ThreeXuiAdapter
- parse_config
- Proxy Control
- test_naive_manager.py
- PlanError
- create_app
- RoutingService
- Troubleshooting Proxy Control
- esc
- InstallerConfig
- OwnershipError
- test_installer_version_agent.py
- VersionAgent
- ._sync_client
- TrafficCollector
- test_fleet.py
- test_xray_router_geodata.py
- nodes.js
- RoutingRule
- test_installer_mcp.py
- Панель управления Proxy Control
- CoreError
- XrayRouterManager
- install-bootstrap
- upstream
- ManagedStore
- MieruAdapter
- version_agent/service.py
- test_mieru_management.py
- docs/README.md
- CommandRunner
- test_installer_mieru.py
- NaiveAdapter
- test_installer_nginx.py
- Isolated Ubuntu 24.04 installer lab
- MieruManager
- Sharing Mieru configurations
- ExitInput
- common.js
- mcp_server/server.py
- installer/audit.py
- RuntimeInstaller
- AuditFacts
- Матрица негативных и security-тестов vNext (Task 39)
- EgressInvalid
- release.py
- test_installer_fresh_host.py
- test_installer_naive.py
- test_version_agent_panel.py
- test_mieru_manager.py
- naive_manager/egress.py
- xray_router_manager/service.py
- firewall.py
- _DefaultNaiveRunner
- Управление Mieru / mita 3.35–3.36
- main.js
- wizard.py
- Action
- test_version_agent.py
- test_mieru_egress.py
- test_installer_xray_router.py
- test_mieru_manager_lanes.py
- DomainFacade
- NodeClient
- test_installer_credentials.py
- compile
- test_subscription_events.py
- XrayRouterAdapter
- register_routing_routes
- TelemtAdapter
- DeployCliTests
- CDP
- test_proxyctl_runtime.py
- Planned File Structure
- vNext v0.2 local control plane implementation plan
- clients.js
- app.py
- curated.py
- panel
- test_installer_release.py
- installer/cli.py
- Scenario
- test_installer_transaction.py
- query
- English
- test_fleet_v2_reconcile.py
- qemu_lab.py
- .step_05c_chains
- CentralProcess
- UnixHTTPServer
- _DefaultMieruRunner
- _Checked
- test_node_lifecycle.py
- Reconciler
- test_installer_docs.py
- ProtocolError
- config
- PolicyInput
- v1.1.0 audit and rc.2 acceptance report
- isCurrent
- test_naive_manager_egress.py
- test_mieru_deployment.py
- Interactive Release Installer Design
- test_installer_cli.py
- test_grant_lifecycle.py
- test_mcp_server.py
- _DefaultCoreRunner
- Accounting semantics
- MieruClient
- build.py
- TransactionEngine
- test_naive_manager_lanes.py
- proxyctl.py
- grant.js
- XrayError
- i18n.js
- Host
- Dedicated Proxy-Control-owned xray-router
- managed-xui-clients.py
- MemoryMieru
- tools.py
- guest-runner.sh
- test_release_build.py
- Журнал изменений
- Panel version-agent
- test_xray_routing_compiler.py
- PackagesAdapter
- test_installer_reports.py
- main
- Ownership boundaries and adapter order
- renderers/base.py
- test_installer_warp_transaction_recovery.py
- test_version_agent_host.py
- _render_at_phone_viewport
- WarpAdapter
- test_proxyctl_transactions.py
- QemuLabTests
- Store
- mieru_manager/service.py
- test_fleet_v2_node_api.py
- prepare-naive-state.py
- MitaCLI
- FleetStore
- test_panel_entrypoint.py
- Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация
- _DefaultXrayRouterRunner
- TopologyError
- Acceptance
- test_three_xui_api.py
- NaiveClient
- BoundedBodyMiddleware
- index.cjs
- test_update_host.py
- register_fleet_v2_central_routes
- DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)
- test_routing_router_service.py
- ThreeXuiApiError
- test_users_adapter_ui.py
- test_xray_router_mtproxy.py
- fleet.js
- CatalogError
- ReleaseManifest
- test_subscription_lifecycle.py
- test_routing_ui_contract.py
- 3x-ui mode: managed-new
- Check
- ingress_upgrade.py
- XrayRouterClient
- importer.py
- v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router
- document_digest
- CertificateAuthority
- register_fleet_v2_node_routes
- full_config
- RouterTarget
- Keyring
- WizardIO
- Task 6: Encrypted secret versions and master key
- .compose
- safe_extract_zip
- Browser
- LaneService
- _PinningStream
- v0.11 — обновления из upstream и обзор в одну строку
- QuotaEnforcer
- MemoryTelemt
- test_fleet_acceptance_script.py
- test_routing_service.py
- TelemtClient
- pytest
- Global Constraints
- Task 4: Unified DB layer and migrations
- FakeFleet
- script
- MTProxy acceptance failure: Connection closed
- core_checks
- Installer CLI commands
- test_routing_presets.py
- AgentTransportServer
- register_subscription_admin_routes
- StubManager
- docker_lab.py
- xray_router_manager/healthcheck.py
- warp_routing
- Task 1: ADRs and v0.2 architecture record
- Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext
- ThreeXuiClient
- RuntimeRunner
- test_routing_lanes_routes.py
- Router
- test_version_agent_artifacts.py
- English
- Proxy Control v0.1.0 Beta
- English
- Disposable lab host ams-test
- CommandRunner
- Task 3.2: installer deploys WARP automatically
- English
- _panel_health_diagnosis
- test_installer_chains.py
- ensure_pinned_package
- register_auth_admin_audit_routes
- test_client_links.py
- register_node_routes
- .view_central
- test_placement_ui_contract.py
- English
- v0.10 — клиент на нескольких узлах и подписка под рукой
- accepted_sha256
- RelayRegistry
- test_cleanup_signals_process_group_even_if_leader_exited
- test_dashboard_ui_contract.py
- test_view_addressing_ui.py
- CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22
- v0.11 Upstream Updates & MCP Handoff
- 3. Задачи
- 3x-ui mode managed-new: install on clean server, create inbounds
- English
- host.py
- admin
- v1.1 — маршрутизация MTProxy через Xray-router
- config
- ManagerHandler
- run_captured
- .handle
- test_xray_router_deployment.py
- compose fleet-agent overlay service
- CorePaths
- AgentJournal
- i18n-strings.py
- guest-runner.sh script
- NaivePaths
- CONTINUE-HERE.md
- English
- test_proxyctl.py
- English
- English
- The Xray-router (v0.5): one dedicated egress router per node
- Xray-router (v0.5): один выделенный egress-роутер на узел
- ManagedClient
- ManagerHandler
- TelemtIndeterminate
- test_subscription_ui_contract.py
- sbom.py
- rotate-xray-router-ingress.sh
- ReleaseMatrixTests
- test_socks5_stub.py
- Proxy Control Cover Art
- CONTINUE-HERE-v0.7.md
- Аудит Proxy Control v1.1.0 и проверка исправлений rc.2
- FleetPusher
- Trust Boundaries
- prepare_mieru_token.py
- ImageMetadataTests
- Рабочий протокол для AI-агентов
- mieru-client/probe.py
- Audit event names
- MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP
- fleet-measure.py
- English
- English
- English
- The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP
- Verification matrix — maintained functions and their proofs
- test_clients_filters_ui.py
- container_cmd
- installer_cmd
- FakePanel
- test_readiness.py
- test_fetch_reports_the_hop_that_names_the_release
- BearerGate
- Промпт для продолжения работы в новом контексте
- CONTINUE HERE — v0.3 центральная панель
- Промпт для продолжения работы в новом контексте
- Post-rc.2 hardening implementation plan
- status / resume / repair
- ArtifactError
- test_api_key_auth.py
- test_telemt_adapter_does_not_leak_secret_in_errors
- Api
- English
- update-host.sh
- English
- test_the_repository_ignores_its_own_release_outputs
- CONTINUE HERE — v0.4 маршрутизация
- CONTINUE HERE — v0.6 сверка функций v0.2–v0.5
- English
- test_management_ui_contract.py
- test_routing_routes.py
- Handler
- install-release.sh
- Api
- container_setup
- client_probe
- prepare-xray-router-state.sh
- English
- NginxReloadRecovery
- Post-rc.2 update hardening
- test_mtproxy_respq_probe.py
- RuleMatch
- Archived v0.3 credential capture confirmation
- Archived v0.4 remote rollback boundary
- CONTINUE HERE — v0.5 Xray egress-router
- CONTINUE-HERE-v0.9.md
- SecretGenerator
- _serve
- test_route_coverage.py
- Нативная проверка кандидата 1.1.1-rc.3
- test_rbac_audit.py
- probe/install.sh
- secrets
- skills/README.md
- ContainerScenarioTests
- ReleaseFixtureTests
- FakeClock
- Private Vulnerability Reporting Path
- Telemt MTProto data plane
- ADR 001: Pull-only node transport
- ADR 002: Declarative immutable generations
- ADR 005: Secrets travel as references
- Archived v0.1 real traffic acceptance
- CONTINUE HERE — v0.7 (цепи и полосы)
- lab-amd64 CI release lab
- Продолжение работы над Proxy Control
- English
- Русский
- 4. Автоматическое развёртывание узла
- ADR 007: Routing enforcement ownership
- https_probe
- _panel_probe
- .request
- _await_panel_health
- .plan
- GuestRunnerPreflightScripts
- ReleaseRootLayout
- ReleaseConfigMatchesItsFixture
- _preparer
- ADR 004: Client, AccessGrant and subscription as a projection
- CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)
- _deploy_hook_text
- RenderedNaive
- ThreeXuiPaths
- mieru-mss-clamp.sh
- ContainerInputTests
- RecordedRunTests
- SequentialSecrets
- ReleaseArtifactTests
- test_naive_bootstrap_log_matches_the_manager_accounting_writer
- test_store.py
- Archived v0.10 automatic client subscription
- CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой)
- Archived v0.11 upstream component updates
- Archived v0.6 verification matrix
- Archived v0.7 chains and lanes
- ingress_credential
- entrypoint.sh
- test_telemt_client_batches_inventory_reads_until_access_changes
- SecurityHeadersMiddleware
- test_managed_provision_actually_applies_warp_and_subscription
- test_naive_acceptance_tunnels_a_real_inner_tls_session
- ADR 003: One writer per resource
- LabConfigurationsAreValid
- test_installer_naive_command_completion.py
- test_mieru_acceptance_deletes_with_a_compare_and_set_revision
- test_compose_failure_retains_bounded_sanitized_diagnostics
- Screenshot Sanitization Policy
- telemt-entrypoint.sh
- install.sh
- facts_with_uid
- test_the_shared_core_project_is_not_mistaken_for_naive_resources
- Panel dev/test toolchain (pytest, ruff)
- FetchingRunner
- check-deployment.sh
- check-naive-caddy-build.sh
- check-js-syntax.sh
- host-teardown.sh
- three-xui-existing.sh
- test_a_failed_identity_lookup_is_not_a_collision
- test_the_release_manifest_pins_x86_64_only
- uninstall.sh
- v0.10 Multi-node Client & Subscription Handoff
- Archived v0.8 automatic client import
- Archived v0.8 custom exits
- Archived v0.8 geodata updates
- aurora.sky.dubr1kkk.uk (Proxy Control panel, cert: yes)
- comet.sky.dubr1kkk.uk (NaiveProxy, cert: yes)
- nova.sky.dubr1kkk.uk (Hysteria2, cert: yes)
- orion.sky.dubr1kkk.uk (Mieru, cert: no)
- pulsar.sky.dubr1kkk.uk (VLESS Reality XHTTP, cert: no)
- sirius.sky.dubr1kkk.uk (3x-ui panel, cert: yes)
- vega.sky.dubr1kkk.uk (VLESS Reality TCP, cert: no)
- CuratedTool
- _command_failure
- _sanitize_diagnostic
- test_the_verify_tool_runs_as_a_script_from_the_repository_root
- test_the_install_script_names_exactly_the_pinned_artifact_versions
- test_the_knowledge_graph_is_tracked_but_never_shipped

## God Nodes (most connected - your core abstractions)
1. `Action` - 234 edges
2. `AuditFacts` - 196 edges
3. `InstallerConfig` - 145 edges
4. `query()` - 143 edges
5. `Proxy Control` - 132 edges
6. `CoreAdapter` - 130 edges
7. `Database` - 122 edges
8. `GrantIntent` - 111 edges
9. `MieruAdapter` - 108 edges
10. `esc()` - 107 edges

## Surprising Connections (you probably didn't know these)
- `7. Установщик: `[egress]` (Task 28)` --references--> `ConfigError`  [INFERRED]
  docs/superpowers/specs/2026-09-14-v0.4-routing-design.md → installer/config.py
- `What not to do` --references--> `client_subscription()`  [INFERRED]
  skills/proxy-control-diagnosing-access/SKILL.md → mcp_server/curated.py
- `Pitfalls` --references--> `audit_tail()`  [INFERRED]
  skills/proxy-control-granting-access/SKILL.md → mcp_server/curated.py
- `Stop rules` --references--> `audit_tail()`  [INFERRED]
  skills/proxy-control-updating-components/SKILL.md → mcp_server/curated.py
- `Task 5: mieru-manager — egress API (Task 29b)` --references--> `_transaction_mode()`  [INFERRED]
  docs/superpowers/plans/2026-09-14-v0.4-routing.md → mieru_manager/service.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Sequential Project Handoff Documentation Chain** — docs_plans_continue_here_continue_here_md__active, docs_archive_handoffs_readme_handoffs_archive_readme, docs_superpowers_plans_2026_10_02_audit_hardening_audit_hardening_plan__2026_10_02 [EXTRACTED 0.90]
- **Audit Hardening Deployment & Verification Environment** — docs_superpowers_plans_2026_10_02_audit_hardening_audit_hardening_plan__2026_10_02, docs_plans_continue_here_ams_test__staging_host, docs_plans_continue_here_ams_z__production_host, docs_superpowers_plans_2026_10_02_audit_hardening_v1_1_1_rc_2__candidate [EXTRACTED 0.95]
- **Proxy Control vNext Evolution Milestones** — docs_archive_handoffs_continue_here_v0_3_v0_3_central_panel_handoff, docs_archive_handoffs_continue_here_v0_4_v0_4_routing_handoff, docs_archive_handoffs_continue_here_v0_5_v0_5_xray_egress_router_handoff, docs_archive_handoffs_continue_here_v0_6_v0_6_verification_handoff, docs_archive_handoffs_continue_here_v0_10_v0_10_multi_node_client___subscription_handoff, docs_archive_handoffs_continue_here_v0_11_v0_11_upstream_updates___mcp_handoff [EXTRACTED 0.95]
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

## Communities (452 total, 123 thin omitted)

### Community 0 - "test_routing_fleet_router.py"
Cohesion: 0.06
Nodes (36): Task 9: Fleet v2 — `companion`, `egress.router.v1`, порядок применения на узле, удалённые attach/detach, publish_for_client(), compile(), content_digest(), DesiredStore, egress_section(), node_capabilities(), publish() (+28 more)

### Community 1 - "AccessGrant"
Cohesion: 0.03
Nodes (36): Context, Decision, Task 10: Lifecycle грантов (enable/disable/rotate/delete) для local и remote, Task 9: Pusher — heartbeat и доставка поколений, Узел (fleet_v2 node, local lifecycle), Task 4: Подписка выдаётся вместе с клиентом, 6. Центр, Goal of v0.2 (+28 more)

### Community 2 - "Database"
Cohesion: 0.03
Nodes (61): Task 1: Миграция 20 и `secret_ref` у подписки, main(), Database, DatabaseError, apply_migrations(), _columns(), _legacy_upgrade(), Migration (+53 more)

### Community 3 - "json"
Cohesion: 0.03
Nodes (43): load_env(), main(), _decode_adjacent_routes(), _valid_adjacent_backend(), _download(), _identity_from_entry(), _sanitize_diagnostic(), atomic_write() (+35 more)

### Community 4 - "GrantRef"
Cohesion: 0.05
Nodes (19): Runtime users (protocol routes), Task 6: Панель — клиенты менеджеров и адаптеры egress, applied_egress_from_view(), AppliedEgress, AppliedGrant, egress_error(), egress_target_from_view(), GrantRef (+11 more)

### Community 5 - "test_installer_wizard.py"
Cohesion: 0.09
Nodes (27): Locale, pinned_version(), TerminalIO, validate(), WizardSaved, _run_cli_in_pty(), _scripted(), test_a_typed_panel_password_is_saved_privately_and_never_in_the_config() (+19 more)

### Community 6 - "GrantIntent"
Cohesion: 0.02
Nodes (137): Task 7: `NodeClient` — HTTP-клиент центра к узлу, GrantIntent, MtproxyOptions, NaiveOptions, ObservedGeneration, ObservedRelay, ObservedResource, PushResponse (+129 more)

### Community 7 - "test_installer_three_xui.py"
Cohesion: 0.04
Nodes (72): AcceptanceError, parse_reality_keypair(), ThreeXuiConfig, SystemSecrets, adapter(), build_release(), config_with_clients_and_reality_secret(), existing_config() (+64 more)

### Community 8 - "MemoryXrayRouter"
Cohesion: 0.04
Nodes (50): Task 6: Панель — клиент роутера, `RouterTarget`, адаптер, wiring, RouterAdapter, attach_document(), _adapter(), anyio_backend(), Bridge, _item(), stand() (+42 more)

### Community 9 - "NaiveCredentialManager"
Cohesion: 0.05
Nodes (20): Task 4: naive-manager — egress API (Task 29a), _assert_regular(), _assert_safe_parent_chain(), _atomic_write(), _durable_mkdir(), _durable_unlink(), _fsync_directory(), lifecycle_synchronized() (+12 more)

### Community 10 - "ThreeXuiAdapter"
Cohesion: 0.05
Nodes (13): ArtifactError, _client_count(), _DefaultThreeXuiRunner, _plain_audit(), _safe_text(), _tags(), ThreeXuiAdapter, ThreeXuiAudit (+5 more)

### Community 11 - "parse_config"
Cohesion: 0.06
Nodes (75): _as_dict(), _boolean(), ConfigError, _domain(), _domains(), _enum(), _integer(), _keys() (+67 more)

### Community 12 - "Proxy Control"
Cohesion: 0.04
Nodes (85): In-lab verification checklist, Documentation contract runs every documented command through the CLI parser, Pinned external artifacts catalog release/external-artifacts.json, Profiles and adapters (packages, nginx, certificates, firewall, core, naive, mieru, three_xui), Naive site on port-only address with probe resistance, Per-protocol acceptance with real clients, Release acceptance lab (container and bare metal), 0.1.0 — first packaged release (+77 more)

### Community 13 - "test_naive_manager.py"
Cohesion: 0.05
Nodes (71): ManagerHTTPServer, ManagerRecoveryError, _bootstrapped(), Hooks, manager(), test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), test_adapted_semantic_drift_makes_health_unready(), test_additional_basic_auth_outside_managed_block_makes_health_unready() (+63 more)

### Community 14 - "PlanError"
Cohesion: 0.10
Nodes (36): _assert_secret_free(), build_plan(), _canonical_fact_value(), _canonical_json_value(), _freeze(), _nonempty(), PlanError, _sort_key() (+28 more)

### Community 15 - "create_app"
Cohesion: 0.02
Nodes (53): Task 5: Reconciler узла, Task 12: Панель — `check()`, компонент `xray`, `/api/versions/check`, relay для узлов, create_app(), _lifespan(), AccessEnforcer, MemoryNaive, NaiveError, canonical() (+45 more)

### Community 16 - "RoutingService"
Cohesion: 0.05
Nodes (6): direct_document(), lane_policies(), Compiled, RoutingPolicy, RoutingError, RoutingService

### Community 17 - "Troubleshooting Proxy Control"
Cohesion: 0.07
Nodes (33): caddy adapt --adapter caddyfile --validate, Compose reports orphans, panel.cli create-admin --password-stdin, Initial diagnostics, Login failure, MTProxy healthy but clients fail, Naive identity split (manager 10002:101, Caddy 10003:10004, accounting group 10004), Naive manager unhealthy (+25 more)

### Community 18 - "esc"
Cohesion: 0.06
Nodes (102): Task 10: UI «Маршрутизация» (Task 27), Task 10: UI «Маршрутизация» — роутер, esc(), number(), queryAll(), commandRow(), inventoryList(), nodeDetail() (+94 more)

### Community 19 - "InstallerConfig"
Cohesion: 0.06
Nodes (34): Task 0: Ветка, спека, план, Task 11: Лаборатория — сценарии routing и tier `routing`, Task 12: Документация, ADR, CHANGELOG, VERSION, Task 13: Гейт релиза и живая проверка (Task 31A), Task 3: Установщик — секция `[egress]` (Task 28), Task 5: mieru-manager — egress API (Task 29b), Структура файлов, _valid_warp_selector() (+26 more)

### Community 20 - "OwnershipError"
Cohesion: 0.09
Nodes (15): _assert_contained(), durable_copy2(), durable_symlink(), ensure_parent(), fsync_file(), fsync_tree(), operation_lock(), _owned_path() (+7 more)

### Community 21 - "test_installer_version_agent.py"
Cohesion: 0.06
Nodes (36): _command_failure(), _DefaultVersionAgentRunner, _env_key(), _env_values(), VersionAgentAdapter, VersionAgentError, VersionAgentPaths, action_for() (+28 more)

### Community 22 - "VersionAgent"
Cohesion: 0.06
Nodes (13): Global Constraints, Self-review, Task 8: `mita` — обновление закреплённого потребителя вместо отказа, Task 9: Компонент `xray`, v0.11 — обновления из upstream и обзор в одну строку: план реализации, sha256_bytes(), _atomic_write(), ConflictError (+5 more)

### Community 23 - "._sync_client"
Cohesion: 0.13
Nodes (3): _describe(), _ImportState, _inventory_digest()

### Community 24 - "TrafficCollector"
Cohesion: 0.05
Nodes (43): build_manager(), _assert_safe_parent_chain(), _Candidate, _now(), TrafficCollector, collector(), record(), test_active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() (+35 more)

### Community 25 - "test_fleet.py"
Cohesion: 0.07
Nodes (27): Task 0: Spike — принимает ли пиннутый Telemt-форк caller-supplied `secret`, 12. Отклонения от Phase 5 спеки vNext, 3. Архитектурные решения, Executor, build_executor(), main(), required(), run() (+19 more)

### Community 26 - "test_xray_router_geodata.py"
Cohesion: 0.06
Nodes (40): _clocked(), _field(), geodata_file(), _loyal(), _old_meta(), test_a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays(), test_automatic_updates_run_at_the_interval_from_the_watchdog(), test_block_document_still_applies_after_an_update() (+32 more)

### Community 27 - "nodes.js"
Cohesion: 0.07
Nodes (51): Task 12: UI — API-ключи, «Узлы → Добавить панель», карточка узла, выбор узла в «Клиентах», refreshCommands(), updateCommandFieldsAfterRender(), actions(), bindLinkDialog(), bindNodes(), certificateLine(), checklist() (+43 more)

### Community 28 - "RoutingRule"
Cohesion: 0.07
Nodes (32): Task 7: Панель — компилятор v3 (полосы, цепи, причины), ChainHop, _check_lane(), compile_intent(), _diff(), intent_of(), intent_v2(), egress_map() (+24 more)

### Community 29 - "test_installer_mcp.py"
Cohesion: 0.07
Nodes (29): _command_failure(), _DefaultMcpRunner, mcp_handoff(), mcp_url(), McpAdapter, McpError, McpPaths, _plaintext_of() (+21 more)

### Community 30 - "Панель управления Proxy Control"
Cohesion: 0.04
Nodes (103): Synthetic Compose render inputs, Busy buttons: capture event.currentTarget before finally, Client-specific Native/Karing/manual reveals, Host resource card via version-agent GET /v1/host, Generation-specific Karing profile name after rotation, Former host/systemd MTProxy install scripts removed, Atomic SQLite login-attempt reservation before Argon2, Complete mieru-client.json in Native reveal (+95 more)

### Community 31 - "CoreError"
Cohesion: 0.05
Nodes (16): capture(), add(), CoreError, _file_sha256(), _path_sha256(), probe_sources_digest(), _read_existing_users(), RenderedCore (+8 more)

### Community 32 - "XrayRouterManager"
Cohesion: 0.07
Nodes (7): _atomic_write(), ManualInterventionRequired, _now(), revision_of(), _test_failure(), XrayRouterManager, run()

### Community 33 - "install-bootstrap"
Cohesion: 0.05
Nodes (55): Commands, Configuration file, Fleet v1 Telemt-only limit, Hard stops, host_mode (fresh | coexist), initial_user, Interactive release installer reference, Interactive wizard (+47 more)

### Community 34 - "upstream"
Cohesion: 0.04
Nodes (57): [0.5.0-beta.1] - 2026-09-16, Безопасность, Добавлено, Изменено, Отложено (дорожная карта), Consequences, END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`, Non-goals (+49 more)

### Community 35 - "ManagedStore"
Cohesion: 0.04
Nodes (39): Self-review, Task 13: Документация, миграционные заметки, версия, Task 15: Живая проверка AMS_Z ↔ ams-test (разрешение владельца от 2026-09-11), Task 16: Релизный гейт v0.3.0-beta.1, Task 1: Идентичность панели и API-ключи (хранилище), Task 2: Bearer-аутентификация, scope-гейты и `/api/keys`, Task 3: Протокол поколений и хранилище узла, Task 4: Адаптеры — caller-supplied secret для Telemt и `update_options` (+31 more)

### Community 36 - "MieruAdapter"
Cohesion: 0.07
Nodes (6): _command_failure(), _decode_transports(), MieruAdapter, MieruError, _validate_ownership_mapping(), durable_remove()

### Community 37 - "version_agent/service.py"
Cohesion: 0.07
Nodes (49): fetcher_from(), fetch(), test_an_older_image_the_registry_does_not_answer_for_is_skipped(), test_an_older_release_without_a_digest_is_skipped_without_a_reason(), test_asset_hosted_outside_the_repository_download_path_is_refused(), test_candidates_are_capped_at_the_six_newest_releases(), test_compare_versions_orders_numerically_and_prereleases_lower(), test_every_published_mita_with_a_digest_is_offered() (+41 more)

### Community 38 - "test_mieru_management.py"
Cohesion: 0.06
Nodes (33): check(), main(), _domain_created(), mieru_access(), register_mieru_routes(), escrow(), kept(), kept_share_url() (+25 more)

### Community 39 - "docs/README.md"
Cohesion: 0.07
Nodes (49): Changelog, Transactional release installer with durable journal, 1.0.0 — initial MTProxy release (2026-02-11), 1.1.0 — Fake TLS and hardening (2026-02-21), 1.2.0 — legacy installer fixes (2026-02-22), 1.3.0 — legacy MTProxy installer (2026-08-11), Развёртывание MTProto за Nginx SNI (RU), Backup and restore contract (EN) (+41 more)

### Community 40 - "CommandRunner"
Cohesion: 0.10
Nodes (43): audit_host(), AuditError, CommandRunner, _validated_argv(), audit(), Profile, ThreeXuiMode, test_per_call_timeout_cannot_exceed_runner_limit() (+35 more)

### Community 41 - "test_installer_mieru.py"
Cohesion: 0.08
Nodes (45): adapter(), applied(), FakeMieruRunner, host(), stage_client_package(), _stage_router_secret(), staged_action(), test_mieru_acceptance_requires_every_end_to_end_fact() (+37 more)

### Community 42 - "NaiveAdapter"
Cohesion: 0.09
Nodes (6): _encode_adjacent_routes(), NaiveAdapter, NaiveError, _validate_ownership_mapping(), test_naive_plan_is_empty_without_the_naive_profile(), test_naive_plan_keeps_only_audited_adjacent_routes()

### Community 43 - "test_installer_nginx.py"
Cohesion: 0.09
Nodes (48): _certificate_groups(), ensure_stream_context(), NginxAdapter, HostMode, IngressConfig, config(), facts(), FreshExecutor (+40 more)

### Community 44 - "Isolated Ubuntu 24.04 installer lab"
Cohesion: 0.04
Nodes (66): attest job, build-twice-and-compare job, draft-release job, lab-amd64 job, publish job, quality job, Release workflow, Tag, VERSION and manifest agreement check (+58 more)

### Community 45 - "MieruManager"
Cohesion: 0.11
Nodes (3): ConfigConflict, MieruManager, _pruned_operations()

### Community 46 - "Sharing Mieru configurations"
Cohesion: 0.06
Nodes (55): Cache-Control: no-store reveal response, Client matrix, Create access flow, Dialog closed too early, Ephemeral reveal dialog, Karing URL scheme documentation, Karing install-config deep link, mieru import config command (+47 more)

### Community 47 - "ExitInput"
Cohesion: 0.06
Nodes (9): ExitCredential, ExitInput, ExitInUse, ExitSecurity, ExitStore, ExitTransport, _host(), _row() (+1 more)

### Community 48 - "common.js"
Cohesion: 0.09
Nodes (50): Task 7: Окно клиента: показ ссылки по кнопке, матрица, «Применить», Task 8: «Новый клиент» с матрицей и блок подписки в «Доступы выданы», bindClients(), openClientModal(), proposeUsername(), locale(), OPERATION_MESSAGE, OPERATION_OK (+42 more)

### Community 49 - "mcp_server/server.py"
Cohesion: 0.07
Nodes (7): Config, _read_secret(), main(), build_server(), create_app(), test_a_host_outside_the_allowlist_is_refused(), test_config_reads_secrets_from_files_and_requires_allowed_hosts()

### Community 50 - "installer/audit.py"
Cohesion: 0.06
Nodes (52): _applicable_caa(), _audit_host(), _bounded_execute(), _bounded_resolve(), _caa_compatible(), _canonical_caa_record(), _canonical_ip(), _certificate_fact() (+44 more)

### Community 52 - "AuditFacts"
Cohesion: 0.06
Nodes (62): CoreAdapter, WizardRunner, AuditFacts, InstallPlan, ReleaseIdentity, _plan_from_dict(), config(), core_action() (+54 more)

### Community 53 - "Матрица негативных и security-тестов vNext (Task 39)"
Cohesion: 0.09
Nodes (35): Матрица негативных и security-тестов vNext (Task 39), Task 4: `xray_router_manager` — рантайм и типизированный менеджер (Task 33), _artifact(), FakeRunner, _lanes_doc(), manager(), _state(), test_apply_conflict_on_stale_revision() (+27 more)

### Community 54 - "EgressInvalid"
Cohesion: 0.07
Nodes (48): Task 1: Xray-router — intent схемы 2 (полосы, выходы, цепи), test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector(), test_credentials_are_masked_in_the_redacted_intent(), test_exit_outbounds_render_the_way_xray_dials_them(), test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(), test_the_intent_names_exits_and_a_rule_may_leave_through_one(), test_unix_api_exit_test_route(), test_validate_exit_normalises_every_protocol_and_refuses_the_impossible() (+40 more)

### Community 55 - "release.py"
Cohesion: 0.10
Nodes (47): _best_effort_remove_tree_at(), _copy_regular_member(), _copy_verified_archive(), _create_private_stage(), _decode_bounded_tar(), _destination_identity(), _DestinationAnchor, _digest_open_file() (+39 more)

### Community 56 - "test_installer_fresh_host.py"
Cohesion: 0.09
Nodes (55): FirewallAdapter, CertificatePlan, test_existing_valid_lineage_can_defer_only_renewal_simulation(), test_renewal_does_not_retry_a_real_acme_failure(), test_renewal_retries_deactivated_authorization_race_without_hiding_errors(), test_renewal_retries_the_order_not_ready_race_once(), test_renewal_reuses_only_same_process_same_lineage_evidence(), canonical_ufw() (+47 more)

### Community 57 - "test_installer_naive.py"
Cohesion: 0.11
Nodes (42): adapter(), applied(), FakeNaiveRunner, host(), naive_action(), _router_config(), _stage_router_secret(), test_naive_acceptance_requires_closed_connect_accounting() (+34 more)

### Community 58 - "test_version_agent_panel.py"
Cohesion: 0.10
Nodes (39): _mutations(), _panel_archive(), _PanelHost, _release_tar(), _state(), test_a_second_panel_update_is_refused_while_one_is_running(), test_a_version_file_ahead_of_the_running_panel_does_not_hide_the_update(), test_direct_panel_update_allows_declared_running_mcp() (+31 more)

### Community 59 - "test_mieru_manager.py"
Cohesion: 0.07
Nodes (40): _authenticate_journal(), FakeMita, manager(), MergingMita, RecoveryMita, _service(), _status_cli(), test_a_caller_password_is_validated_and_operations_are_pruned() (+32 more)

### Community 60 - "naive_manager/egress.py"
Cohesion: 0.08
Nodes (38): Task 1: Fix-wave — отложенные замечания v0.4, block_lines(), canonical(), check_reachable(), document_digest(), EgressInvalid, forward_proxy_bounds(), _indent() (+30 more)

### Community 61 - "xray_router_manager/service.py"
Cohesion: 0.09
Nodes (32): test_render_without_an_mtproxy_ingress_is_unchanged(), _intent(), test_generation_digest_changes_with_credentials_and_redact_hides_accounts(), test_redact_masks_relay_and_chain_secrets_too(), test_render_bypass_private_precedes_every_rule_per_tag(), test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous(), test_render_default_egress_warp_needs_warp_url(), test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() (+24 more)

### Community 62 - "firewall.py"
Cohesion: 0.11
Nodes (29): _action_enable(), _action_ipv6_enabled(), _action_rules(), _action_ssh_port(), _assert_foreign_preserved(), _assert_owned_rules_recognized(), _assert_ssh_preserved(), _canonical_source() (+21 more)

### Community 63 - "_DefaultNaiveRunner"
Cohesion: 0.06
Nodes (13): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _DefaultNaiveRunner, relay(), NaiveAcceptance, _require_acceptance(), test_h2_curl_failure_exposes_only_allowlisted_tls_reason() (+5 more)

### Community 64 - "Управление Mieru / mita 3.35–3.36"
Cohesion: 0.07
Nodes (46): Fleet v1 Telemt-only, Opt-in systemd Mieru TCP MSS clamp, Pinned mita 3.36.x admitted alongside 3.35.x, First valid generation before the hardened mita unit, Full-snapshot CAS config transactions with journal v3 HMAC, compose.mieru.yaml overlay, MIERU_MITA_SHA256 executable digest gate, Fleet v1 is Telemt-only for Mieru (+38 more)

### Community 65 - "main.js"
Cohesion: 0.06
Nodes (73): ADR-0008, Task 13: Экран версий — кнопка проверки, пометка источника, карточка Xray, api(), API_REASONS, cookie(), DETAIL_WORTH_SHOWING, problemText(), registerReasons() (+65 more)

### Community 66 - "wizard.py"
Cohesion: 0.11
Nodes (16): locale_from_environment(), parse_locale(), text(), _domain(), EditField, _egress_choice(), _email(), _flatten() (+8 more)

### Community 67 - "Action"
Cohesion: 0.06
Nodes (14): Adapter, _certificate_action(), _certificate_checkpoint(), _certificate_sans(), _certificate_vhost_path(), _effective_source_sections(), _render_certificate_vhost(), Action (+6 more)

### Community 68 - "test_version_agent.py"
Cohesion: 0.08
Nodes (42): _agent(), _build_catalog(), test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(), test_archive_member_hash_is_checked_against_the_archive_not_the_file(), test_binary_rollback_restart_is_not_success_without_health(), test_binary_update_records_the_pin_the_unit_check_reads(), test_binary_update_restores_the_previous_pin_when_the_service_fails(), test_binary_update_rolls_back_when_service_restart_fails() (+34 more)

### Community 69 - "test_mieru_egress.py"
Cohesion: 0.08
Nodes (35): Task 5: naive-manager и mieru-manager — провайдер `router`, canonical(), check_reachable(), _cidr(), document_digest(), _domain(), EgressInvalid, EgressUnreachable (+27 more)

### Community 70 - "test_installer_xray_router.py"
Cohesion: 0.12
Nodes (31): Task 11: Установщик — `[egress] router`, адаптер `xray_router`, секреты, ротация, action_for(), adapter(), _agent_state(), _applied(), _archive_bytes(), FakeRunner, host() (+23 more)

### Community 71 - "test_mieru_manager_lanes.py"
Cohesion: 0.07
Nodes (24): 7. Fleet v2, account_url(), empty_config(), _host(), LanesInvalid, parse_slots(), service_share_template(), Slot (+16 more)

### Community 72 - "DomainFacade"
Cohesion: 0.05
Nodes (29): DomainFacade, bridge_env(), _credential(), _fake_router(), handle(), _run(), _socks(), test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways() (+21 more)

### Community 73 - "NodeClient"
Cohesion: 0.02
Nodes (69): Task 8: Связи с узлами — миграция, `NodeLinkService`, `DesiredStore`, компиляция поколений, node_fingerprint(), fingerprint(), NodeAuthFailed, NodeClient, NodeRejected, NodeUnreachable, _public_address() (+61 more)

### Community 74 - "test_installer_credentials.py"
Cohesion: 0.10
Nodes (23): _anchor(), CredentialError, credentials_path(), discard_staged_credentials(), OperatorCredentials, read_credentials(), stage_credentials(), stage_operator_credentials() (+15 more)

### Community 75 - "compile"
Cohesion: 0.23
Nodes (31): Task 7: Routing IR — модели, хранилище, миграция 14, компилятор (Task 26), compile(), _policy(), _rule(), _target(), test_compile_capability_missing_from_target(), test_compile_diff_against_applied(), test_compile_digest_is_canonical() (+23 more)

### Community 76 - "test_subscription_events.py"
Cohesion: 0.08
Nodes (24): [1.0.3] - 2026-10-01, Live check (the fleet: ams-server → AMS_Z, AMS_Z → ams-test), Added, English, Fixed, Upgrading from v1.0.2, v1.0.3 — скрипт установки в каждом выпуске, исправленный мастер установки, Добавлено (+16 more)

### Community 77 - "XrayRouterAdapter"
Cohesion: 0.10
Nodes (3): _command_failure(), XrayRouterAdapter, XrayRouterError

### Community 78 - "register_routing_routes"
Cohesion: 0.10
Nodes (24): _outcome(), policy_view(), _refusal(), register_routing_routes(), apply(), attach(), _ctx(), delete_policy() (+16 more)

### Community 79 - "TelemtAdapter"
Cohesion: 0.06
Nodes (10): _RuntimeCollision, AdapterError, probe_bridge(), _probe_bridge(), TelemtAdapter, broken(), test_telemt_adapter_wraps_a_failing_readback(), broken() (+2 more)

### Community 80 - "DeployCliTests"
Cohesion: 0.05
Nodes (3): Task 13: Phase 8 — backup/restore, матрица негативных тестов, замороженные идентификаторы, DeployCliTests, attempt()

### Community 81 - "CDP"
Cohesion: 0.12
Nodes (12): Global Constraints, Task 0: Ветка, спека, план, Task 1: Инвентарь функций и матрица сверки (TDD: тест-страж первым), Task 2: Tier `ui` — драйвер и view без второй панели, Task 3: Tier `ui` — центр (вторая панель) и Fleet-экраны, Task 4: Дыры бэкенда, Task 5: Живая проверка AMS_Z, Task 6: Релиз (+4 more)

### Community 82 - "test_proxyctl_runtime.py"
Cohesion: 0.10
Nodes (24): FakeRunner, plan(), runtime_root(), test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(), test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps(), run(), test_failed_install_rollback_is_retried_before_reinstall(), test_generated_acme_and_panel_sites_pass_native_nginx_syntax_check() (+16 more)

### Community 83 - "Planned File Structure"
Cohesion: 0.08
Nodes (38): audit_host -> AuditFacts, AuditFacts, parse_config / render_config / load_config, examples/installer/*.toml, Full profile order, import_runtime_v2 legacy importer, installer.cli main (wizard/plan/install/status/repair/uninstall/upgrade), InstallerConfig (frozen dataclass) (+30 more)

### Community 84 - "vNext v0.2 local control plane implementation plan"
Cohesion: 0.09
Nodes (37): ADR 004: Client / AccessGrant / subscription, tests/fixtures/vnext-capabilities.json (4 protocols x 23 capabilities), Audit finding 2: Panel vhost is rendered in two places, Audit finding 3: uvicorn writes an access log to container stdout, Audit finding 6: Credential re-reveal differs per protocol, Audit finding 10: UI is ES modules without a bundler, Audit finding 11: Fleet tables and the reserved local node, Reserved node local (+29 more)

### Community 85 - "clients.js"
Cohesion: 0.09
Nodes (47): Task 2: Счётчик клиентов в навигации, acceptPage(), actions(), adopt(), adoptNote(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT (+39 more)

### Community 86 - "app.py"
Cohesion: 0.02
Nodes (115): Task 11: Маршруты центра — связи, импорт пользователей узла, версии, подписки по узлам, Task 6: Fleet API v2 узла и защита ресурсов центра, register_api_key_routes(), create_key(), _ctx(), delete_key(), set_enabled(), _client() (+107 more)

### Community 87 - "curated.py"
Cohesion: 0.23
Nodes (26): Добавлено, Tools, Инструменты, 9a. MCP-сервер `proxy-control-mcp` (решение владельца 2026-09-21: в v0.11, полный набор, доступ с ноутбука через SNI), audit_tail(), client_subscription(), create_client(), derive_username() (+18 more)

### Community 88 - "panel"
Cohesion: 0.07
Nodes (26): Live check (AMS_Z ↔ ams-test), Живая проверка (AMS_Z ↔ ams-test), 7.1 Модель, 7.2 Выдать доступ на узел из центра (пошагово), 7.3 Подписка клиента, 7.4 Включить / выключить / ротировать / удалить, 7.5 Локальные клиенты узла, 7. Клиенты, доступы и подписки из центра (+18 more)

### Community 89 - "test_installer_release.py"
Cohesion: 0.18
Nodes (33): ArchiveEntry, ArchiveManifest, _manifest_data(), safe_extract_tar(), _stage_paths(), _tar(), test_archive_digest_is_verified_before_tar_processing(), test_archive_path_swap_cannot_change_verified_bytes() (+25 more)

### Community 90 - "installer/cli.py"
Cohesion: 0.13
Nodes (26): _adopt_legacy_if_needed(), _automated_install(), _bounded_error(), _bounded_text(), CliError, CliServices, _default_services(), plan() (+18 more)

### Community 91 - "Scenario"
Cohesion: 0.10
Nodes (3): describe_artifact(), Scenario, adopted()

### Community 92 - "test_installer_transaction.py"
Cohesion: 0.08
Nodes (51): import_runtime_v2(), TransactionBusyError, TransactionStore, action_for(), engine_for(), InjectedCrash, installed_runtime_v2(), plan_for() (+43 more)

### Community 93 - "query"
Cohesion: 0.07
Nodes (60): [0.7.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Исправлено (после v0.6, в ветке до этого тега), 6.1 Модель (`panel/routing/models.py`, схема базы 16), 6.2 Сервис маршрутизации и цели, 6.3 Экран «Маршрутизация и цепи» (+52 more)

### Community 94 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`), Installing, Screenshots, Upgrading, v0.8.0-beta.1 — свои выходы, таблица правил, geodata, автоимпорт, What the verification found, What this release is (+7 more)

### Community 95 - "test_fleet_v2_reconcile.py"
Cohesion: 0.11
Nodes (26): _accept(), anyio_backend(), _imported(), _push(), _resource(), test_a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user(), test_a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply(), test_a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user() (+18 more)

### Community 96 - "qemu_lab.py"
Cohesion: 0.10
Nodes (29): acceleration(), allocate_port(), _archive(), cleanup(), finalize_results(), full_egress_policy(), guest_remote(), junit_xml() (+21 more)

### Community 97 - ".step_05c_chains"
Cohesion: 0.12
Nodes (9): Task 12: Лаборатория — staging, `lab-host` с роутером, сценарии `router-*`, tier `router`, redact(), lane_built(), slot_learned(), warp_reachable(), settled(), settled(), settled() (+1 more)

### Community 98 - "CentralProcess"
Cohesion: 0.06
Nodes (9): Task 2: Spike — нативные возможности Caddy forwardproxy и mita (Task 30), central_environment(), CentralProcess, main(), parse_args(), Probes, read_node_credentials(), Stub (+1 more)

### Community 99 - "UnixHTTPServer"
Cohesion: 0.15
Nodes (9): Task 11: Сервер агента — `POST /v1/upstream/check`, долгий таймаут для сборки, FakeAgent, test_unix_socket_server_answers_a_panel_update_as_accepted_and_async(), test_unix_socket_server_checks_upstream_on_post(), test_unix_socket_server_preserves_update_contract(), test_unix_socket_server_reports_a_failed_or_disabled_upstream_check(), check_upstream(), test_unix_socket_server_returns_distinct_rollback_failed_state() (+1 more)

### Community 100 - "_DefaultMieruRunner"
Cohesion: 0.07
Nodes (9): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _client_config_for(), _DefaultMieruRunner, MieruAcceptance, _require_acceptance(), test_real_mieru_runner_recognizes_existing_named_system_group() (+1 more)

### Community 102 - "test_node_lifecycle.py"
Cohesion: 0.12
Nodes (16): CommandConflict, CertificateRegistry, CertificateInfo, NodeView, derive(), _link_view(), NodeConflict, NodeLifecycleService (+8 more)

### Community 103 - "Reconciler"
Cohesion: 0.05
Nodes (30): EgressDocument, GenerationDocument, PushRequest, RelayAccount, RelaySection, Resource, _Strict, Reconciler (+22 more)

### Community 104 - "test_installer_docs.py"
Cohesion: 0.08
Nodes (27): _parser(), checked_commands(), documented_files(), install_steps(), install_text(), python_requirements(), readme(), reference() (+19 more)

### Community 105 - "ProtocolError"
Cohesion: 0.13
Nodes (12): ProtocolError, validate_inventory(), validate_payload(), validate_result(), _walk_secret_free(), AgentTransportClient, _csrf(), test_every_protocol_access_is_re_revealable() (+4 more)

### Community 106 - "config"
Cohesion: 0.13
Nodes (18): build_managed_clients(), build_managed_inbounds(), ManagedInbound, config(), DeterministicSecrets, test_a_hysteria_client_authenticates_with_auth_not_password(), test_acceptance_clients_are_distinct_from_persistent_clients(), test_hysteria_matches_the_shape_a_running_server_actually_serves() (+10 more)

### Community 107 - "PolicyInput"
Cohesion: 0.10
Nodes (16): backends_for(), PolicyInput, PolicyPut, PolicyConflict, PolicyNotFound, RoutingStore, test_delete_cascades_rules(), test_mark_and_history_limit() (+8 more)

### Community 108 - "v1.1.0 audit and rc.2 acceptance report"
Cohesion: 0.06
Nodes (28): Historical handoff archive index, Current continuation checkpoint, 2026-10-03, Latest published release remains v1.1.0, 1.1.1-rc.2 accepted in main and origin/main at 5c41c9a; unpublished, Nine imported test accesses remain; owner declined cleanup, Single mtproxy Compose project; preserve full COMPOSE_FILE overlays, Bilingual documentation index, Fleet v2 management begins after accepted generation (+20 more)

### Community 109 - "isCurrent"
Cohesion: 0.14
Nodes (30): 2. Обзор и навигация (панель, только фронт), bytes(), icon(), localDateTime(), clientsCount(), fillBars(), fleetCount(), followHost() (+22 more)

### Community 110 - "test_naive_manager_egress.py"
Cohesion: 0.12
Nodes (28): EgressUnreachable, _block(), EgressHooks, manager(), router_manager(), test_a_failed_reload_restores_the_previous_bytes(), test_a_readback_mismatch_rolls_back_with_its_own_code(), test_apply_conflicts_on_a_stale_revision_without_touching_anything() (+20 more)

### Community 111 - "test_mieru_deployment.py"
Cohesion: 0.12
Nodes (30): owned_private_file(), render_mieru_compose(), run_state_preparer(), run_token_preparer(), test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(), test_mieru_overlay_has_only_intended_writable_runtime_mounts(), test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access(), test_naive_caddy_identity_cannot_access_mieru_state() (+22 more)

### Community 112 - "Interactive Release Installer Design"
Cohesion: 0.06
Nodes (51): README dependency surface list, Global Constraints, docs/INSTALLER_REFERENCE.ru.md / .en.md, tests/lab/clients/compose.yaml protocol clients, Operator requirements recorded 2026-09-04, QEMU lab modes release-amd64 / release-arm64, release/build.py reproducible builder, Release-readiness commit v0.1.0 (+43 more)

### Community 113 - "test_installer_cli.py"
Cohesion: 0.15
Nodes (21): load_config(), main(), _plan(), ReturningWizard, _run(), _run_in_pty(), _services(), _state() (+13 more)

### Community 114 - "test_grant_lifecycle.py"
Cohesion: 0.09
Nodes (41): _drifted_report(), _enabled(), _local(), test_background_timer_expires_access_without_a_request(), test_drift_report_does_not_infer_node_runtime_from_central_clock(), test_lifespan_enforces_expired_local_access_before_serving(), test_local_clock_transition_enables_then_expires_without_request(), test_local_enable_cannot_bypass_suspension_or_expiry() (+33 more)

### Community 115 - "test_mcp_server.py"
Cohesion: 0.10
Nodes (21): anyio_backend(), config(), fake(), FakePanel, registry(), _rpc(), test_a_confirmed_call_reaches_the_panel_and_its_error_comes_back_as_tool_text(), test_client_subscription_reveals_the_url_again() (+13 more)

### Community 116 - "_DefaultCoreRunner"
Cohesion: 0.05
Nodes (26): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _compose_publishes_telemt_api(), CoreAcceptance, _DefaultCoreRunner, _alive(), test_interrupt_stops_the_process_group() (+18 more)

### Community 117 - "Accounting semantics"
Cohesion: 0.05
Nodes (49): Accounting semantics, Mieru rolling session-admission quota, Naive completed-CONNECT byte collector, Telemt total_octets and quota usage counter, Proxy Control architecture, Caddy/NaiveProxy runtime and manager, Complete COMPOSE_FILE overlay set, FastAPI panel on loopback (+41 more)

### Community 118 - "MieruClient"
Cohesion: 0.09
Nodes (10): 8.1 API (`panel/routing/routes.py`, owner для мутаций, viewer — чтение), 8.2 Локальный узел, 8.3 Подключённые панели (Fleet v2), 8.4 UI («Маршрутизация», `panel/static/js/routing.js`), 8. Панель, MieruClient, test_mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body(), test_mieru_client_rotate_sends_the_caller_credential_and_operation_id() (+2 more)

### Community 119 - "build.py"
Cohesion: 0.11
Nodes (21): archive_names(), assert_clean(), build_release(), BuiltRelease, _canonical(), commit_epoch(), _executable(), _external_artifacts() (+13 more)

### Community 120 - "TransactionEngine"
Cohesion: 0.09
Nodes (17): AcceptedDigestError, _canonical_json(), _checkpoint_data(), _evidence_to_dict(), _freeze(), _freeze_mapping(), _pretty_json(), _thaw() (+9 more)

### Community 121 - "test_naive_manager_lanes.py"
Cohesion: 0.11
Nodes (19): handler_lines(), lane_credentials(), lanes_span(), LanesInvalid, outside_lanes(), primary_forward_proxy(), render(), validate_request() (+11 more)

### Community 122 - "proxyctl.py"
Cohesion: 0.19
Nodes (17): sha256(), _apply_plan_unlocked(), _audit_mapping(), _canonical_route(), _host_path(), InstallerConflict, _load_state(), _owned_route_marker() (+9 more)

### Community 123 - "grant.js"
Cohesion: 0.11
Nodes (31): filename(), jsonConfig(), karingVariant(), mieruNative(), naiveNative(), naiveNekobox(), normaliseAccessPayload(), plainObject() (+23 more)

### Community 124 - "XrayError"
Cohesion: 0.06
Nodes (11): test_a_router_that_does_not_come_back_after_the_swap_is_recorded(), broken_start(), probe_trace(), check_hop_reachable(), _fsync_directory(), _port_open(), _sha256_file(), _socket_open() (+3 more)

### Community 125 - "i18n.js"
Cohesion: 0.09
Nodes (32): Gate checklist (lab host `ams-test`), English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.6.0-beta.1, Screenshots, Upgrading (+24 more)

### Community 126 - "Host"
Cohesion: 0.08
Nodes (8): Decision, Results — Mieru via the router (`mieru` ingress), Results — NaiveProxy via the router (`naive` ingress), Results — the router itself, Xray egress-router spike (v0.5, Task 32), Docker, Host, RoutingProbes

### Community 127 - "Dedicated Proxy-Control-owned xray-router"
Cohesion: 0.08
Nodes (35): ADR 006: routing policy IR, ADR 007: routing enforcement ownership, v0.4 acceptance criteria, v0.5 acceptance criteria, CompiledRoutingGeneration (policy_revision, backend_id, compiler/runtime versions, binary/geodata/config digests), EgressProvider (direct | warp | socks | xray-router), EnforcementBackend (native | os-isolation | xray-router; fallback fail-closed | explicitly-approved-direct), Immutable management/control bypass (+27 more)

### Community 128 - "managed-xui-clients.py"
Cohesion: 0.18
Nodes (18): assert_port_free(), classify_case(), cleanup_group(), Echo, empty_report(), _field(), listener_owned_by_group(), main() (+10 more)

### Community 129 - "MemoryMieru"
Cohesion: 0.13
Nodes (3): MemoryMieru, MieruError, test_memory_mieru_replays_a_caller_credential_and_refuses_a_generated_one()

### Community 130 - "tools.py"
Cohesion: 0.15
Nodes (12): PanelError, _body_schema(), _build(), build_operations(), is_excluded(), is_irreversible(), Operation, resolve_refs() (+4 more)

### Community 131 - "guest-runner.sh"
Cohesion: 0.06
Nodes (6): CASE_STATUS, dns_tls_fixture(), full_audit(), full_dns_tls(), full_plan(), runtime_cmd()

### Community 132 - "test_release_build.py"
Cohesion: 0.13
Nodes (23): build(), checkout_with_private_files(), clean_checkout(), git(), gzip_rewrap(), _run_published_script(), sha256(), tar_names() (+15 more)

### Community 133 - "Журнал изменений"
Cohesion: 0.07
Nodes (30): [0.10.0-beta.1] - 2026-09-21, [0.11.0-beta.1] - 2026-09-22, [0.12.0-beta.1] - 2026-09-22, [0.13.0-beta.1] - 2026-09-23, [0.14.0-beta.1] - 2026-09-23, [0.15.0-beta.1] - 2026-09-23, [0.4.0-beta.1] - 2026-09-14, [0.6.0-beta.1] - 2026-09-17 (+22 more)

### Community 134 - "Panel version-agent"
Cohesion: 0.11
Nodes (20): Start of change window, .env secrecy, Перед началом смены, Секретность .env, NaiveProxy/Caddy and Mieru/mita binary update flow, Caddyfile and module checker validation, Compose project label com.docker.compose.project=mtproxy, version-overrides/compose.versions.yaml (+12 more)

### Community 135 - "test_xray_routing_compiler.py"
Cohesion: 0.23
Nodes (27): Task 7: Routing IR — backend `xray_router`, `geosites/geoips`, миграция 15, компилятор, _lane(), Resolver, test_a_service_without_lanes_or_node_exits_still_compiles_to_schema_1(), test_compiling_a_lane_policy_folds_the_service_and_the_other_lanes(), test_explain_walks_a_lanes_rules_for_a_destination(), test_lanes_and_node_exits_need_the_router_and_the_attachment(), test_lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains() (+19 more)

### Community 136 - "PackagesAdapter"
Cohesion: 0.15
Nodes (18): _action_packages(), _assert_added_unchanged(), _assert_preexisting_unchanged(), _checkpoint_packages(), PackageError, PackagesAdapter, _version_mapping(), AptRunner (+10 more)

### Community 137 - "test_installer_reports.py"
Cohesion: 0.12
Nodes (17): AcceptanceReport, _assert_public(), CredentialHandoff, _encode(), ReportError, ReportWriter, handoff_with_secrets(), public_report_values() (+9 more)

### Community 138 - "main"
Cohesion: 0.08
Nodes (27): adapt(), curl_socks(), forward_proxy_handler(), walk(), load(), main(), apply_mita(), naive_probe() (+19 more)

### Community 139 - "Ownership boundaries and adapter order"
Cohesion: 0.08
Nodes (33): certificates adapter, firewall adapter, naive adapter, nginx adapter, Адаптер certificates, Адаптер firewall, Адаптер naive, Адаптер nginx (+25 more)

### Community 140 - "renderers/base.py"
Cohesion: 0.07
Nodes (29): AccessArtifact, _link(), Manifest, ManifestGrant, check(), credential_reason(), finish(), hosts_by_node() (+21 more)

### Community 141 - "test_installer_warp_transaction_recovery.py"
Cohesion: 0.10
Nodes (20): HostCommands, PowerLoss, test_apply_refuses_foreign_state_appearing_after_prepare(), test_apply_waits_for_transient_daemon_status(), test_cleanup_fsyncs_removed_entries_before_engine_completion(), test_egress_probe_overrides_inherited_no_proxy(), test_engine_completes_unpacked_package_on_resume(), test_engine_recovers_sigkill_before_owner_replace() (+12 more)

### Community 142 - "test_version_agent_host.py"
Cohesion: 0.19
Nodes (7): _Proc, test_a_stalled_counter_reports_null_rather_than_a_confident_zero(), test_cpu_utilisation_is_a_delta_between_two_samples(), test_host_endpoint_is_read_only_and_rejects_writes(), test_memory_counts_reclaimable_cache_as_available(), test_missing_proc_files_degrade_each_section_independently(), test_swap_is_reported_beside_memory_and_a_host_without_swap_says_so()

### Community 143 - "_render_at_phone_viewport"
Cohesion: 0.09
Nodes (12): Task 9: Мобильный аудит окна клиента, _cards_from_real_renderers(), test_mobile_cards_have_semantic_icons_and_quick_settings_align(), _browser(), DevTools, _render_at_phone_viewport(), test_access_cards_and_navigation_do_not_collide_on_phone(), client_card() (+4 more)

### Community 144 - "WarpAdapter"
Cohesion: 0.15
Nodes (6): WarpAdapter, WarpError, test_warp_rollback_checks_all_ownership_before_any_mutation(), test_download_never_reuses_attacker_link(), test_warp_is_owned_before_consumers_and_requires_real_egress(), test_warp_owned_lifecycle_and_foreign_install_refusal()

### Community 145 - "test_proxyctl_transactions.py"
Cohesion: 0.17
Nodes (21): AuditFacts, apply_plan(), InstallPlan, repair_installation(), uninstall_installation(), facts_from_root(), host_root(), make_plan() (+13 more)

### Community 147 - "Store"
Cohesion: 0.16
Nodes (3): ConflictError, Store, test_creating_the_first_owner_twice_is_not_an_error()

### Community 148 - "mieru_manager/service.py"
Cohesion: 0.18
Nodes (17): _atomic(), _canonical(), _fsync_dir(), _go_duration_ns(), _hash(), _object(), _positive_int(), _read_secure() (+9 more)

### Community 149 - "test_fleet_v2_node_api.py"
Cohesion: 0.16
Nodes (17): _doc(), _node_key(), _push(), test_a_push_landing_during_unlink_cannot_resurrect_managed_rows(), test_capture_answers_null_not_500_while_telemt_is_down(), down(), test_capture_unlink_and_versions_update(), test_central_owned_users_refuse_local_mutation_and_leave_local_inventory() (+9 more)

### Community 150 - "prepare-naive-state.py"
Cohesion: 0.17
Nodes (17): _assert_directory(), _assert_identities(), _assert_identity_free(), _assert_owned_state(), _assert_safe_parents(), _assert_state_entry(), _create_directory(), _fail() (+9 more)

### Community 151 - "MitaCLI"
Cohesion: 0.12
Nodes (8): MitaCLI, MitaError, _process_running(), test_cli_eof_before_child_exit_is_sanitized_and_reaps_child(), test_cli_passes_complete_config_through_anonymous_fd_and_bounds_output(), test_cli_refuses_unpinned_or_changed_executable_before_launch(), test_cli_success_kills_same_group_descendant_after_direct_child_exits(), test_cli_timeout_kills_descendant_that_inherits_output_pipes()

### Community 152 - "FleetStore"
Cohesion: 0.22
Nodes (7): _canonical(), FleetStore, test_fleet_inventory_and_results_are_recursively_secret_free(), test_fleet_store_assigns_monotonic_sequences_and_enforces_idempotency(), test_fleet_v1_hides_and_retires_legacy_mieru_state(), test_fleet_v1_rejects_mieru_inventory_advertisement(), test_result_upload_retry_is_idempotent_but_conflicting_replay_is_rejected()

### Community 153 - "test_panel_entrypoint.py"
Cohesion: 0.18
Nodes (21): main(), open_source(), stage(), StageError, validate_source(), verify(), _fake_command(), logged_commands() (+13 more)

### Community 154 - "Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация"
Cohesion: 0.07
Nodes (30): 10.1 Парк с нуля (центр + два узла), 10.2 Добавить узел в существующий парк, 10.3 Выдать доступ клиенту на другом узле, 10.4 Включить WARP для сервиса на узле, 10.5 Вывести узел из парка, 10. Сквозные чек-листы, 1. Термины, 2.1 Один узел: что на нём работает (+22 more)

### Community 155 - "_DefaultXrayRouterRunner"
Cohesion: 0.11
Nodes (4): 3.6 Исправления, _DefaultXrayRouterRunner, test_the_real_runner_fetches_over_https_only(), test_the_real_runner_sees_only_the_router_compose_service()

### Community 156 - "TopologyError"
Cohesion: 0.06
Nodes (52): _action_specification(), _address_facts(), _checkpoint_identity(), _client_ip_backend(), _copy_checkpoint(), derive_owned_route_variable(), _desired_content(), _glob_path_matches() (+44 more)

### Community 158 - "test_three_xui_api.py"
Cohesion: 0.11
Nodes (33): api_with(), client(), failing_api(), ok(), _panel(), secret_values(), sensitive_values(), template() (+25 more)

### Community 159 - "NaiveClient"
Cohesion: 0.15
Nodes (3): NaiveClient, _optional(), test_naive_adapter_accepts_empty_204_delete_response()

### Community 160 - "BoundedBodyMiddleware"
Cohesion: 0.33
Nodes (3): receive(), BoundedBodyMiddleware, replay()

### Community 161 - "index.cjs"
Cohesion: 0.09
Nodes (22): dependencies, prebuilt-tdlib, tdl, description, engines, node, license, name (+14 more)

### Community 162 - "test_update_host.py"
Cohesion: 0.19
Nodes (16): Agent, host(), _run(), test_a_digest_other_than_the_verified_one_changes_nothing(), test_a_host_already_on_the_release_only_rebuilds_what_is_missing(), test_compose_service_lookup_failure_refuses_before_panel_update(), test_container_lookup_failure_refuses_manager_build(), test_declared_running_mcp_is_allowed() (+8 more)

### Community 163 - "register_fleet_v2_central_routes"
Cohesion: 0.04
Nodes (55): What is new, Что нового, bundle(), public_hosts_for(), _refusal(), register_fleet_v2_central_routes(), _linked(), node_auth_failed() (+47 more)

### Community 164 - "DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)"
Cohesion: 0.11
Nodes (27): ADR 002: declarative generations, Audit finding 1: Manager tests live in tests/test_naive_manager.py and tests/test_mieru_manager.py, Audit finding 7: Managers generate passwords themselves, Audit finding 8: Telemt list_users allows credential recovery, v0.3 acceptance criteria, DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation), Fleet v2 exchange (/agent/v2/nodes/{node_id}/heartbeat, desired, observed, secrets/resolve, secret-results), ObservedGeneration (applied_generation, bundle_digest, reconcile_state, resource_statuses, safe_drift_summary) (+19 more)

### Community 165 - "test_routing_router_service.py"
Cohesion: 0.19
Nodes (21): Task 8: RoutingService — targets с роутером, attach/detach, apply/rollback через роутер (локально), _audits(), _block(), _item(), _rules(), test_apply_native_policy_on_attached_service_is_422(), test_apply_router_failure_marks_failed_and_maps_codes(), test_apply_router_policy_calls_router_and_records_applied() (+13 more)

### Community 166 - "ThreeXuiApiError"
Cohesion: 0.11
Nodes (6): _form_value(), parse_csrf_token(), ThreeXuiApi, ThreeXuiApiError, test_a_page_without_a_usable_csrf_token_fails_closed(), test_csrf_token_is_read_from_the_page_the_panel_serves()

### Community 167 - "test_users_adapter_ui.py"
Cohesion: 0.07
Nodes (6): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_busy_buttons_capture_their_target_instead_of_reading_it_after_await(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires(), test_the_domain_writer_adopts_a_user_it_did_not_create(), test_the_domain_writer_records_a_client_and_grant_for_every_protocol(), _writer()

### Community 168 - "test_xray_router_mtproxy.py"
Cohesion: 0.15
Nodes (15): _inbound(), manager(), SocketRunner, test_a_chain_for_mtproxy_renders_like_any_service(), test_a_malformed_credential_is_a_manual_intervention_not_a_new_one(), test_a_manager_without_the_socket_does_not_know_mtproxy(), test_a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(), test_a_stale_socket_is_removed_before_xray_starts() (+7 more)

### Community 169 - "fleet.js"
Cohesion: 0.14
Nodes (21): ACTION_NAMES, applyFilters(), auditBody(), auditMarkup(), auditQuery(), auditRow(), handleAuditClick(), handleAuditSubmit() (+13 more)

### Community 170 - "CatalogError"
Cohesion: 0.09
Nodes (26): Task 10: `naive` — пересборка Caddy, Task 14: Установщик принимает версии из `state.json` агента, Task 15: Документация и changelog, Task 16: Гейт на ams-test и живая проверка на AMS_Z, Task 1: Обзор — без «Application bytes», ресурсы одной строкой, три карточки, Task 4: Каталог — `xray`, `source`, `archive`, `kind: build`, Task 5: Извлечение member из архива, Task 6: Опрос upstream — GitHub Releases, ghcr.io, Docker Hub (+18 more)

### Community 171 - "ReleaseManifest"
Cohesion: 0.11
Nodes (20): ArtifactPin, ExternalArtifact, ReleaseManifest, _load_manifest(), main(), _parser(), sha256_file(), stage_xray() (+12 more)

### Community 172 - "test_subscription_lifecycle.py"
Cohesion: 0.11
Nodes (10): anyio_backend(), client_id(), clients(), Clock, _grant(), subscriptions(), test_a_client_and_its_subscription_are_born_in_one_transaction(), test_a_second_active_subscription_cannot_exist() (+2 more)

### Community 173 - "test_routing_ui_contract.py"
Cohesion: 0.08
Nodes (9): _interpolations(), test_every_interpolated_value_from_the_api_is_escaped(), test_routing_card_forgets_the_previous_policy_before_it_paints(), test_routing_js_seam_fixes_of_v09(), test_routing_js_speaks_lanes_chains_and_the_relay(), test_routing_js_speaks_presets_exits_and_geodata(), test_routing_js_speaks_the_router(), test_routing_js_tells_the_operator_when_the_node_already_runs_the_policy() (+1 more)

### Community 174 - "3x-ui mode: managed-new"
Cohesion: 0.09
Nodes (29): release/external-artifacts.json, Managed inbound templates vless_reality_tcp / vless_reality_xhttp / hysteria2_tls, parse_effective_nginx / select_route_target, ThreeXuiAdapter.plan_existing_upgrade, ReleaseManifest / ExternalArtifact.for_platform, safe_extract_tar, Task 12: Existing and staged 3x-ui lifecycle, Task 13: Managed 3x-ui inbounds, clients and optional WARP (+21 more)

### Community 175 - "Check"
Cohesion: 0.11
Nodes (10): UI, v0.3 — задачи после слияния (post-merge issues), Спека (follow-ups, не дефекты реализации), Стенд и приёмка, assert_secret_free(), walk(), mtproxy_secret(), NodeB (+2 more)

### Community 176 - "ingress_upgrade.py"
Cohesion: 0.10
Nodes (27): _mcp_vhost_text(), _panel_vhost_text(), _subscription_vhost_text(), main(), _panel_template(), _read(), _reload(), _stream_template() (+19 more)

### Community 178 - "importer.py"
Cohesion: 0.17
Nodes (14): confirm(), _existing(), ImportDecision, ImportResult, _integer(), inventory(), InventoryItem, _mieru_options() (+6 more)

### Community 179 - "v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router"
Cohesion: 0.06
Nodes (31): [0.8.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Custom exits, quick settings and geodata (v0.8), Свои выходы, быстрые настройки и geodata (v0.8), 10. Лаборатория и гейт, 11. План работ (оценка) (+23 more)

### Community 180 - "document_digest"
Cohesion: 0.07
Nodes (38): Политика, Task 9: Fleet v2 — egress в поколении, узел и центр (Task 31), Task 6: Модуль матрицы `placement.js` — рендер, чтение, диф, 11. Безопасность, 9.1 API (`panel/routing/routes.py`; owner для мутаций, viewer — чтение), 9.2 Локальный узел, 9.3 Подключённые панели (Fleet v2), 9.4 UI («Маршрутизация», `panel/static/js/routing.js`) (+30 more)

### Community 182 - "register_fleet_v2_node_routes"
Cohesion: 0.10
Nodes (24): _conflict(), _log_late_outcome(), register_fleet_v2_node_routes(), capture(), _daemon(), _egress_entry(), _enabled(), _geodata() (+16 more)

### Community 183 - "full_config"
Cohesion: 0.16
Nodes (17): clean_facts(), config_without_initial_user(), full_config(), mieru_action(), test_recovery_verifies_nonempty_manager_state_and_new_token_is_32_bytes(), _router_config(), test_generated_manager_token_is_valid_http_text(), test_mieru_bootstrap_config_proxies_all_traffic_with_warp() (+9 more)

### Community 184 - "RouterTarget"
Cohesion: 0.12
Nodes (12): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 14: Документация, ADR 007, CHANGELOG, VERSION, релизная заметка, Task 15: Гейт релиза на `ams-test` и точка продолжения, Task 3: Spike — Xray как egress-router на стенде (Task 32), v0.5 Xray Router Implementation Plan, Структура файлов (+4 more)

### Community 185 - "Keyring"
Cohesion: 0.03
Nodes (51): Центральная панель (fleet_v2 central), Task 1: Fix-wave — отложенные замечания v0.3, Global Constraints, Self-review, Task 10: Документация выпуска и VERSION, Task 11: Гейт на ams-test и живая проверка AMS_Z → ams-test, Task 2: Escrow при выдаче, гашение при ротации/отзыве, `reveal_token`, Task 3: Ручка `POST /api/clients/{id}/subscription/reveal` и расширенный обзор (+43 more)

### Community 187 - "Task 6: Encrypted secret versions and master key"
Cohesion: 0.14
Nodes (18): ADR 005: secret references, compose.yaml secret panel-master-key, Pinned cryptography dependency, panel/entrypoint.sh master-key staging, Audit finding 9: Panel container is read_only with secrets staged into /run/panel, Installer renders secrets/panel-master-key, panel.keyring.Keyring (load/generate/save/rotate/retire_all_but_active), panel.cli master-key-init / master-key-rotate / master-key-verify (+10 more)

### Community 188 - ".compose"
Cohesion: 0.32
Nodes (3): Drill, main(), sha256()

### Community 189 - "safe_extract_zip"
Cohesion: 0.25
Nodes (15): Task 2: Артефакт Xray в каталоге релиза и `safe_extract_zip`, _copy_zip_member(), MemberPin, safe_extract_zip(), _validate_zip_members(), _pins(), _sha(), test_safe_extract_zip_extracts_named_members_only() (+7 more)

### Community 192 - "_PinningStream"
Cohesion: 0.11
Nodes (3): _NodeBackend, _NodeTransport, _PinningStream

### Community 193 - "v0.11 — обновления из upstream и обзор в одну строку"
Cohesion: 0.22
Nodes (9): 10. Тесты и проверка, 1. Цель, 5. Компонент `xray`, 6. Компонент `mita` и закреплённый потребитель, 7. Компонент `naive` — пересборка Caddy, 8. API и данные, 9. Ошибки, v0.11 — обновления из upstream и обзор в одну строку (+1 more)

### Community 194 - "QuotaEnforcer"
Cohesion: 0.10
Nodes (9): caddy_adapt(), command_reload(), command_validate(), main(), QuotaEnforcer, _rewrite_listener(), test_caddy_adapt_unwraps_caddy_211_envelope(), test_private_listener_rewrite_disables_automatic_https_redirects() (+1 more)

### Community 195 - "MemoryTelemt"
Cohesion: 0.08
Nodes (8): MemoryTelemt, test_telemt_adapter_egress_is_direct_only_without_a_router(), adapter(), anyio_backend(), backends(), anyio_backend(), backends(), test_rotate_double_indeterminate_propagates_raw_not_adapter_error()

### Community 196 - "test_fleet_acceptance_script.py"
Cohesion: 0.10
Nodes (5): _run(), test_naive_probe_retries_a_cut_connection_but_not_a_refusal(), test_routing_scenarios_are_opt_in_and_sit_after_the_grants(), test_scenario_report_is_secret_free_and_stops_the_central_on_failure(), test_scenario_runs_all_eleven_steps_on_fakes()

### Community 197 - "test_routing_service.py"
Cohesion: 0.26
Nodes (13): Task 8: Routing — сервис и HTTP API (локальный узел), _audits(), _block(), test_apply_io_outside_transaction(), test_apply_local_calls_manager_and_records_applied(), test_apply_manager_conflict_marks_failed(), test_apply_unreachable_provider_leaves_policy_unchanged(), test_apply_unsupported_is_422_without_manager_call() (+5 more)

### Community 199 - "pytest"
Cohesion: 0.03
Nodes (51): MieruOptions, redact_document(), _b64(), _name_from(), parse_share_link(), _query(), _security_from(), _transport_from() (+43 more)

### Community 200 - "Global Constraints"
Cohesion: 0.05
Nodes (38): Chains and per-client lanes spike (v0.7, Task 1), S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user, S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray, S3 — Mieru: a second mita daemon beside the managed one, What v0.7 builds on this, Global Constraints, Task 0: Ветка, спайк, спека, план, Task 10: Установщик — `relay_port`, `lane_slots`, обновление (+30 more)

### Community 201 - "Task 4: Unified DB layer and migrations"
Cohesion: 0.16
Nodes (19): CommandRunner (bounded, sanitized errors), panel.audit.digest (sha256 of canonical JSON), panel.audit.record(db, ...), panel.audit.scrub (recursive), Migration 2 audit-structured, Migration 1 baseline-v0.1.0, panel.database.Database (WAL, foreign_keys, transaction()), panel.cli db-migrate / db-status (+11 more)

### Community 203 - "script"
Cohesion: 0.11
Nodes (12): script(), FakeConnection, FakeResponse, serve(), test_api_refuses_an_oversized_response(), script(), test_login_fetches_a_csrf_token_and_sends_it(), script() (+4 more)

### Community 204 - "MTProxy acceptance failure: Connection closed"
Cohesion: 0.13
Nodes (12): ams-test disposable install server, Fake-TLS handshake, Full install log capture (install.err, docker compose logs, journalctl nginx, container state), full profile with three_xui.mode managed-new, /root/install.toml and /root/install.credentials, Let's Encrypt certificates (four issued), nebula.sky.dubr1kkk.uk (MTProxy, cert: yes), proxy-control-mtproxy container (127.0.0.1:8445) (+4 more)

### Community 205 - "core_checks"
Cohesion: 0.16
Nodes (7): core_checks(), fetch(), _ip_through(), main(), Panel, _run(), _socks5_udp_dns()

### Community 206 - "Installer CLI commands"
Cohesion: 0.07
Nodes (30): report.json public acceptance report, Installer CLI commands, credentials/handoff.json, install --accept-plan, --purge-data opt-in, repair command, report command, resume command (+22 more)

### Community 207 - "test_routing_presets.py"
Cohesion: 0.13
Nodes (13): Self-review (спека → план), GeodataSource, EgressTarget, explain(), rule_for(), GeodataSourceBody, target_from_identity(), _policy() (+5 more)

### Community 208 - "AgentTransportServer"
Cohesion: 0.14
Nodes (8): AgentTransportServer, issue_fixture(), mtls_context(), start_server(), test_agent_client_retries_result_from_durable_outbox_without_reexecution(), test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(), test_revocation_and_request_body_bound_fail_closed(), test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node()

### Community 209 - "register_subscription_admin_routes"
Cohesion: 0.21
Nodes (12): _public(), register_subscription_admin_routes(), create(), issue(), overview(), read(), reveal(), revoke() (+4 more)

### Community 210 - "StubManager"
Cohesion: 0.13
Nodes (3): request(), StubManager, test_manager_unix_api_is_authenticated_bounded_and_no_store()

### Community 211 - "docker_lab.py"
Cohesion: 0.21
Nodes (10): _architecture(), build_image(), copy_inputs(), DockerLabError, guest_command(), main(), run(), run_acceptance() (+2 more)

### Community 213 - "xray_router_manager/healthcheck.py"
Cohesion: 0.10
Nodes (16): test_healthcheck_status_flag_prints_the_manager_status(), _serve(), test_unix_api_lanes_and_relay_routes(), test_unix_api_manual_intervention_and_readback_codes(), test_unix_api_reports_artifact_mismatch_and_broken_router(), test_unix_api_routes_codes_and_health(), check(), main() (+8 more)

### Community 214 - "warp_routing"
Cohesion: 0.40
Nodes (4): warp_routing(), test_warp_appends_rules_without_replacing_the_final_policy(), test_warp_emits_nothing_when_disabled(), test_warp_requires_operator_confirmed_domains()

### Community 215 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.23
Nodes (12): ADR 001: pull-only node transport, ADR 003: one writer per resource, Task 1: ADRs and v0.2 architecture record, Task 2: Characterization tests of current boundaries, Task 3: Capability matrix and fixture, Ownership manifest, Fleet v1 Telemt-only command queue, Resource ownership terms: managed | adopted | foreign | drifted | tombstoned (+4 more)

### Community 216 - "Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext"
Cohesion: 0.14
Nodes (14): 10. Spike (Task 32) — что проверяется на стенде, 12. Backup/restore и матрица негативных тестов (Tasks 37, 39), 13. Лаборатория и гейт (Tasks 36, 40), 14. Документация и релиз (Task 41), 15. Отклонения от спеки vNext и решения, принятые за владельца, 1. Цель, 2. Паритет с 3x-ui, 3. Архитектурные решения (+6 more)

### Community 217 - "ThreeXuiClient"
Cohesion: 0.13
Nodes (5): _default_api_factory(), _Sanitized, ThreeXuiClient, test_api_refuses_a_non_loopback_endpoint(), test_panel_client_uses_tls_and_pins_certificate_before_credentials()

### Community 219 - "test_routing_lanes_routes.py"
Cohesion: 0.27
Nodes (11): _attach(), _csrf(), _grant(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first(), test_lane_refusals_carry_codes() (+3 more)

### Community 221 - "test_version_agent_artifacts.py"
Cohesion: 0.26
Nodes (12): _targz(), test_escaping_members_unknown_formats_and_garbage_are_refused(), test_missing_member_symlink_and_oversize_are_refused(), test_tar_member_may_sit_under_a_directory(), test_tar_member_written_with_a_dot_slash_prefix_is_still_found(), test_zip_member_is_returned_by_exact_name(), _zip(), ArtifactError (+4 more)

### Community 222 - "English"
Cohesion: 0.12
Nodes (16): Common rules, Development and continuation, English, Getting started, Operations, Protocols and panel, Proxy Control documentation, Releases (+8 more)

### Community 223 - "Proxy Control v0.1.0 Beta"
Cohesion: 0.16
Nodes (11): Archive SHA-256 checksum for proxy-control-v0.1.0.tar.gz, Mieru (TCP/UDP proxy on explicit public ports), mita local manager for Mieru, NaiveProxy (HTTPS proxy with cover site, users, quotas, completed-tunnel accounting), Proxy Control panel (owner/admin/viewer roles, secret-free audit, one-time credential disclosure), Proxy Control v0.1.0 Beta, Four release assets (archive, SHA256SUMS, release-manifest.json, sbom.spdx.json), sbom.spdx.json SBOM (+3 more)

### Community 224 - "English"
Cohesion: 0.12
Nodes (16): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z → ams-test), Proxy Control v0.7.0-beta.1, Screenshots, Upgrading, What the verification found (+8 more)

### Community 225 - "Disposable lab host ams-test"
Cohesion: 0.24
Nodes (10): Disposable lab host ams-test, Baseline main@8c787c5 (2026-09-10), Audit finding 14: Current state of ams-test, Audit finding 15: Baseline on ams-test, Verification levels A-F (quick, full, compose, lab-container, lab-host, real install), Task 0: ams-test stand and baseline, Task 40: Repository and isolated-system gates, remote() (+2 more)

### Community 226 - "CommandRunner"
Cohesion: 0.11
Nodes (5): CommandRunner, RuntimePlan, test_command_runner_reports_captured_stderr_for_failed_command(), test_compose_discovery_reports_unavailable_when_docker_is_not_installed(), test_compose_reconciliation_uses_declared_project_identity()

### Community 227 - "Task 3.2: installer deploys WARP automatically"
Cohesion: 0.18
Nodes (11): ams-server production reference server, cloudflare-warp client / warp-svc.service, release/external-artifacts.json (pinned external artifacts), Task 3.2: installer deploys WARP automatically, Task 3.3: selective WARP routing via 3x-ui, three_xui.warp_domains config option, WARP selective domain list (geosite:openai, anthropic, tiktok, reddit, google-gemini, google-play), WARP proxy mode on local SOCKS5 port 40000 (+3 more)

### Community 228 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`, tree `841a086`, 2026-09-14), Installing, Live check (AMS_Z), Proxy Control v0.4.0-beta.1, Screenshots, Upgrading, What's new (+7 more)

### Community 229 - "_panel_health_diagnosis"
Cohesion: 0.11
Nodes (8): _as_text(), _command_failure(), _panel_health_diagnosis(), _sanitize_diagnostic(), _without_health_polling(), test_a_failed_panel_health_check_says_what_the_containers_were_doing(), test_the_panel_diagnosis_drops_its_own_health_polling(), test_the_panel_diagnosis_never_lets_a_diagnostic_failure_mask_the_real_one()

### Community 230 - "test_installer_chains.py"
Cohesion: 0.09
Nodes (17): ArtifactError, MieruPaths, _slot_action(), _slot_config(), SlotRunner, _stage_router(), test_healthcheck_relay_flags_post_and_get(), test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them() (+9 more)

### Community 231 - "ensure_pinned_package"
Cohesion: 0.09
Nodes (6): ensure_pinned_package(), StagedMita, test_a_download_that_does_not_match_its_pin_is_discarded(), test_a_missing_package_is_fetched_from_its_pin(), fetch(), test_a_package_that_is_already_staged_is_not_fetched_again()

### Community 233 - "test_client_links.py"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 234 - "register_node_routes"
Cohesion: 0.26
Nodes (13): _local_identity(), register_node_routes(), _context(), disable(), enable(), node(), nodes(), register() (+5 more)

### Community 236 - "test_placement_ui_contract.py"
Cohesion: 0.30
Nodes (6): run(), test_diff_creates_enables_and_disables_from_ticks(), test_render_marks_cells_and_disables_what_cannot_change(), test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants(), test_settling_is_true_while_a_node_has_not_confirmed_and_ignores_deleted_grants(), test_unoffered_rows_are_never_part_of_the_diff()

### Community 237 - "English"
Cohesion: 0.15
Nodes (13): English, Gate checklist (lab host `ams-test`, tree `ade7fcc`, 2026-09-14 — after the three rounds of the final-review fix wave), Installing, Proxy Control v0.3.0-beta.1, Screenshots, Upgrading, What's new, Обновление (+5 more)

### Community 238 - "v0.10 — клиент на нескольких узлах и подписка под рукой"
Cohesion: 0.15
Nodes (13): 1. Цель, 3. API, 4. Реестр аудита и события, 5.1 Окно клиента, 5.2 Диалог «Новый клиент», 5.3 Диалог «Выдать доступ», 5.4 Экраны MTProxy / NaiveProxy / Mieru, 5. Интерфейс (+5 more)

### Community 239 - "accepted_sha256"
Cohesion: 0.28
Nodes (7): accepted_caddy_pins(), accepted_sha256(), agent_component(), _state(), test_invalid_state_yields_only_the_pin(), test_missing_or_failed_state_yields_only_the_pin(), test_state_adds_the_agent_installed_hashes()

### Community 240 - "RelayRegistry"
Cohesion: 0.13
Nodes (3): Nodes (central side), 6. Модель политики и компилятор (`panel/routing/`), RelayRegistry

### Community 242 - "test_dashboard_ui_contract.py"
Cohesion: 0.14
Nodes (3): test_host_card_follows_the_host_while_the_overview_is_open(), test_overview_placeholder_has_the_overviews_own_shape(), test_panel_version_is_on_screen_for_every_role_and_on_a_phone()

### Community 243 - "test_view_addressing_ui.py"
Cohesion: 0.21
Nodes (7): index_html(), main_js(), test_an_unknown_or_forbidden_view_falls_back_to_the_overview(), test_back_and_forward_move_between_views(), test_boot_opens_the_view_the_address_names(), test_every_menu_item_has_an_address(), test_navigation_writes_the_view_into_the_address()

### Community 244 - "CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22"
Cohesion: 0.15
Nodes (13): 2026-09-22 — окно клиента, гейт, раскатка, CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22, MCP — СДЕЛАНО (2026-09-21, вечер), MCP-сервер (решение владельца: в v0.11, полный набор, с ноутбука через SNI, только на центре), WARP на парке единообразно (2026-09-22, по слову владельца), ВЫПУЩЕНО 2026-09-22 (по слову владельца), Обновление компонентов на парке (2026-09-22, по слову владельца «обнови»), Открытые мелочи (+5 more)

### Community 245 - "v0.11 Upstream Updates & MCP Handoff"
Cohesion: 0.15
Nodes (13): MCP Server for Panel Tools, v0.11 Upstream Updates & MCP Handoff, Version Agent Upstream Service, Cloudflare WARP Selective Routing, v0.1 Handoff and Plan, v0.3 Central Panel Handoff, v0.4 Routing Handoff, v0.5 Xray Egress Router Handoff (+5 more)

### Community 246 - "3. Задачи"
Cohesion: 0.15
Nodes (12): 1. Где остановились, 2. Как WARP устроен на рабочем сервере (снято с `ams-server`), 3.1 Добить установку, 3.2 Автоматический WARP, 3.3 Выборочная маршрутизация через 3x-ui, 3.4 Подписка 3x-ui (девятый домен), 3.5 Релизная лаборатория, 3. Задачи (+4 more)

### Community 247 - "3x-ui mode managed-new: install on clean server, create inbounds"
Cohesion: 0.21
Nodes (13): Task 3.4: 3x-ui subscription on ninth domain, zenith.sky.dubr1kkk.uk (reserved: 3x-ui subscription), Bilingual install wizard, Hysteria2 inbound, Nginx mode coexist: existing Nginx stream keeps TCP/443, Nginx mode fresh: installer installs and configures Nginx, Nine distinct domains for full profile + managed-new + subscription (eight without subscription), Shared TCP/443 SNI routing (+5 more)

### Community 248 - "English"
Cohesion: 0.14
Nodes (14): English, Installing, Live check (AMS_Z), Proxy Control v0.5.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z) (+6 more)

### Community 249 - "host.py"
Cohesion: 0.19
Nodes (10): test_disk_reports_space_an_operator_can_actually_write(), test_real_proc_is_parsed_on_linux(), _cpu(), _cpu_times(), _disk(), host_metrics(), _load_average(), _meminfo() (+2 more)

### Community 250 - "admin"
Cohesion: 0.06
Nodes (35): ADR 008: Panel-to-panel transport with scoped API keys, Consequences, Context, Decision, Non-goals, 6.3 Привязка: три действия на центре, 10. Тестирование, 11. Критерии приёмки v0.3 (+27 more)

### Community 251 - "v1.1 — маршрутизация MTProxy через Xray-router"
Cohesion: 0.15
Nodes (12): 1. Цель, 2. Что доказано на стенде (ams-test, 2026-10-01), 3. Топология, 4. Xray-router (менеджер), 5. Мост `xray-router-ingress`, 6. Панель, 7. Установщик, 7a. Обновление одной командой (добавлено владельцем 2026-10-01) (+4 more)

### Community 252 - "config"
Cohesion: 0.20
Nodes (6): _relay_config(), RelayRunner, test_a_router_action_without_relay_keys_still_applies_and_verifies(), test_router_apply_enables_the_relay_and_verify_proves_its_public_part(), test_router_plan_carries_the_relay_and_refuses_a_claimed_relay_port(), config()

### Community 254 - "run_captured"
Cohesion: 0.21
Nodes (13): full_idempotence(), full_install(), host_idempotence(), host_install(), interrupt_install_recovery(), release_idempotence(), release_install(), release_install_full_xui() (+5 more)

### Community 255 - ".handle"
Cohesion: 0.21
Nodes (5): _main(), _pump(), _read_target(), _reply(), Stub

### Community 256 - "test_xray_router_deployment.py"
Cohesion: 0.22
Nodes (7): render_compose(), run_state_preparer(), test_prepare_and_verify_state_directory(), test_router_overlay_gives_managers_their_ingress_and_the_panel_its_socket(), test_router_overlay_is_loopback_only_read_only_and_pinned(), test_router_overlay_without_mieru_still_renders(), test_state_preparer_refuses_bad_paths()

### Community 257 - "compose fleet-agent overlay service"
Cohesion: 0.20
Nodes (6): compose fleet-agent overlay service, compose fleet-ingress overlay service, Typed per-node command queue, Fleet central mTLS ingress, Outbound mTLS fleet transport v1, panel.cli fleet CA/enrollment commands

### Community 260 - "i18n-strings.py"
Cohesion: 0.26
Nodes (7): _clean(), fragments(), main(), _read_string(), _read_template(), _scan_code(), _skip_comment()

### Community 261 - "guest-runner.sh script"
Cohesion: 0.26
Nodes (12): case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), full_environment_preflight(), host_diagnostics(), host_environment_preflight() (+4 more)

### Community 264 - "English"
Cohesion: 0.20
Nodes (9): Changes, Deployment and rollback, English, v0.14.0-beta.1 — совместное использование 443 и приёмка Naive, Validation scope, Изменения, Развёртывание и откат, Русский (+1 more)

### Community 265 - "test_proxyctl.py"
Cohesion: 0.36
Nodes (7): facts_from_root(), fixture_root(), test_audit_discovers_stream_conf_d_routes(), test_audit_reports_existing_shared_443_without_dumping_secrets(), test_domain_validation_normalizes_valid_hostname(), test_install_plan_rejects_domain_and_port_collisions(), test_install_plan_rejects_unknown_nginx_and_gates_unavailable_by_mode()

### Community 266 - "English"
Cohesion: 0.18
Nodes (11): Added, Changed, English, Fixed, Upgrading from v1.0.0, v1.0.1 — любые версии компонентов, региональные geodata с автообновлением, Добавлено, Изменено (+3 more)

### Community 267 - "English"
Cohesion: 0.18
Nodes (11): Added, Changed, English, Fixed, Upgrading from v1.0.1, v1.0.2 — окно доступа, поиск и фильтры клиентов, аккуратная вёрстка, Добавлено, Изменено (+3 more)

### Community 268 - "The Xray-router (v0.5): one dedicated egress router per node"
Cohesion: 0.18
Nodes (11): A third ingress: MTProxy (v1.1), Credentials and rotation, DNS and private destinations, Lanes, chains and the relay (v0.7), Limits and what is deferred, Operations, The runtime, The transaction (+3 more)

### Community 269 - "Xray-router (v0.5): один выделенный egress-роутер на узел"
Cohesion: 0.18
Nodes (11): DNS и приватные адреса, Xray-router (v0.5): один выделенный egress-роутер на узел, Ключи и ротация, Ограничения и что отложено, Полосы, цепи и relay (v0.7), Рантайм, Транзакция, Третий вход: MTProxy (v1.1) (+3 more)

### Community 272 - "TelemtIndeterminate"
Cohesion: 0.13
Nodes (15): TelemtIndeterminate, blocked_rotate(), test_create_double_indeterminate_propagates_raw_not_adapter_error(), create_user(), rotate(), anyio_backend(), _client(), telemt() (+7 more)

### Community 274 - "sbom.py"
Cohesion: 0.26
Nodes (7): build_sbom(), _external_packages(), _identifier(), main(), SbomError, test_sbom_is_deterministic_for_one_commit(), test_sbom_requires_at_least_one_packaged_file()

### Community 275 - "rotate-xray-router-ingress.sh"
Cohesion: 0.27
Nodes (10): compose(), fail(), MIERU_MANAGER_UID, NAIVE_MANAGER_GID, NAIVE_MANAGER_UID, random_hex(), random_password(), ROUTER_GID (+2 more)

### Community 276 - "ReleaseMatrixTests"
Cohesion: 0.24
Nodes (3): _passing_report(), ReleaseMatrixTests, report_without()

### Community 277 - "test_socks5_stub.py"
Cohesion: 0.31
Nodes (7): _connect_through(), _echo(), _load(), _refuses(), _relays(), test_stub_logs_connect_target_and_relays(), test_stub_reports_a_refused_target_and_refuses_when_told_to()

### Community 278 - "Proxy Control Cover Art"
Cohesion: 0.33
Nodes (8): Anime Key-Art Illustration Style, Beam vs Hammer Clash Metaphor, Twin-Tailed Girl Blocking With Stone Hammer, Proxy Control Cover Art, Central Impact Burst Where Beam Meets Hammer, Proxy Control Repository Branding Asset, Night Ruined Colosseum Arena Backdrop, Rearing Unicorn Emitting Magenta Horn Beam

### Community 279 - "CONTINUE-HERE-v0.7.md"
Cohesion: 0.33
Nodes (8): v0.7.0-beta.1 (Release), v0.8.0-beta.1 (Release), Handoffs Archive README, ams-test (Staging Host), AMS_Z (Production Host), CONTINUE-HERE.md (Active), Audit Hardening Plan (2026-10-02), v1.1.1-rc.2 (Candidate)

### Community 280 - "Аудит Proxy Control v1.1.0 и проверка исправлений rc.2"
Cohesion: 0.20
Nodes (9): Аудит Proxy Control v1.1.0 и проверка исправлений rc.2, Дополнение для кандидата 1.1.1-rc.2, Исходные доказательства, Контрольная точка кандидата (2026-10-02), Незавершённые проверки и ограничения, Последовательность, Следующие улучшения за пределами исправлений, Слияние в main (2026-10-03) (+1 more)

### Community 281 - "FleetPusher"
Cohesion: 0.10
Nodes (3): _Backoff, FleetPusher, test_overlapping_ticks_share_a_global_concurrency_limit_and_visit_every_node()

### Community 282 - "Trust Boundaries"
Cohesion: 0.20
Nodes (6): Pull Request Boundary Checklist, Contribution Architecture Rules, Local Development Gate Commands, Trust Boundaries, Caddy Builder Digest and forwardproxy Commit Pin, Third-Party License Boundary Summary

### Community 284 - "prepare_mieru_token.py"
Cohesion: 0.36
Nodes (6): fail(), main(), prepare_or_verify(), TokenError, validate_path(), validate_source()

### Community 286 - "Рабочий протокол для AI-агентов"
Cohesion: 0.22
Nodes (9): Главное правило, Изолированная установка и реальные проверки, Обязательные проверки репозитория, Перед изменением, Правила, которые уже спасали от ложных отчётов, Правила отчёта, Проверка всех Compose-моделей и образов, Рабочий протокол для AI-агентов (+1 more)

### Community 287 - "mieru-client/probe.py"
Cohesion: 0.36
Nodes (5): _endpoint(), main(), _run(), _socks5_connect(), _status_through()

### Community 288 - "Audit event names"
Cohesion: 0.25
Nodes (8): Audit event names, Authentication and administrators, Clients, grants and subscriptions, Nodes (node side, through the central's key), Routing (v0.4), Global Constraints, audit_log(), test_audit_event_names_are_documented_once()

### Community 289 - "MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP"
Cohesion: 0.22
Nodes (9): MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP, Выключить, Как включить, Подключение, Правило `confirm`, Проверка, Ротация токена и ключа, Скиллы (+1 more)

### Community 290 - "fleet-measure.py"
Cohesion: 0.24
Nodes (3): distribution(), main(), measure()

### Community 291 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.14, v0.15.0-beta.1 — версия панели и обновления узлов из центра, Добавлено, Исправлено, Обновление с v0.12–v0.14 (+1 more)

### Community 292 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.15, v1.0.0 — первый стабильный выпуск: понятная маршрутизация, английский интерфейс, сохранённые ключи Mieru, Добавлено, Исправлено, Обновление с v0.12–v0.15 (+1 more)

### Community 293 - "English"
Cohesion: 0.22
Nodes (9): Added, Changed, English, Upgrading from v1.0.3, v1.1.0 — маршрутизация MTProxy через Xray-router, Добавлено, Изменено, Обновление с v1.0.3 (+1 more)

### Community 294 - "The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP"
Cohesion: 0.22
Nodes (9): Connecting, How to enable, Rotating the token and the key, Skills, The `confirm` rule, The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP, Turning it off, Verification (+1 more)

### Community 295 - "Verification matrix — maintained functions and their proofs"
Cohesion: 0.22
Nodes (9): backend, clients, fleet, installer, release, router, routing, ui (+1 more)

### Community 296 - "test_clients_filters_ui.py"
Cohesion: 0.39
Nodes (5): _node(), test_import_still_offers_clients_outside_the_current_page(), test_paging_and_server_search_keep_the_dom_bounded_and_discard_stale_responses(), test_search_and_filters_select_the_right_clients(), test_the_card_lists_clickable_grant_rows_and_escapes_names()

### Community 297 - "container_cmd"
Cohesion: 0.22
Nodes (9): container_audit(), container_cmd(), container_nginx_multi_map(), container_uninstall_foreign_identity(), host_crash_every_phase(), host_reboot_recovery(), host_repair(), host_report() (+1 more)

### Community 298 - "installer_cmd"
Cohesion: 0.22
Nodes (9): installer_cmd(), release_audit(), release_coexist_existing_xui(), release_crash_every_phase(), release_nginx_multi_map(), release_reboot_recovery(), release_repair(), release_uninstall() (+1 more)

### Community 300 - "test_readiness.py"
Cohesion: 0.22
Nodes (4): login(), test_database_query_failure_reports_hard_failure(), test_node_state_uses_actual_applied_timestamp(), test_readiness_requires_owner_or_admin_and_does_not_change_healthz()

### Community 301 - "test_fetch_reports_the_hop_that_names_the_release"
Cohesion: 0.20
Nodes (4): test_fetch_reports_the_hop_that_names_the_release(), build_opener(), fetch(), redirect_request()

### Community 303 - "Промпт для продолжения работы в новом контексте"
Cohesion: 0.25
Nodes (8): Задача 1: добить установку, Задача 2: автоматический WARP, Задача 3: релиз, Отложено владельцем, Правила, добытые дорогой ценой, Промпт для продолжения работы в новом контексте, Прочитай сначала, Что уже сделано

### Community 304 - "CONTINUE HERE — v0.3 центральная панель"
Cohesion: 0.25
Nodes (8): CONTINUE HERE — v0.3 центральная панель, Где мы, Гейт v0.3.0-beta.1 (2026-09-14 11:42–11:59 UTC, дерево `ade7fcc`, чистое — после трёх раундов фикс-волны), Действия владельца, Отложенные minor и out-of-scope наблюдения, Рулинги, принятые за владельца (в итоговый отчёт), Точка продолжения, Что дальше по ветке

### Community 305 - "Промпт для продолжения работы в новом контексте"
Cohesion: 0.25
Nodes (8): Task 19A — релизный гейт v0.2 на `ams-test` (пройден 2026-09-11), Как проверять (единственный способ), Правила, добытые в этой серии, Промпт для продолжения работы в новом контексте, Прочитай сначала, Состояние репозитория (2026-09-11), Что делать первым делом, Что уже сделано (Tasks 0–14)

### Community 306 - "Post-rc.2 hardening implementation plan"
Cohesion: 0.20
Nodes (9): Continuation on 3 October, Global constraints, Integration and handoff, Post-rc.2 hardening implementation plan, Review focus, Task 1: Update ownership handoff and legacy recovery, Task 2: Compose scope preflight, Task 3: Readiness diagnostic (+1 more)

### Community 307 - "status / resume / repair"
Cohesion: 0.33
Nodes (7): Ownership journal /var/lib/proxy-control/installer/state.json, status / resume / repair, uninstall and --purge-data, Журнал владения state.json, uninstall и --purge-data, Uninstalling, Удаление

### Community 309 - "test_api_key_auth.py"
Cohesion: 0.46
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 310 - "test_telemt_adapter_does_not_leak_secret_in_errors"
Cohesion: 0.25
Nodes (6): test_telemt_adapter_does_not_leak_secret_in_errors(), handler(), test_telemt_adapter_patches_limits_and_resets_quota(), handler(), test_telemt_adapter_reads_3425_quota_stats_route(), test_telemt_adapter_sends_auth_and_maps_envelope()

### Community 312 - "English"
Cohesion: 0.22
Nodes (9): English, Fresh install, Upgrading from v0.9 or v0.10, v0.11.0-beta.1 — обновления из upstream, What changed for you, Обновление с v0.9 или v0.10, Русский, Установка с нуля (+1 more)

### Community 313 - "update-host.sh"
Cohesion: 0.47
Nodes (8): agent(), fail(), has(), health(), json(), preflight_compose_scope(), say(), update-host.sh script

### Community 314 - "English"
Cohesion: 0.22
Nodes (9): English, Installing, Upgrading from v0.11, v0.12.0-beta.1 — адрес у каждого раздела, ссылки MTProxy в карточке клиента, What changed for you, Обновление с v0.11, Русский, Установка с нуля (+1 more)

### Community 316 - "CONTINUE HERE — v0.4 маршрутизация"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.4 маршрутизация, Где мы, Гейт (Task 13) — итог, Известные ограничения/решения (для ревью и v0.5), Коммиты ветки (по порядку), Публикация (по поручению владельца 2026-09-14), Что дальше (владелец)

### Community 317 - "CONTINUE HERE — v0.6 сверка функций v0.2–v0.5"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.6 сверка функций v0.2–v0.5, Где мы, Гейт (финальное дерево) и живая проверка, Известные ограничения/решения, Публикация (сделано 2026-09-17 11:18–11:30 UTC), Что дальше (владелец), Что сделано (коммиты по порядку)

### Community 318 - "English"
Cohesion: 0.22
Nodes (9): English, Fixed, Upgrading from v0.12, v0.13.0-beta.1 — мобильные карточки и быстрые настройки, Verification and rollout scope, Исправлено, Обновление с v0.12, Русский (+1 more)

### Community 320 - "test_routing_routes.py"
Cohesion: 0.48
Nodes (5): _csrf(), test_apply_rollback_delete_and_history(), test_preview_of_a_draft_does_not_save(), test_put_upserts_with_expected_revision_and_keeps_rule_ids(), test_viewer_reads_and_previews_but_never_mutates()

### Community 322 - "install-release.sh"
Cohesion: 0.52
Nodes (6): check_manifest(), fail(), requirements(), say(), install-release.sh script, usage()

### Community 324 - "container_setup"
Cohesion: 0.33
Nodes (7): add_hosts(), container_setup(), container_write_configs(), host_ip(), host_setup(), setup_full_host(), write_fake_certbot()

### Community 325 - "client_probe"
Cohesion: 0.29
Nodes (7): client_probe(), release_hysteria_client(), release_mieru_client(), release_naive_client(), release_telemt_client(), release_vless_tcp_client(), release_vless_xhttp_client()

### Community 326 - "prepare-xray-router-state.sh"
Cohesion: 0.43
Nodes (6): fail(), ROUTER_GID, ROUTER_MODE, ROUTER_UID, prepare-xray-router-state.sh script, verify_regular_file()

### Community 327 - "English"
Cohesion: 0.22
Nodes (9): English, Installer fixes, Installing, Proxy Control v0.2.0-beta.1, Verified for this release (on the lab host), Исправлено в установщике, Проверено для этого выпуска (на стенде), Русский (+1 more)

### Community 328 - "NginxReloadRecovery"
Cohesion: 0.29
Nodes (3): NginxReloadRecovery, run(), test_a_reload_that_kills_nginx_is_recovered_and_reported()

### Community 329 - "Post-rc.2 update hardening"
Cohesion: 0.25
Nodes (7): 1. Installer ownership after a panel update, 2. Enabled Compose services, 3. Readiness, 4. Acceptance readiness, Intent and boundaries, Post-rc.2 update hardening, Release criterion

### Community 330 - "test_mtproxy_respq_probe.py"
Cohesion: 0.57
Nodes (4): run_wrapper(), test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(), test_wrapper_rejects_invalid_arguments_without_starting_docker(), test_wrapper_requires_root()

### Community 331 - "RuleMatch"
Cohesion: 0.06
Nodes (21): ADR 006: Engine-neutral routing policy IR, Amended in v1.1 (2026-10-01): MTProxy through the Xray-router, As shipped in v0.4, Consequences, Context, Decision, Non-goals, Живая проверка (парк: ams-server → AMS_Z, AMS_Z → ams-test) (+13 more)

### Community 332 - "Archived v0.3 credential capture confirmation"
Cohesion: 0.33
Nodes (3): Archived v0.3 Fleet v2 central panel, Archived v0.2 local control plane, Archived v0.2 subscription rendering

### Community 333 - "Archived v0.4 remote rollback boundary"
Cohesion: 0.33
Nodes (4): Archived v0.4 manager egress APIs, Archived v0.4 routing policies, Archived v0.5 router attachment, Archived v0.5 Xray egress router

### Community 334 - "CONTINUE HERE — v0.5 Xray egress-router"
Cohesion: 0.33
Nodes (6): CONTINUE HERE — v0.5 Xray egress-router, Где мы, Гейт (Task 15) — итог, Известные ограничения/решения (для ревью и после v0.5), Коммиты ветки (по порядку), Что дальше (владелец)

### Community 335 - "CONTINUE-HERE-v0.9.md"
Cohesion: 0.33
Nodes (5): CONTINUE HERE — v0.9 (стык фронт/бэк, matches_node, мобильный UI, Xray-router на центре), v0.9.0-beta.1 (Release), Сделано, Что дальше, ams-server (Central Host)

### Community 337 - "_serve"
Cohesion: 0.38
Nodes (5): _serve(), _answer(), do_GET(), do_POST(), get_request()

### Community 339 - "Нативная проверка кандидата 1.1.1-rc.3"
Cohesion: 0.25
Nodes (7): Границы доказательства, Исправления после 512be74, Нативная проверка кандидата 1.1.1-rc.3, Проверки кода и артефактов, Проверяемый артефакт, Чистая установка, Штатное обновление и repair

### Community 341 - "probe/install.sh"
Cohesion: 0.33
Nodes (5): DESTINATION, IMAGE, install.sh script, TDL_VERSION, TDLIB_VERSION

### Community 343 - "secrets"
Cohesion: 0.11
Nodes (18): ADR 009: Lanes per client and chains through the fleet's relays, Consequences, Context, Decision, Chains and lanes (v0.7), MTProxy через Xray-router (v1.1), WARP на хосте, Безопасность и аудит (+10 more)

### Community 344 - "skills/README.md"
Cohesion: 0.11
Nodes (13): Changing routing, Steps, `unsupported` reasons and what to do, What to tell the owner, Diagnosing a client's access, Report to the owner, Symptom → likely cause, What not to do (+5 more)

### Community 348 - "Private Vulnerability Reporting Path"
Cohesion: 0.40
Nodes (5): Sanitized Bug Report Template, Issue Template Config (blank issues disabled), Security Reporting Guidance Template, Code of Conduct, Private Vulnerability Reporting Path

### Community 349 - "Telemt MTProto data plane"
Cohesion: 0.40
Nodes (3): Private-network Caddy mask / cover site, Host Nginx stream/SNI router, Telemt MTProto data plane

### Community 350 - "ADR 001: Pull-only node transport"
Cohesion: 0.40
Nodes (5): ADR 001: Pull-only node transport, Consequences, Context, Decision, Non-goals

### Community 351 - "ADR 002: Declarative immutable generations"
Cohesion: 0.40
Nodes (5): ADR 002: Declarative immutable generations, Consequences, Context, Decision, Non-goals

### Community 352 - "ADR 005: Secrets travel as references"
Cohesion: 0.40
Nodes (5): ADR 005: Secrets travel as references, Consequences, Context, Decision, Non-goals

### Community 354 - "CONTINUE HERE — v0.7 (цепи и полосы)"
Cohesion: 0.40
Nodes (5): CONTINUE HERE — v0.7 (цепи и полосы), Выпуск (сделано 2026-09-18 10:16–12:50 UTC), Слияние и раскатка парка (сделано 2026-09-18 13:00–13:35 UTC, по решению владельца), Что дальше (владелец), Что оставлено на хостах

### Community 355 - "lab-amd64 CI release lab"
Cohesion: 0.40
Nodes (3): lab-amd64 CI release lab, Task 3.5: release lab lab-amd64, Verified: exact-archive lifecycle on isolated amd64 VPS (install, repair, idempotence, reboot/crash recovery, uninstall, coexistence)

### Community 356 - "Продолжение работы над Proxy Control"
Cohesion: 0.40
Nodes (5): Ограничения эксплуатации, Последние доказательства, Продолжение работы над Proxy Control, Репозиторий и кандидат, Следующие задачи

### Community 357 - "English"
Cohesion: 0.40
Nodes (5): Domains and shared port 443, English, Included, Installation, Verified for this release

### Community 358 - "Русский"
Cohesion: 0.40
Nodes (5): Домены и общий 443, Проверено для этого выпуска, Русский, Установка, Что входит

### Community 359 - "4. Автоматическое развёртывание узла"
Cohesion: 0.25
Nodes (8): 4.1 Требования к хосту, 4.2 Скачать и проверить релиз (без root), 4.3 Мастер: вопросы по порядку, 4.4 План и digest, 4.6 Приёмка, отчёты, где пароли, 4.7 Первые действия в панели, 4.8 Повторный запуск, resume, repair, uninstall, 4. Автоматическое развёртывание узла

### Community 360 - "ADR 007: Routing enforcement ownership"
Cohesion: 0.67
Nodes (3): ADR 007: Routing enforcement ownership, Context, Decision

### Community 362 - "_panel_probe"
Cohesion: 0.25
Nodes (3): _panel_probe(), test_a_panel_that_answers_with_an_error_code_reports_that_code(), test_a_panel_that_cannot_be_reached_still_raises()

### Community 365 - "_await_panel_health"
Cohesion: 0.29
Nodes (3): _await_panel_health(), test_panel_acceptance_gives_up_and_reports_the_last_refusal(), test_panel_acceptance_waits_for_the_panel_instead_of_racing_it()

### Community 371 - "_preparer"
Cohesion: 0.40
Nodes (4): _preparer(), test_state_preparer_refuses_a_symlinked_boundary(), test_state_preparer_refuses_unnormalized_and_relative_paths(), test_state_preparer_requires_root()

### Community 372 - "ADR 004: Client, AccessGrant and subscription as a projection"
Cohesion: 0.50
Nodes (4): ADR 004: Client, AccessGrant and subscription as a projection, Consequences, Context, Non-goals

### Community 373 - "CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)"
Cohesion: 0.50
Nodes (4): CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт), Сделано, Что дальше, Что оставлено на хостах

### Community 377 - "mieru-mss-clamp.sh"
Cohesion: 0.83
Nodes (3): check_rule(), mieru-mss-clamp.sh script, usage()

### Community 386 - "CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой)"
Cohesion: 0.67
Nodes (3): CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой), Сделано, Что дальше

### Community 387 - "Archived v0.11 upstream component updates"
Cohesion: 0.67
Nodes (3): Archived v0.11 central MCP server, Archived v0.11 installer version agent, Archived v0.11 upstream component updates

### Community 395 - "SecurityHeadersMiddleware"
Cohesion: 0.33
Nodes (3): send(), SecurityHeadersMiddleware, secured_send()

### Community 398 - "ADR 003: One writer per resource"
Cohesion: 0.50
Nodes (4): ADR 003: One writer per resource, Consequences, Decision, Non-goals

### Community 406 - "facts_with_uid"
Cohesion: 0.50
Nodes (4): facts_with_uid(), test_naive_plan_adopts_its_own_reserved_identities(), test_naive_plan_stops_on_fixed_accounting_group_collision(), test_naive_plan_stops_on_fixed_identity_collision()

## Ambiguous Edges - Review These
- `WARP as one loopback SOCKS5 endpoint` → `WARP as one SOCKS5 endpoint 127.0.0.1:40000`  [AMBIGUOUS]
  CHANGELOG.md · relation: semantically_similar_to
- `Beam vs Hammer Clash Metaphor` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: rationale_for
- `Proxy Control Repository Branding Asset` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: conceptually_related_to

## Knowledge Gaps
- **775 isolated node(s):** `telemt-entrypoint.sh script`, `install.sh script`, `entrypoint.sh script`, `TELEMT_API_TOKEN_FILE`, `API_REASONS` (+770 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 3707 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **123 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `WARP as one loopback SOCKS5 endpoint` and `WARP as one SOCKS5 endpoint 127.0.0.1:40000`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **What is the exact relationship between `Beam vs Hammer Clash Metaphor` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: rationale_for) - confidence is low._
- **What is the exact relationship between `Proxy Control Repository Branding Asset` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `Матрица негативных и security-тестов vNext (Task 39)` connect `Матрица негативных и security-тестов vNext (Task 39)` to `test_routing_fleet_router.py`, `AccessGrant`, `GrantIntent`, `test_xray_routing_compiler.py`, `create_app`, `test_fleet_v2_node_api.py`, `FleetStore`, `test_fleet.py`, `ManagedStore`, `test_routing_router_service.py`, `docs/README.md`, `test_users_adapter_ui.py`, `ReleaseManifest`, `v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router`, `document_digest`, `EgressInvalid`, `test_mieru_manager.py`, `naive_manager/egress.py`, `safe_extract_zip`, `xray_router_manager/service.py`, `test_fleet_acceptance_script.py`, `test_routing_service.py`, `test_installer_xray_router.py`, `test_mieru_egress.py`, `NodeClient`, `script`, `AgentTransportServer`, `DeployCliTests`, `test_rbac_audit.py`, `xray_router_manager/healthcheck.py`, `test_installer_release.py`, `Scenario`, `test_installer_transaction.py`, `test_fleet_v2_reconcile.py`, `PolicyInput`, `test_naive_manager_egress.py`, `test_grant_lifecycle.py`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `vNext architecture (v0.2 and v0.3)` connect `ManagedStore` to `AccessGrant`, `docs/README.md`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `Task 10: NaiveProxy adapter` connect `Ownership boundaries and adapter order` to `prepare-naive-state.py`, `Planned File Structure`, `3x-ui mode: managed-new`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `Action` (e.g. with `Adapter` and `CoreAdapter`) actually correct?**
  _`Action` has 38 INFERRED edges - model-reasoned connections that need verification._