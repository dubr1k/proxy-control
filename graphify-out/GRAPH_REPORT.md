# Graph Report - proxy-control-rc2-hardening  (2026-10-03)

## Corpus Check
- 551 files · ~1,126,735 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 40 file(s) not represented in the graph (top: (none) 14, .service 8, .conf 5)

## Summary
- 12862 nodes · 36729 edges · 435 communities (324 shown, 111 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 3826 edges (avg confidence: 0.93)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `512be74b`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_routing_fleet_chains.py
- AccessGrant
- pytest
- json
- GrantRef
- test_installer_wizard.py
- GrantIntent
- test_installer_three_xui.py
- MemoryTelemt
- NaiveCredentialManager
- ThreeXuiAdapter
- parse_config
- Proxy Control
- test_naive_manager.py
- AuditFacts
- create_app
- RoutingService
- Troubleshooting Proxy Control
- routing.js
- InstallerConfig
- MemoryNaive
- test_installer_version_agent.py
- ._update_binary
- ._sync_client
- TrafficCollector
- AgentJournal
- test_xray_router_geodata.py
- nodes.js
- RoutingRule
- test_installer_mcp.py
- Панель управления Proxy Control
- Action
- XrayRouterManager
- Interactive release installer
- upstream
- app.py
- MieruAdapter
- test_version_agent_upstream.py
- test_mieru_management.py
- docs/README.md
- test_installer_audit.py
- test_installer_mieru.py
- NaiveAdapter
- test_installer_nginx.py
- Isolated Ubuntu 24.04 installer lab
- MieruManager
- Sharing Mieru configurations
- ExitInput
- common.js
- test_mcp_server.py
- installer/audit.py
- proxyctl.py
- test_installer_core.py
- Матрица негативных и security-тестов vNext (Task 39)
- xray_router_manager/service.py
- release.py
- test_installer_fresh_host.py
- test_installer_naive.py
- test_version_agent_panel.py
- test_mieru_manager.py
- naive_manager/egress.py
- render_config
- firewall.py
- _DefaultNaiveRunner
- Управление Mieru / mita 3.35–3.36
- query
- test_client_import.py
- TopologyError
- VersionAgent
- test_mieru_egress.py
- test_installer_xray_router.py
- test_mieru_manager_lanes.py
- DomainFacade
- NodeClient
- test_installer_credentials.py
- proxy-control-lab-clients Compose project
- test_subscription_events.py
- XrayRouterAdapter
- register_routing_routes
- TelemtAdapter
- DeployCliTests
- Структура файлов
- RuntimeInstaller
- Planned File Structure
- vNext v0.2 local control plane implementation plan
- clients.js
- schemas.py
- curated.py
- register_naive_routes
- test_installer_release.py
- installer/cli.py
- Scenario
- test_installer_transaction.py
- createGrantDialog
- panel
- test_fleet_v2_reconcile.py
- qemu_lab.py
- .step_05c_chains
- CentralProcess
- UnixHTTPServer
- adapters/mieru.py
- UpdateError
- test_node_lifecycle.py
- Reconciler
- test_installer_docs.py
- ProtocolError
- config
- PolicyInput
- v1.1.0 audit and rc.2 acceptance report
- esc
- test_naive_manager_egress.py
- test_mieru_deployment.py
- Task 16: Reproducible release builder and GitHub workflow
- test_fleet_v2_post_merge.py
- test_grant_lifecycle.py
- Ownership boundaries and adapter order
- _DefaultCoreRunner
- Accounting semantics
- MieruClient
- build.py
- transaction.py
- test_naive_manager_lanes.py
- TelemtError
- grant.js
- test_xray_router_mtproxy.py
- i18n.js
- Host
- Dedicated Proxy-Control-owned xray-router
- managed-xui-clients.py
- MemoryMieru
- Path
- guest-runner.sh
- test_release_build.py
- Журнал изменений
- Panel version-agent
- test_xray_routing_compiler.py
- PackagesAdapter
- Evidence
- main
- Task 14: Profile orchestration, reports and acceptance contract
- renderers/base.py
- test_installer_warp_transaction_recovery.py
- test_version_agent_host.py
- _render_at_phone_viewport
- WarpAdapter
- test_proxyctl_transactions.py
- QemuLabTests
- Store
- ValidationError
- management.js
- prepare-naive-state.py
- MitaCLI
- FleetStore
- test_panel_entrypoint.py
- Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация
- _DefaultXrayRouterRunner
- nginx.py
- Acceptance
- test_three_xui_api.py
- NaiveClient
- test_resource_boundaries.py
- index.cjs
- test_update_host.py
- register_fleet_v2_central_routes
- DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)
- test_routing_router_service.py
- ThreeXuiApiError
- test_users_adapter_ui.py
- ManagerHandler
- Interactive Release Installer Design
- CatalogError
- ReleaseManifest
- test_subscription_lifecycle.py
- test_routing_ui_contract.py
- 3x-ui mode: managed-new
- Check
- UpgradeError
- XrayRouterClient
- AcceptanceError
- v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router
- test_egress_adapters.py
- CertificateAuthority
- register_fleet_v2_node_routes
- Proxy Control v0.3 — центральная панель и подключённые панели
- install-bootstrap
- SubscriptionService
- owner
- Task 6: Encrypted secret versions and master key
- .compose
- safe_extract_zip
- Browser
- LaneService
- _PinningStream
- RolledBackError
- QuotaEnforcer
- test_protocol_adapter_contract.py
- test_fleet_acceptance_script.py
- test_routing_service.py
- TelemtClient
- test_ui_browser_findings.py
- Global Constraints
- Task 4: Unified DB layer and migrations
- FakeFleet
- script
- MTProxy acceptance failure: Connection closed
- core_checks
- Configuration change procedure
- EgressTarget
- test_agent_transport.py
- register_mieru_routes
- docker_lab.py
- xray_router_manager/healthcheck.py
- warp_routing
- Task 1: ADRs and v0.2 architecture record
- Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext
- ThreeXuiClient
- RuntimeRunner
- test_routing_lanes_routes.py
- Router
- version_agent/service.py
- English
- Proxy Control v0.1.0 Beta
- English
- Interactive Release Installer Implementation Plan
- CommandRunner
- Task 3.2: installer deploys WARP automatically
- English
- _panel_health_diagnosis
- ArtifactError
- ensure_pinned_package
- AgentTransportServer
- test_client_links.py
- test_provisioning_saga.py
- test_security.py
- xray_router_manager/__main__.py
- Live check (AMS_Z ↔ ams-test)
- v0.10 — клиент на нескольких узлах и подписка под рукой
- accepted_sha256
- RelayRegistry
- test_managed_xui_clients.py
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
- test_a_router_action_without_relay_keys_still_applies_and_verifies
- agent_service.py
- run_captured
- .handle
- test_xray_router_deployment.py
- compose fleet-agent overlay service
- installer/adapters/__init__.py
- Panel
- i18n-strings.py
- guest-runner.sh script
- Panel
- CONTINUE-HERE.md
- English
- test_subscription_renderers.py
- English
- English
- The Xray-router (v0.5): one dedicated egress router per node
- Xray-router (v0.5): один выделенный egress-роутер на узел
- ManagedClient
- ManagerHandler
- test_telemt_recovery.py
- test_subscription_ui_contract.py
- build_sbom
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
- CDP
- update-host.sh
- ._push
- test_the_release_carries_the_mcp_server
- CONTINUE HERE — v0.4 маршрутизация
- CONTINUE HERE — v0.6 сверка функций v0.2–v0.5
- .run
- test_management_ui_contract.py
- test_routing_routes.py
- Handler
- install-release.sh
- Api
- container_setup
- client_probe
- prepare-xray-router-state.sh
- api
- NginxReloadRecovery
- Post-rc.2 update hardening
- test_mtproxy_respq_probe.py
- ADR 006: Engine-neutral routing policy IR
- Archived v0.3 credential capture confirmation
- Archived v0.4 remote rollback boundary
- CONTINUE HERE — v0.5 Xray egress-router
- CONTINUE-HERE-v0.9.md
- SecretGenerator
- _serve
- rejecting
- ._adopt
- test_rbac_audit.py
- probe/install.sh
- ADR 009: Lanes per client and chains through the fleet's relays
- skills/README.md
- ContainerScenarioTests
- ReleaseFixtureTests
- FakeClock
- Private Vulnerability Reporting Path
- Telemt MTProto data plane
- TypedCommand
- ADR 002: Declarative immutable generations
- ADR 005: Secrets travel as references
- Archived v0.1 real traffic acceptance
- CONTINUE HERE — v0.7 (цепи и полосы)
- lab-amd64 CI release lab
- Продолжение работы над Proxy Control
- English
- Русский
- ADR 007: Routing enforcement ownership
- https_probe
- AccessEnforcer
- test_the_domain_writer_adopts_a_user_it_did_not_create
- _ScopedClientDouble
- test_audit_names_a_foreign_holder_of_every_reserved_identity
- GuestRunnerPreflightScripts
- ReleaseRootLayout
- ReleaseConfigMatchesItsFixture
- _preparer
- ADR 004: Client, AccessGrant and subscription as a projection
- CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт)
- _deploy_hook_text
- RenderedNaive
- hosts_by_node
- mieru-mss-clamp.sh
- ContainerInputTests
- RecordedRunTests
- ReleaseArtifactTests
- test_naive_bootstrap_log_matches_the_manager_accounting_writer
- Archived v0.10 automatic client subscription
- CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой)
- Archived v0.11 upstream component updates
- Archived v0.6 verification matrix
- Archived v0.7 chains and lanes
- ingress_credential
- entrypoint.sh
- test_telemt_client_batches_inventory_reads_until_access_changes
- pinned_client
- test_mieru_acceptance_deletes_with_a_compare_and_set_revision
- test_installer_mieru_startup_diagnostics.py
- Screenshot Sanitization Policy
- telemt-entrypoint.sh
- install.sh
- Panel dev/test toolchain (pytest, ruff)
- check-deployment.sh
- check-naive-caddy-build.sh
- check-js-syntax.sh
- host-teardown.sh
- three-xui-existing.sh
- _identity_from_entry
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

## God Nodes (most connected - your core abstractions)
1. `Action` - 234 edges
2. `AuditFacts` - 196 edges
3. `InstallerConfig` - 145 edges
4. `query()` - 143 edges
5. `Proxy Control` - 132 edges
6. `CoreAdapter` - 128 edges
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

## Communities (435 total, 111 thin omitted)

### Community 0 - "test_routing_fleet_chains.py"
Cohesion: 0.04
Nodes (89): Task 9: Fleet v2 — egress в поколении, узел и центр (Task 31), Task 9: Fleet v2 — `companion`, `egress.router.v1`, порядок применения на узле, удалённые attach/detach, compile(), content_digest(), egress_section(), node_capabilities(), relay_section(), canonical_digest() (+81 more)

### Community 1 - "AccessGrant"
Cohesion: 0.03
Nodes (45): ADR 003: One writer per resource, Consequences, Context, Decision, Non-goals, Узел (fleet_v2 node, local lifecycle), Task 4: Подписка выдаётся вместе с клиентом, Decision records (+37 more)

### Community 2 - "pytest"
Cohesion: 0.03
Nodes (68): Task 1: Миграция 20 и `secret_ref` у подписки, ApiKeyService, _hash(), publish_for_client(), Database, DatabaseError, publish(), apply_migrations() (+60 more)

### Community 3 - "json"
Cohesion: 0.02
Nodes (46): load_env(), main(), 7. Fleet v2, _mcp_vhost_text(), _panel_vhost_text(), _subscription_vhost_text(), _panel_template(), check() (+38 more)

### Community 4 - "GrantRef"
Cohesion: 0.05
Nodes (18): Runtime users (protocol routes), Task 4: Адаптеры — caller-supplied secret для Telemt и `update_options`, applied_egress_from_view(), AppliedEgress, AppliedGrant, egress_error(), GrantRef, ManualInterventionRequired (+10 more)

### Community 5 - "test_installer_wizard.py"
Cohesion: 0.04
Nodes (63): load_config(), Locale, locale_from_environment(), parse_locale(), text(), _domain(), EditField, _email() (+55 more)

### Community 6 - "GrantIntent"
Cohesion: 0.04
Nodes (78): GrantIntent, MtproxyOptions, NaiveOptions, test_local_enforcement_batches_runtime_inventory_per_protocol(), test_an_interrupted_operation_is_resumed_through_the_api(), test_compile_leaves_mtproxy_expiration_out_of_the_options(), test_a_compensated_local_grant_is_purged(), refuse() (+70 more)

### Community 7 - "test_installer_three_xui.py"
Cohesion: 0.03
Nodes (72): AcceptanceError, parse_reality_keypair(), SystemSecrets, adapter(), build_release(), config_with_clients_and_reality_secret(), existing_config(), existing_facts() (+64 more)

### Community 8 - "MemoryTelemt"
Cohesion: 0.03
Nodes (48): RouterAdapter, attach_document(), attached_to_router(), canonical(), MemoryTelemt, _adapter(), anyio_backend(), Bridge (+40 more)

### Community 9 - "NaiveCredentialManager"
Cohesion: 0.05
Nodes (20): Task 4: naive-manager — egress API (Task 29a), _assert_regular(), _assert_safe_parent_chain(), _atomic_write(), _durable_mkdir(), _durable_unlink(), _fsync_directory(), lifecycle_synchronized() (+12 more)

### Community 10 - "ThreeXuiAdapter"
Cohesion: 0.04
Nodes (16): ArtifactError, _client_count(), _DefaultThreeXuiRunner, _plain_audit(), _safe_text(), _tags(), ThreeXuiAdapter, ThreeXuiAudit (+8 more)

### Community 11 - "parse_config"
Cohesion: 0.05
Nodes (77): _certificate_groups(), _as_dict(), _boolean(), ConfigError, _domain(), _domains(), _enum(), _integer() (+69 more)

### Community 12 - "Proxy Control"
Cohesion: 0.05
Nodes (79): In-lab verification checklist, Documentation contract runs every documented command through the CLI parser, Pinned external artifacts catalog release/external-artifacts.json, Host resource card via version-agent GET /v1/host, Profiles and adapters (packages, nginx, certificates, firewall, core, naive, mieru, three_xui), Naive site on port-only address with probe resistance, Per-protocol acceptance with real clients, Release acceptance lab (container and bare metal) (+71 more)

### Community 13 - "test_naive_manager.py"
Cohesion: 0.05
Nodes (71): ManagerHTTPServer, ManagerRecoveryError, _bootstrapped(), Hooks, manager(), test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), test_adapted_semantic_drift_makes_health_unready(), test_additional_basic_auth_outside_managed_block_makes_health_unready() (+63 more)

### Community 14 - "AuditFacts"
Cohesion: 0.06
Nodes (45): Adapter, WizardRunner, _assert_secret_free(), AuditFacts, build_plan(), _canonical_fact_value(), _canonical_json_value(), _freeze() (+37 more)

### Community 15 - "create_app"
Cohesion: 0.03
Nodes (72): Task 12: Панель — `check()`, компонент `xray`, `/api/versions/check`, relay для узлов, 2. Хранение токена: escrow под keyring, 7. Тесты, create_app(), _lifespan(), main(), Key, Keyring (+64 more)

### Community 16 - "RoutingService"
Cohesion: 0.05
Nodes (10): Self-review (спека → план), RouterTarget, direct_document(), lane_policies(), Compiled, RoutingPolicy, router_target_from_identity(), RoutingError (+2 more)

### Community 17 - "Troubleshooting Proxy Control"
Cohesion: 0.07
Nodes (37): caddy adapt --adapter caddyfile --validate, Compose reports orphans, panel.cli create-admin --password-stdin, Initial diagnostics, Login failure, Mieru manager unhealthy, Stable /run/mita/mita.sock, MTProxy healthy but clients fail (+29 more)

### Community 18 - "routing.js"
Cohesion: 0.07
Nodes (95): Task 10: UI «Маршрутизация» — роутер, number(), queryAll(), attachment(), BACKEND_NAMES, bindRouting(), cardActions(), codeOptions() (+87 more)

### Community 19 - "InstallerConfig"
Cohesion: 0.07
Nodes (58): Task 3: Установщик — секция `[egress]` (Task 28), _canonical_dataclass(), DomainConfig, EgressChoice, EgressConfig, FirewallConfig, HostMode, InstallerConfig (+50 more)

### Community 20 - "MemoryNaive"
Cohesion: 0.06
Nodes (10): Task 5: Reconciler узла, MemoryNaive, NaiveError, test_dashboard_stays_available_when_enabled_naive_manager_is_degraded(), health(), list_users(), test_enabling_an_exhausted_user_reports_the_quota_reason_not_an_outage(), test_memory_naive_replays_an_operation_and_can_lose_a_response() (+2 more)

### Community 21 - "test_installer_version_agent.py"
Cohesion: 0.06
Nodes (34): _command_failure(), _DefaultVersionAgentRunner, _env_key(), _env_values(), VersionAgentAdapter, VersionAgentError, VersionAgentPaths, action_for() (+26 more)

### Community 22 - "._update_binary"
Cohesion: 0.06
Nodes (22): Global Constraints, Self-review, Task 10: `naive` — пересборка Caddy, Task 14: Установщик принимает версии из `state.json` агента, Task 15: Документация и changelog, Task 16: Гейт на ams-test и живая проверка на AMS_Z, Task 1: Обзор — без «Application bytes», ресурсы одной строкой, три карточки, Task 4: Каталог — `xray`, `source`, `archive`, `kind: build` (+14 more)

### Community 24 - "TrafficCollector"
Cohesion: 0.05
Nodes (43): build_manager(), _assert_safe_parent_chain(), _Candidate, _now(), TrafficCollector, collector(), record(), test_active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() (+35 more)

### Community 25 - "AgentJournal"
Cohesion: 0.09
Nodes (12): Executor, AgentJournal, ExecutionIndeterminate, NodeAgent, command_envelope(), test_agent_journal_prevents_reexecution_after_restart_and_rejects_sequence_gap(), test_concurrent_duplicate_does_not_corrupt_inflight_execution(), test_exclusive_startup_recovery_marks_crash_residue_without_reexecution() (+4 more)

### Community 26 - "test_xray_router_geodata.py"
Cohesion: 0.06
Nodes (40): _clocked(), _field(), geodata_file(), _loyal(), _old_meta(), test_a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays(), test_automatic_updates_run_at_the_interval_from_the_watchdog(), test_block_document_still_applies_after_an_update() (+32 more)

### Community 27 - "nodes.js"
Cohesion: 0.06
Nodes (65): Task 12: UI — API-ключи, «Узлы → Добавить панель», карточка узла, выбор узла в «Клиентах», date(), commandForm(), commandPayload(), commandRow(), commandStatus(), FLEET_OPERATIONS, idempotencyKey() (+57 more)

### Community 28 - "RoutingRule"
Cohesion: 0.04
Nodes (44): Task 7: Панель — компилятор v3 (полосы, цепи, причины), GeodataSource, ChainHop, _check_lane(), compile_intent(), _diff(), intent_of(), intent_v2() (+36 more)

### Community 29 - "test_installer_mcp.py"
Cohesion: 0.07
Nodes (29): _command_failure(), _DefaultMcpRunner, mcp_handoff(), mcp_url(), McpAdapter, McpError, McpPaths, _plaintext_of() (+21 more)

### Community 30 - "Панель управления Proxy Control"
Cohesion: 0.04
Nodes (105): Synthetic Compose render inputs, Busy buttons: capture event.currentTarget before finally, Client-specific Native/Karing/manual reveals, Generation-specific Karing profile name after rotation, Former host/systemd MTProxy install scripts removed, Atomic SQLite login-attempt reservation before Argon2, Complete mieru-client.json in Native reveal, Mieru no longer re-hashes blanked passwords (+97 more)

### Community 31 - "Action"
Cohesion: 0.06
Nodes (19): CoreAdapter, capture(), add(), CoreError, _decode_adjacent_routes(), _encode_adjacent_routes(), _file_sha256(), _path_sha256() (+11 more)

### Community 32 - "XrayRouterManager"
Cohesion: 0.07
Nodes (8): _atomic_write(), _free_port(), ManagerConflict, ManualInterventionRequired, _now(), revision_of(), XrayRouterManager, run()

### Community 33 - "Interactive release installer"
Cohesion: 0.04
Nodes (66): report.json public acceptance report, Installer CLI commands, Commands, Configuration file, credentials/handoff.json, Fleet v1 Telemt-only limit, Hard stops, host_mode (fresh | coexist) (+58 more)

### Community 34 - "upstream"
Cohesion: 0.03
Nodes (74): [0.5.0-beta.1] - 2026-09-16, Безопасность, Добавлено, Изменено, Отложено (дорожная карта), Consequences, END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`, Non-goals (+66 more)

### Community 35 - "app.py"
Cohesion: 0.03
Nodes (53): Центральная панель (fleet_v2 central), Task 1: Fix-wave — отложенные замечания v0.3, digest(), _forbidden(), record(), scrub(), confirm(), ImportDecision (+45 more)

### Community 36 - "MieruAdapter"
Cohesion: 0.08
Nodes (5): _decode_transports(), MieruAdapter, MieruError, _validate_ownership_mapping(), durable_remove()

### Community 37 - "test_version_agent_upstream.py"
Cohesion: 0.07
Nodes (50): Task 6: Опрос upstream — GitHub Releases, ghcr.io, Docker Hub, fetcher_from(), fetch(), test_an_older_image_the_registry_does_not_answer_for_is_skipped(), test_an_older_release_without_a_digest_is_skipped_without_a_reason(), test_asset_hosted_outside_the_repository_download_path_is_refused(), test_candidates_are_capped_at_the_six_newest_releases(), test_compare_versions_orders_numerically_and_prereleases_lower() (+42 more)

### Community 38 - "test_mieru_management.py"
Cohesion: 0.05
Nodes (16): check(), main(), mieru_access(), _password(), request(), StubManager, test_deleting_on_the_protocol_pages_takes_the_kept_grant_with_it(), test_manager_healthcheck_uses_authenticated_unix_health_endpoint() (+8 more)

### Community 39 - "docs/README.md"
Cohesion: 0.07
Nodes (45): Changelog, Transactional release installer with durable journal, 1.0.0 — initial MTProxy release (2026-02-11), 1.1.0 — Fake TLS and hardening (2026-02-21), 1.2.0 — legacy installer fixes (2026-02-22), 1.3.0 — legacy MTProxy installer (2026-08-11), Развёртывание MTProto за Nginx SNI (RU), Backup and restore contract (EN) (+37 more)

### Community 40 - "test_installer_audit.py"
Cohesion: 0.13
Nodes (30): audit_host(), config(), host_responses(), MissingOptionalExecutor, resolver(), scripted_audit(), ScriptedExecutor, test_a_non_x86_host_is_refused_by_name() (+22 more)

### Community 41 - "test_installer_mieru.py"
Cohesion: 0.08
Nodes (48): adapter(), applied(), FakeMieruRunner, host(), mieru_action(), test_recovery_verifies_nonempty_manager_state_and_new_token_is_32_bytes(), stage_client_package(), _stage_router_secret() (+40 more)

### Community 42 - "NaiveAdapter"
Cohesion: 0.08
Nodes (6): _command_failure(), NaiveAdapter, NaiveError, _sanitize_diagnostic(), _validate_ownership_mapping(), test_compose_runs_to_completion_not_through_diagnostic_capture()

### Community 43 - "test_installer_nginx.py"
Cohesion: 0.09
Nodes (47): ensure_stream_context(), NginxAdapter, config(), facts(), FreshExecutor, materialize_route(), RecordingExecutor, runner_for() (+39 more)

### Community 44 - "Isolated Ubuntu 24.04 installer lab"
Cohesion: 0.05
Nodes (55): attest job, build-twice-and-compare job, draft-release job, lab-amd64 job, publish job, quality job, Release workflow, Tag, VERSION and manifest agreement check (+47 more)

### Community 45 - "MieruManager"
Cohesion: 0.10
Nodes (8): _atomic(), _canonical(), ConfigConflict, _fsync_dir(), _hash(), MieruManager, _pruned_operations(), _read_secure()

### Community 46 - "Sharing Mieru configurations"
Cohesion: 0.06
Nodes (55): Cache-Control: no-store reveal response, Client matrix, Create access flow, Dialog closed too early, Ephemeral reveal dialog, Karing URL scheme documentation, Karing install-config deep link, mieru import config command (+47 more)

### Community 47 - "ExitInput"
Cohesion: 0.04
Nodes (23): Task 6: Панель — модель политики v3 и миграция 16, _b64(), ExitCredential, ExitInput, ExitInUse, ExitSecurity, ExitStore, ExitTransport (+15 more)

### Community 48 - "common.js"
Cohesion: 0.09
Nodes (48): Task 7: Окно клиента: показ ссылки по кнопке, матрица, «Применить», proposeUsername(), locale(), OPERATION_MESSAGE, OPERATION_OK, updatedAt(), cell(), cellStatus() (+40 more)

### Community 49 - "test_mcp_server.py"
Cohesion: 0.04
Nodes (40): Config, _read_secret(), main(), PanelError, build_server(), create_app(), _body_schema(), _build() (+32 more)

### Community 50 - "installer/audit.py"
Cohesion: 0.05
Nodes (63): _applicable_caa(), _audit_host(), AuditError, _bounded_execute(), _bounded_resolve(), _caa_compatible(), _canonical_caa_record(), _canonical_ip() (+55 more)

### Community 51 - "proxyctl.py"
Cohesion: 0.06
Nodes (38): English, Installer fixes, Installing, Proxy Control v0.2.0-beta.1, Verified for this release (on the lab host), What is new, Исправлено в установщике, Проверено для этого выпуска (на стенде) (+30 more)

### Community 52 - "test_installer_core.py"
Cohesion: 0.05
Nodes (58): _await_panel_health(), _panel_probe(), InstallPlan, ReleaseIdentity, PanelOwnershipHandoff, config(), core_action(), FakeRunner (+50 more)

### Community 53 - "Матрица негативных и security-тестов vNext (Task 39)"
Cohesion: 0.09
Nodes (43): Матрица негативных и security-тестов vNext (Task 39), Task 4: `xray_router_manager` — рантайм и типизированный менеджер (Task 33), _doc(), test_validate_document_limits_and_size(), test_validate_document_rejects_private_geoip_and_empty_rule(), test_validate_document_rejects_unknown_fields_schema_and_raw_json(), _artifact(), _lanes_doc() (+35 more)

### Community 54 - "xray_router_manager/service.py"
Cohesion: 0.07
Nodes (44): Task 1: Xray-router — intent схемы 2 (полосы, выходы, цепи), test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector(), test_credentials_are_masked_in_the_redacted_intent(), test_exit_outbounds_render_the_way_xray_dials_them(), test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(), test_the_intent_names_exits_and_a_rule_may_leave_through_one(), test_validate_exit_normalises_every_protocol_and_refuses_the_impossible(), _v2() (+36 more)

### Community 55 - "release.py"
Cohesion: 0.10
Nodes (47): _best_effort_remove_tree_at(), _copy_regular_member(), _copy_verified_archive(), _create_private_stage(), _decode_bounded_tar(), _destination_identity(), _DestinationAnchor, _digest_open_file() (+39 more)

### Community 56 - "test_installer_fresh_host.py"
Cohesion: 0.11
Nodes (49): FirewallAdapter, CertificatePlan, test_existing_valid_lineage_can_defer_only_renewal_simulation(), test_renewal_does_not_retry_a_real_acme_failure(), test_renewal_retries_deactivated_authorization_race_without_hiding_errors(), test_renewal_retries_the_order_not_ready_race_once(), test_renewal_reuses_only_same_process_same_lineage_evidence(), CertRunner (+41 more)

### Community 57 - "test_installer_naive.py"
Cohesion: 0.10
Nodes (43): adapter(), applied(), FakeNaiveRunner, host(), naive_action(), _router_config(), _stage_router_secret(), test_naive_acceptance_requires_closed_connect_accounting() (+35 more)

### Community 58 - "test_version_agent_panel.py"
Cohesion: 0.09
Nodes (40): _mutations(), _owned_panel_host(), _panel_archive(), _PanelHost, _release_tar(), _state(), test_a_second_panel_update_is_refused_while_one_is_running(), test_a_version_file_ahead_of_the_running_panel_does_not_hide_the_update() (+32 more)

### Community 59 - "test_mieru_manager.py"
Cohesion: 0.07
Nodes (40): _authenticate_journal(), FakeMita, manager(), MergingMita, RecoveryMita, _service(), _status_cli(), test_a_caller_password_is_validated_and_operations_are_pruned() (+32 more)

### Community 60 - "naive_manager/egress.py"
Cohesion: 0.08
Nodes (38): Task 1: Fix-wave — отложенные замечания v0.4, block_lines(), canonical(), check_reachable(), document_digest(), EgressInvalid, forward_proxy_bounds(), _indent() (+30 more)

### Community 61 - "render_config"
Cohesion: 0.11
Nodes (30): test_render_without_an_mtproxy_ingress_is_unchanged(), _intent(), test_generation_digest_changes_with_credentials_and_redact_hides_accounts(), test_redact_masks_relay_and_chain_secrets_too(), test_render_bypass_private_precedes_every_rule_per_tag(), test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous(), test_render_default_egress_warp_needs_warp_url(), test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() (+22 more)

### Community 62 - "firewall.py"
Cohesion: 0.10
Nodes (31): _action_enable(), _action_ipv6_enabled(), _action_rules(), _action_ssh_port(), _assert_foreign_preserved(), _assert_owned_rules_recognized(), _assert_ssh_preserved(), _canonical_source() (+23 more)

### Community 63 - "_DefaultNaiveRunner"
Cohesion: 0.06
Nodes (8): _DefaultNaiveRunner, NaivePaths, test_h2_curl_failure_exposes_only_allowlisted_tls_reason(), test_h2_curl_omits_http_connect_code_for_successful_h2_tunnel(), test_naive_acceptance_h2_uses_private_config_and_checks_nested_tls(), fake_curl(), test_naive_acceptance_tunnels_a_real_inner_tls_session(), serve()

### Community 64 - "Управление Mieru / mita 3.35–3.36"
Cohesion: 0.07
Nodes (46): Fleet v1 Telemt-only, Opt-in systemd Mieru TCP MSS clamp, Pinned mita 3.36.x admitted alongside 3.35.x, First valid generation before the hardened mita unit, Full-snapshot CAS config transactions with journal v3 HMAC, compose.mieru.yaml overlay, MIERU_MITA_SHA256 executable digest gate, Fleet v1 is Telemt-only for Mieru (+38 more)

### Community 65 - "query"
Cohesion: 0.07
Nodes (72): Task 8: «Новый клиент» с матрицей и блок подписки в «Доступы выданы», applyFilters(), handleAuditSubmit(), bindClients(), collectDecisions(), issueOnNode(), loadNodeOptions(), openClientModal() (+64 more)

### Community 66 - "test_client_import.py"
Cohesion: 0.16
Nodes (13): _render(), _seed(), test_a_locally_imported_mtproxy_user_renders_with_telemts_link_host(), test_a_remotely_imported_mtproxy_user_renders_with_the_nodes_telemt_link_host(), test_a_username_the_runtime_already_uses_is_refused_before_anything_is_written(), test_adopt_batch_reports_what_it_could_not_take(), test_adopting_an_imported_grant_makes_it_renderable(), test_import_can_attach_to_an_existing_client() (+5 more)

### Community 67 - "TopologyError"
Cohesion: 0.09
Nodes (15): _action_specification(), _certificate_action(), _certificate_checkpoint(), _certificate_vhost_path(), _checkpoint_identity(), _client_ip_backend(), _desired_content(), _effective_source_sections() (+7 more)

### Community 68 - "VersionAgent"
Cohesion: 0.08
Nodes (37): _agent(), _build_catalog(), exdev_between_directories(), test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(), test_archive_member_hash_is_checked_against_the_archive_not_the_file(), test_binary_rollback_restart_is_not_success_without_health(), test_binary_update_records_the_pin_the_unit_check_reads(), test_binary_update_restores_the_previous_pin_when_the_service_fails() (+29 more)

### Community 69 - "test_mieru_egress.py"
Cohesion: 0.08
Nodes (35): Task 5: naive-manager и mieru-manager — провайдер `router`, canonical(), check_reachable(), _cidr(), document_digest(), _domain(), EgressInvalid, EgressUnreachable (+27 more)

### Community 70 - "test_installer_xray_router.py"
Cohesion: 0.11
Nodes (31): Task 11: Установщик — `[egress] router`, адаптер `xray_router`, секреты, ротация, action_for(), adapter(), _agent_state(), _applied(), _archive_bytes(), FakeRunner, FetchingRunner (+23 more)

### Community 71 - "test_mieru_manager_lanes.py"
Cohesion: 0.07
Nodes (20): empty_config(), LanesInvalid, parse_slots(), Slot, slot_config(), validate_request(), main(), ManagerHTTPServer (+12 more)

### Community 72 - "DomainFacade"
Cohesion: 0.05
Nodes (30): Task 10: Lifecycle грантов (enable/disable/rotate/delete) для local и remote, DomainFacade, bridge_env(), _credential(), _fake_router(), handle(), _run(), _socks() (+22 more)

### Community 73 - "NodeClient"
Cohesion: 0.02
Nodes (99): Self-review, Task 13: Документация, миграционные заметки, версия, Task 15: Живая проверка AMS_Z ↔ ams-test (разрешение владельца от 2026-09-11), Task 16: Релизный гейт v0.3.0-beta.1, Task 1: Идентичность панели и API-ключи (хранилище), Task 2: Bearer-аутентификация, scope-гейты и `/api/keys`, Task 3: Протокол поколений и хранилище узла, Task 7: `NodeClient` — HTTP-клиент центра к узлу (+91 more)

### Community 74 - "test_installer_credentials.py"
Cohesion: 0.10
Nodes (24): _anchor(), CredentialError, credentials_path(), discard_staged_credentials(), OperatorCredentials, read_credentials(), stage_credentials(), stage_operator_credentials() (+16 more)

### Community 75 - "proxy-control-lab-clients Compose project"
Cohesion: 0.23
Nodes (16): Post-install acceptance checks, Installer transaction steps 1–7, External MTProto probe (TDLib addProxy/pingProxy), Приёмка после установки, Шаги транзакции установщика 1–7, Внешняя проба MTProto (TDLib), --config … --expect-status probe contract, https-cover curl probe (+8 more)

### Community 76 - "test_subscription_events.py"
Cohesion: 0.13
Nodes (11): _events(), test_fetches_emit_with_their_status_and_misses_emit_nothing(), test_generation_change_emits_inside_the_transaction_or_not_at_all(), test_no_event_carries_a_token_a_link_or_a_delivery_claim(), test_revocation_and_rotation_emit_revoked_for_the_old_url(), test_the_bus_refuses_unknown_names_and_scrubs_payloads(), client_id(), Clock (+3 more)

### Community 77 - "XrayRouterAdapter"
Cohesion: 0.12
Nodes (3): _command_failure(), XrayRouterAdapter, XrayRouterError

### Community 78 - "register_routing_routes"
Cohesion: 0.06
Nodes (34): redact_diff(), redact_document(), ExitImportBody, ExplainBody, GeodataSettingsBody, GeodataSourceBody, LaneModeBody, _outcome() (+26 more)

### Community 79 - "TelemtAdapter"
Cohesion: 0.05
Nodes (21): AdapterError, CredentialPlan, TelemtAdapter, TelemtIndeterminate, broken(), test_telemt_adapter_wraps_a_failing_readback(), broken(), blocked_rotate() (+13 more)

### Community 80 - "DeployCliTests"
Cohesion: 0.05
Nodes (3): Task 13: Phase 8 — backup/restore, матрица негативных тестов, замороженные идентификаторы, DeployCliTests, attempt()

### Community 81 - "Структура файлов"
Cohesion: 0.20
Nodes (9): Global Constraints, Task 0: Ветка, спека, план, Task 1: Инвентарь функций и матрица сверки (TDD: тест-страж первым), Task 3: Tier `ui` — центр (вторая панель) и Fleet-экраны, Task 4: Дыры бэкенда, Task 5: Живая проверка AMS_Z, Task 6: Релиз, v0.6 Verification Implementation Plan (+1 more)

### Community 82 - "RuntimeInstaller"
Cohesion: 0.11
Nodes (24): RuntimeInstaller, FakeRunner, plan(), runtime_root(), test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(), test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps(), test_failed_install_rollback_is_retried_before_reinstall(), test_generated_acme_and_panel_sites_pass_native_nginx_syntax_check() (+16 more)

### Community 83 - "Planned File Structure"
Cohesion: 0.10
Nodes (34): audit_host -> AuditFacts, AuditFacts, parse_config / render_config / load_config, examples/installer/*.toml, Full profile order, import_runtime_v2 legacy importer, installer.cli main (wizard/plan/install/status/repair/uninstall/upgrade), InstallerConfig (frozen dataclass) (+26 more)

### Community 84 - "vNext v0.2 local control plane implementation plan"
Cohesion: 0.09
Nodes (37): ADR 004: Client / AccessGrant / subscription, tests/fixtures/vnext-capabilities.json (4 protocols x 23 capabilities), Audit finding 3: uvicorn writes an access log to container stdout, Audit finding 6: Credential re-reveal differs per protocol, Audit finding 10: UI is ES modules without a bundler, Audit finding 11: Fleet tables and the reserved local node, Reserved node local, PANEL_VNEXT_WRITER feature flag (+29 more)

### Community 85 - "clients.js"
Cohesion: 0.09
Nodes (46): Task 2: Счётчик клиентов в навигации, acceptPage(), actions(), adopt(), adoptNote(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT (+38 more)

### Community 86 - "schemas.py"
Cohesion: 0.03
Nodes (90): Decision, Global Constraints, Task 11: Маршруты центра — связи, импорт пользователей узла, версии, подписки по узлам, register_api_key_routes(), create_key(), _ctx(), delete_key(), set_enabled() (+82 more)

### Community 87 - "curated.py"
Cohesion: 0.14
Nodes (30): Добавлено, Tools, Инструменты, 9a. MCP-сервер `proxy-control-mcp` (решение владельца 2026-09-21: в v0.11, полный набор, доступ с ноутбука через SNI), audit_tail(), client_subscription(), create_client(), CuratedTool (+22 more)

### Community 88 - "register_naive_routes"
Cohesion: 0.09
Nodes (36): Task 6: Fleet API v2 узла и защита ресурсов центра, register_naive_routes(), escrow(), local_only(), naive_access(), naive_add(), naive_delete(), naive_operation() (+28 more)

### Community 89 - "test_installer_release.py"
Cohesion: 0.18
Nodes (33): ArchiveEntry, ArchiveManifest, _manifest_data(), safe_extract_tar(), _stage_paths(), _tar(), test_archive_digest_is_verified_before_tar_processing(), test_archive_path_swap_cannot_change_verified_bytes() (+25 more)

### Community 90 - "installer/cli.py"
Cohesion: 0.08
Nodes (30): _adopt_legacy_if_needed(), _automated_install(), _bounded_error(), _bounded_text(), CliError, CliServices, _default_services(), plan() (+22 more)

### Community 91 - "Scenario"
Cohesion: 0.11
Nodes (3): describe_artifact(), Scenario, adopted()

### Community 92 - "test_installer_transaction.py"
Cohesion: 0.08
Nodes (44): TransactionStore, action_for(), engine_for(), InjectedCrash, plan_for(), RecordingAdapter, test_a_completed_rollback_does_not_block_the_next_attempt(), test_a_completed_uninstall_does_not_block_the_next_install() (+36 more)

### Community 93 - "createGrantDialog"
Cohesion: 0.17
Nodes (25): [0.7.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Исправлено (после v0.6, в ветке до этого тега), 6.1 Модель (`panel/routing/models.py`, схема базы 16), 6.2 Сервис маршрутизации и цели, 6.3 Экран «Маршрутизация и цепи» (+17 more)

### Community 94 - "panel"
Cohesion: 0.04
Nodes (50): English, Fresh install, Upgrading from v0.9 or v0.10, v0.11.0-beta.1 — обновления из upstream, What changed for you, Обновление с v0.9 или v0.10, Русский, Установка с нуля (+42 more)

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
Cohesion: 0.07
Nodes (8): central_environment(), CentralProcess, main(), NodeB, parse_args(), Probes, Stub, _terminate()

### Community 99 - "UnixHTTPServer"
Cohesion: 0.15
Nodes (9): Task 11: Сервер агента — `POST /v1/upstream/check`, долгий таймаут для сборки, FakeAgent, test_unix_socket_server_answers_a_panel_update_as_accepted_and_async(), test_unix_socket_server_checks_upstream_on_post(), test_unix_socket_server_preserves_update_contract(), test_unix_socket_server_reports_a_failed_or_disabled_upstream_check(), check_upstream(), test_unix_socket_server_returns_distinct_rollback_failed_state() (+1 more)

### Community 100 - "adapters/mieru.py"
Cohesion: 0.07
Nodes (11): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _client_config_for(), _command_failure(), _DefaultMieruRunner, _encode_transports(), MieruAcceptance (+3 more)

### Community 101 - "UpdateError"
Cohesion: 0.08
Nodes (6): _Checked, CatalogEntry, ConflictError, _load_state(), RollbackFailedError, UpdateError

### Community 102 - "test_node_lifecycle.py"
Cohesion: 0.11
Nodes (16): 3. Архитектурные решения, CertificateRegistry, CertificateInfo, NodeView, derive(), _link_view(), NodeConflict, NodeLifecycleService (+8 more)

### Community 103 - "Reconciler"
Cohesion: 0.08
Nodes (4): Resource, Reconciler, _RuntimeCollision, _state()

### Community 104 - "test_installer_docs.py"
Cohesion: 0.09
Nodes (26): checked_commands(), documented_files(), install_steps(), install_text(), python_requirements(), readme(), reference(), test_documentation_declares_checked_command_blocks() (+18 more)

### Community 105 - "ProtocolError"
Cohesion: 0.20
Nodes (11): ProtocolError, validate_inventory(), validate_payload(), validate_result(), _walk_secret_free(), _csrf(), test_every_protocol_access_is_re_revealable(), test_fleet_v1_rejects_secret_bearing_payload() (+3 more)

### Community 106 - "config"
Cohesion: 0.13
Nodes (18): build_managed_clients(), build_managed_inbounds(), ManagedInbound, config(), DeterministicSecrets, test_a_hysteria_client_authenticates_with_auth_not_password(), test_acceptance_clients_are_distinct_from_persistent_clients(), test_hysteria_matches_the_shape_a_running_server_actually_serves() (+10 more)

### Community 107 - "PolicyInput"
Cohesion: 0.07
Nodes (50): As shipped in v0.4, Task 7: Routing IR — модели, хранилище, миграция 14, компилятор (Task 26), compile(), backends_for(), normalise_lane(), PolicyInput, RuleMatch, PolicyConflict (+42 more)

### Community 108 - "v1.1.0 audit and rc.2 acceptance report"
Cohesion: 0.06
Nodes (28): Historical handoff archive index, Current continuation checkpoint, 2026-10-03, Latest published release remains v1.1.0, 1.1.1-rc.2 accepted in main and origin/main at 5c41c9a; unpublished, Nine imported test accesses remain; owner declined cleanup, Single mtproxy Compose project; preserve full COMPOSE_FILE overlays, Bilingual documentation index, Fleet v2 management begins after accepted generation (+20 more)

### Community 109 - "esc"
Cohesion: 0.12
Nodes (40): Task 10: UI «Маршрутизация» (Task 27), 2. Обзор и навигация (панель, только фронт), ACTION_NAMES, auditBody(), auditMarkup(), auditQuery(), auditRow(), handleAuditClick() (+32 more)

### Community 110 - "test_naive_manager_egress.py"
Cohesion: 0.12
Nodes (28): EgressUnreachable, _block(), EgressHooks, manager(), router_manager(), test_a_failed_reload_restores_the_previous_bytes(), test_a_readback_mismatch_rolls_back_with_its_own_code(), test_apply_conflicts_on_a_stale_revision_without_touching_anything() (+20 more)

### Community 111 - "test_mieru_deployment.py"
Cohesion: 0.12
Nodes (30): owned_private_file(), render_mieru_compose(), run_state_preparer(), run_token_preparer(), test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(), test_mieru_overlay_has_only_intended_writable_runtime_mounts(), test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access(), test_naive_caddy_identity_cannot_access_mieru_state() (+22 more)

### Community 112 - "Task 16: Reproducible release builder and GitHub workflow"
Cohesion: 0.09
Nodes (34): README dependency surface list, Global Constraints, docs/INSTALLER_REFERENCE.ru.md / .en.md, tests/lab/clients/compose.yaml protocol clients, Operator requirements recorded 2026-09-04, QEMU lab modes release-amd64 / release-arm64, release/build.py reproducible builder, Release-readiness commit v0.1.0 (+26 more)

### Community 113 - "test_fleet_v2_post_merge.py"
Cohesion: 0.11
Nodes (25): _Answering, _escrowed(), _events(), _link(), _link_row(), test_a_404_heartbeat_answer_is_still_offline(), test_a_429_or_5xx_heartbeat_answer_is_not_offline(), test_a_bare_gateway_5xx_is_offline() (+17 more)

### Community 114 - "test_grant_lifecycle.py"
Cohesion: 0.09
Nodes (36): _drifted_report(), _enabled(), _local(), test_background_timer_expires_access_without_a_request(), test_drift_report_does_not_infer_node_runtime_from_central_clock(), test_lifespan_enforces_expired_local_access_before_serving(), test_local_clock_transition_enables_then_expires_without_request(), test_local_enable_cannot_bypass_suspension_or_expiry() (+28 more)

### Community 115 - "Ownership boundaries and adapter order"
Cohesion: 0.10
Nodes (27): certificates adapter, firewall adapter, naive adapter, nginx adapter, Адаптер certificates, Адаптер firewall, Адаптер naive, Адаптер nginx (+19 more)

### Community 116 - "_DefaultCoreRunner"
Cohesion: 0.05
Nodes (28): _AcceptanceCollision, AcceptanceError, _as_text(), _command_failure(), _compose_publishes_telemt_api(), _DefaultCoreRunner, _sanitize_diagnostic(), _alive() (+20 more)

### Community 117 - "Accounting semantics"
Cohesion: 0.06
Nodes (45): Accounting semantics, Mieru rolling session-admission quota, Naive completed-CONNECT byte collector, Telemt total_octets and quota usage counter, Proxy Control architecture, Caddy/NaiveProxy runtime and manager, Complete COMPOSE_FILE overlay set, FastAPI panel on loopback (+37 more)

### Community 118 - "MieruClient"
Cohesion: 0.10
Nodes (9): 8.1 API (`panel/routing/routes.py`, owner для мутаций, viewer — чтение), 8.2 Локальный узел, 8.3 Подключённые панели (Fleet v2), 8.4 UI («Маршрутизация», `panel/static/js/routing.js`), 8. Панель, MieruClient, test_mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body(), test_mieru_client_sanitizes_manager_errors() (+1 more)

### Community 119 - "build.py"
Cohesion: 0.12
Nodes (21): archive_names(), assert_clean(), build_release(), BuiltRelease, _canonical(), commit_epoch(), _executable(), _external_artifacts() (+13 more)

### Community 120 - "transaction.py"
Cohesion: 0.05
Nodes (40): AcceptedDigestError, _assert_contained(), _canonical_json(), _checkpoint_data(), durable_copy2(), durable_symlink(), ensure_parent(), _evidence_to_dict() (+32 more)

### Community 121 - "test_naive_manager_lanes.py"
Cohesion: 0.11
Nodes (19): handler_lines(), lane_credentials(), lanes_span(), LanesInvalid, outside_lanes(), primary_forward_proxy(), render(), validate_request() (+11 more)

### Community 122 - "TelemtError"
Cohesion: 0.10
Nodes (14): GenerationSuperseded, TelemtError, _audit(), _doc(), _node_key(), _push(), test_capture_is_audited_and_answers_local_users_only_for_an_import(), test_capture_with_an_unknown_purpose_is_422() (+6 more)

### Community 123 - "grant.js"
Cohesion: 0.07
Nodes (48): createAccessDialogs(), bind(), bindClientDialog(), clearBundleSubscription(), clearClientDialog(), openOperationBundle(), renderVariant(), revealMieruToken() (+40 more)

### Community 124 - "test_xray_router_mtproxy.py"
Cohesion: 0.07
Nodes (20): test_a_router_that_does_not_come_back_after_the_swap_is_recorded(), broken_start(), FakeRunner, _inbound(), manager(), SocketRunner, test_a_chain_for_mtproxy_renders_like_any_service(), test_a_malformed_credential_is_a_manual_intervention_not_a_new_one() (+12 more)

### Community 125 - "i18n.js"
Cohesion: 0.09
Nodes (31): Gate checklist (lab host `ams-test`), English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.6.0-beta.1, Screenshots, Upgrading (+23 more)

### Community 126 - "Host"
Cohesion: 0.08
Nodes (8): Decision, Results — Mieru via the router (`mieru` ingress), Results — NaiveProxy via the router (`naive` ingress), Results — the router itself, Xray egress-router spike (v0.5, Task 32), Docker, Host, RoutingProbes

### Community 127 - "Dedicated Proxy-Control-owned xray-router"
Cohesion: 0.09
Nodes (33): ADR 006: routing policy IR, ADR 007: routing enforcement ownership, v0.4 acceptance criteria, v0.5 acceptance criteria, CompiledRoutingGeneration (policy_revision, backend_id, compiler/runtime versions, binary/geodata/config digests), EgressProvider (direct | warp | socks | xray-router), EnforcementBackend (native | os-isolation | xray-router; fallback fail-closed | explicitly-approved-direct), Immutable management/control bypass (+25 more)

### Community 128 - "managed-xui-clients.py"
Cohesion: 0.18
Nodes (18): assert_port_free(), classify_case(), cleanup_group(), Echo, empty_report(), _field(), listener_owned_by_group(), main() (+10 more)

### Community 129 - "MemoryMieru"
Cohesion: 0.13
Nodes (3): MemoryMieru, MieruError, test_memory_mieru_replays_a_caller_credential_and_refuses_a_generated_one()

### Community 130 - "Path"
Cohesion: 0.10
Nodes (5): probe_trace(), check_hop_reachable(), _fsync_directory(), _sha256_file(), XrayRunner

### Community 131 - "guest-runner.sh"
Cohesion: 0.06
Nodes (6): CASE_STATUS, dns_tls_fixture(), full_audit(), full_dns_tls(), full_plan(), runtime_cmd()

### Community 132 - "test_release_build.py"
Cohesion: 0.13
Nodes (23): build(), checkout_with_private_files(), clean_checkout(), git(), gzip_rewrap(), _run_published_script(), sha256(), tar_names() (+15 more)

### Community 133 - "Журнал изменений"
Cohesion: 0.06
Nodes (34): [0.10.0-beta.1] - 2026-09-21, [0.11.0-beta.1] - 2026-09-22, [0.12.0-beta.1] - 2026-09-22, [0.13.0-beta.1] - 2026-09-23, [0.14.0-beta.1] - 2026-09-23, [0.15.0-beta.1] - 2026-09-23, [0.4.0-beta.1] - 2026-09-14, [0.6.0-beta.1] - 2026-09-17 (+26 more)

### Community 134 - "Panel version-agent"
Cohesion: 0.11
Nodes (20): Start of change window, .env secrecy, Перед началом смены, Секретность .env, NaiveProxy/Caddy and Mieru/mita binary update flow, Caddyfile and module checker validation, Compose project label com.docker.compose.project=mtproxy, version-overrides/compose.versions.yaml (+12 more)

### Community 135 - "test_xray_routing_compiler.py"
Cohesion: 0.13
Nodes (38): Global Constraints, Task 0: Ветка, спека, план, Task 14: Документация, ADR 007, CHANGELOG, VERSION, релизная заметка, Task 15: Гейт релиза на `ams-test` и точка продолжения, Task 3: Spike — Xray как egress-router на стенде (Task 32), Task 6: Панель — клиент роутера, `RouterTarget`, адаптер, wiring, Task 7: Routing IR — backend `xray_router`, `geosites/geoips`, миграция 15, компилятор, v0.5 Xray Router Implementation Plan (+30 more)

### Community 136 - "PackagesAdapter"
Cohesion: 0.11
Nodes (24): _action_packages(), _assert_added_unchanged(), _assert_preexisting_unchanged(), _checkpoint_packages(), PackageError, PackagesAdapter, _version_mapping(), AptRunner (+16 more)

### Community 137 - "Evidence"
Cohesion: 0.10
Nodes (20): Evidence, AcceptanceReport, _assert_public(), CredentialHandoff, _encode(), _public_action(), ReportError, ReportWriter (+12 more)

### Community 138 - "main"
Cohesion: 0.10
Nodes (24): curl_socks(), forward_proxy_handler(), walk(), load(), main(), apply_mita(), naive_probe(), mihomo_config() (+16 more)

### Community 139 - "Task 14: Profile orchestration, reports and acceptance contract"
Cohesion: 0.12
Nodes (19): AcceptanceReport, adapters_for(config) exact profile selection, CoreAdapter / CorePaths / CoreAcceptance, MieruAdapter / MieruPaths / MieruAcceptance, NaiveAdapter / NaivePaths / NaiveAcceptance, ReportWriter (write_public / write_credentials), Task 10: NaiveProxy adapter, Task 11: Mieru adapter (+11 more)

### Community 140 - "renderers/base.py"
Cohesion: 0.08
Nodes (27): AccessArtifact, MieruShare, parse_share_url(), singbox_outbounds(), Manifest, ManifestGrant, check(), credential_reason() (+19 more)

### Community 141 - "test_installer_warp_transaction_recovery.py"
Cohesion: 0.10
Nodes (19): HostCommands, PowerLoss, test_apply_refuses_foreign_state_appearing_after_prepare(), test_apply_waits_for_transient_daemon_status(), test_cleanup_fsyncs_removed_entries_before_engine_completion(), test_egress_probe_overrides_inherited_no_proxy(), test_engine_completes_unpacked_package_on_resume(), test_engine_recovers_sigkill_before_owner_replace() (+11 more)

### Community 142 - "test_version_agent_host.py"
Cohesion: 0.19
Nodes (7): _Proc, test_a_stalled_counter_reports_null_rather_than_a_confident_zero(), test_cpu_utilisation_is_a_delta_between_two_samples(), test_host_endpoint_is_read_only_and_rejects_writes(), test_memory_counts_reclaimable_cache_as_available(), test_missing_proc_files_degrade_each_section_independently(), test_swap_is_reported_beside_memory_and_a_host_without_swap_says_so()

### Community 143 - "_render_at_phone_viewport"
Cohesion: 0.09
Nodes (12): Task 9: Мобильный аудит окна клиента, _cards_from_real_renderers(), test_mobile_cards_have_semantic_icons_and_quick_settings_align(), _browser(), DevTools, _render_at_phone_viewport(), test_access_cards_and_navigation_do_not_collide_on_phone(), client_card() (+4 more)

### Community 144 - "WarpAdapter"
Cohesion: 0.16
Nodes (5): WarpAdapter, WarpError, test_warp_rollback_checks_all_ownership_before_any_mutation(), test_download_never_reuses_attacker_link(), test_warp_is_owned_before_consumers_and_requires_real_egress()

### Community 145 - "test_proxyctl_transactions.py"
Cohesion: 0.13
Nodes (26): AuditFacts, apply_plan(), InstallPlan, repair_installation(), facts_from_root(), fixture_root(), test_audit_discovers_stream_conf_d_routes(), test_audit_reports_existing_shared_443_without_dumping_secrets() (+18 more)

### Community 147 - "Store"
Cohesion: 0.12
Nodes (5): ConflictError, Store, test_store_startup_uses_valid_policy_matched_precomputed_dummy_hash(), test_unknown_admin_performs_one_argon2_verify_without_logging_password(), test_creating_the_first_owner_twice_is_not_an_error()

### Community 148 - "ValidationError"
Cohesion: 0.15
Nodes (14): _conflict_code(), ManagerHandler, _go_duration_ns(), _object(), _positive_int(), _transaction_mode(), validate_config(), _validate_traffic() (+6 more)

### Community 149 - "management.js"
Cohesion: 0.15
Nodes (21): ADR-0008, Task 13: Экран версий — кнопка проверки, пометка источника, карточка Xray, cssEscape(), initials(), versionOptions(), expiresAt(), handleKeysClick(), keyAction() (+13 more)

### Community 150 - "prepare-naive-state.py"
Cohesion: 0.17
Nodes (17): _assert_directory(), _assert_identities(), _assert_identity_free(), _assert_owned_state(), _assert_safe_parents(), _assert_state_entry(), _create_directory(), _fail() (+9 more)

### Community 151 - "MitaCLI"
Cohesion: 0.13
Nodes (8): MitaCLI, MitaError, _process_running(), test_cli_eof_before_child_exit_is_sanitized_and_reaps_child(), test_cli_passes_complete_config_through_anonymous_fd_and_bounds_output(), test_cli_refuses_unpinned_or_changed_executable_before_launch(), test_cli_success_kills_same_group_descendant_after_direct_child_exits(), test_cli_timeout_kills_descendant_that_inherits_output_pipes()

### Community 152 - "FleetStore"
Cohesion: 0.12
Nodes (10): _canonical(), CommandConflict, FleetStore, test_fleet_inventory_and_results_are_recursively_secret_free(), test_fleet_store_assigns_monotonic_sequences_and_enforces_idempotency(), test_fleet_v1_hides_and_retires_legacy_mieru_state(), test_fleet_v1_rejects_mieru_inventory_advertisement(), test_fleet_v1_rejects_mieru_operations() (+2 more)

### Community 153 - "test_panel_entrypoint.py"
Cohesion: 0.18
Nodes (21): main(), open_source(), stage(), StageError, validate_source(), verify(), _fake_command(), logged_commands() (+13 more)

### Community 154 - "Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация"
Cohesion: 0.09
Nodes (23): 10.1 Парк с нуля (центр + два узла), 10.2 Добавить узел в существующий парк, 10.3 Выдать доступ клиенту на другом узле, 10.4 Включить WARP для сервиса на узле, 10.5 Вывести узел из парка, 10. Сквозные чек-листы, 1. Термины, 3.1 Какие имена нужны одному узлу (+15 more)

### Community 155 - "_DefaultXrayRouterRunner"
Cohesion: 0.10
Nodes (3): 3.6 Исправления, _DefaultXrayRouterRunner, test_the_real_runner_sees_only_the_router_compose_service()

### Community 156 - "nginx.py"
Cohesion: 0.08
Nodes (42): _address_facts(), _certificate_sans(), _copy_checkpoint(), derive_owned_route_variable(), _glob_path_matches(), _listen_port(), _literal_backend(), MapRoute (+34 more)

### Community 157 - "Acceptance"
Cohesion: 0.18
Nodes (3): Task 9b: Браузерный сценарий `ui-acceptance.py` под окно клиента и матрицу, Acceptance, main()

### Community 158 - "test_three_xui_api.py"
Cohesion: 0.11
Nodes (33): api_with(), client(), failing_api(), ok(), _panel(), secret_values(), sensitive_values(), template() (+25 more)

### Community 159 - "NaiveClient"
Cohesion: 0.15
Nodes (3): NaiveClient, _optional(), test_naive_adapter_accepts_empty_204_delete_response()

### Community 160 - "test_resource_boundaries.py"
Cohesion: 0.09
Nodes (10): test_body_limit_stops_consuming_oversize_stream(), test_bounded_body_preserves_bytes_for_handler(), test_incomplete_body_never_dispatches_or_becomes_server_error(), receive(), send(), test_static_files_ignore_excessive_ranges(), BoundedBodyMiddleware, replay() (+2 more)

### Community 161 - "index.cjs"
Cohesion: 0.09
Nodes (22): dependencies, prebuilt-tdlib, tdl, description, engines, node, license, name (+14 more)

### Community 162 - "test_update_host.py"
Cohesion: 0.19
Nodes (16): Agent, host(), _run(), test_a_digest_other_than_the_verified_one_changes_nothing(), test_a_host_already_on_the_release_only_rebuilds_what_is_missing(), test_compose_service_lookup_failure_refuses_before_panel_update(), test_container_lookup_failure_refuses_manager_build(), test_declared_running_mcp_is_allowed() (+8 more)

### Community 163 - "register_fleet_v2_central_routes"
Cohesion: 0.13
Nodes (19): 6.5 Карточка узла и ежедневная проверка, _refusal(), register_fleet_v2_central_routes(), _linked(), node_auth_failed(), node_generations(), node_import(), node_inventory() (+11 more)

### Community 164 - "DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation)"
Cohesion: 0.11
Nodes (27): ADR 002: declarative generations, Audit finding 1: Manager tests live in tests/test_naive_manager.py and tests/test_mieru_manager.py, Audit finding 7: Managers generate passwords themselves, Audit finding 8: Telemt list_users allows credential recovery, v0.3 acceptance criteria, DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation), Fleet v2 exchange (/agent/v2/nodes/{node_id}/heartbeat, desired, observed, secrets/resolve, secret-results), ObservedGeneration (applied_generation, bundle_digest, reconcile_state, resource_statuses, safe_drift_summary) (+19 more)

### Community 165 - "test_routing_router_service.py"
Cohesion: 0.17
Nodes (22): Task 8: RoutingService — targets с роутером, attach/detach, apply/rollback через роутер (локально), anyio_backend(), _audits(), _block(), _item(), _rules(), test_apply_native_policy_on_attached_service_is_422(), test_apply_router_failure_marks_failed_and_maps_codes() (+14 more)

### Community 166 - "ThreeXuiApiError"
Cohesion: 0.11
Nodes (6): _form_value(), parse_csrf_token(), ThreeXuiApi, ThreeXuiApiError, test_a_page_without_a_usable_csrf_token_fails_closed(), test_csrf_token_is_read_from_the_page_the_panel_serves()

### Community 167 - "test_users_adapter_ui.py"
Cohesion: 0.07
Nodes (3): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_busy_buttons_capture_their_target_instead_of_reading_it_after_await(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires()

### Community 169 - "Interactive Release Installer Design"
Cohesion: 0.11
Nodes (17): 3x-ui modes, Architecture, Artifact policy, Configuration file, Domain and certificate model, Entry points, Existing 3x-ui, Goal (+9 more)

### Community 170 - "CatalogError"
Cohesion: 0.17
Nodes (15): test_catalog_accepts_a_caddy_build_entry(), test_catalog_accepts_a_panel_release_entry_and_refuses_it_elsewhere(), test_catalog_rejects_archive_members_that_escape(), test_catalog_rejects_non_https_binary_sources(), test_catalog_requires_immutable_artifacts(), test_catalog_requires_the_xray_member_set_and_a_single_member_elsewhere(), _archive(), _build() (+7 more)

### Community 171 - "ReleaseManifest"
Cohesion: 0.10
Nodes (20): ArtifactPin, ExternalArtifact, ReleaseManifest, _load_manifest(), main(), _parser(), sha256_file(), stage_xray() (+12 more)

### Community 172 - "test_subscription_lifecycle.py"
Cohesion: 0.11
Nodes (9): anyio_backend(), client_id(), clients(), Clock, _grant(), subscriptions(), test_a_client_and_its_subscription_are_born_in_one_transaction(), test_a_second_active_subscription_cannot_exist() (+1 more)

### Community 173 - "test_routing_ui_contract.py"
Cohesion: 0.08
Nodes (9): _interpolations(), test_every_interpolated_value_from_the_api_is_escaped(), test_routing_card_forgets_the_previous_policy_before_it_paints(), test_routing_js_seam_fixes_of_v09(), test_routing_js_speaks_lanes_chains_and_the_relay(), test_routing_js_speaks_presets_exits_and_geodata(), test_routing_js_speaks_the_router(), test_routing_js_tells_the_operator_when_the_node_already_runs_the_policy() (+1 more)

### Community 174 - "3x-ui mode: managed-new"
Cohesion: 0.13
Nodes (20): release/external-artifacts.json, Managed inbound templates vless_reality_tcp / vless_reality_xhttp / hysteria2_tls, ThreeXuiAdapter.plan_existing_upgrade, ReleaseManifest / ExternalArtifact.for_platform, safe_extract_tar, Task 12: Existing and staged 3x-ui lifecycle, Task 13: Managed 3x-ui inbounds, clients and optional WARP, Task 5: Release manifest, artifact hashing and safe extraction (+12 more)

### Community 175 - "Check"
Cohesion: 0.14
Nodes (9): UI, v0.3 — задачи после слияния (post-merge issues), Спека (follow-ups, не дефекты реализации), Стенд и приёмка, assert_secret_free(), walk(), mtproxy_secret(), Check (+1 more)

### Community 176 - "UpgradeError"
Cohesion: 0.16
Nodes (19): main(), _read(), _reload(), _stream_template(), upgrade(), _upgrade(), write(), UpgradeError (+11 more)

### Community 178 - "AcceptanceError"
Cohesion: 0.13
Nodes (8): _acceptance_value(), _AcceptanceCollision, AcceptanceError, relay(), NaiveAcceptance, _require_acceptance(), test_naive_acceptance_counts_must_be_non_negative(), test_naive_acceptance_reads_the_url_from_the_native_client_entry()

### Community 179 - "v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router"
Cohesion: 0.07
Nodes (27): Custom exits, quick settings and geodata (v0.8), Свои выходы, быстрые настройки и geodata (v0.8), 10. Лаборатория и гейт, 11. План работ (оценка), 12. Вопросы владельцу, 1. Цель, 2. Словарь, 3. Архитектурные решения (+19 more)

### Community 180 - "test_egress_adapters.py"
Cohesion: 0.10
Nodes (6): test_apply_egress_maps_the_manager_failure_codes(), test_apply_egress_refuses_an_unreachable_provider_and_changes_nothing(), test_apply_egress_returns_the_applied_entry_and_moves_the_target(), test_egress_target_reports_backend_capabilities_and_providers_without_the_url(), test_manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes(), test_telemt_adapter_egress_is_direct_only_without_a_router()

### Community 182 - "register_fleet_v2_node_routes"
Cohesion: 0.06
Nodes (41): _conflict(), _log_late_outcome(), register_fleet_v2_node_routes(), capture(), _daemon(), _egress_entry(), _enabled(), _geodata() (+33 more)

### Community 183 - "Proxy Control v0.3 — центральная панель и подключённые панели"
Cohesion: 0.11
Nodes (17): 6.1 Порядок раскатки парка, 6.2 Подготовка узла, 6.3 Привязка: три действия на центре, 6.4 Импорт существующих пользователей узла, 6.6 Отвязка, удаление, ротация ключа, 6. Центр и узлы: привязка панелей, 10. Тестирование, 11. Критерии приёмки v0.3 (+9 more)

### Community 184 - "install-bootstrap"
Cohesion: 0.19
Nodes (9): Reproducible builds, SBOM, provenance, install-bootstrap, sbom.spdx.json, SHA256SUMS, Проверка релиза, release-manifest.json, Primary install path: verified release, Основной путь: проверенный релиз, Step 1: verify the release and extract install-bootstrap (+1 more)

### Community 185 - "SubscriptionService"
Cohesion: 0.05
Nodes (29): Global Constraints, Self-review, Task 10: Документация выпуска и VERSION, Task 11: Гейт на ams-test и живая проверка AMS_Z → ams-test, Task 2: Escrow при выдаче, гашение при ротации/отзыве, `reveal_token`, Task 3: Ручка `POST /api/clients/{id}/subscription/reveal` и расширенный обзор, Task 5: Аудит и документация модели (ADR 004, OPERATIONS), v0.10 — клиент на нескольких узлах и подписка под рукой: план реализации (+21 more)

### Community 186 - "owner"
Cohesion: 0.12
Nodes (18): [1.0.3] - 2026-10-01, 2.1 Один узел: что на нём работает, 2.2 Общий 443: как один порт обслуживает всё, 2.3 Панель: роли, ключи, секреты, аудит, 2.4 Центр и узлы: общая картина, 2.5 Чего в v0.6 нет (чтобы не искать), 2. Итоговая архитектура, Added (+10 more)

### Community 187 - "Task 6: Encrypted secret versions and master key"
Cohesion: 0.14
Nodes (18): ADR 005: secret references, compose.yaml secret panel-master-key, Pinned cryptography dependency, panel/entrypoint.sh master-key staging, Audit finding 9: Panel container is read_only with secrets staged into /run/panel, Installer renders secrets/panel-master-key, panel.keyring.Keyring (load/generate/save/rotate/retire_all_but_active), panel.cli master-key-init / master-key-rotate / master-key-verify (+10 more)

### Community 188 - ".compose"
Cohesion: 0.12
Nodes (17): Connecting, How to enable, Rotating the token and the key, Skills, The `confirm` rule, The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP, Turning it off, Verification (+9 more)

### Community 189 - "safe_extract_zip"
Cohesion: 0.25
Nodes (15): Task 2: Артефакт Xray в каталоге релиза и `safe_extract_zip`, _copy_zip_member(), MemberPin, safe_extract_zip(), _validate_zip_members(), _pins(), _sha(), test_safe_extract_zip_extracts_named_members_only() (+7 more)

### Community 192 - "_PinningStream"
Cohesion: 0.11
Nodes (3): _NodeBackend, _NodeTransport, _PinningStream

### Community 193 - "RolledBackError"
Cohesion: 0.15
Nodes (12): 10. Тесты и проверка, 1. Цель, 3.1. Артефакты внутри архивов, 3. Источники upstream (version-agent), 5. Компонент `xray`, 6. Компонент `mita` и закреплённый потребитель, 7. Компонент `naive` — пересборка Caddy, 8. API и данные (+4 more)

### Community 194 - "QuotaEnforcer"
Cohesion: 0.10
Nodes (9): caddy_adapt(), command_reload(), command_validate(), main(), QuotaEnforcer, _rewrite_listener(), test_caddy_adapt_unwraps_caddy_211_envelope(), test_private_listener_rewrite_disables_automatic_https_redirects() (+1 more)

### Community 195 - "test_protocol_adapter_contract.py"
Cohesion: 0.15
Nodes (16): adapter(), anyio_backend(), backends(), _credential(), _grant_row(), _imported(), _intent(), test_a_credential_plan_must_match_the_protocol() (+8 more)

### Community 196 - "test_fleet_acceptance_script.py"
Cohesion: 0.10
Nodes (5): _run(), test_naive_probe_retries_a_cut_connection_but_not_a_refusal(), test_routing_scenarios_are_opt_in_and_sit_after_the_grants(), test_scenario_report_is_secret_free_and_stops_the_central_on_failure(), test_scenario_runs_all_eleven_steps_on_fakes()

### Community 197 - "test_routing_service.py"
Cohesion: 0.22
Nodes (14): Task 8: Routing — сервис и HTTP API (локальный узел), anyio_backend(), _audits(), _block(), test_apply_io_outside_transaction(), test_apply_local_calls_manager_and_records_applied(), test_apply_manager_conflict_marks_failed(), test_apply_unreachable_provider_leaves_policy_unchanged() (+6 more)

### Community 199 - "test_ui_browser_findings.py"
Cohesion: 0.10
Nodes (9): test_a_mieru_grant_without_options_means_no_quota(), test_an_audit_row_stacks_its_main_line_and_its_details(), test_every_documented_audit_action_has_a_journal_label(), test_no_module_renders_an_inline_style_attribute(), test_the_brand_mark_is_the_product_artwork_that_actually_ships(), test_the_grant_dialog_body_issues_a_mieru_grant(), test_the_grant_dialog_reads_only_its_own_protocol_boxes(), test_the_login_form_shows_a_refusal_instead_of_reloading() (+1 more)

### Community 200 - "Global Constraints"
Cohesion: 0.05
Nodes (39): Chains and per-client lanes spike (v0.7, Task 1), S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user, S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray, S3 — Mieru: a second mita daemon beside the managed one, What v0.7 builds on this, Global Constraints, Task 0: Ветка, спайк, спека, план, Task 10: Установщик — `relay_port`, `lane_slots`, обновление (+31 more)

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
Cohesion: 0.18
Nodes (7): Task 14: Лаборатория на стенде — `fleet-acceptance.py` и tier `fleet`, core_checks(), fetch(), _ip_through(), main(), _run(), _socks5_udp_dns()

### Community 206 - "Configuration change procedure"
Cohesion: 0.16
Nodes (12): Bounded log queries, Configuration change procedure, Incident sequence, Log redaction before sharing, scripts/proxyctl.py repair, Restart and recovery, Ограниченные запросы логов, Изменение конфигурации (+4 more)

### Community 207 - "EgressTarget"
Cohesion: 0.14
Nodes (12): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 11: Лаборатория — сценарии routing и tier `routing`, Task 12: Документация, ADR, CHANGELOG, VERSION, Task 13: Гейт релиза и живая проверка (Task 31A), Task 5: mieru-manager — egress API (Task 29b), Task 6: Панель — клиенты менеджеров и адаптеры egress (+4 more)

### Community 208 - "test_agent_transport.py"
Cohesion: 0.22
Nodes (8): AgentTransportClient, issue_fixture(), mtls_context(), start_server(), test_agent_client_retries_result_from_durable_outbox_without_reexecution(), test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(), test_revocation_and_request_body_bound_fail_closed(), test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node()

### Community 209 - "register_mieru_routes"
Cohesion: 0.34
Nodes (14): register_mieru_routes(), escrow(), kept(), kept_share_url(), live_template(), local_only(), mieru_create(), mieru_delete() (+6 more)

### Community 211 - "docker_lab.py"
Cohesion: 0.21
Nodes (10): _architecture(), build_image(), copy_inputs(), DockerLabError, guest_command(), main(), run(), run_acceptance() (+2 more)

### Community 213 - "xray_router_manager/healthcheck.py"
Cohesion: 0.20
Nodes (8): test_healthcheck_relay_flags_post_and_get(), test_healthcheck_status_flag_prints_the_manager_status(), check(), main(), relay(), relay_enable(), _request(), status()

### Community 214 - "warp_routing"
Cohesion: 0.40
Nodes (4): warp_routing(), test_warp_appends_rules_without_replacing_the_final_policy(), test_warp_emits_nothing_when_disabled(), test_warp_requires_operator_confirmed_domains()

### Community 215 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.18
Nodes (13): ADR 001: pull-only node transport, ADR 003: one writer per resource, Task 1: ADRs and v0.2 architecture record, Task 2: Characterization tests of current boundaries, Task 3: Capability matrix and fixture, Ownership manifest, Fleet v1 Telemt-only command queue, Resource ownership terms: managed | adopted | foreign | drifted | tombstoned (+5 more)

### Community 216 - "Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext"
Cohesion: 0.11
Nodes (18): 10. Spike (Task 32) — что проверяется на стенде, 12. Backup/restore и матрица негативных тестов (Tasks 37, 39), 13. Лаборатория и гейт (Tasks 36, 40), 14. Документация и релиз (Task 41), 15. Отклонения от спеки vNext и решения, принятые за владельца, 1. Цель, 2. Паритет с 3x-ui, 3. Архитектурные решения (+10 more)

### Community 217 - "ThreeXuiClient"
Cohesion: 0.13
Nodes (5): _default_api_factory(), _Sanitized, ThreeXuiClient, test_api_refuses_a_non_loopback_endpoint(), test_panel_client_uses_tls_and_pins_certificate_before_credentials()

### Community 219 - "test_routing_lanes_routes.py"
Cohesion: 0.27
Nodes (11): _attach(), _csrf(), _grant(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first(), test_lane_refusals_carry_codes() (+3 more)

### Community 221 - "version_agent/service.py"
Cohesion: 0.21
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

### Community 225 - "Interactive Release Installer Implementation Plan"
Cohesion: 0.17
Nodes (12): Interactive Release Installer Implementation Plan, Disposable lab host ams-test, Baseline main@8c787c5 (2026-09-10), Audit finding 14: Current state of ams-test, Audit finding 15: Baseline on ams-test, Verification levels A-F (quick, full, compose, lab-container, lab-host, real install), Task 0: ams-test stand and baseline, TDD and repository gates (+4 more)

### Community 226 - "CommandRunner"
Cohesion: 0.15
Nodes (4): CommandRunner, test_command_runner_reports_captured_stderr_for_failed_command(), test_compose_discovery_reports_unavailable_when_docker_is_not_installed(), test_compose_reconciliation_uses_declared_project_identity()

### Community 227 - "Task 3.2: installer deploys WARP automatically"
Cohesion: 0.18
Nodes (11): ams-server production reference server, cloudflare-warp client / warp-svc.service, release/external-artifacts.json (pinned external artifacts), Task 3.2: installer deploys WARP automatically, Task 3.3: selective WARP routing via 3x-ui, three_xui.warp_domains config option, WARP selective domain list (geosite:openai, anthropic, tiktok, reddit, google-gemini, google-play), WARP proxy mode on local SOCKS5 port 40000 (+3 more)

### Community 228 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`, tree `841a086`, 2026-09-14), Installing, Live check (AMS_Z), Proxy Control v0.4.0-beta.1, Screenshots, Upgrading, What's new (+7 more)

### Community 229 - "_panel_health_diagnosis"
Cohesion: 0.15
Nodes (5): _panel_health_diagnosis(), _without_health_polling(), test_a_failed_panel_health_check_says_what_the_containers_were_doing(), test_the_panel_diagnosis_drops_its_own_health_polling(), test_the_panel_diagnosis_never_lets_a_diagnostic_failure_mask_the_real_one()

### Community 230 - "ArtifactError"
Cohesion: 0.12
Nodes (13): ArtifactError, MieruPaths, _slot_action(), SlotRunner, _stage_router(), test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them(), test_mieru_without_slots_starts_none_and_a_slotted_action_needs_the_router(), artifact_action() (+5 more)

### Community 231 - "ensure_pinned_package"
Cohesion: 0.09
Nodes (7): _download(), ensure_pinned_package(), StagedMita, test_a_download_that_does_not_match_its_pin_is_discarded(), test_a_missing_package_is_fetched_from_its_pin(), fetch(), test_a_package_that_is_already_staged_is_not_fetched_again()

### Community 232 - "AgentTransportServer"
Cohesion: 0.22
Nodes (4): main(), required(), serve(), AgentTransportServer

### Community 233 - "test_client_links.py"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 234 - "test_provisioning_saga.py"
Cohesion: 0.25
Nodes (11): anyio_backend(), backends(), _grants(), _intent(), test_a_clean_run_activates_every_grant_with_a_stored_credential(), test_a_refused_preflight_reserves_nothing(), test_compensation_never_deletes_what_the_operation_did_not_create(), test_every_fault_ends_in_a_declared_outcome_and_resumes() (+3 more)

### Community 235 - "test_security.py"
Cohesion: 0.13
Nodes (4): test_concurrent_login_batch_reserves_attempts_and_bounds_argon2(), test_login_limiter_migrates_existing_reservations(), test_successful_login_preserves_concurrent_failed_reservation(), interleaved_verify()

### Community 236 - "xray_router_manager/__main__.py"
Cohesion: 0.18
Nodes (6): test_unix_api_exit_test_route(), build_manager(), _env(), main(), ManagerHTTPServer, ArtifactMismatch

### Community 237 - "Live check (AMS_Z ↔ ams-test)"
Cohesion: 0.10
Nodes (16): English, Gate checklist (lab host `ams-test`, tree `ade7fcc`, 2026-09-14 — after the three rounds of the final-review fix wave), Installing, Live check (AMS_Z ↔ ams-test), Proxy Control v0.3.0-beta.1, Screenshots, Upgrading, What's new (+8 more)

### Community 238 - "v0.10 — клиент на нескольких узлах и подписка под рукой"
Cohesion: 0.15
Nodes (13): 1. Цель, 3. API, 4. Реестр аудита и события, 5.1 Окно клиента, 5.2 Диалог «Новый клиент», 5.3 Диалог «Выдать доступ», 5.4 Экраны MTProxy / NaiveProxy / Mieru, 5. Интерфейс (+5 more)

### Community 239 - "accepted_sha256"
Cohesion: 0.32
Nodes (7): accepted_caddy_pins(), accepted_sha256(), agent_component(), _state(), test_invalid_state_yields_only_the_pin(), test_missing_or_failed_state_yields_only_the_pin(), test_state_adds_the_agent_installed_hashes()

### Community 241 - "test_managed_xui_clients.py"
Cohesion: 0.17
Nodes (8): test_cleanup_signals_process_group_even_if_leader_exited(), test_hysteria_requires_lazy_auth_in_both_variants(), test_preflight_refuses_unrelated_route_or_noncredential_change(), test_preflight_requires_all_positive_negative_configs_and_distinct_ports(), test_preflight_requires_root_private_manifest_and_configs(), test_run_reports_per_case_differential_without_credentials(), test_vless_wrong_credential_must_remain_valid_uuid(), _valid_manifest()

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
Cohesion: 0.12
Nodes (17): ADR 008: Panel-to-panel transport with scoped API keys, Consequences, Context, Decision, Non-goals, 5.1 API-ключи, 5.2 Эндпоинты `/api/fleet/v2/*` (scope `node-sync` или `admin`), 5.3 Reconcile на узле (`panel/fleet_v2/reconcile.py`) (+9 more)

### Community 251 - "v1.1 — маршрутизация MTProxy через Xray-router"
Cohesion: 0.15
Nodes (12): 1. Цель, 2. Что доказано на стенде (ams-test, 2026-10-01), 3. Топология, 4. Xray-router (менеджер), 5. Мост `xray-router-ingress`, 6. Панель, 7. Установщик, 7a. Обновление одной командой (добавлено владельцем 2026-10-01) (+4 more)

### Community 253 - "agent_service.py"
Cohesion: 0.22
Nodes (10): Task 0: Spike — принимает ли пиннутый Telemt-форк caller-supplied `secret`, 12. Отклонения от Phase 5 спеки vNext, build_executor(), main(), required(), run(), secret(), LocalTelemtExecutor (+2 more)

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

### Community 258 - "installer/adapters/__init__.py"
Cohesion: 0.11
Nodes (5): _acceptance_value(), CoreAcceptance, CorePaths, test_acceptance_dataclass_rejects_inconsistent_counts(), test_core_paths_keep_fixed_project_and_probe_locations()

### Community 260 - "i18n-strings.py"
Cohesion: 0.26
Nodes (7): _clean(), fragments(), main(), _read_string(), _read_template(), _scan_code(), _skip_comment()

### Community 261 - "guest-runner.sh script"
Cohesion: 0.26
Nodes (12): case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), full_environment_preflight(), host_diagnostics(), host_environment_preflight() (+4 more)

### Community 264 - "English"
Cohesion: 0.20
Nodes (9): Changes, Deployment and rollback, English, v0.14.0-beta.1 — совместное использование 443 и приёмка Naive, Validation scope, Изменения, Развёртывание и откат, Русский (+1 more)

### Community 265 - "test_subscription_renderers.py"
Cohesion: 0.09
Nodes (12): Что нового, Subscription client compatibility, adapters(), artifacts(), _database_bytes(), manifest(), manifest_with_canary(), test_every_renderer_emits_its_media_type_and_no_malformed_links() (+4 more)

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

### Community 272 - "test_telemt_recovery.py"
Cohesion: 0.19
Nodes (10): anyio_backend(), _client(), telemt(), test_a_reply_lost_after_the_request_was_sent_is_indeterminate(), timeout(), test_a_request_that_never_left_is_a_plain_failure_not_indeterminate(), test_current_access_reads_the_live_link_from_the_user_listing(), listing() (+2 more)

### Community 274 - "build_sbom"
Cohesion: 0.25
Nodes (7): build_sbom(), _external_packages(), _identifier(), main(), SbomError, test_sbom_is_deterministic_for_one_commit(), test_sbom_requires_at_least_one_packaged_file()

### Community 275 - "rotate-xray-router-ingress.sh"
Cohesion: 0.27
Nodes (10): compose(), fail(), MIERU_MANAGER_UID, NAIVE_MANAGER_GID, NAIVE_MANAGER_UID, random_hex(), random_password(), ROUTER_GID (+2 more)

### Community 276 - "ReleaseMatrixTests"
Cohesion: 0.24
Nodes (3): _passing_report(), ReleaseMatrixTests, report_without()

### Community 277 - "test_socks5_stub.py"
Cohesion: 0.24
Nodes (8): Task 2: Spike — нативные возможности Caddy forwardproxy и mita (Task 30), _connect_through(), _echo(), _load(), _refuses(), _relays(), test_stub_logs_connect_target_and_relays(), test_stub_reports_a_refused_target_and_refuses_when_told_to()

### Community 278 - "Proxy Control Cover Art"
Cohesion: 0.33
Nodes (8): Anime Key-Art Illustration Style, Beam vs Hammer Clash Metaphor, Twin-Tailed Girl Blocking With Stone Hammer, Proxy Control Cover Art, Central Impact Burst Where Beam Meets Hammer, Proxy Control Repository Branding Asset, Night Ruined Colosseum Arena Backdrop, Rearing Unicorn Emitting Magenta Horn Beam

### Community 279 - "CONTINUE-HERE-v0.7.md"
Cohesion: 0.33
Nodes (8): v0.7.0-beta.1 (Release), v0.8.0-beta.1 (Release), Handoffs Archive README, ams-test (Staging Host), AMS_Z (Production Host), CONTINUE-HERE.md (Active), Audit Hardening Plan (2026-10-02), v1.1.1-rc.2 (Candidate)

### Community 280 - "Аудит Proxy Control v1.1.0 и проверка исправлений rc.2"
Cohesion: 0.20
Nodes (9): Аудит Proxy Control v1.1.0 и проверка исправлений rc.2, Дополнение для кандидата 1.1.1-rc.2, Исходные доказательства, Контрольная точка кандидата (2026-10-02), Незавершённые проверки и ограничения, Последовательность, Следующие улучшения за пределами исправлений, Слияние в main (2026-10-03) (+1 more)

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
Cohesion: 0.22
Nodes (8): Audit event names, Authentication and administrators, Clients, grants and subscriptions, Nodes (central side), Nodes (node side, through the central's key), Routing (v0.4), 6. Модель политики и компилятор (`panel/routing/`), test_audit_event_names_are_documented_once()

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
Cohesion: 0.22
Nodes (8): Global constraints, Integration and handoff, Post-rc.2 hardening implementation plan, Review focus, Task 1: Update ownership handoff and legacy recovery, Task 2: Compose scope preflight, Task 3: Readiness diagnostic, Task 4: Native-stand acceptance preparation

### Community 307 - "status / resume / repair"
Cohesion: 0.33
Nodes (7): Ownership journal /var/lib/proxy-control/installer/state.json, status / resume / repair, uninstall and --purge-data, Журнал владения state.json, uninstall и --purge-data, Uninstalling, Удаление

### Community 309 - "test_api_key_auth.py"
Cohesion: 0.46
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 310 - "test_telemt_adapter_does_not_leak_secret_in_errors"
Cohesion: 0.25
Nodes (6): test_telemt_adapter_does_not_leak_secret_in_errors(), handler(), test_telemt_adapter_patches_limits_and_resets_quota(), handler(), test_telemt_adapter_reads_3425_quota_stats_route(), test_telemt_adapter_sends_auth_and_maps_envelope()

### Community 312 - "CDP"
Cohesion: 0.31
Nodes (3): Task 2: Tier `ui` — драйвер и view без второй панели, CDP, _recv_exact()

### Community 313 - "update-host.sh"
Cohesion: 0.47
Nodes (8): agent(), fail(), has(), health(), json(), preflight_compose_scope(), say(), update-host.sh script

### Community 315 - "test_the_release_carries_the_mcp_server"
Cohesion: 0.14
Nodes (4): test_the_install_script_names_exactly_the_pinned_artifact_versions(), test_the_release_carries_the_mcp_server(), test_the_repository_ignores_its_own_release_outputs(), test_the_verify_tool_runs_as_a_script_from_the_repository_root()

### Community 316 - "CONTINUE HERE — v0.4 маршрутизация"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.4 маршрутизация, Где мы, Гейт (Task 13) — итог, Известные ограничения/решения (для ревью и v0.5), Коммиты ветки (по порядку), Публикация (по поручению владельца 2026-09-14), Что дальше (владелец)

### Community 317 - "CONTINUE HERE — v0.6 сверка функций v0.2–v0.5"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.6 сверка функций v0.2–v0.5, Где мы, Гейт (финальное дерево) и живая проверка, Известные ограничения/решения, Публикация (сделано 2026-09-17 11:18–11:30 UTC), Что дальше (владелец), Что сделано (коммиты по порядку)

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

### Community 327 - "api"
Cohesion: 0.32
Nodes (7): 5. Runtime и менеджер `xray_router_manager`, api(), API_REASONS, cookie(), DETAIL_WORTH_SHOWING, problemText(), registerReasons()

### Community 328 - "NginxReloadRecovery"
Cohesion: 0.22
Nodes (4): NginxReloadRecovery, test_a_reload_failure_that_leaves_nginx_running_is_still_an_error(), run(), test_a_reload_that_kills_nginx_is_recovered_and_reported()

### Community 329 - "Post-rc.2 update hardening"
Cohesion: 0.25
Nodes (7): 1. Installer ownership after a panel update, 2. Enabled Compose services, 3. Readiness, 4. Acceptance readiness, Intent and boundaries, Post-rc.2 update hardening, Release criterion

### Community 330 - "test_mtproxy_respq_probe.py"
Cohesion: 0.57
Nodes (4): run_wrapper(), test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(), test_wrapper_rejects_invalid_arguments_without_starting_docker(), test_wrapper_requires_root()

### Community 331 - "ADR 006: Engine-neutral routing policy IR"
Cohesion: 0.33
Nodes (6): ADR 006: Engine-neutral routing policy IR, Amended in v1.1 (2026-10-01): MTProxy through the Xray-router, Consequences, Context, Decision, Non-goals

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

### Community 341 - "probe/install.sh"
Cohesion: 0.33
Nodes (5): DESTINATION, IMAGE, install.sh script, TDL_VERSION, TDLIB_VERSION

### Community 343 - "ADR 009: Lanes per client and chains through the fleet's relays"
Cohesion: 0.50
Nodes (4): ADR 009: Lanes per client and chains through the fleet's relays, Consequences, Context, Decision

### Community 344 - "skills/README.md"
Cohesion: 0.08
Nodes (18): Changing routing, Steps, `unsupported` reasons and what to do, What to tell the owner, Diagnosing a client's access, Report to the owner, Steps, Symptom → likely cause (+10 more)

### Community 348 - "Private Vulnerability Reporting Path"
Cohesion: 0.40
Nodes (5): Sanitized Bug Report Template, Issue Template Config (blank issues disabled), Security Reporting Guidance Template, Code of Conduct, Private Vulnerability Reporting Path

### Community 349 - "Telemt MTProto data plane"
Cohesion: 0.40
Nodes (3): Private-network Caddy mask / cover site, Host Nginx stream/SNI router, Telemt MTProto data plane

### Community 350 - "TypedCommand"
Cohesion: 0.19
Nodes (9): ADR 001: Pull-only node transport, Consequences, Context, Decision, Non-goals, TypedCommand, command(), test_local_executor_is_loopback_only_and_sends_revision_precondition() (+1 more)

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

### Community 360 - "ADR 007: Routing enforcement ownership"
Cohesion: 0.67
Nodes (3): ADR 007: Routing enforcement ownership, Context, Decision

### Community 364 - "test_the_domain_writer_adopts_a_user_it_did_not_create"
Cohesion: 0.40
Nodes (3): test_the_domain_writer_adopts_a_user_it_did_not_create(), test_the_domain_writer_records_a_client_and_grant_for_every_protocol(), _writer()

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

## Ambiguous Edges - Review These
- `WARP as one loopback SOCKS5 endpoint` → `WARP as one SOCKS5 endpoint 127.0.0.1:40000`  [AMBIGUOUS]
  CHANGELOG.md · relation: semantically_similar_to
- `Beam vs Hammer Clash Metaphor` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: rationale_for
- `Proxy Control Repository Branding Asset` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: conceptually_related_to

## Knowledge Gaps
- **769 isolated node(s):** `telemt-entrypoint.sh script`, `install.sh script`, `entrypoint.sh script`, `TELEMT_API_TOKEN_FILE`, `API_REASONS` (+764 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 3699 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **111 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `WARP as one loopback SOCKS5 endpoint` and `WARP as one SOCKS5 endpoint 127.0.0.1:40000`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **What is the exact relationship between `Beam vs Hammer Clash Metaphor` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: rationale_for) - confidence is low._
- **What is the exact relationship between `Proxy Control Repository Branding Asset` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `vNext architecture (v0.2 and v0.3)` connect `AccessGrant` to `NodeClient`, `test_subscription_renderers.py`, `docs/README.md`?**
  _High betweenness centrality (0.066) - this node is a cross-community bridge._
- **Why does `Матрица негативных и security-тестов vNext (Task 39)` connect `Матрица негативных и security-тестов vNext (Task 39)` to `test_routing_fleet_chains.py`, `pytest`, `GrantIntent`, `test_xray_routing_compiler.py`, `test_subscription_renderers.py`, `create_app`, `FleetStore`, `AgentJournal`, `test_routing_router_service.py`, `docs/README.md`, `test_users_adapter_ui.py`, `ReleaseManifest`, `v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router`, `register_fleet_v2_node_routes`, `xray_router_manager/service.py`, `test_mieru_manager.py`, `naive_manager/egress.py`, `safe_extract_zip`, `render_config`, `test_fleet_acceptance_script.py`, `test_routing_service.py`, `test_installer_xray_router.py`, `test_mieru_egress.py`, `NodeClient`, `script`, `test_agent_transport.py`, `DeployCliTests`, `test_rbac_audit.py`, `test_installer_release.py`, `Scenario`, `test_fleet_v2_reconcile.py`, `PolicyInput`, `test_naive_manager_egress.py`, `test_fleet_v2_post_merge.py`, `transaction.py`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Why does `AccessGrant` connect `AccessGrant` to `test_routing_fleet_chains.py`, `pytest`, `app.py`, `GrantRef`, `json`, `GrantIntent`, `test_protocol_adapter_contract.py`, `DomainFacade`, `NodeClient`, `test_subscription_renderers.py`, `test_subscription_lifecycle.py`, `TelemtAdapter`, `create_app`, `schemas.py`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `Action` (e.g. with `Adapter` and `CoreAdapter`) actually correct?**
  _`Action` has 38 INFERRED edges - model-reasoned connections that need verification._