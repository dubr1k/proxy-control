# Graph Report - proxy-control  (2026-10-03)

## Corpus Check
- 624 files · ~1,117,960 words. Structural graph rebuilt; semantic refresh limited to 15 changed documents.

## Summary
- 12732 nodes · 36251 edges · 446 communities (332 shown, 114 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 3784 edges (avg confidence: 0.93)
- Token cost: 49,979 input · 6,780 output

Semantic refresh: OpenRouter (`google/gemini-3.8-flash`) processed 15 changed documents; local agents supplied reviewed checkpoint and archive details. Token counts above cover OpenRouter usage only; host-agent usage is not separately metered.

## Graph Freshness
- Built from commit: `d7507a0a`
- Check source changes with `git diff --name-only d7507a0 -- . ':!graphify-out'`; graph-only commits do not make the source graph stale.
- Run `graphify update .` after code changes (no API cost).
- For changed document semantics, use `graphify extract . --backend openrouter` with the configured environment.

## Integrity Check

- No missing source files, dangling edge endpoints, exact duplicate edges, or collapsed endpoint pairs.
- The 60 existing self-loop `calls` edges are unchanged from the previous graph; these extractor-produced call relationships were retained, not treated as obsolete documents.

## Community Hubs (Navigation)
- test_routing_fleet_chains.py
- AccessGrant
- pytest
- json
- GrantRef
- AuditFacts
- GrantIntent
- test_installer_three_xui.py
- MemoryTelemt
- NaiveCredentialManager
- ThreeXuiAdapter
- parse_config
- Proxy Control
- test_naive_manager.py
- Action
- create_app
- RoutingService
- Troubleshooting Proxy Control
- routing.js
- InstallerConfig
- MemoryNaive
- VersionAgentAdapter
- VersionAgent
- FleetPusher
- TrafficCollector
- ProtocolError
- test_xray_router_geodata.py
- nodes.js
- RoutingRule
- test_installer_mcp.py
- Панель управления Proxy Control
- CoreError
- XrayRouterManager
- install-bootstrap
- upstream
- app.py
- MieruAdapter
- version_agent/service.py
- test_mieru_management.py
- Proxy Control documentation index
- CommandRunner
- test_installer_mieru.py
- NaiveAdapter
- AuditFacts
- Isolated Ubuntu 24.04 installer lab
- MieruManager
- Sharing Mieru configurations
- ExitInput
- common.js
- mcp_server/server.py
- installer/audit.py
- proxyctl.py
- CoreAdapter
- Матрица негативных и security-тестов vNext (Task 39)
- EgressInvalid
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
- test_fleet_v2_post_merge_node.py
- TopologyError
- test_version_agent.py
- test_mieru_egress.py
- test_installer_xray_router.py
- test_mieru_manager_lanes.py
- DomainFacade
- test_fleet_v2_client.py
- test_installer_credentials.py
- Automated installation on Ubuntu 24.04
- test_subscription_http.py
- XrayRouterAdapter
- register_routing_routes
- ProvisioningService
- DeployCliTests
- register_client_routes()
- RuntimeInstaller
- Planned File Structure
- vNext v0.2 local control plane implementation plan
- clients.js
- app.py
- curated.py
- naive_routes.py
- test_installer_release.py
- test_mcp_server.py
- .wait
- test_installer_transaction.py
- createGrantDialog
- panel()
- test_fleet_v2_reconcile.py
- qemu_lab.py
- Scenario
- CentralProcess
- test_version_agent_server.py
- _DefaultMieruRunner
- TopologyError
- test_node_lifecycle.py
- NodeClient
- test_installer_docs.py
- NodeLinkService
- config
- PolicyInput
- v1.1.0 audit and rc.2 acceptance report
- esc
- test_naive_manager_egress.py
- test_mieru_deployment.py
- Task 16: Reproducible release builder and GitHub workflow
- test_fleet_v2_post_merge.py
- RuleMatch
- _DefaultCoreRunner
- _DefaultCoreRunner
- Backup and restore contract (EN)
- Панель управления Proxy Control
- build.py
- TransactionEngine
- test_naive_manager_lanes.py
- NodeUnreachable
- grant.js
- XrayError
- i18n.js
- Host
- Dedicated Proxy-Control-owned xray-router
- compile
- MemoryMieru
- MemoryXrayRouter
- guest-runner.sh
- test_release_build.py
- Журнал изменений
- Panel version-agent
- test_xray_routing_compiler.py
- PackagesAdapter
- ReportWriter
- admin
- Границы владения и порядок адаптеров
- renderers/base.py
- test_installer_warp_transaction_recovery.py
- test_version_agent_host.py
- _render_at_phone_viewport
- WarpAdapter
- test_proxyctl_transactions.py
- QemuLabTests
- Store
- ValidationError
- query
- prepare-naive-state.py
- MitaCLI
- FleetStore
- test_panel_entrypoint.py
- Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация
- XrayRouterAdapter
- TopologyError
- Acceptance
- test_three_xui_api.py
- NaiveClient
- test_resource_boundaries.py
- index.cjs
- test_update_host.py
- register_fleet_v2_central_routes
- Task 1: ADRs and v0.2 architecture record
- test_routing_router_service.py
- ThreeXuiApiError
- test_users_adapter_ui.py
- test_xray_router_mtproxy.py
- Interactive Release Installer Design
- test_version_agent.py
- ReleaseManifest
- OwnershipError
- test_routing_ui_contract.py
- 3x-ui mode: managed-new
- Check
- UpgradeError
- XrayRouterClient
- Installer CLI commands
- v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router
- Структура файлов
- CertificateAuthority
- register_fleet_v2_node_routes
- Proxy Control v0.3 — центральная панель и подключённые панели
- DomainFacade
- AccessGrant
- TransactionStore
- Task 6: Encrypted secret versions and master key
- .compose
- safe_extract_zip
- Browser
- LaneService
- _PinningStream
- Карта файлов
- QuotaEnforcer
- TelemtAdapter
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
- AccessGrant
- Global Constraints
- InstallPlan
- register_mieru_routes
- renderers/base.py
- docker_lab.py
- xray_router_manager/healthcheck.py
- test_three_xui_api.py
- Task 1: ADRs and v0.2 architecture record
- Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext
- ThreeXuiClient
- TransactionStore
- test_routing_lanes_routes.py
- admin
- test_version_agent_artifacts.py
- Русский
- Proxy Control v0.1.0 Beta
- English
- Disposable lab host ams-test
- CommandRunner
- Task 2: automatic WARP with selective routing
- English
- _panel_health_diagnosis
- test_installer_mieru.py
- MieruAdapter
- AgentTransportServer
- test_client_links.py
- pytest
- test_security.py
- xray_router_manager/healthcheck.py
- Живая проверка (AMS_Z ↔ ams-test)
- v0.10 — клиент на нескольких узлах и подписка под рукой
- accepted_sha256
- register_node_routes
- renderers/base.py
- test_dashboard_ui_contract.py
- test_view_addressing_ui.py
- secrets
- Product Overview and Quick Start
- 3. Задачи
- 3x-ui mode managed-new: install on clean server, create inbounds
- English
- .view_central
- 3. Что v0.6 добавляет
- v1.1 — маршрутизация MTProxy через Xray-router
- test_installer_mieru.py
- installer/audit.py
- run_captured
- .handle
- test_xray_router_deployment.py
- compose fleet-agent overlay service
- CorePaths
- test_placement_ui_contract.py
- i18n-strings.py
- guest-runner.sh script
- admin
- CONTINUE-HERE.md
- English
- .install
- English
- English
- The Xray-router (v0.5): one dedicated egress router per node
- Xray-router (v0.5): один выделенный egress-роутер на узел
- ManagedClient
- ManagerHandler
- test_fleet_v2_central_routes.py
- test_subscription_ui_contract.py
- sbom.py
- rotate-xray-router-ingress.sh
- ReleaseMatrixTests
- test_socks5_stub.py
- Proxy Control Cover Art
- CONTINUE-HERE-v0.7.md
- Аудит Proxy Control v1.1.0 и проверка исправлений rc.2
- NaivePaths
- MemoryXrayRouter
- prepare_mieru_token.py
- ImageMetadataTests
- Рабочий протокол для AI-агентов
- probe.py
- The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP
- MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP
- panel
- English
- English
- English
- Структура файлов
- Verification matrix — maintained functions and their proofs
- test_clients_filters_ui.py
- container_cmd
- installer_cmd
- FakePanel
- test_route_coverage.py
- test_fetch_reports_the_hop_that_names_the_release
- mcp_server/server.py
- CONTINUE-HERE.md
- TelemtError
- Структура файлов
- .install
- _panel_probe
- XrayRouterAdapter
- test_api_key_auth.py
- test_telemt_adapter_does_not_leak_secret_in_errors
- Api
- CDP
- update-host.sh
- replace
- test_the_release_carries_the_mcp_server()
- UpgradeError
- CONTINUE HERE — v0.6 сверка функций v0.2–v0.5
- _await_panel_health
- test_management_ui_contract.py
- test_routing_routes.py
- verification-matrix.py
- install-release.sh
- Api
- container_setup
- client_probe
- prepare-xray-router-state.sh
- facts_with_uid
- NginxReloadRecovery
- SequentialSecrets
- run_wrapper
- RuleMatch
- Archived v0.2 local control plane
- Archived v0.5 Xray egress router
- .compose
- query
- RenderedCore
- ThreeXuiApiError
- rejecting
- test_rbac_audit.py
- probe/install.sh
- .wait
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
- Proxy Control v0.3 — центральная панель и подключённые панели
- Task 3: release v0.1.0 through CI
- Продолжение работы над Proxy Control
- English
- Proxy Control v0.1.0 Beta
- Proxy Control v0.3 — центральная панель и подключённые панели
- vNext capability matrix
- https_probe
- AccessEnforcer
- test_fleet_v2_central_routes.py
- test_the_domain_writer_adopts_a_user_it_did_not_create
- skills/README.md
- skills/README.md
- GuestRunnerPreflightScripts
- ReleaseRootLayout
- ReleaseConfigMatchesItsFixture
- _preparer
- ADR 004: Client, AccessGrant and subscription as a projection
- CONTINUE-HERE.md
- .apply
- NaiveAdapter
- renderers/base.py
- mieru-mss-clamp.sh
- ContainerInputTests
- RecordedRunTests
- LabConfigurationsAreValid
- ReleaseArtifactTests
- test_naive_bootstrap_log_matches_the_manager_accounting_writer
- test_the_shared_core_project_is_not_mistaken_for_naive_resources
- Archived v0.10 automatic client subscription
- CONTINUE-HERE.md
- Archived v0.11 upstream component updates
- Archived v0.6 verification matrix
- Archived v0.7 chains and lanes
- test_installer_xray_router.py
- entrypoint.sh
- test_telemt_client_batches_inventory_reads_until_access_changes
- ContainerImageTests
- DockerAvailableTests
- Handler
- test_a_failed_core_command_names_the_command_that_failed
- test_a_failed_core_command_never_echoes_a_credential
- test_compose_builds_the_images_from_the_release_it_installs
- test_installer_xray_router.py
- test_installer_mieru.py
- replace
- Screenshot Sanitization Policy
- telemt-entrypoint.sh
- install.sh
- MieruAdapter
- .apply
- Panel dev/test toolchain (pytest, ruff)
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

## God Nodes (most connected - your core abstractions)
1. `Action` - 234 edges
2. `AuditFacts` - 185 edges
3. `InstallerConfig` - 145 edges
4. `query()` - 143 edges
5. `Proxy Control` - 132 edges
6. `Database` - 122 edges
7. `CoreAdapter` - 117 edges
8. `GrantIntent` - 111 edges
9. `MieruAdapter` - 108 edges
10. `esc()` - 107 edges

## Surprising Connections (you probably didn't know these)
- `6.1 Модель (`panel/routing/models.py`, схема базы 16)` --references--> `PolicyInput`  [INFERRED]
  docs/superpowers/specs/2026-09-17-v0.7-chains-design.md → panel/routing/models.py
- `6. Панель` --references--> `TelemtAdapter`  [INFERRED]
  docs/superpowers/specs/2026-10-01-v1.1-mtproxy-routing-design.md → panel/protocols/telemt.py
- `7. Установщик: `[egress]` (Task 28)` --references--> `ConfigError`  [INFERRED]
  docs/superpowers/specs/2026-09-14-v0.4-routing-design.md → installer/config.py
- `Task 11: Гейт на ams-test и живая проверка AMS_Z → ams-test` --references--> `Browser`  [INFERRED]
  docs/superpowers/plans/2026-09-20-v0.10-client-subscription-nodes.md → scripts/lab/ui-acceptance.py
- `Task 3: Spike — Xray как egress-router на стенде (Task 32)` --references--> `EgressTarget`  [INFERRED]
  docs/superpowers/plans/2026-09-16-v0.5-xray-router.md → panel/protocols/base.py

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

## Communities (446 total, 114 thin omitted)

### Community 0 - "test_routing_fleet_chains.py"
Cohesion: 0.02
Nodes (130): Task 13: Документация, миграционные заметки, версия, Task 15: Живая проверка AMS_Z ↔ ams-test (разрешение владельца от 2026-09-11), Task 16: Релизный гейт v0.3.0-beta.1, Task 1: Идентичность панели и API-ключи (хранилище), Task 3: Протокол поколений и хранилище узла, Task 5: Reconciler узла, Task 6: Fleet API v2 узла и защита ресурсов центра, Task 7: `NodeClient` — HTTP-клиент центра к узлу (+122 more)

### Community 1 - "AccessGrant"
Cohesion: 0.02
Nodes (85): ADR 003: One writer per resource, Consequences, Context, Decision, Non-goals, Decision, Task 9: Pusher — heartbeat и доставка поколений, Узел (fleet_v2 node, local lifecycle) (+77 more)

### Community 2 - "pytest"
Cohesion: 0.02
Nodes (102): Live check (AMS_Z ↔ ams-test), Центральная панель (fleet_v2 central), Task 1: Миграция 20 и `secret_ref` у подписки, Task 2: Escrow при выдаче, гашение при ротации/отзыве, `reveal_token`, 2. Хранение токена: escrow под keyring, 7. Тесты, ApiKeyService, _hash() (+94 more)

### Community 3 - "json"
Cohesion: 0.03
Nodes (45): load_env(), main(), _decode_adjacent_routes(), _encode_adjacent_routes(), _file_sha256(), _mcp_vhost_text(), _panel_vhost_text(), _subscription_vhost_text() (+37 more)

### Community 4 - "GrantRef"
Cohesion: 0.03
Nodes (55): Runtime users (protocol routes), Task 4: Адаптеры — caller-supplied secret для Telemt и `update_options`, Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 12: Документация, ADR, CHANGELOG, VERSION, Task 6: Панель — клиенты менеджеров и адаптеры egress, v0.4 Routing Implementation Plan (+47 more)

### Community 5 - "AuditFacts"
Cohesion: 0.03
Nodes (95): _address_facts(), _validate_certificate_facts(), _adopt_legacy_if_needed(), _automated_install(), _bounded_error(), _bounded_text(), CliError, CliServices (+87 more)

### Community 6 - "GrantIntent"
Cohesion: 0.03
Nodes (107): GrantIntent, NaiveOptions, _drifted_report(), _enabled(), _local(), test_background_timer_expires_access_without_a_request(), test_drift_report_does_not_infer_node_runtime_from_central_clock(), test_lifespan_enforces_expired_local_access_before_serving() (+99 more)

### Community 7 - "test_installer_three_xui.py"
Cohesion: 0.03
Nodes (72): AcceptanceError, parse_reality_keypair(), _plain_audit(), ThreeXuiAudit, ThreeXuiPaths, ArtifactPin, SystemSecrets, adapter() (+64 more)

### Community 8 - "MemoryTelemt"
Cohesion: 0.03
Nodes (57): RouterAdapter, attach_document(), router_target_from_identity(), access_from_user(), MemoryTelemt, TelemtError, TelemtIndeterminate, test_a_compensated_local_grant_is_purged() (+49 more)

### Community 9 - "NaiveCredentialManager"
Cohesion: 0.05
Nodes (20): Task 4: naive-manager — egress API (Task 29a), _assert_regular(), _assert_safe_parent_chain(), _atomic_write(), _durable_mkdir(), _durable_unlink(), _fsync_directory(), lifecycle_synchronized() (+12 more)

### Community 10 - "ThreeXuiAdapter"
Cohesion: 0.04
Nodes (17): _validate_users(), ArtifactError, _client_count(), _default_api_factory(), _DefaultThreeXuiRunner, _safe_text(), _tags(), ThreeXuiAdapter (+9 more)

### Community 11 - "parse_config"
Cohesion: 0.05
Nodes (76): _certificate_groups(), _as_dict(), _boolean(), ConfigError, _domain(), _domains(), _enum(), _integer() (+68 more)

### Community 12 - "Proxy Control"
Cohesion: 0.04
Nodes (87): Documentation contract runs every documented command through the CLI parser, Pinned external artifacts catalog release/external-artifacts.json, Fleet v1 Telemt-only, Profiles and adapters (packages, nginx, certificates, firewall, core, naive, mieru, three_xui), Naive site on port-only address with probe resistance, Per-protocol acceptance with real clients, Release acceptance lab (container and bare metal), Reproducible builds, SBOM, provenance, install-bootstrap (+79 more)

### Community 13 - "test_naive_manager.py"
Cohesion: 0.05
Nodes (71): ManagerHTTPServer, ManagerRecoveryError, _bootstrapped(), Hooks, manager(), test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), test_adapted_semantic_drift_makes_health_unready(), test_additional_basic_auth_outside_managed_block_makes_health_unready() (+63 more)

### Community 14 - "Action"
Cohesion: 0.05
Nodes (44): Adapter, _encode_transports(), _assert_secret_free(), build_plan(), _canonical_fact_value(), _canonical_json_value(), Evidence, _freeze() (+36 more)

### Community 15 - "create_app"
Cohesion: 0.04
Nodes (36): Task 12: Панель — `check()`, компонент `xray`, `/api/versions/check`, relay для узлов, create_app(), _lifespan(), Settings, anyio_backend(), _app(), bridge_answers(), client() (+28 more)

### Community 16 - "RoutingService"
Cohesion: 0.06
Nodes (6): direct_document(), lane_policies(), Compiled, RoutingPolicy, RoutingError, RoutingService

### Community 17 - "Troubleshooting Proxy Control"
Cohesion: 0.04
Nodes (70): Accounting semantics, Mieru acceptance evidence, mieru adapter, NaiveProxy acceptance evidence, naive adapter, Адаптер mieru, Адаптер naive, Bounded log queries (+62 more)

### Community 18 - "routing.js"
Cohesion: 0.07
Nodes (91): Task 10: UI «Маршрутизация» — роутер, attachment(), BACKEND_NAMES, bindRouting(), cardActions(), codeOptions(), currentLane(), currentTarget() (+83 more)

### Community 19 - "InstallerConfig"
Cohesion: 0.06
Nodes (58): Task 3: Установщик — секция `[egress]` (Task 28), reserved_tcp_ports(), _canonical_dataclass(), DomainConfig, EgressChoice, EgressConfig, FirewallConfig, HostMode (+50 more)

### Community 20 - "MemoryNaive"
Cohesion: 0.04
Nodes (31): MemoryNaive, NaiveError, canonical(), anyio_backend(), backend(), test_apply_egress_maps_the_manager_failure_codes(), test_apply_egress_refuses_an_unreachable_provider_and_changes_nothing(), test_apply_egress_returns_the_applied_entry_and_moves_the_target() (+23 more)

### Community 21 - "VersionAgentAdapter"
Cohesion: 0.06
Nodes (35): _command_failure(), _DefaultVersionAgentRunner, _env_key(), _env_values(), VersionAgentAdapter, VersionAgentError, VersionAgentPaths, action_for() (+27 more)

### Community 22 - "VersionAgent"
Cohesion: 0.06
Nodes (10): Self-review, Task 8: `mita` — обновление закреплённого потребителя вместо отказа, Task 9: Компонент `xray`, sha256_bytes(), _atomic_write(), ConflictError, _load_state(), _restore_copy() (+2 more)

### Community 23 - "FleetPusher"
Cohesion: 0.03
Nodes (24): Audit event names, Authentication and administrators, Clients, grants and subscriptions, Nodes (central side), Nodes (node side, through the central's key), Routing (v0.4), Global Constraints, Self-review (+16 more)

### Community 24 - "TrafficCollector"
Cohesion: 0.05
Nodes (43): build_manager(), _assert_safe_parent_chain(), _Candidate, _now(), TrafficCollector, collector(), record(), test_active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget() (+35 more)

### Community 25 - "ProtocolError"
Cohesion: 0.05
Nodes (37): Task 0: Spike — принимает ли пиннутый Telemt-форк caller-supplied `secret`, 12. Отклонения от Phase 5 спеки vNext, 3. Архитектурные решения, Executor, build_executor(), main(), required(), run() (+29 more)

### Community 26 - "test_xray_router_geodata.py"
Cohesion: 0.06
Nodes (38): _clocked(), _field(), geodata_file(), _loyal(), _old_meta(), test_a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays(), test_automatic_updates_run_at_the_interval_from_the_watchdog(), test_block_document_still_applies_after_an_update() (+30 more)

### Community 27 - "nodes.js"
Cohesion: 0.06
Nodes (82): Task 12: UI — API-ключи, «Узлы → Добавить панель», карточка узла, выбор узла в «Клиентах», Task 10: UI «Маршрутизация» (Task 27), auditBody(), auditRow(), date(), esc(), icon(), number() (+74 more)

### Community 28 - "RoutingRule"
Cohesion: 0.05
Nodes (40): Task 7: Панель — компилятор v3 (полосы, цепи, причины), GeodataSource, ChainHop, _check_lane(), compile_intent(), _diff(), intent_of(), intent_v2() (+32 more)

### Community 29 - "test_installer_mcp.py"
Cohesion: 0.07
Nodes (28): _command_failure(), _DefaultMcpRunner, mcp_handoff(), mcp_url(), McpAdapter, McpError, McpPaths, _plaintext_of() (+20 more)

### Community 30 - "Панель управления Proxy Control"
Cohesion: 0.05
Nodes (73): compose-and-images job, Pinned Caddy build check with negative case, Synthetic Compose render inputs, Pinned Caddy negative build check, Validate every Compose model and image, Atomic SQLite login-attempt reservation before Argon2, NekoBox naive+https tab in Naive reveal, Tabs without verified QR drop the QR pane (+65 more)

### Community 31 - "CoreError"
Cohesion: 0.06
Nodes (17): _as_text(), _command_failure(), capture(), add(), CoreError, _path_sha256(), probe_sources_digest(), _read_existing_users() (+9 more)

### Community 32 - "XrayRouterManager"
Cohesion: 0.07
Nodes (7): _atomic_write(), ManualInterventionRequired, _now(), revision_of(), _test_failure(), XrayRouterManager, run()

### Community 33 - "install-bootstrap"
Cohesion: 0.05
Nodes (63): Acceptance per protocol, Commands, Configuration file, Core acceptance evidence, core adapter, Fleet v1 Telemt-only limit, Hard stops, host_mode (fresh | coexist) (+55 more)

### Community 34 - "upstream"
Cohesion: 0.03
Nodes (72): [0.5.0-beta.1] - 2026-09-16, Безопасность, Добавлено, Изменено, Отложено (дорожная карта), Consequences, END` inside `forward_proxy` of its Caddyfile, the mieru-manager owns the `egress`, Non-goals (+64 more)

### Community 35 - "app.py"
Cohesion: 0.06
Nodes (23): register_api_key_routes(), create_key(), _ctx(), delete_key(), set_enabled(), register_fleet_routes(), _local_services(), _probe() (+15 more)

### Community 36 - "MieruAdapter"
Cohesion: 0.08
Nodes (4): _decode_transports(), MieruAdapter, MieruError, _validate_ownership_mapping()

### Community 37 - "version_agent/service.py"
Cohesion: 0.07
Nodes (51): Task 6: Опрос upstream — GitHub Releases, ghcr.io, Docker Hub, fetcher_from(), fetch(), test_an_older_image_the_registry_does_not_answer_for_is_skipped(), test_an_older_release_without_a_digest_is_skipped_without_a_reason(), test_asset_hosted_outside_the_repository_download_path_is_refused(), test_candidates_are_capped_at_the_six_newest_releases(), test_compare_versions_orders_numerically_and_prereleases_lower() (+43 more)

### Community 38 - "test_mieru_management.py"
Cohesion: 0.04
Nodes (20): check(), main(), MieruClient, mieru_access(), _password(), request(), StubManager, test_deleting_on_the_protocol_pages_takes_the_kept_grant_with_it() (+12 more)

### Community 39 - "Proxy Control documentation index"
Cohesion: 0.12
Nodes (20): Changelog, 1.0.0 — initial MTProxy release (2026-02-11), 1.1.0 — Fake TLS and hardening (2026-02-21), 1.2.0 — legacy installer fixes (2026-02-22), 1.3.0 — legacy MTProxy installer (2026-08-11), Развёртывание MTProto за Nginx SNI (RU), ADR 007: Routing enforcement ownership, Context (+12 more)

### Community 40 - "CommandRunner"
Cohesion: 0.09
Nodes (42): audit_host(), AuditError, CommandRunner, _validated_argv(), audit(), Profile, test_per_call_timeout_cannot_exceed_runner_limit(), config() (+34 more)

### Community 41 - "test_installer_mieru.py"
Cohesion: 0.08
Nodes (45): adapter(), applied(), FakeMieruRunner, host(), stage_client_package(), _stage_router_secret(), staged_action(), test_mieru_acceptance_requires_every_end_to_end_fact() (+37 more)

### Community 42 - "NaiveAdapter"
Cohesion: 0.09
Nodes (5): NaiveAdapter, NaiveError, _sanitize_diagnostic(), _validate_ownership_mapping(), test_compose_runs_to_completion_not_through_diagnostic_capture()

### Community 43 - "AuditFacts"
Cohesion: 0.10
Nodes (44): ensure_stream_context(), NginxAdapter, config(), facts(), FreshExecutor, materialize_route(), RecordingExecutor, runner_for() (+36 more)

### Community 44 - "Isolated Ubuntu 24.04 installer lab"
Cohesion: 0.05
Nodes (55): attest job, build-twice-and-compare job, draft-release job, lab-amd64 job, publish job, quality job, Release workflow, Tag, VERSION and manifest agreement check (+47 more)

### Community 45 - "MieruManager"
Cohesion: 0.10
Nodes (7): _atomic(), _canonical(), ConfigConflict, _hash(), MieruManager, _pruned_operations(), _read_secure()

### Community 46 - "Sharing Mieru configurations"
Cohesion: 0.06
Nodes (55): Cache-Control: no-store reveal response, Client matrix, Create access flow, Dialog closed too early, Ephemeral reveal dialog, Karing URL scheme documentation, Karing install-config deep link, mieru import config command (+47 more)

### Community 47 - "ExitInput"
Cohesion: 0.05
Nodes (25): Task 6: Панель — модель политики v3 и миграция 16, _b64(), ExitCredential, ExitInput, ExitInUse, ExitSecurity, ExitStore, ExitTransport (+17 more)

### Community 48 - "common.js"
Cohesion: 0.08
Nodes (60): Task 7: Окно клиента: показ ссылки по кнопке, матрица, «Применить», Task 13: Экран версий — кнопка проверки, пометка источника, карточка Xray, bindClients(), collectDecisions(), openClientModal(), proposeUsername(), locale(), OPERATION_MESSAGE (+52 more)

### Community 49 - "mcp_server/server.py"
Cohesion: 0.04
Nodes (13): Config, _read_secret(), main(), _json_text(), PanelError, build_server(), create_app(), ToolRegistry (+5 more)

### Community 50 - "installer/audit.py"
Cohesion: 0.06
Nodes (51): _applicable_caa(), _audit_host(), _bounded_execute(), _bounded_resolve(), _caa_compatible(), _canonical_caa_record(), _canonical_ip(), _certificate_fact() (+43 more)

### Community 51 - "proxyctl.py"
Cohesion: 0.09
Nodes (22): derive_owned_route_variable(), remove_owned_map_block(), sha256(), _fsync_dir(), _apply_plan_unlocked(), _audit_mapping(), _canonical_route(), _host_path() (+14 more)

### Community 52 - "CoreAdapter"
Cohesion: 0.09
Nodes (43): CoreAdapter, IngressConfig, config(), core_action(), FakeRunner, test_a_generated_password_is_used_when_the_operator_chose_none(), test_absent_filesystem_adoption_refuses_active_fixed_label_resources(), test_acceptance_uses_transaction_unique_name_and_all_configured_credentials() (+35 more)

### Community 53 - "Матрица негативных и security-тестов vNext (Task 39)"
Cohesion: 0.07
Nodes (43): Матрица негативных и security-тестов vNext (Task 39), Task 4: `xray_router_manager` — рантайм и типизированный менеджер (Task 33), test_bootstrap_seeds_the_geodata_directory_from_the_pinned_pair(), test_settings_are_validated(), test_the_hour_is_a_setting_of_the_manager_api(), test_direct_document_is_the_floor(), _artifact(), FakeRunner (+35 more)

### Community 54 - "EgressInvalid"
Cohesion: 0.08
Nodes (43): test_the_router_intent_and_the_xray_rule_carry_the_protocol_selector(), test_credentials_are_masked_in_the_redacted_intent(), test_exit_outbounds_render_the_way_xray_dials_them(), test_exit_test_runs_a_throwaway_xray_and_reports_what_the_far_end_saw(), test_the_intent_names_exits_and_a_rule_may_leave_through_one(), test_validate_exit_normalises_every_protocol_and_refuses_the_impossible(), _v2(), _doc() (+35 more)

### Community 55 - "release.py"
Cohesion: 0.10
Nodes (47): _best_effort_remove_tree_at(), _copy_regular_member(), _copy_verified_archive(), _create_private_stage(), _decode_bounded_tar(), _destination_identity(), _DestinationAnchor, _digest_open_file() (+39 more)

### Community 56 - "test_installer_fresh_host.py"
Cohesion: 0.11
Nodes (49): canonical_ufw(), CertRunner, config(), dns_facts(), firewall_facts(), test_certificate_apply_refuses_lineage_that_appeared_after_prepare(), test_certificate_commands_and_checkpoint_are_secret_free(), test_certificate_owns_http01_vhost_before_certbot_and_removes_only_it() (+41 more)

### Community 57 - "test_installer_naive.py"
Cohesion: 0.11
Nodes (42): adapter(), applied(), FakeNaiveRunner, host(), naive_action(), _router_config(), _stage_router_secret(), test_naive_acceptance_requires_closed_connect_accounting() (+34 more)

### Community 58 - "test_version_agent_panel.py"
Cohesion: 0.09
Nodes (38): 10. Тесты и проверка, 1. Цель, 5. Компонент `xray`, 6. Компонент `mita` и закреплённый потребитель, 7. Компонент `naive` — пересборка Caddy, 8. API и данные, 9. Ошибки, v0.11 — обновления из upstream и обзор в одну строку (+30 more)

### Community 59 - "test_mieru_manager.py"
Cohesion: 0.07
Nodes (40): _authenticate_journal(), FakeMita, manager(), MergingMita, RecoveryMita, _service(), _status_cli(), test_a_caller_password_is_validated_and_operations_are_pruned() (+32 more)

### Community 60 - "naive_manager/egress.py"
Cohesion: 0.08
Nodes (38): Task 1: Fix-wave — отложенные замечания v0.4, block_lines(), canonical(), check_reachable(), document_digest(), EgressInvalid, forward_proxy_bounds(), _indent() (+30 more)

### Community 61 - "render_config"
Cohesion: 0.07
Nodes (34): test_render_without_an_mtproxy_ingress_is_unchanged(), _intent(), test_generation_digest_changes_with_credentials_and_redact_hides_accounts(), test_redact_masks_relay_and_chain_secrets_too(), test_render_bypass_private_precedes_every_rule_per_tag(), test_render_chain_is_a_vless_reality_outbound_per_hop_dialled_through_the_previous(), test_render_default_egress_warp_needs_warp_url(), test_render_inbounds_have_password_auth_no_udp_and_sniffing_route_only() (+26 more)

### Community 62 - "firewall.py"
Cohesion: 0.12
Nodes (31): _action_enable(), _action_ipv6_enabled(), _action_rules(), _action_ssh_port(), _assert_foreign_preserved(), _assert_owned_rules_recognized(), _assert_ssh_preserved(), _canonical_source() (+23 more)

### Community 63 - "_DefaultNaiveRunner"
Cohesion: 0.05
Nodes (16): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _DefaultNaiveRunner, relay(), NaiveAcceptance, _require_acceptance(), timeout() (+8 more)

### Community 64 - "Управление Mieru / mita 3.35–3.36"
Cohesion: 0.07
Nodes (45): Opt-in systemd Mieru TCP MSS clamp, Pinned mita 3.36.x admitted alongside 3.35.x, Next integrations: Panel/Naive, Mieru, Fleet, Следующие интеграции, First valid generation before the hardened mita unit, Full-snapshot CAS config transactions with journal v3 HMAC, compose.mieru.yaml overlay, MIERU_MITA_SHA256 executable digest gate (+37 more)

### Community 65 - "query"
Cohesion: 0.08
Nodes (50): ADR-0008, 11. Безопасность, api(), API_REASONS, cookie(), DETAIL_WORTH_SHOWING, problemText(), registerReasons() (+42 more)

### Community 66 - "test_fleet_v2_post_merge_node.py"
Cohesion: 0.06
Nodes (39): Task 11: Маршруты центра — связи, импорт пользователей узла, версии, подписки по узлам, bundle(), public_hosts_for(), import_resources(), ImportItem, _label(), GenerationSuperseded, render() (+31 more)

### Community 67 - "TopologyError"
Cohesion: 0.09
Nodes (24): _action_specification(), _checkpoint_identity(), _client_ip_backend(), _copy_checkpoint(), _desired_content(), _glob_path_matches(), _nginx_runtime_prefix(), _normalize_include_pattern() (+16 more)

### Community 68 - "test_version_agent.py"
Cohesion: 0.08
Nodes (36): _agent(), _build_catalog(), exdev_between_directories(), test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(), test_archive_member_hash_is_checked_against_the_archive_not_the_file(), test_binary_rollback_restart_is_not_success_without_health(), test_binary_update_records_the_pin_the_unit_check_reads(), test_binary_update_restores_the_previous_pin_when_the_service_fails() (+28 more)

### Community 69 - "test_mieru_egress.py"
Cohesion: 0.08
Nodes (35): Task 5: naive-manager и mieru-manager — провайдер `router`, canonical(), check_reachable(), _cidr(), document_digest(), _domain(), EgressInvalid, EgressUnreachable (+27 more)

### Community 70 - "test_installer_xray_router.py"
Cohesion: 0.11
Nodes (31): Task 11: Установщик — `[egress] router`, адаптер `xray_router`, секреты, ротация, action_for(), adapter(), _agent_state(), _applied(), _archive_bytes(), FakeRunner, FetchingRunner (+23 more)

### Community 71 - "test_mieru_manager_lanes.py"
Cohesion: 0.06
Nodes (27): Task 5: mieru-manager — слоты, Task 8: Панель — сервис маршрутизации, цели, relay-учётки, полосы доступов, 7. Fleet v2, account_url(), empty_config(), _host(), LanesInvalid, parse_slots() (+19 more)

### Community 72 - "DomainFacade"
Cohesion: 0.08
Nodes (28): bridge_env(), _credential(), _fake_router(), handle(), _run(), _socks(), test_a_connect_becomes_a_vless_request_and_bytes_flow_both_ways(), scenario() (+20 more)

### Community 73 - "test_fleet_v2_client.py"
Cohesion: 0.07
Nodes (30): 6. Центр, node_fingerprint(), NodeAuthFailed, NodeRejected, validate_panel_url(), _client(), _EmptyHandler, _OneShotTLSServer (+22 more)

### Community 74 - "test_installer_credentials.py"
Cohesion: 0.10
Nodes (24): _anchor(), CredentialError, credentials_path(), discard_staged_credentials(), OperatorCredentials, read_credentials(), stage_credentials(), stage_operator_credentials() (+16 more)

### Community 75 - "Automated installation on Ubuntu 24.04"
Cohesion: 0.07
Nodes (38): Post-install acceptance checks, Bilingual wizard writes TOML and shows a plan, install --accept-plan DIGEST, Automated installation on Ubuntu 24.04, Installer does not touch DNS, WARP, Fleet, foreign containers or routes, Installer transaction steps 1–7, External MTProto probe (TDLib addProxy/pingProxy), Ownership journal /var/lib/proxy-control/installer/state.json (+30 more)

### Community 76 - "test_subscription_http.py"
Cohesion: 0.06
Nodes (29): [1.0.3] - 2026-10-01, Added, English, Fixed, Upgrading from v1.0.2, v1.0.3 — скрипт установки в каждом выпуске, исправленный мастер установки, Добавлено, Исправлено (+21 more)

### Community 77 - "XrayRouterAdapter"
Cohesion: 0.11
Nodes (3): _command_failure(), XrayRouterAdapter, XrayRouterError

### Community 78 - "register_routing_routes"
Cohesion: 0.07
Nodes (32): ExitImportBody, ExplainBody, GeodataSettingsBody, GeodataSourceBody, LaneModeBody, _outcome(), policy_view(), PolicyPut (+24 more)

### Community 79 - "ProvisioningService"
Cohesion: 0.08
Nodes (4): Task 1: Fix-wave — отложенные замечания v0.3, OperationResult, ProvisioningService, StepResult

### Community 80 - "DeployCliTests"
Cohesion: 0.05
Nodes (3): Task 13: Phase 8 — backup/restore, матрица негативных тестов, замороженные идентификаторы, DeployCliTests, attempt()

### Community 81 - "register_client_routes()"
Cohesion: 0.07
Nodes (39): Global Constraints, Task 0: Ветка, спека, план, Task 1: Инвентарь функций и матрица сверки (TDD: тест-страж первым), Task 3: Tier `ui` — центр (вторая панель) и Fleet-экраны, Task 4: Дыры бэкенда, Task 5: Живая проверка AMS_Z, Task 6: Релиз, v0.6 Verification Implementation Plan (+31 more)

### Community 82 - "RuntimeInstaller"
Cohesion: 0.11
Nodes (24): RuntimeInstaller, FakeRunner, plan(), runtime_root(), test_compose_start_failure_reports_bounded_sanitized_diagnostics_and_rolls_back(), test_compose_start_keeps_health_diagnostics_ahead_of_bounded_logs_and_ps(), test_failed_install_rollback_is_retried_before_reinstall(), test_generated_acme_and_panel_sites_pass_native_nginx_syntax_check() (+16 more)

### Community 83 - "Planned File Structure"
Cohesion: 0.08
Nodes (42): audit_host -> AuditFacts, AuditFacts, parse_config / render_config / load_config, examples/installer/*.toml, Full profile order, import_runtime_v2 legacy importer, installer.cli main (wizard/plan/install/status/repair/uninstall/upgrade), InstallerConfig (frozen dataclass) (+34 more)

### Community 84 - "vNext v0.2 local control plane implementation plan"
Cohesion: 0.08
Nodes (37): ADR 004: Client / AccessGrant / subscription, tests/fixtures/vnext-capabilities.json (4 protocols x 23 capabilities), Audit finding 3: uvicorn writes an access log to container stdout, Audit finding 6: Credential re-reveal differs per protocol, Audit finding 10: UI is ES modules without a bundler, Audit finding 11: Fleet tables and the reserved local node, Reserved node local, PANEL_VNEXT_WRITER feature flag (+29 more)

### Community 85 - "clients.js"
Cohesion: 0.09
Nodes (45): Task 2: Счётчик клиентов в навигации, acceptPage(), actions(), adopt(), adoptNote(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT (+37 more)

### Community 86 - "app.py"
Cohesion: 0.08
Nodes (35): VersionUpdateRequest, AdminCreate, AdminUpdate, ApiKeyCreate, ApiKeyEnabled, ClientCreate, ClientImport, ClientState (+27 more)

### Community 87 - "curated.py"
Cohesion: 0.15
Nodes (33): Добавлено, Tools, Инструменты, 9a. MCP-сервер `proxy-control-mcp` (решение владельца 2026-09-21: в v0.11, полный набор, доступ с ноутбука через SNI), audit_tail(), client_subscription(), create_client(), CuratedTool (+25 more)

### Community 88 - "naive_routes.py"
Cohesion: 0.09
Nodes (37): Task 2: Tier `ui` — драйвер и view без второй панели, 3.3 Tier `ui` — `scripts/lab/ui-acceptance.py` (+ `remote-gate.sh ui`), require_unmanaged(), _domain_created(), register_naive_routes(), escrow(), local_only(), naive_access() (+29 more)

### Community 89 - "test_installer_release.py"
Cohesion: 0.17
Nodes (33): ArchiveEntry, ArchiveManifest, _manifest_data(), safe_extract_tar(), _stage_paths(), _tar(), test_archive_digest_is_verified_before_tar_processing(), test_archive_path_swap_cannot_change_verified_bytes() (+25 more)

### Community 90 - "test_mcp_server.py"
Cohesion: 0.08
Nodes (30): _body_schema(), _build(), build_operations(), is_excluded(), is_irreversible(), Operation, resolve_refs(), tool_name() (+22 more)

### Community 91 - ".wait"
Cohesion: 0.11
Nodes (3): Scenario, adopted(), slot_learned()

### Community 92 - "test_installer_transaction.py"
Cohesion: 0.14
Nodes (31): action_for(), engine_for(), plan_for(), RecordingAdapter, test_a_completed_rollback_does_not_block_the_next_attempt(), test_a_completed_uninstall_does_not_block_the_next_install(), test_a_service_rewritten_owned_file_is_not_foreign_drift(), test_an_interrupted_transaction_still_blocks_a_fresh_start() (+23 more)

### Community 93 - "createGrantDialog"
Cohesion: 0.09
Nodes (43): [0.7.0-beta.1] - 2026-09-18, Добавлено, Изменено, Исправлено, Исправлено (после v0.6, в ветке до этого тега), 6.1 Модель (`panel/routing/models.py`, схема базы 16), 6.2 Сервис маршрутизации и цели, 6.3 Экран «Маршрутизация и цепи» (+35 more)

### Community 94 - "panel()"
Cohesion: 0.05
Nodes (41): English, Fresh install, Upgrading from v0.9 or v0.10, v0.11.0-beta.1 — обновления из upstream, What changed for you, Обновление с v0.9 или v0.10, Русский, Установка с нуля (+33 more)

### Community 95 - "test_fleet_v2_reconcile.py"
Cohesion: 0.11
Nodes (26): _accept(), anyio_backend(), _imported(), _push(), _resource(), test_a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user(), test_a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply(), test_a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user() (+18 more)

### Community 96 - "qemu_lab.py"
Cohesion: 0.10
Nodes (29): acceleration(), allocate_port(), _archive(), cleanup(), finalize_results(), full_egress_policy(), guest_remote(), junit_xml() (+21 more)

### Community 97 - "Scenario"
Cohesion: 0.12
Nodes (9): Task 11: Лаборатория — сценарии routing и tier `routing`, Task 12: Лаборатория — staging, `lab-host` с роутером, сценарии `router-*`, tier `router`, redact(), lane_built(), warp_reachable(), settled(), settled(), settled() (+1 more)

### Community 98 - "CentralProcess"
Cohesion: 0.06
Nodes (9): Task 2: Spike — нативные возможности Caddy forwardproxy и mita (Task 30), central_environment(), CentralProcess, main(), parse_args(), Probes, read_node_credentials(), Stub (+1 more)

### Community 99 - "test_version_agent_server.py"
Cohesion: 0.08
Nodes (19): Task 11: Сервер агента — `POST /v1/upstream/check`, долгий таймаут для сборки, unconfirmed(), _Checked, FakeAgent, test_the_automatic_upstream_check_survives_a_failure_and_stops_on_request(), wait(), test_the_automatic_upstream_check_waits_for_the_cache_to_age(), test_unix_socket_server_answers_a_panel_update_as_accepted_and_async() (+11 more)

### Community 100 - "_DefaultMieruRunner"
Cohesion: 0.07
Nodes (9): _acceptance_value(), _AcceptanceCollision, AcceptanceError, _client_config_for(), _DefaultMieruRunner, MieruAcceptance, _require_acceptance(), test_real_mieru_runner_recognizes_existing_named_system_group() (+1 more)

### Community 101 - "TopologyError"
Cohesion: 0.10
Nodes (12): _certificate_action(), _certificate_checkpoint(), _certificate_sans(), _certificate_vhost_path(), CertificatePlan, _effective_source_sections(), _render_certificate_vhost(), test_renewal_does_not_retry_a_real_acme_failure() (+4 more)

### Community 102 - "test_node_lifecycle.py"
Cohesion: 0.11
Nodes (15): CertificateRegistry, CertificateInfo, NodeView, derive(), _link_view(), NodeConflict, NodeLifecycleService, _cert() (+7 more)

### Community 103 - "NodeClient"
Cohesion: 0.07
Nodes (10): NodeClient, test_client_scope_closes_after_transport_failure(), test_dns_is_checked_again_for_each_connection_and_only_numeric_ip_is_dialed(), test_dns_private_addresses_are_refused_before_connect(), connect(), resolve(), test_dns_timeout_is_bounded_and_typed(), test_explicit_private_opt_in_reaches_loopback() (+2 more)

### Community 104 - "test_installer_docs.py"
Cohesion: 0.09
Nodes (26): checked_commands(), documented_files(), install_steps(), install_text(), python_requirements(), readme(), reference(), test_documentation_declares_checked_command_blocks() (+18 more)

### Community 105 - "NodeLinkService"
Cohesion: 0.08
Nodes (3): Task 8: Связи с узлами — миграция, `NodeLinkService`, `DesiredStore`, компиляция поколений, NodeLinkService, NodeRegistry

### Community 106 - "config"
Cohesion: 0.10
Nodes (21): build_managed_clients(), build_managed_inbounds(), SecretGenerator, warp_routing(), config(), DeterministicSecrets, test_a_hysteria_client_authenticates_with_auth_not_password(), test_acceptance_clients_are_distinct_from_persistent_clients() (+13 more)

### Community 107 - "PolicyInput"
Cohesion: 0.11
Nodes (13): PolicyInput, PolicyConflict, PolicyNotFound, RoutingStore, test_delete_cascades_rules(), test_mark_and_history_limit(), test_upsert_conflict(), test_upsert_creates_with_revision_1() (+5 more)

### Community 108 - "v1.1.0 audit and rc.2 acceptance report"
Cohesion: 0.06
Nodes (28): Historical handoff archive index, Current continuation checkpoint, 2026-10-03, Latest published release remains v1.1.0, 1.1.1-rc.2 accepted in main and origin/main at 5c41c9a; unpublished, Nine imported test accesses remain; owner declined cleanup, Single mtproxy Compose project; preserve full COMPOSE_FILE overlays, Bilingual documentation index, Fleet v2 management begins after accepted generation (+20 more)

### Community 109 - "esc"
Cohesion: 0.11
Nodes (36): 2. Обзор и навигация (панель, только фронт), ACTION_NAMES, applyFilters(), auditMarkup(), auditQuery(), handleAuditClick(), handleAuditSubmit(), loadAudit() (+28 more)

### Community 110 - "test_naive_manager_egress.py"
Cohesion: 0.12
Nodes (28): EgressUnreachable, _block(), EgressHooks, manager(), router_manager(), test_a_failed_reload_restores_the_previous_bytes(), test_a_readback_mismatch_rolls_back_with_its_own_code(), test_apply_conflicts_on_a_stale_revision_without_touching_anything() (+20 more)

### Community 111 - "test_mieru_deployment.py"
Cohesion: 0.12
Nodes (30): owned_private_file(), render_mieru_compose(), run_state_preparer(), run_token_preparer(), test_combined_panel_runtime_has_only_mieru_group_and_private_staged_token(), test_mieru_overlay_has_only_intended_writable_runtime_mounts(), test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access(), test_naive_caddy_identity_cannot_access_mieru_state() (+22 more)

### Community 112 - "Task 16: Reproducible release builder and GitHub workflow"
Cohesion: 0.09
Nodes (36): README dependency surface list, Global Constraints, docs/INSTALLER_REFERENCE.ru.md / .en.md, tests/lab/clients/compose.yaml protocol clients, Operator requirements recorded 2026-09-04, QEMU lab modes release-amd64 / release-arm64, release/build.py reproducible builder, Release-readiness commit v0.1.0 (+28 more)

### Community 113 - "test_fleet_v2_post_merge.py"
Cohesion: 0.11
Nodes (23): _Answering, _escrowed(), _events(), _link(), _link_row(), test_a_404_heartbeat_answer_is_still_offline(), test_a_429_or_5xx_heartbeat_answer_is_not_offline(), test_a_bare_gateway_5xx_is_offline() (+15 more)

### Community 114 - "RuleMatch"
Cohesion: 0.08
Nodes (12): As shipped in v0.4, _Intent, normalise_cidr(), normalise_domain(), normalise_geo_code(), normalise_port(), RuleMatch, _unique() (+4 more)

### Community 115 - "_DefaultCoreRunner"
Cohesion: 0.09
Nodes (9): _acceptance_value(), _AcceptanceCollision, AcceptanceError, CoreAcceptance, test_a_failed_acceptance_step_carries_what_the_probe_said(), test_acceptance_dataclass_rejects_inconsistent_counts(), test_panel_client_accepts_a_full_reveal_payload(), test_preexisting_unowned_acceptance_collision_is_not_deleted() (+1 more)

### Community 116 - "_DefaultCoreRunner"
Cohesion: 0.07
Nodes (14): _DefaultCoreRunner, _alive(), test_interrupt_stops_the_process_group(), test_run_suppresses_stdout_preserves_stderr_stdin_and_env(), test_timeout_drain_is_bounded_when_a_daemon_escapes_the_group(), test_timeout_preserves_stderr_without_exposing_stdout(), test_timeout_stops_term_ignoring_child_before_rollback(), test_a_probe_image_built_from_older_sources_is_not_compatible() (+6 more)

### Community 117 - "Backup and restore contract (EN)"
Cohesion: 0.07
Nodes (28): Pull Request Boundary Checklist, Contribution Architecture Rules, Local Development Gate Commands, Mieru rolling session-admission quota, Naive completed-CONNECT byte collector, Telemt total_octets and quota usage counter, Proxy Control architecture, Caddy/NaiveProxy runtime and manager (+20 more)

### Community 118 - "Панель управления Proxy Control"
Cohesion: 0.08
Nodes (34): Busy buttons: capture event.currentTarget before finally, Client-specific Native/Karing/manual reveals, Host resource card via version-agent GET /v1/host, Generation-specific Karing profile name after rotation, Former host/systemd MTProxy install scripts removed, Complete mieru-client.json in Native reveal, Mieru no longer re-hashes blanked passwords, MTProxy reveal carries QR so list refreshes (+26 more)

### Community 119 - "build.py"
Cohesion: 0.12
Nodes (21): archive_names(), assert_clean(), build_release(), BuiltRelease, _canonical(), commit_epoch(), _executable(), _external_artifacts() (+13 more)

### Community 120 - "TransactionEngine"
Cohesion: 0.17
Nodes (8): _checkpoint_data(), _evidence_to_dict(), _thaw(), TransactionCheckpoint, TransactionEngine, TransactionState, RecordingEngine, RecordingStore

### Community 121 - "test_naive_manager_lanes.py"
Cohesion: 0.11
Nodes (19): handler_lines(), lane_credentials(), lanes_span(), LanesInvalid, outside_lanes(), primary_forward_proxy(), render(), validate_request() (+11 more)

### Community 122 - "NodeUnreachable"
Cohesion: 0.09
Nodes (25): NodeUnreachable, LinkConflict, _linked(), test_a_grant_change_publishes_a_generation_for_the_linked_node_in_the_same_transaction(), test_a_panel_cannot_link_itself(), test_add_refuses_a_second_link_to_the_same_panel_and_a_bad_url(), test_add_writes_node_link_key_and_audit_together_and_the_view_is_secret_free(), test_client_for_reveals_the_key_and_reaches_the_node() (+17 more)

### Community 123 - "grant.js"
Cohesion: 0.12
Nodes (31): createAccessDialogs(), bind(), bindClientDialog(), clearBundleSubscription(), clearClientDialog(), openOperationBundle(), renderVariant(), revealMieruToken() (+23 more)

### Community 124 - "XrayError"
Cohesion: 0.07
Nodes (10): test_a_router_that_does_not_come_back_after_the_swap_is_recorded(), broken_start(), check_hop_reachable(), _fsync_directory(), _port_open(), _sha256_file(), _socket_open(), SubprocessXrayRunner (+2 more)

### Community 125 - "i18n.js"
Cohesion: 0.08
Nodes (33): Gate checklist (lab host `ams-test`), Чек-лист гейта (стенд `ams-test`), English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z), Proxy Control v0.6.0-beta.1, Screenshots (+25 more)

### Community 126 - "Host"
Cohesion: 0.07
Nodes (8): Decision, Results — Mieru via the router (`mieru` ingress), Results — NaiveProxy via the router (`naive` ingress), Results — the router itself, Xray egress-router spike (v0.5, Task 32), Docker, Host, RoutingProbes

### Community 127 - "Dedicated Proxy-Control-owned xray-router"
Cohesion: 0.09
Nodes (33): ADR 006: routing policy IR, ADR 007: routing enforcement ownership, v0.4 acceptance criteria, v0.5 acceptance criteria, CompiledRoutingGeneration (policy_revision, backend_id, compiler/runtime versions, binary/geodata/config digests), EgressProvider (direct | warp | socks | xray-router), EnforcementBackend (native | os-isolation | xray-router; fallback fail-closed | explicitly-approved-direct), Immutable management/control bypass (+25 more)

### Community 128 - "compile"
Cohesion: 0.23
Nodes (31): Task 7: Routing IR — модели, хранилище, миграция 14, компилятор (Task 26), compile(), _policy(), _rule(), _target(), test_compile_capability_missing_from_target(), test_compile_diff_against_applied(), test_compile_digest_is_canonical() (+23 more)

### Community 129 - "MemoryMieru"
Cohesion: 0.13
Nodes (3): MemoryMieru, MieruError, test_memory_mieru_replays_a_caller_credential_and_refuses_a_generated_one()

### Community 130 - "MemoryXrayRouter"
Cohesion: 0.15
Nodes (3): test_memory_router_behaves_like_the_manager(), MemoryXrayRouter, XrayRouterError

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
Cohesion: 0.10
Nodes (21): Обновление существующего 3x-ui, Start of change window, .env secrecy, Перед началом смены, Секретность .env, NaiveProxy/Caddy and Mieru/mita binary update flow, Caddyfile and module checker validation, Compose project label com.docker.compose.project=mtproxy (+13 more)

### Community 135 - "test_xray_routing_compiler.py"
Cohesion: 0.22
Nodes (27): Task 7: Routing IR — backend `xray_router`, `geosites/geoips`, миграция 15, компилятор, _lane(), Resolver, test_a_service_without_lanes_or_node_exits_still_compiles_to_schema_1(), test_compiling_a_lane_policy_folds_the_service_and_the_other_lanes(), test_explain_walks_a_lanes_rules_for_a_destination(), test_lanes_and_node_exits_need_the_router_and_the_attachment(), test_lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains() (+19 more)

### Community 136 - "PackagesAdapter"
Cohesion: 0.16
Nodes (17): _action_packages(), _assert_added_unchanged(), _assert_preexisting_unchanged(), _checkpoint_packages(), PackageError, PackagesAdapter, _version_mapping(), AptRunner (+9 more)

### Community 137 - "ReportWriter"
Cohesion: 0.12
Nodes (17): AcceptanceReport, _assert_public(), CredentialHandoff, _encode(), ReportError, ReportWriter, handoff_with_secrets(), public_report_values() (+9 more)

### Community 138 - "admin"
Cohesion: 0.11
Nodes (25): adapt(), curl_socks(), forward_proxy_handler(), walk(), load(), main(), apply_mita(), naive_probe() (+17 more)

### Community 139 - "Границы владения и порядок адаптеров"
Cohesion: 0.09
Nodes (28): certificates adapter, firewall adapter, nginx adapter, Адаптер certificates, Адаптер firewall, Адаптер nginx, Адаптер packages, AcceptanceReport (+20 more)

### Community 140 - "renderers/base.py"
Cohesion: 0.16
Nodes (13): Manifest, check(), finish(), link_of(), Renderer, RenderError, ClashRenderer, _mapping_item() (+5 more)

### Community 141 - "test_installer_warp_transaction_recovery.py"
Cohesion: 0.11
Nodes (17): HostCommands, PowerLoss, test_apply_refuses_foreign_state_appearing_after_prepare(), test_apply_waits_for_transient_daemon_status(), test_cleanup_fsyncs_removed_entries_before_engine_completion(), test_egress_probe_overrides_inherited_no_proxy(), test_engine_completes_unpacked_package_on_resume(), test_engine_recovers_sigkill_before_owner_replace() (+9 more)

### Community 142 - "test_version_agent_host.py"
Cohesion: 0.11
Nodes (17): _Proc, test_a_stalled_counter_reports_null_rather_than_a_confident_zero(), test_cpu_utilisation_is_a_delta_between_two_samples(), test_disk_reports_space_an_operator_can_actually_write(), test_host_endpoint_is_read_only_and_rejects_writes(), test_memory_counts_reclaimable_cache_as_available(), test_missing_proc_files_degrade_each_section_independently(), test_real_proc_is_parsed_on_linux() (+9 more)

### Community 143 - "_render_at_phone_viewport"
Cohesion: 0.09
Nodes (12): Task 9: Мобильный аудит окна клиента, _cards_from_real_renderers(), test_mobile_cards_have_semantic_icons_and_quick_settings_align(), _browser(), DevTools, _render_at_phone_viewport(), test_access_cards_and_navigation_do_not_collide_on_phone(), client_card() (+4 more)

### Community 144 - "WarpAdapter"
Cohesion: 0.18
Nodes (4): WarpAdapter, WarpError, test_warp_rollback_checks_all_ownership_before_any_mutation(), test_download_never_reuses_attacker_link()

### Community 145 - "test_proxyctl_transactions.py"
Cohesion: 0.18
Nodes (20): apply_plan(), InstallPlan, repair_installation(), uninstall_installation(), facts_from_root(), host_root(), make_plan(), test_apply_is_transactional_preserves_metadata_and_writes_private_manifest() (+12 more)

### Community 147 - "Store"
Cohesion: 0.12
Nodes (5): ConflictError, Store, test_store_startup_uses_valid_policy_matched_precomputed_dummy_hash(), test_unknown_admin_performs_one_argon2_verify_without_logging_password(), test_creating_the_first_owner_twice_is_not_an_error()

### Community 148 - "ValidationError"
Cohesion: 0.13
Nodes (15): Task 5: mieru-manager — egress API (Task 29b), _conflict_code(), ManagerHandler, _go_duration_ns(), _object(), _positive_int(), _transaction_mode(), validate_config() (+7 more)

### Community 149 - "query"
Cohesion: 0.13
Nodes (28): Task 8: «Новый клиент» с матрицей и блок подписки в «Доступы выданы», issueOnNode(), loadNodeOptions(), initials(), sumNaiveTraffic(), bindMieru(), collectQuotaRows(), createQuotas() (+20 more)

### Community 150 - "prepare-naive-state.py"
Cohesion: 0.17
Nodes (17): _assert_directory(), _assert_identities(), _assert_identity_free(), _assert_owned_state(), _assert_safe_parents(), _assert_state_entry(), _create_directory(), _fail() (+9 more)

### Community 151 - "MitaCLI"
Cohesion: 0.12
Nodes (8): MitaCLI, MitaError, _process_running(), test_cli_eof_before_child_exit_is_sanitized_and_reaps_child(), test_cli_passes_complete_config_through_anonymous_fd_and_bounds_output(), test_cli_refuses_unpinned_or_changed_executable_before_launch(), test_cli_success_kills_same_group_descendant_after_direct_child_exits(), test_cli_timeout_kills_descendant_that_inherits_output_pipes()

### Community 152 - "FleetStore"
Cohesion: 0.14
Nodes (12): _canonical(), CommandConflict, FleetStore, command_envelope(), test_expired_command_advances_node_sequence_without_executing_mutation(), test_fleet_inventory_and_results_are_recursively_secret_free(), test_fleet_store_assigns_monotonic_sequences_and_enforces_idempotency(), test_fleet_v1_hides_and_retires_legacy_mieru_state() (+4 more)

### Community 153 - "test_panel_entrypoint.py"
Cohesion: 0.18
Nodes (21): main(), open_source(), stage(), StageError, validate_source(), verify(), _fake_command(), logged_commands() (+13 more)

### Community 154 - "Proxy Control v0.6 — руководство оператора: архитектура, домены, автоматическое развёртывание, узлы, доступы из центра, маршрутизация"
Cohesion: 0.07
Nodes (29): 10.1 Парк с нуля (центр + два узла), 10.2 Добавить узел в существующий парк, 10.3 Выдать доступ клиенту на другом узле, 10.4 Включить WARP для сервиса на узле, 10.5 Вывести узел из парка, 10. Сквозные чек-листы, 1. Термины, 2.1 Один узел: что на нём работает (+21 more)

### Community 155 - "XrayRouterAdapter"
Cohesion: 0.07
Nodes (5): 3.6 Исправления, _DefaultXrayRouterRunner, XrayRouterPaths, test_the_real_runner_fetches_over_https_only(), test_the_real_runner_sees_only_the_router_compose_service()

### Community 156 - "TopologyError"
Cohesion: 0.11
Nodes (26): _listen_port(), _literal_backend(), MapRoute, _matching_close(), NginxMap, NginxTopology, parse_effective_nginx(), _parse_file_nginx() (+18 more)

### Community 157 - "Acceptance"
Cohesion: 0.20
Nodes (3): Acceptance, main(), redact()

### Community 158 - "test_three_xui_api.py"
Cohesion: 0.11
Nodes (21): api_with(), ok(), test_a_panel_certificate_path_must_be_absolute(), test_a_refusal_names_its_kind_but_never_repeats_the_panels_message(), test_api_refuses_a_response_outside_the_contract_schema(), test_api_refuses_an_endpoint_outside_the_pinned_contract(), test_configure_panel_refuses_a_non_loopback_listener(), test_configure_panel_refuses_a_web_path_it_cannot_vouch_for() (+13 more)

### Community 159 - "NaiveClient"
Cohesion: 0.12
Nodes (7): 8.1 API (`panel/routing/routes.py`, owner для мутаций, viewer — чтение), 8.2 Локальный узел, 8.4 UI («Маршрутизация», `panel/static/js/routing.js`), 8. Панель, NaiveClient, _optional(), test_naive_adapter_accepts_empty_204_delete_response()

### Community 160 - "test_resource_boundaries.py"
Cohesion: 0.08
Nodes (12): test_body_limit_stops_consuming_oversize_stream(), test_bounded_body_preserves_bytes_for_handler(), test_connection_context_commits_and_closes(), test_connection_context_rolls_back_and_closes(), test_incomplete_body_never_dispatches_or_becomes_server_error(), receive(), send(), test_static_files_ignore_excessive_ranges() (+4 more)

### Community 161 - "index.cjs"
Cohesion: 0.09
Nodes (22): dependencies, prebuilt-tdlib, tdl, description, engines, node, license, name (+14 more)

### Community 162 - "test_update_host.py"
Cohesion: 0.14
Nodes (18): Agent, host(), _run(), _serve(), _answer(), do_GET(), do_POST(), get_request() (+10 more)

### Community 163 - "register_fleet_v2_central_routes"
Cohesion: 0.11
Nodes (20): 6.5 Карточка узла и ежедневная проверка, _refusal(), register_fleet_v2_central_routes(), _linked(), node_auth_failed(), node_generations(), node_import(), node_inventory() (+12 more)

### Community 164 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.12
Nodes (26): ADR 002: declarative generations, Audit finding 1: Manager tests live in tests/test_naive_manager.py and tests/test_mieru_manager.py, Audit finding 7: Managers generate passwords themselves, Audit finding 8: Telemt list_users allows credential recovery, v0.3 acceptance criteria, DesiredGeneration (node_id, generation, schema_version, digest, resources_json, required_capabilities, previous_generation), Fleet v2 exchange (/agent/v2/nodes/{node_id}/heartbeat, desired, observed, secrets/resolve, secret-results), ObservedGeneration (applied_generation, bundle_digest, reconcile_state, resource_statuses, safe_drift_summary) (+18 more)

### Community 165 - "test_routing_router_service.py"
Cohesion: 0.17
Nodes (22): Task 8: RoutingService — targets с роутером, attach/detach, apply/rollback через роутер (локально), anyio_backend(), _audits(), _block(), _item(), _rules(), test_apply_native_policy_on_attached_service_is_422(), test_apply_router_failure_marks_failed_and_maps_codes() (+14 more)

### Community 166 - "ThreeXuiApiError"
Cohesion: 0.15
Nodes (3): _form_value(), ThreeXuiApi, ThreeXuiApiError

### Community 167 - "test_users_adapter_ui.py"
Cohesion: 0.07
Nodes (3): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_busy_buttons_capture_their_target_instead_of_reading_it_after_await(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires()

### Community 168 - "test_xray_router_mtproxy.py"
Cohesion: 0.14
Nodes (15): _inbound(), manager(), SocketRunner, test_a_chain_for_mtproxy_renders_like_any_service(), test_a_malformed_credential_is_a_manual_intervention_not_a_new_one(), test_a_manager_without_the_socket_does_not_know_mtproxy(), test_a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(), test_a_stale_socket_is_removed_before_xray_starts() (+7 more)

### Community 169 - "Interactive Release Installer Design"
Cohesion: 0.10
Nodes (24): CertificatePlan, Task 8: Fresh-host packages, certificates and UFW ownership, 3x-ui modes, Artifact policy, Coexistence behavior, Configuration file, Domain and certificate model, Entry points (+16 more)

### Community 170 - "test_version_agent.py"
Cohesion: 0.18
Nodes (17): Task 7: Агент — `check_upstream`, кэш в `state.json`, выбор версии из upstream, test_catalog_accepts_a_caddy_build_entry(), test_catalog_accepts_a_panel_release_entry_and_refuses_it_elsewhere(), test_catalog_rejects_archive_members_that_escape(), test_catalog_rejects_non_https_binary_sources(), test_catalog_requires_immutable_artifacts(), test_catalog_requires_the_xray_member_set_and_a_single_member_elsewhere(), _archive() (+9 more)

### Community 171 - "ReleaseManifest"
Cohesion: 0.13
Nodes (17): ExternalArtifact, ReleaseManifest, _load_manifest(), main(), _parser(), _manifest_bytes(), test_an_architecture_this_release_does_not_build_for_is_refused(), test_external_artifact_is_arch_specific_and_version_pinned() (+9 more)

### Community 172 - "OwnershipError"
Cohesion: 0.14
Nodes (6): _owned_path(), OwnershipError, _path_identity(), RuntimeV2Adapter, validate_legacy_runtime_v2(), RuntimePlan

### Community 173 - "test_routing_ui_contract.py"
Cohesion: 0.08
Nodes (9): _interpolations(), test_every_interpolated_value_from_the_api_is_escaped(), test_routing_card_forgets_the_previous_policy_before_it_paints(), test_routing_js_seam_fixes_of_v09(), test_routing_js_speaks_lanes_chains_and_the_relay(), test_routing_js_speaks_presets_exits_and_geodata(), test_routing_js_speaks_the_router(), test_routing_js_tells_the_operator_when_the_node_already_runs_the_policy() (+1 more)

### Community 174 - "3x-ui mode: managed-new"
Cohesion: 0.11
Nodes (21): release/external-artifacts.json, Managed inbound templates vless_reality_tcp / vless_reality_xhttp / hysteria2_tls, ThreeXuiAdapter.plan_existing_upgrade, ReleaseManifest / ExternalArtifact.for_platform, safe_extract_tar, Task 12: Existing and staged 3x-ui lifecycle, Task 13: Managed 3x-ui inbounds, clients and optional WARP, Task 5: Release manifest, artifact hashing and safe extraction (+13 more)

### Community 175 - "Check"
Cohesion: 0.12
Nodes (9): UI, v0.3 — задачи после слияния (post-merge issues), Спека (follow-ups, не дефекты реализации), Стенд и приёмка, assert_secret_free(), walk(), NodeB, Panel (+1 more)

### Community 176 - "UpgradeError"
Cohesion: 0.16
Nodes (19): main(), _read(), _reload(), _stream_template(), upgrade(), _upgrade(), write(), UpgradeError (+11 more)

### Community 178 - "Installer CLI commands"
Cohesion: 0.13
Nodes (20): report.json public acceptance report, Installer CLI commands, credentials/handoff.json, install --accept-plan, plan command, --purge-data opt-in, repair command, report command (+12 more)

### Community 179 - "v0.8 — «Выходы и правила»: маршрутизация в духе 3x-ui поверх Xray-router"
Cohesion: 0.12
Nodes (23): Custom exits, quick settings and geodata (v0.8), Свои выходы, быстрые настройки и geodata (v0.8), 10. Лаборатория и гейт, 11. План работ (оценка), 12. Вопросы владельцу, 1. Цель, 2. Словарь, 3. Архитектурные решения (+15 more)

### Community 180 - "Структура файлов"
Cohesion: 0.09
Nodes (6): Task 2: Bearer-аутентификация, scope-гейты и `/api/keys`, register_auth_admin_audit_routes(), current(), fleet_key(), mutation(), check()

### Community 181 - "CertificateAuthority"
Cohesion: 0.18
Nodes (8): CertificateAuthority, issue_fixture(), mtls_context(), start_server(), test_agent_client_retries_result_from_durable_outbox_without_reexecution(), test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(), test_revocation_and_request_body_bound_fail_closed(), test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node()

### Community 182 - "register_fleet_v2_node_routes"
Cohesion: 0.14
Nodes (20): register_fleet_v2_node_routes(), capture(), _daemon(), _egress_entry(), _enabled(), _geodata(), geodata_action(), geodata_codes() (+12 more)

### Community 183 - "Proxy Control v0.3 — центральная панель и подключённые панели"
Cohesion: 0.10
Nodes (22): ADR 008: Panel-to-panel transport with scoped API keys, Consequences, Context, Decision, Non-goals, 6.3 Привязка: три действия на центре, 10. Тестирование, 11. Критерии приёмки v0.3 (+14 more)

### Community 185 - "AccessGrant"
Cohesion: 0.13
Nodes (3): Self-review, _hash(), SubscriptionService

### Community 186 - "TransactionStore"
Cohesion: 0.15
Nodes (15): import_runtime_v2(), TransactionBusyError, TransactionStore, installed_runtime_v2(), test_legacy_import_rejects_noncanonical_managed_path(), test_operation_lock_rejects_final_symlink_without_chmod_or_flock(), test_operation_lock_rejects_hard_link_before_chmod_or_flock(), test_runtime_v2_adapter_fails_closed_before_lifecycle_drift() (+7 more)

### Community 187 - "Task 6: Encrypted secret versions and master key"
Cohesion: 0.16
Nodes (17): compose.yaml secret panel-master-key, Pinned cryptography dependency, panel/entrypoint.sh master-key staging, Audit finding 9: Panel container is read_only with secrets staged into /run/panel, Installer renders secrets/panel-master-key, panel.keyring.Keyring (load/generate/save/rotate/retire_all_but_active), panel.cli master-key-init / master-key-rotate / master-key-verify, Master key documentation (BACKUP_RESTORE, UPGRADING, PANEL) (+9 more)

### Community 188 - ".compose"
Cohesion: 0.21
Nodes (8): Task 13: Гейт релиза и живая проверка (Task 31A), Task 12: Лаборатория — сценарий `chains` (второй узел на стенде) и tier'ы, Task 15: Релиз, 11. Лаборатория и гейт (Task 31A), 13. Лаборатория и гейт (Tasks 36, 40), Drill, main(), sha256()

### Community 189 - "safe_extract_zip"
Cohesion: 0.25
Nodes (15): Task 2: Артефакт Xray в каталоге релиза и `safe_extract_zip`, _copy_zip_member(), MemberPin, safe_extract_zip(), _validate_zip_members(), _pins(), _sha(), test_safe_extract_zip_extracts_named_members_only() (+7 more)

### Community 192 - "_PinningStream"
Cohesion: 0.10
Nodes (4): _NodeBackend, _NodeTransport, _PinningStream, _public_address()

### Community 193 - "Карта файлов"
Cohesion: 0.10
Nodes (17): Global Constraints, Task 10: `naive` — пересборка Caddy, Task 14: Установщик принимает версии из `state.json` агента, Task 15: Документация и changelog, Task 16: Гейт на ams-test и живая проверка на AMS_Z, Task 1: Обзор — без «Application bytes», ресурсы одной строкой, три карточки, Task 4: Каталог — `xray`, `source`, `archive`, `kind: build`, Task 5: Извлечение member из архива (+9 more)

### Community 194 - "QuotaEnforcer"
Cohesion: 0.10
Nodes (9): caddy_adapt(), command_reload(), command_validate(), main(), QuotaEnforcer, _rewrite_listener(), test_caddy_adapt_unwraps_caddy_211_envelope(), test_private_listener_rewrite_disables_automatic_https_redirects() (+1 more)

### Community 195 - "TelemtAdapter"
Cohesion: 0.16
Nodes (14): anyio_backend(), backends(), _credential(), _imported(), _intent(), test_a_credential_plan_must_match_the_protocol(), test_adopting_mieru_with_rotation_replaces_the_credential_exactly_once(), test_adoption_records_what_happened_and_never_the_credential() (+6 more)

### Community 196 - "test_fleet_acceptance_script.py"
Cohesion: 0.10
Nodes (5): _run(), test_naive_probe_retries_a_cut_connection_but_not_a_refusal(), test_routing_scenarios_are_opt_in_and_sit_after_the_grants(), test_scenario_report_is_secret_free_and_stops_the_central_on_failure(), test_scenario_runs_all_eleven_steps_on_fakes()

### Community 197 - "test_routing_service.py"
Cohesion: 0.22
Nodes (14): Task 8: Routing — сервис и HTTP API (локальный узел), anyio_backend(), _audits(), _block(), test_apply_io_outside_transaction(), test_apply_local_calls_manager_and_records_applied(), test_apply_manager_conflict_marks_failed(), test_apply_unreachable_provider_leaves_policy_unchanged() (+6 more)

### Community 199 - "pytest"
Cohesion: 0.10
Nodes (9): test_a_mieru_grant_without_options_means_no_quota(), test_an_audit_row_stacks_its_main_line_and_its_details(), test_every_documented_audit_action_has_a_journal_label(), test_no_module_renders_an_inline_style_attribute(), test_the_brand_mark_is_the_product_artwork_that_actually_ships(), test_the_grant_dialog_body_issues_a_mieru_grant(), test_the_grant_dialog_reads_only_its_own_protocol_boxes(), test_the_login_form_shows_a_refusal_instead_of_reloading() (+1 more)

### Community 200 - "Global Constraints"
Cohesion: 0.11
Nodes (16): Chains and per-client lanes spike (v0.7, Task 1), S1 — NaiveProxy: one Caddy site, several `forward_proxy` handlers, one upstream per user, S2 — Xray: per-user routing on one ingress, a VLESS+Reality relay to a second Xray, S3 — Mieru: a second mita daemon beside the managed one, What v0.7 builds on this, Global Constraints, Task 0: Ветка, спайк, спека, план, Task 10: Установщик — `relay_port`, `lane_slots`, обновление (+8 more)

### Community 201 - "Task 4: Unified DB layer and migrations"
Cohesion: 0.16
Nodes (19): CommandRunner (bounded, sanitized errors), panel.audit.digest (sha256 of canonical JSON), panel.audit.record(db, ...), panel.audit.scrub (recursive), Migration 2 audit-structured, Migration 1 baseline-v0.1.0, panel.database.Database (WAL, foreign_keys, transaction()), panel.cli db-migrate / db-status (+11 more)

### Community 203 - "script"
Cohesion: 0.13
Nodes (10): script(), FakeConnection, FakeResponse, serve(), test_api_refuses_an_oversized_response(), script(), test_login_fetches_a_csrf_token_and_sends_it(), script() (+2 more)

### Community 204 - "MTProxy acceptance failure: Connection closed"
Cohesion: 0.13
Nodes (12): ams-test disposable install server, Fake-TLS handshake, Full install log capture (install.err, docker compose logs, journalctl nginx, container state), full profile with three_xui.mode managed-new, /root/install.toml and /root/install.credentials, Let's Encrypt certificates (four issued), nebula.sky.dubr1kkk.uk (MTProxy, cert: yes), proxy-control-mtproxy container (127.0.0.1:8445) (+4 more)

### Community 205 - "core_checks"
Cohesion: 0.15
Nodes (8): Task 14: Лаборатория на стенде — `fleet-acceptance.py` и tier `fleet`, core_checks(), fetch(), _ip_through(), main(), Panel, _run(), _socks5_udp_dns()

### Community 206 - "AccessGrant"
Cohesion: 0.18
Nodes (5): Global Constraints, v0.10 — клиент на нескольких узлах и подписка под рукой: план реализации, Subscription, SubscriptionStore, to_subscription()

### Community 207 - "Global Constraints"
Cohesion: 0.11
Nodes (18): 10. Лаборатория и гейт, 11. Живая проверка (AMS_Z → ams-test), 12. Документация и релиз, 13. Решения, принятые за владельца, 1. Цель, 2. Словарь, 3. Архитектурные решения, 4.1 Intent схемы 2 (+10 more)

### Community 208 - "InstallPlan"
Cohesion: 0.16
Nodes (6): AcceptedDigestError, _canonical_json(), _freeze(), _freeze_mapping(), _pretty_json(), TransactionError

### Community 209 - "register_mieru_routes"
Cohesion: 0.24
Nodes (16): _domain_created(), register_mieru_routes(), escrow(), kept(), kept_share_url(), live_template(), local_only(), mieru_create() (+8 more)

### Community 210 - "renderers/base.py"
Cohesion: 0.14
Nodes (7): MieruShare, parse_share_url(), singbox_outbounds(), _proxies(), _mieru_outbounds(), _naive_outbound(), _place()

### Community 211 - "docker_lab.py"
Cohesion: 0.21
Nodes (10): _architecture(), build_image(), copy_inputs(), DockerLabError, guest_command(), main(), run(), run_acceptance() (+2 more)

### Community 213 - "xray_router_manager/healthcheck.py"
Cohesion: 0.20
Nodes (8): test_healthcheck_relay_flags_post_and_get(), test_healthcheck_status_flag_prints_the_manager_status(), check(), main(), relay(), relay_enable(), _request(), status()

### Community 214 - "test_three_xui_api.py"
Cohesion: 0.20
Nodes (15): client(), failing_api(), _panel(), secret_values(), sensitive_values(), template(), test_add_inbound_posts_the_pinned_contract_path_and_returns_the_id(), test_add_inbound_rejects_a_response_without_an_identifier() (+7 more)

### Community 215 - "Task 1: ADRs and v0.2 architecture record"
Cohesion: 0.17
Nodes (14): ADR 001: pull-only node transport, ADR 003: one writer per resource, ADR 005: secret references, Task 1: ADRs and v0.2 architecture record, Task 2: Characterization tests of current boundaries, Task 3: Capability matrix and fixture, Ownership manifest, Fleet v1 Telemt-only command queue (+6 more)

### Community 216 - "Proxy Control v0.5 — выделенный Xray egress-router и финализация vNext"
Cohesion: 0.12
Nodes (17): 10. Spike (Task 32) — что проверяется на стенде, 12. Backup/restore и матрица негативных тестов (Tasks 37, 39), 14. Документация и релиз (Task 41), 15. Отклонения от спеки vNext и решения, принятые за владельца, 1. Цель, 2. Паритет с 3x-ui, 3. Архитектурные решения, 4. Артефакты и каталог релиза (+9 more)

### Community 217 - "ThreeXuiClient"
Cohesion: 0.15
Nodes (4): _Sanitized, ThreeXuiClient, test_api_refuses_a_non_loopback_endpoint(), test_panel_client_uses_tls_and_pins_certificate_before_credentials()

### Community 218 - "TransactionStore"
Cohesion: 0.12
Nodes (5): InjectedCrash, RuntimeRunner, crash_before_derived_journal(), crash_after_started(), die_after_terminal_state()

### Community 219 - "test_routing_lanes_routes.py"
Cohesion: 0.22
Nodes (12): _attach(), _csrf(), _grant(), router(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first() (+4 more)

### Community 220 - "admin"
Cohesion: 0.15
Nodes (4): _port_open(), Router, sha256_file(), stage_xray()

### Community 221 - "test_version_agent_artifacts.py"
Cohesion: 0.28
Nodes (12): _targz(), test_escaping_members_unknown_formats_and_garbage_are_refused(), test_missing_member_symlink_and_oversize_are_refused(), test_tar_member_may_sit_under_a_directory(), test_tar_member_written_with_a_dot_slash_prefix_is_still_found(), test_zip_member_is_returned_by_exact_name(), _zip(), ArtifactError (+4 more)

### Community 222 - "Русский"
Cohesion: 0.12
Nodes (16): Common rules, Development and continuation, English, Getting started, Operations, Protocols and panel, Proxy Control documentation, Releases (+8 more)

### Community 223 - "Proxy Control v0.1.0 Beta"
Cohesion: 0.16
Nodes (11): Archive SHA-256 checksum for proxy-control-v0.1.0.tar.gz, Mieru (TCP/UDP proxy on explicit public ports), mita local manager for Mieru, NaiveProxy (HTTPS proxy with cover site, users, quotas, completed-tunnel accounting), Proxy Control panel (owner/admin/viewer roles, secret-free audit, one-time credential disclosure), Proxy Control v0.1.0 Beta, Four release assets (archive, SHA256SUMS, release-manifest.json, sbom.spdx.json), sbom.spdx.json SBOM (+3 more)

### Community 224 - "English"
Cohesion: 0.12
Nodes (16): English, Gate checklist (lab host `ams-test`), Installing, Live check (AMS_Z → ams-test), Proxy Control v0.7.0-beta.1, Screenshots, Upgrading, What the verification found (+8 more)

### Community 225 - "Disposable lab host ams-test"
Cohesion: 0.17
Nodes (11): Interactive Release Installer Implementation Plan, Disposable lab host ams-test, Baseline main@8c787c5 (2026-09-10), Audit finding 14: Current state of ams-test, Audit finding 15: Baseline on ams-test, Verification levels A-F (quick, full, compose, lab-container, lab-host, real install), Task 0: ams-test stand and baseline, Task 40: Repository and isolated-system gates (+3 more)

### Community 226 - "CommandRunner"
Cohesion: 0.17
Nodes (4): CommandRunner, test_command_runner_reports_captured_stderr_for_failed_command(), test_compose_discovery_reports_unavailable_when_docker_is_not_installed(), test_compose_reconciliation_uses_declared_project_identity()

### Community 227 - "Task 2: automatic WARP with selective routing"
Cohesion: 0.18
Nodes (11): ams-server production reference server, cloudflare-warp client / warp-svc.service, release/external-artifacts.json (pinned external artifacts), Task 3.2: installer deploys WARP automatically, Task 3.3: selective WARP routing via 3x-ui, three_xui.warp_domains config option, WARP selective domain list (geosite:openai, anthropic, tiktok, reddit, google-gemini, google-play), WARP proxy mode on local SOCKS5 port 40000 (+3 more)

### Community 228 - "English"
Cohesion: 0.13
Nodes (15): English, Gate checklist (lab host `ams-test`, tree `841a086`, 2026-09-14), Installing, Live check (AMS_Z), Proxy Control v0.4.0-beta.1, Screenshots, Upgrading, What's new (+7 more)

### Community 229 - "_panel_health_diagnosis"
Cohesion: 0.13
Nodes (6): _panel_health_diagnosis(), _sanitize_diagnostic(), _without_health_polling(), test_a_failed_panel_health_check_says_what_the_containers_were_doing(), test_the_panel_diagnosis_drops_its_own_health_polling(), test_the_panel_diagnosis_never_lets_a_diagnostic_failure_mask_the_real_one()

### Community 230 - "test_installer_mieru.py"
Cohesion: 0.19
Nodes (9): ArtifactError, test_mieru_without_slots_starts_none_and_a_slotted_action_needs_the_router(), artifact_action(), fake_deb(), test_a_download_that_does_not_match_its_pin_is_discarded(), test_mieru_rejects_a_package_with_a_wrong_package_digest(), test_mieru_rejects_valid_package_with_wrong_executable_digest(), test_mieru_stage_leaves_no_extraction_directory_on_failure() (+1 more)

### Community 232 - "AgentTransportServer"
Cohesion: 0.21
Nodes (4): main(), required(), serve(), AgentTransportServer

### Community 233 - "test_client_links.py"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 234 - "pytest"
Cohesion: 0.25
Nodes (11): anyio_backend(), backends(), _grants(), _intent(), test_a_clean_run_activates_every_grant_with_a_stored_credential(), test_a_refused_preflight_reserves_nothing(), test_compensation_never_deletes_what_the_operation_did_not_create(), test_every_fault_ends_in_a_declared_outcome_and_resumes() (+3 more)

### Community 235 - "test_security.py"
Cohesion: 0.13
Nodes (4): test_concurrent_login_batch_reserves_attempts_and_bounds_argon2(), test_login_limiter_migrates_existing_reservations(), test_successful_login_preserves_concurrent_failed_reservation(), interleaved_verify()

### Community 236 - "xray_router_manager/healthcheck.py"
Cohesion: 0.18
Nodes (6): test_unix_api_exit_test_route(), build_manager(), _env(), main(), ManagerHTTPServer, ArtifactMismatch

### Community 237 - "Живая проверка (AMS_Z ↔ ams-test)"
Cohesion: 0.14
Nodes (14): English, Gate checklist (lab host `ams-test`, tree `ade7fcc`, 2026-09-14 — after the three rounds of the final-review fix wave), Installing, Proxy Control v0.3.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z ↔ ams-test) (+6 more)

### Community 238 - "v0.10 — клиент на нескольких узлах и подписка под рукой"
Cohesion: 0.15
Nodes (13): 1. Цель, 3. API, 4. Реестр аудита и события, 5.1 Окно клиента, 5.2 Диалог «Новый клиент», 5.3 Диалог «Выдать доступ», 5.4 Экраны MTProxy / NaiveProxy / Mieru, 5. Интерфейс (+5 more)

### Community 239 - "accepted_sha256"
Cohesion: 0.32
Nodes (7): accepted_caddy_pins(), accepted_sha256(), agent_component(), _state(), test_invalid_state_yields_only_the_pin(), test_missing_or_failed_state_yields_only_the_pin(), test_state_adds_the_agent_installed_hashes()

### Community 240 - "register_node_routes"
Cohesion: 0.26
Nodes (13): _local_identity(), register_node_routes(), _context(), disable(), enable(), node(), nodes(), register() (+5 more)

### Community 241 - "renderers/base.py"
Cohesion: 0.21
Nodes (7): ManifestGrant, credential_reason(), _in_force(), naive_share_url(), _grant_section(), HtmlRenderer, _matrix()

### Community 242 - "test_dashboard_ui_contract.py"
Cohesion: 0.14
Nodes (3): test_host_card_follows_the_host_while_the_overview_is_open(), test_overview_placeholder_has_the_overviews_own_shape(), test_panel_version_is_on_screen_for_every_role_and_on_a_phone()

### Community 243 - "test_view_addressing_ui.py"
Cohesion: 0.21
Nodes (7): index_html(), main_js(), test_an_unknown_or_forbidden_view_falls_back_to_the_overview(), test_back_and_forward_move_between_views(), test_boot_opens_the_view_the_address_names(), test_every_menu_item_has_an_address(), test_navigation_writes_the_view_into_the_address()

### Community 244 - "secrets"
Cohesion: 0.15
Nodes (13): 2026-09-22 — окно клиента, гейт, раскатка, CONTINUE HERE — v0.11 (обновления из upstream), состояние на 2026-09-22, MCP — СДЕЛАНО (2026-09-21, вечер), MCP-сервер (решение владельца: в v0.11, полный набор, с ноутбука через SNI, только на центре), WARP на парке единообразно (2026-09-22, по слову владельца), ВЫПУЩЕНО 2026-09-22 (по слову владельца), Обновление компонентов на парке (2026-09-22, по слову владельца «обнови»), Открытые мелочи (+5 more)

### Community 245 - "Product Overview and Quick Start"
Cohesion: 0.15
Nodes (13): MCP Server for Panel Tools, v0.11 Upstream Updates & MCP Handoff, Version Agent Upstream Service, Cloudflare WARP Selective Routing, v0.1 Handoff and Plan, v0.3 Central Panel Handoff, v0.4 Routing Handoff, v0.5 Xray Egress Router Handoff (+5 more)

### Community 246 - "3. Задачи"
Cohesion: 0.15
Nodes (12): 1. Где остановились, 2. Как WARP устроен на рабочем сервере (снято с `ams-server`), 3.1 Добить установку, 3.2 Автоматический WARP, 3.3 Выборочная маршрутизация через 3x-ui, 3.4 Подписка 3x-ui (девятый домен), 3.5 Релизная лаборатория, 3. Задачи (+4 more)

### Community 247 - "3x-ui mode managed-new: install on clean server, create inbounds"
Cohesion: 0.21
Nodes (13): Task 3.4: 3x-ui subscription on ninth domain, zenith.sky.dubr1kkk.uk (reserved: 3x-ui subscription), Bilingual install wizard, Hysteria2 inbound, Nginx mode coexist: existing Nginx stream keeps TCP/443, Nginx mode fresh: installer installs and configures Nginx, Nine distinct domains for full profile + managed-new + subscription (eight without subscription), Shared TCP/443 SNI routing (+5 more)

### Community 248 - "English"
Cohesion: 0.15
Nodes (13): English, Installing, Live check (AMS_Z), Proxy Control v0.5.0-beta.1, Screenshots, Upgrading, What's new, Живая проверка (AMS_Z) (+5 more)

### Community 250 - "3. Что v0.6 добавляет"
Cohesion: 0.15
Nodes (10): 1. Цель, 2. Что уже доказано (не переделывается), 3.1 Матрица сверки — `docs/VERIFICATION_MATRIX.md` + `tests/fixtures/verification-matrix.json`, 3.2 Аудит маршрутов — `scripts/dev/route-coverage.py`, 3.4 Бэкенд: дыры в лабораторном покрытии, 3.5 Живая проверка на AMS_Z (по разрешению владельца), 3. Что v0.6 добавляет, 4. Не входит (+2 more)

### Community 251 - "v1.1 — маршрутизация MTProxy через Xray-router"
Cohesion: 0.15
Nodes (12): 1. Цель, 2. Что доказано на стенде (ams-test, 2026-10-01), 3. Топология, 4. Xray-router (менеджер), 5. Мост `xray-router-ingress`, 6. Панель, 7. Установщик, 7a. Обновление одной командой (добавлено владельцем 2026-10-01) (+4 more)

### Community 252 - "test_installer_mieru.py"
Cohesion: 0.17
Nodes (4): MieruPaths, SlotRunner, _stage_router(), test_mieru_apply_starts_the_slot_units_and_verify_and_repair_check_them()

### Community 253 - "installer/audit.py"
Cohesion: 0.27
Nodes (8): AuditFacts, facts_from_root(), fixture_root(), test_audit_discovers_stream_conf_d_routes(), test_audit_reports_existing_shared_443_without_dumping_secrets(), test_domain_validation_rejects_unsafe_values(), test_install_plan_rejects_domain_and_port_collisions(), test_install_plan_rejects_unknown_nginx_and_gates_unavailable_by_mode()

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

### Community 259 - "test_placement_ui_contract.py"
Cohesion: 0.30
Nodes (6): run(), test_diff_creates_enables_and_disables_from_ticks(), test_render_marks_cells_and_disables_what_cannot_change(), test_rows_offer_local_and_linked_panels_and_keep_nodes_that_already_hold_grants(), test_settling_is_true_while_a_node_has_not_confirmed_and_ignores_deleted_grants(), test_unoffered_rows_are_never_part_of_the_diff()

### Community 260 - "i18n-strings.py"
Cohesion: 0.26
Nodes (7): _clean(), fragments(), main(), _read_string(), _read_template(), _scan_code(), _skip_comment()

### Community 261 - "guest-runner.sh script"
Cohesion: 0.26
Nodes (12): case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), full_environment_preflight(), host_diagnostics(), host_environment_preflight() (+4 more)

### Community 264 - "English"
Cohesion: 0.20
Nodes (9): Changes, Deployment and rollback, English, v0.14.0-beta.1 — совместное использование 443 и приёмка Naive, Validation scope, Изменения, Развёртывание и откат, Русский (+1 more)

### Community 265 - ".install"
Cohesion: 0.18
Nodes (11): English, Installer fixes, Installing, Proxy Control v0.2.0-beta.1, Verified for this release (on the lab host), What is new, Исправлено в установщике, Проверено для этого выпуска (на стенде) (+3 more)

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

### Community 272 - "test_fleet_v2_central_routes.py"
Cohesion: 0.18
Nodes (4): central_http(), test_fingerprint_private_address_requires_explicit_opt_in(), test_fingerprint_request_deadline_also_bounds_slow_system_dns(), test_link_rejects_bad_key_private_url_and_self()

### Community 274 - "sbom.py"
Cohesion: 0.25
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

### Community 282 - "MemoryXrayRouter"
Cohesion: 0.24
Nodes (6): _csrf(), router(), test_a_linked_panels_geodata_is_driven_through_its_fleet_api(), test_geodata_is_owner_only_to_change_and_needs_a_router(), test_local_geodata_view_settings_update_restore_and_audit(), test_node_geodata_and_exit_routes_answer_the_central_key()

### Community 284 - "prepare_mieru_token.py"
Cohesion: 0.36
Nodes (6): fail(), main(), prepare_or_verify(), TokenError, validate_path(), validate_source()

### Community 286 - "Рабочий протокол для AI-агентов"
Cohesion: 0.22
Nodes (9): Главное правило, Изолированная установка и реальные проверки, Обязательные проверки репозитория, Перед изменением, Правила, которые уже спасали от ложных отчётов, Правила отчёта, Проверка всех Compose-моделей и образов, Рабочий протокол для AI-агентов (+1 more)

### Community 287 - "probe.py"
Cohesion: 0.36
Nodes (5): _endpoint(), main(), _run(), _socks5_connect(), _status_through()

### Community 288 - "The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP"
Cohesion: 0.22
Nodes (9): Connecting, How to enable, Rotating the token and the key, Skills, The `confirm` rule, The MCP server (v0.11): the panel as tools for Claude Code, Claude Desktop, Codex and OMP, Turning it off, Verification (+1 more)

### Community 289 - "MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP"
Cohesion: 0.22
Nodes (9): MCP-сервер (v0.11): панель как инструменты Claude Code, Claude Desktop, Codex и OMP, Выключить, Как включить, Подключение, Правило `confirm`, Проверка, Ротация токена и ключа, Скиллы (+1 more)

### Community 290 - "panel"
Cohesion: 0.22
Nodes (9): English, Installing, Upgrading from v0.11, v0.12.0-beta.1 — адрес у каждого раздела, ссылки MTProxy в карточке клиента, What changed for you, Обновление с v0.11, Русский, Установка с нуля (+1 more)

### Community 291 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.14, v0.15.0-beta.1 — версия панели и обновления узлов из центра, Добавлено, Исправлено, Обновление с v0.12–v0.14 (+1 more)

### Community 292 - "English"
Cohesion: 0.22
Nodes (9): Added, English, Fixed, Upgrading from v0.12–v0.15, v1.0.0 — первый стабильный выпуск: понятная маршрутизация, английский интерфейс, сохранённые ключи Mieru, Добавлено, Исправлено, Обновление с v0.12–v0.15 (+1 more)

### Community 293 - "English"
Cohesion: 0.22
Nodes (9): Added, Changed, English, Upgrading from v1.0.3, v1.1.0 — маршрутизация MTProxy через Xray-router, Добавлено, Изменено, Обновление с v1.0.3 (+1 more)

### Community 294 - "Структура файлов"
Cohesion: 0.22
Nodes (8): Global Constraints, Self-review (спека → план), Task 0: Ветка, спека, план, Task 14: Документация, ADR 007, CHANGELOG, VERSION, релизная заметка, Task 15: Гейт релиза на `ams-test` и точка продолжения, Task 3: Spike — Xray как egress-router на стенде (Task 32), v0.5 Xray Router Implementation Plan, Структура файлов

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

### Community 301 - "test_fetch_reports_the_hop_that_names_the_release"
Cohesion: 0.22
Nodes (3): test_fetch_reports_the_hop_that_names_the_release(), fetch(), redirect_request()

### Community 303 - "CONTINUE-HERE.md"
Cohesion: 0.25
Nodes (8): Задача 1: добить установку, Задача 2: автоматический WARP, Задача 3: релиз, Отложено владельцем, Правила, добытые дорогой ценой, Промпт для продолжения работы в новом контексте, Прочитай сначала, Что уже сделано

### Community 304 - "TelemtError"
Cohesion: 0.25
Nodes (8): CONTINUE HERE — v0.3 центральная панель, Где мы, Гейт v0.3.0-beta.1 (2026-09-14 11:42–11:59 UTC, дерево `ade7fcc`, чистое — после трёх раундов фикс-волны), Действия владельца, Отложенные minor и out-of-scope наблюдения, Рулинги, принятые за владельца (в итоговый отчёт), Точка продолжения, Что дальше по ветке

### Community 305 - "Структура файлов"
Cohesion: 0.25
Nodes (8): Task 19A — релизный гейт v0.2 на `ams-test` (пройден 2026-09-11), Как проверять (единственный способ), Правила, добытые в этой серии, Промпт для продолжения работы в новом контексте, Прочитай сначала, Состояние репозитория (2026-09-11), Что делать первым делом, Что уже сделано (Tasks 0–14)

### Community 306 - ".install"
Cohesion: 0.25
Nodes (8): 4.1 Требования к хосту, 4.2 Скачать и проверить релиз (без root), 4.3 Мастер: вопросы по порядку, 4.4 План и digest, 4.6 Приёмка, отчёты, где пароли, 4.7 Первые действия в панели, 4.8 Повторный запуск, resume, repair, uninstall, 4. Автоматическое развёртывание узла

### Community 307 - "_panel_probe"
Cohesion: 0.25
Nodes (3): _panel_probe(), test_a_panel_that_answers_with_an_error_code_reports_that_code(), test_a_panel_that_cannot_be_reached_still_raises()

### Community 309 - "test_api_key_auth.py"
Cohesion: 0.46
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 310 - "test_telemt_adapter_does_not_leak_secret_in_errors"
Cohesion: 0.25
Nodes (6): test_telemt_adapter_does_not_leak_secret_in_errors(), handler(), test_telemt_adapter_patches_limits_and_resets_quota(), handler(), test_telemt_adapter_reads_3425_quota_stats_route(), test_telemt_adapter_sends_auth_and_maps_envelope()

### Community 313 - "update-host.sh"
Cohesion: 0.46
Nodes (7): agent(), fail(), has(), health(), json(), say(), update-host.sh script

### Community 314 - "replace"
Cohesion: 0.32
Nodes (7): clean_facts(), mieru_action(), test_recovery_verifies_nonempty_manager_state_and_new_token_is_32_bytes(), test_mieru_env_carries_router_provider(), test_mieru_plan_is_empty_without_the_mieru_profile(), test_mieru_plan_pins_the_release_and_stays_secret_free(), test_mieru_plan_proxies_egress_only_when_warp_is_selected()

### Community 315 - "test_the_release_carries_the_mcp_server()"
Cohesion: 0.14
Nodes (4): test_the_install_script_names_exactly_the_pinned_artifact_versions(), test_the_release_carries_the_mcp_server(), test_the_repository_ignores_its_own_release_outputs(), test_the_verify_tool_runs_as_a_script_from_the_repository_root()

### Community 316 - "UpgradeError"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.4 маршрутизация, Где мы, Гейт (Task 13) — итог, Известные ограничения/решения (для ревью и v0.5), Коммиты ветки (по порядку), Публикация (по поручению владельца 2026-09-14), Что дальше (владелец)

### Community 317 - "CONTINUE HERE — v0.6 сверка функций v0.2–v0.5"
Cohesion: 0.29
Nodes (7): CONTINUE HERE — v0.6 сверка функций v0.2–v0.5, Где мы, Гейт (финальное дерево) и живая проверка, Известные ограничения/решения, Публикация (сделано 2026-09-17 11:18–11:30 UTC), Что дальше (владелец), Что сделано (коммиты по порядку)

### Community 318 - "_await_panel_health"
Cohesion: 0.29
Nodes (3): _await_panel_health(), test_panel_acceptance_gives_up_and_reports_the_last_refusal(), test_panel_acceptance_waits_for_the_panel_instead_of_racing_it()

### Community 320 - "test_routing_routes.py"
Cohesion: 0.48
Nodes (5): _csrf(), test_apply_rollback_delete_and_history(), test_preview_of_a_draft_does_not_save(), test_put_upserts_with_expected_revision_and_keeps_rule_ids(), test_viewer_reads_and_previews_but_never_mutates()

### Community 321 - "verification-matrix.py"
Cohesion: 0.43
Nodes (4): load(), main(), proof_problem(), render()

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

### Community 327 - "facts_with_uid"
Cohesion: 0.38
Nodes (7): facts_with_uid(), full_config(), test_naive_plan_adopts_its_own_reserved_identities(), test_naive_plan_is_empty_without_the_naive_profile(), test_naive_plan_keeps_only_audited_adjacent_routes(), test_naive_plan_stops_on_fixed_accounting_group_collision(), test_naive_plan_stops_on_fixed_identity_collision()

### Community 328 - "NginxReloadRecovery"
Cohesion: 0.29
Nodes (3): NginxReloadRecovery, run(), test_a_reload_that_kills_nginx_is_recovered_and_reported()

### Community 330 - "run_wrapper"
Cohesion: 0.57
Nodes (4): run_wrapper(), test_wrapper_mounts_secret_file_read_only_without_placing_secret_in_docker_argv(), test_wrapper_rejects_invalid_arguments_without_starting_docker(), test_wrapper_requires_root()

### Community 331 - "RuleMatch"
Cohesion: 0.33
Nodes (6): ADR 006: Engine-neutral routing policy IR, Amended in v1.1 (2026-10-01): MTProxy through the Xray-router, Consequences, Context, Decision, Non-goals

### Community 332 - "Archived v0.2 local control plane"
Cohesion: 0.33
Nodes (3): Archived v0.3 Fleet v2 central panel, Archived v0.2 local control plane, Archived v0.2 subscription rendering

### Community 333 - "Archived v0.5 Xray egress router"
Cohesion: 0.33
Nodes (4): Archived v0.4 manager egress APIs, Archived v0.4 routing policies, Archived v0.5 router attachment, Archived v0.5 Xray egress router

### Community 334 - ".compose"
Cohesion: 0.33
Nodes (6): CONTINUE HERE — v0.5 Xray egress-router, Где мы, Гейт (Task 15) — итог, Известные ограничения/решения (для ревью и после v0.5), Коммиты ветки (по порядку), Что дальше (владелец)

### Community 335 - "query"
Cohesion: 0.33
Nodes (5): CONTINUE HERE — v0.9 (стык фронт/бэк, matches_node, мобильный UI, Xray-router на центре), v0.9.0-beta.1 (Release), Сделано, Что дальше, ams-server (Central Host)

### Community 337 - "ThreeXuiApiError"
Cohesion: 0.33
Nodes (3): parse_csrf_token(), test_a_page_without_a_usable_csrf_token_fails_closed(), test_csrf_token_is_read_from_the_page_the_panel_serves()

### Community 341 - "probe/install.sh"
Cohesion: 0.33
Nodes (5): DESTINATION, IMAGE, install.sh script, TDL_VERSION, TDLIB_VERSION

### Community 344 - "skills/README.md"
Cohesion: 0.33
Nodes (5): Diagnosing a client's access, Report to the owner, Steps, Symptom → likely cause, What not to do

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

### Community 354 - "Proxy Control v0.3 — центральная панель и подключённые панели"
Cohesion: 0.40
Nodes (5): CONTINUE HERE — v0.7 (цепи и полосы), Выпуск (сделано 2026-09-18 10:16–12:50 UTC), Слияние и раскатка парка (сделано 2026-09-18 13:00–13:35 UTC, по решению владельца), Что дальше (владелец), Что оставлено на хостах

### Community 355 - "Task 3: release v0.1.0 through CI"
Cohesion: 0.40
Nodes (3): lab-amd64 CI release lab, Task 3.5: release lab lab-amd64, Verified: exact-archive lifecycle on isolated amd64 VPS (install, repair, idempotence, reboot/crash recovery, uninstall, coexistence)

### Community 356 - "Продолжение работы над Proxy Control"
Cohesion: 0.40
Nodes (5): Ограничения эксплуатации, Последние доказательства, Продолжение работы над Proxy Control, Репозиторий и кандидат, Следующие задачи

### Community 357 - "English"
Cohesion: 0.40
Nodes (5): Domains and shared port 443, English, Included, Installation, Verified for this release

### Community 358 - "Proxy Control v0.1.0 Beta"
Cohesion: 0.40
Nodes (5): Домены и общий 443, Проверено для этого выпуска, Русский, Установка, Что входит

### Community 359 - "Proxy Control v0.3 — центральная панель и подключённые панели"
Cohesion: 0.40
Nodes (5): 6.1 Порядок раскатки парка, 6.2 Подготовка узла, 6.4 Импорт существующих пользователей узла, 6.6 Отвязка, удаление, ротация ключа, 6. Центр и узлы: привязка панелей

### Community 360 - "vNext capability matrix"
Cohesion: 0.40
Nodes (5): Control-plane access enforcement, Protocols and the Fleet v1 transport, Spike plan before any routing claim, Subscription clients, vNext capability matrix

### Community 364 - "test_the_domain_writer_adopts_a_user_it_did_not_create"
Cohesion: 0.40
Nodes (3): test_the_domain_writer_adopts_a_user_it_did_not_create(), test_the_domain_writer_records_a_client_and_grant_for_every_protocol(), _writer()

### Community 365 - "skills/README.md"
Cohesion: 0.40
Nodes (4): Granting access to a client, Link variants (`subscription.variants`), Pitfalls, Report to the owner

### Community 366 - "skills/README.md"
Cohesion: 0.40
Nodes (4): Overview of the panel and its nodes, Report shape, What counts as a problem, What to read

### Community 371 - "_preparer"
Cohesion: 0.40
Nodes (4): _preparer(), test_state_preparer_refuses_a_symlinked_boundary(), test_state_preparer_refuses_unnormalized_and_relative_paths(), test_state_preparer_requires_root()

### Community 372 - "ADR 004: Client, AccessGrant and subscription as a projection"
Cohesion: 0.50
Nodes (4): ADR 004: Client, AccessGrant and subscription as a projection, Consequences, Context, Non-goals

### Community 373 - "CONTINUE-HERE.md"
Cohesion: 0.50
Nodes (4): CONTINUE HERE — v0.8 (свои выходы, таблица правил, geodata, автоимпорт), Сделано, Что дальше, Что оставлено на хостах

### Community 377 - "mieru-mss-clamp.sh"
Cohesion: 0.83
Nodes (3): check_rule(), mieru-mss-clamp.sh script, usage()

### Community 386 - "CONTINUE-HERE.md"
Cohesion: 0.67
Nodes (3): CONTINUE HERE — v0.10 (клиент на нескольких узлах, подписка под рукой), Сделано, Что дальше

### Community 387 - "Archived v0.11 upstream component updates"
Cohesion: 0.67
Nodes (3): Archived v0.11 central MCP server, Archived v0.11 installer version agent, Archived v0.11 upstream component updates

## Ambiguous Edges - Review These
- `Beam vs Hammer Clash Metaphor` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: rationale_for
- `Proxy Control Repository Branding Asset` → `Cover Metaphor for Blocking vs Traversing Traffic`  [AMBIGUOUS]
  assets/proxy-control-cover.png · relation: conceptually_related_to
- `WARP as one loopback SOCKS5 endpoint` → `WARP as one SOCKS5 endpoint 127.0.0.1:40000`  [AMBIGUOUS]
  CHANGELOG.md · relation: semantically_similar_to

## Knowledge Gaps
- **756 isolated node(s):** `_Journal`, `OBSERVED`, `PROTOCOL_NAMES`, `PROTOCOLS`, `AUTO_REFRESH` (+751 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 3654 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **114 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Beam vs Hammer Clash Metaphor` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: rationale_for) - confidence is low._
- **What is the exact relationship between `Proxy Control Repository Branding Asset` and `Cover Metaphor for Blocking vs Traversing Traffic`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `WARP as one loopback SOCKS5 endpoint` and `WARP as one SOCKS5 endpoint 127.0.0.1:40000`?**
  _Edge tagged AMBIGUOUS (relation: semantically_similar_to) - confidence is low._
- **Why does `Матрица негативных и security-тестов vNext (Task 39)` connect `Матрица негативных и security-тестов vNext (Task 39)` to `test_routing_fleet_chains.py`, `AccessGrant`, `pytest`, `GrantIntent`, `test_xray_routing_compiler.py`, `test_fleet_v2_central_routes.py`, `MemoryNaive`, `FleetStore`, `ProtocolError`, `test_routing_router_service.py`, `Proxy Control documentation index`, `test_users_adapter_ui.py`, `ReleaseManifest`, `CertificateAuthority`, `EgressInvalid`, `TransactionStore`, `test_mieru_manager.py`, `naive_manager/egress.py`, `safe_extract_zip`, `render_config`, `test_fleet_acceptance_script.py`, `test_routing_service.py`, `test_installer_xray_router.py`, `test_mieru_egress.py`, `test_fleet_v2_client.py`, `script`, `test_subscription_http.py`, `DeployCliTests`, `test_rbac_audit.py`, `test_installer_release.py`, `.wait`, `test_fleet_v2_reconcile.py`, `PolicyInput`, `test_naive_manager_egress.py`, `test_fleet_v2_post_merge.py`?**
  _High betweenness centrality (0.081) - this node is a cross-community bridge._
- **Why does `Proxy Control` connect `Proxy Control` to `Управление Mieru / mita 3.35–3.36`, `install-bootstrap`, `Proxy Control documentation index`, `Automated installation on Ubuntu 24.04`, `v1.1.0 audit and rc.2 acceptance report`, `Isolated Ubuntu 24.04 installer lab`, `Troubleshooting Proxy Control`, `Backup and restore contract (EN)`, `Панель управления Proxy Control`, `Панель управления Proxy Control`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `vNext architecture (v0.2 and v0.3)` connect `AccessGrant` to `test_routing_fleet_chains.py`, `Proxy Control documentation index`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `Action` (e.g. with `Adapter` and `CoreAdapter`) actually correct?**
  _`Action` has 38 INFERRED edges - model-reasoned connections that need verification._
