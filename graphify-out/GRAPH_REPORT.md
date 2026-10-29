# Graph Report - Proxy Control  (2026-10-29)

## Corpus Check
- Source: Proxy Control at `c12a7f67560a3dbf64331a50033c28eb79e00892`
- 1,488 detected files · ~1,841,012 words
- Code: 1,285 files; documents/text: 174; images: 29
- Detection safety filter skipped 165 potentially sensitive paths (mostly synthetic credential/certificate fixtures); ignore rules stayed enabled.
- Two data-only JSON fixtures have no manifest entries: `panel/crates/protocols/tests/fixtures/transcripts.json` and `panel/tests/goldens/subscriptions/subscriptions.json`.

## Summary
- 22735 nodes · 64463 edges · 775 communities (606 shown, 169 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 2988 edges (avg confidence: 0.85)
- Semantic extraction usage, both passes: 659,944 input · 199,379 output tokens. Community-naming usage and the actual API bill are not included.

## Graph Freshness
- Built from commit: `c12a7f67`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Build Provenance
- Fresh AST + semantic build; no old graph or old extraction cache was reused.
- Semantic backend: **OpenRouter**, model **`google/gemini-3.8-flash`** (also used for community naming).
- All **203/203** semantic inputs have graph attribution and manifest stamps: 174 documents/text files and 29 complete image inputs.
- Text input delivery was checked across every source slice; omitted outputs from the initial pass were retried individually.
- Repository source was read from a clean checkout, not local agent workspaces or deployment state.
- `built_at_commit` identifies the analysed source commit; a following graph-only commit does not change that source.

## Community Hubs (Navigation)
- Data Types and Validation
- Installation Filesystem Engine
- Audit Evidence Checkpoints
- CLI and Code Generation
- UI and Audit Tests
- Client Models and Validation
- Central Routing Generation
- Client Error Handling
- AmneziaWG Manager API
- Client Adapter Mock Testing
- Xray Router Intent Configuration
- Host Binary Release Builder
- Node HTTP Hooks Client
- Service Status Dashboard
- Localization and Translation Catalog
- Mieru Proxy Acceptance Tests
- Audit Context and Event Bus
- Installer Audit Verification
- Egress Memory Manager
- Client Subscription Management
- Naive Manager Integration Tests
- Address Policy Resolution
- Fleet Delivery Interoperability Tests
- Document Validation and Ports
- Database Clock Testing Mock
- Planner Adapter Configuration
- Audit CLI Error Handling
- Access Reconciliation Enforcement
- Runtime Fleet Routing
- Caddyfile Accounting Configuration
- Routing Egress Verification
- Protocol Chain Actions
- Installer Domain Configuration Validation
- Egress View Artifacts
- Service Policy Router Tests
- Firewall Rule Enforcement
- Panel Test Fixtures
- TrustTunnel Configuration Parsing
- CLI Argument Parser
- Password Hashing and Querying
- Fake Caddy HTTP Server
- Frontend Audit UI Components
- Mieru Manager Service Journal
- AmneziaWG Manager Lifecycle Tests
- TLS Certificate Inspection
- AmneziaWG Client UI Modals
- Xray Test Mocks and Probes
- MCP Adapter Composition
- UI Metrics and Monitoring
- Access Enforcement Tests
- Grant and Credential State
- Routing Regression Tests
- Acceptance Test Suite
- Protocol Configuration Options
- Central Routing Policy
- Client Protocol Adapters
- State Persistence and Backups
- Route Document Compilation
- Xray Router Mock Tests
- Mieru Manager Tests
- Grant Context and Intents
- Metrics Collector Configuration
- Node Inventory Reconciliation
- TOML Parsing Utilities
- Client Dialog UI Tests
- Routing Policy UI Editor
- AmneziaWG Python Driver
- Atomic State Store
- Fleet Node Management
- Mieru Adapter Management
- Metrics Time Series Store
- Fleet Central Cryptography Errors
- AmneziaWG Service Manager
- Exit Routing Configuration
- Logging Utilities
- Panel Lifecycle Tests
- Safe Archive Extraction
- Version Agent Server
- Node Metrics Source Tests
- Node System Audit Tests
- Router Configuration State Management
- Routing Lanes and Relays
- Healthcheck Verification CLI
- Client Bundle Protocol Adapters
- Container Integration Test Runner
- Database Schema Migrations
- AmneziaWG Configuration Models
- Config Migration and Rollback
- AmneziaWG Egress Adapter
- Access Artifact Manifest Generation
- Tun Device Process Runner
- Subprocess Runner Execution
- Routing Spike Proxy Handlers
- Upstream Release Asset Verification
- Installer CLI Commands
- Manager Egress Error Codes
- Tunnel Lifecycle Integration Tests
- Node Tunnel Reconciliation Tests
- Agent Binary Update Rollback
- Client Request API Models
- MCP Server Client Placement
- Python-Compatible URL Parser
- Version Agent Release Checker
- Xray Router Manager Tests
- Upstream Version Parsing
- Frontend API Error Formatter
- Go Runtime Packages
- AmneziaWG Wizard Configuration Tests
- Node Traffic Counters
- AwgManager Egress Management
- Candidate Update Verification Tests
- File Acceptance Markers
- Proxy Ownership Acceptance
- Traffic Accounting Storage
- Isolated VPN Smoke Tests
- Operator Credentials Validation
- Metrics Route Endpoints
- Client Management UI Actions
- Client Dispatch Replay
- Ordered JSON Deserialization
- Server-Sent Events Streams
- Python-Compatible JSON Serialization
- Adapter Context Registry
- Agent Service Lifecycle Tests
- JSON-RPC Tool Invocation
- HTTP Request Extractors
- Policy Routing Route Handlers
- Atomic Binary Execution Script
- Mita Process Execution Tests
- Safe Archive Extraction Tests
- AwgManager Service Daemon
- Proxy Process Child Isolation
- Fleet Central Certificate Validation
- ACME Certificate Management
- Version Agent Client
- Component Release Catalog
- Nginx Topology Parser
- X25519 Cryptographic Keys
- Three-XUI Adapter Integration
- Relay Lane Policies
- GeoData Asset Fetcher
- Keyring Key Management
- Web Request Infrastructure
- Configuration Obfuscation Generator
- Managed Node Storage Store
- TeleMT Metrics Dashboard Tasks
- Fleet Metrics Source Aggregator
- Nginx Route Configuration Adapter
- Host Process Command Runner
- AmneziaWG Management Client
- HTTP Boundary Regression Tests
- Bounded HTTP Client Operations
- External Link Chooser Tests
- Host Handoff Ownership Verification
- Naive Caddy Deployment Adapter
- Client App Deep Links
- AwgManager Process Supervision
- HTTPS Certificate Validation
- Acceptance and Handoff Reporting
- In-Memory TeleMT Management
- TeleMT Proxy Manager
- Client Lifecycle Scenario Testing
- Naive Manager CLI
- Traffic Accounting Tests
- Host Updater Service
- APT Package Management
- Mieru Egress Management
- HTTP Request Router
- Client Account Provisioning
- Runtime Geodata Management
- Node Link Management
- Fleet Reconciliation Tests
- Client Attention Dashboard UI
- Lane and Route Validation
- Routing Protocol Error Handling
- Node Management Routes
- Node Administration UI
- Host Metrics Collection Tests
- Warp Adapter Package Management
- API Key Management Routes
- In-Memory Protocol Node Mocks
- State Probe and Rollback
- Routing Policy Backend Store
- Chart Value Formatting Utilities
- QEMU Test Platform Automation
- Architecture Documentation and Protocols
- Mieru Quota Models
- VPN Runtime Management
- Cursor and Value Serialization
- Installer CLI Test Suite
- Installation Transaction Lifecycle
- GitHub Actions CI Workflows
- HTTP Server Endpoint Tests
- Test Fixtures and RBAC
- Fleet Verification Claims
- Fleet Metrics Aggregation
- Core Adapter Lifecycle Automation
- Nginx Stream Configuration Rendering
- Python JSON Test Generator
- Subscription Service Test Suite
- Database Schema Migrations
- Static Files and MIME Handling
- Geodata Scheduled Updates
- HTTP Transport Channel Handling
- Web Admin CLI Commands
- MCP Docker Compose Configuration
- Fake Manager Server Tests
- Secrets Keyring Fixture Tests
- API Tool Schema Validation
- Quota Enforcer Server Handler
- Metrics Route Integration Tests
- Egress and Geodata Management
- Router Policy Apply Workflow
- QR Code Generation
- 3X-UI API Integration Tests
- Python Compatibility Helpers
- Database Schema Snapshot V19
- Database Schema Snapshot V21
- Database Schema Snapshot V23
- Database Schema Snapshot V24
- Host Update Script Tests
- Client Audit Golden Tests
- Proxy Smoke Docker Tests
- Egress Configuration Tests
- Database Schema Snapshot v16
- VPN Protocol Transcripts
- Test Mocking and Recording
- Python Compatibility Testing
- Backup and File Management
- Network Egress and Relays
- Node Link Synchronization
- Python JSON Serialization
- Agent Monitoring Scenarios
- API Error Handling
- Trust Tunnel Egress Management
- Node Certificate Management
- Release and Artifact Management
- Client Management and Access Control
- Client Authentication and Access Management
- Client Access Dialog Management
- Mieru SOCKS Client Tests
- Fleet Host Rollback Engine
- Runtime Testkit Evidence
- 3x-ui API Client
- Background Lifespan Tasks
- Central Process Manager
- Port Metrics Discovery
- Version Agent Errors
- Mieru Quotas and Routes
- Xray Router Adapter
- Python String Compatibility Utilities
- Naive Manager Memory Mock
- Proxy Control Panel Documentation
- Host Network Test Device
- Release Notes and Changelog
- Wizard Engine Golden Tests
- Live Xray Router Tests
- HTTP API Response Rendering
- Manifest Grant Subscription Renderers
- TrustTunnel Memory Mock
- Release Verification Matrix
- Manager Client Egress Tests
- Mieru Validation Rules
- Routing Coverage and Capabilities
- Container Metrics Sampler
- Linux Process Host Runner
- Mieru Lanes Configuration
- Python Datetime Compatibility Utilities
- Database Schema Snapshot V11
- Database Schema Snapshot V12
- Exit and Geodata Request Models
- Authentication and Session Flows
- Panel Archive Extraction
- IPv4 Network Utilities
- TrustTunnel and Routing Documentation
- Multi-Protocol Project Changelog
- AmneziaWG Routes and Errors
- Secret Staging Helper
- QEMU Lab Test Suite
- AmneziaWG Configuration Validation
- Version Agent Command Runner
- Proxy Control Installer Guides
- Public Client Format Negotiation
- JSON Load and Parser
- JSON Number Serialization Modes
- HTTP Parsing and Decoding
- Mieru Docker Compose Setup
- Egress Migration Support
- Component Integration Guides
- File Directory Descriptor Operations
- Web Test Client Helpers
- Naive Routes and Escrow
- Caddy Reverse Proxy Client
- PyText Test Data Generator
- Protocol Golden Config Tests
- User Adapter UI Tests
- Host Hardware Metrics Reader
- Host Metrics Collection Timer
- TLS Network Client
- IP Address Normalization
- Core Acceptance Engine Tests
- WARP and TrustTunnel Smoke Tests
- Router Lifecycle Smoke Tests
- MCP HTTP Forwarding Router
- Node Capture and Reconciliation
- Core Checkpoint Validation
- Xray Router Manager Client
- Panel Archive Extraction Helpers
- Service Adapters Installer Reference
- Secrets Store Encryption Tests
- Nginx and VPN Smoke Tests
- Mieru Manager Memory Mock
- HTTP Mock Server Testkit
- ISO Datetime Parsing
- Application State Authentication
- Metrics API Routes
- Admin Subscription Management
- Rust Cargo Workspace Crates
- TDLib Node Dependencies
- Drill API Integration Client
- Fleet Metrics System
- Web Assets and CSP
- Naive Manager Errors
- Application Settings Management
- NaiveProxy Client Management
- Admin Authentication Routes
- TLS Certificate Issuance Tests
- Node Management Routes
- IP Address Utilities
- Process Supervision
- Node Import Models
- Host Configuration Verification
- Fleet Acceptance Testing
- Operations Documentation
- AmneziaWG Port Allocation
- Naive Manager State
- Binary Identity Verification
- Client Rate Limiting
- AmneziaWG Acceptance Script
- AmneziaWG Panel E2E Tests
- Archive Extraction Utilities
- Operational Runbooks and Contracts
- Routing Presets Service
- Updater Integration Tests
- Panel Client Integration
- Installer Error Handling
- Fleet Architecture Specifications
- Core Services Acceptance
- In-Memory AmneziaWG State
- Manager Golden Tests
- Routing Lanes Route Tests
- Route Authorization Coverage
- TrustTunnel Manager State
- Environment File Parser
- MTProxy Dockerfile Setup
- Monitoring Live Checks
- Credential and Report Testing
- Core Adapter Acceptance
- Nginx Regression Tests
- Mieru Manager Service
- Protocol Egress Targets
- IDNA Domain Processing
- Fake Fleet Test Mock
- Metrics Port Discovery
- Installer Audit Tests
- AmneziaWG Forwarding Service
- Installation Bootstrap Guide
- Mieru Setup and Operations
- Issue Template Configuration
- MCP Server Configuration
- Python Compatible IP Parser
- MTProxy Container Specification
- MTProxy Container Configuration
- MTProxy Service Configuration
- MTProxy Compose Configuration
- MTProxy Container Deployment
- MTProxy Compose Specification
- MTProxy Container Settings
- Compose Migration Tests
- Version Agent Golden Tests
- Panel File Ownership
- Python JSON Formatter
- Core API Errors
- Python Text Parsing Tests
- Service Golden Comparison Tests
- Subscription Format Converters
- Installation Hook Handlers
- QEMU Release Artifact Tests
- Managed X-UI Client Tests
- Nftables Counter Parsing
- Xray Router IP Handling
- Web Health Check Probes
- Docker Container Hardening
- Xray Router Environment Variables
- Node Lifecycle Tests
- Database Snapshot v0.4
- Database Snapshot v0.5
- Credential Reconciliation State
- Query Parameter Parsing
- Local Manager State Registry
- Compatibility Matrix Specification
- Live Connection Management
- Client Link Reveal Tests
- Version Update Agent Tests
- Secret Scrubbing Validator
- Container Service Configuration
- Container Service Configuration
- Container Service Configuration
- Container Service Configuration
- Container Service Configuration
- Container Service Configuration
- Container Service Configuration
- Manager Build Host
- Xray Router Manager Errors
- Naive Manager Configuration
- Xray Router Ingress Service
- Version Management API Routes
- Secret Staging CLI Tests
- TLS Certificate Leaf Verification
- Mieru Manager Errors
- TLS Certificate Verification
- IP Address Parsing Utilities
- Frontend Internationalization System
- Panel Host Mocking
- Protocol Route Audit Tests
- Core Compose Base Config
- Security Hardened Container Options
- AmneziaWG Environment Variables
- MTProxy Container Configuration
- Xray Router Panel Compose
- Client Verification Matrix
- GitHub Security Form Schema
- Release Workflow Inputs
- Mieru Manager HTTP Server
- Mock Time Clock
- Managed Route Guard Middleware
- Python-Compatible Float Math
- Version Agent Test Doubles
- Process Execution Utilities
- URL Parsing Utilities
- Panel Performance Profiling
- Coexist Ingress Compose Deployment
- Coexist MTProxy Service Config
- Coexist Ingress Panel Environment
- Direct Core Compose Deployment
- Direct MTProxy Service Config
- Direct Core Panel Environment
- Egress Swapped Compose Deployment
- Egress Swapped MTProxy Config
- Egress Swapped Panel Environment
- Existing 3X-UI Compose Deployment
- Existing 3X-UI MTProxy Config
- Existing 3X-UI Panel Environment
- Kitchen Sink Compose Deployment
- Kitchen Sink MTProxy Config
- Kitchen Sink Panel Environment
- Managed 3X-UI Compose Deployment
- Managed 3X-UI MTProxy Config
- Managed 3X-UI Panel Environment
- Managed 3X-UI Warp Deployment
- Managed 3X-UI Warp MTProxy
- Managed 3X-UI Warp Environment
- Panel Service Core Environment
- Mieru Compose Volume Secrets
- Mieru Panel Compose Integration
- Mieru Manager Container Spec
- Naive Compose Volume Secrets
- Xray Router Container Spec
- GitHub Actions Release Step
- Naive Manager IP Network
- System Clock Utilities
- Time Series Ring Buffer
- Client Grant Model Tests
- HTTP Client Utilities
- Common Python Text Helpers
- 3X-UI Lab Acceptance Scripts
- Protocol Data Transfer Tests
- Runtime Hook Tests
- Mieru Manager Environment Config
- Naive Manager Service Configuration
- Naive Manager Container Hardening
- TrustTunnel Environment Variables
- TrustTunnel Manager Security Settings
- System Compatibility & Contracts
- Feature Releases and Integrations
- CI Workflow Step Definition
- Network CIDR Matching Utilities
- Database Schema Snapshot
- Web UI Dialogs & Interfaces
- API Error Handling Utilities
- Environment Preflight Diagnostics
- Ingress Secret Rotation Scripts
- Rust Logging Utilities
- Xray Router Diff Engine
- Routing Architecture Documentation
- Python Web Golden Tests
- GitHub Workflow Permissions Setup
- Fleet Wire Replay Tests
- Cryptographic Token & ID Helpers
- Python Number Compatibility Parser
- Secure Zip Archive Extraction
- Wizard Setup and Profiles
- Guest Image Metadata Tests
- AmneziaWG Server API Handlers
- Xray Router Compose Service
- Runtime Settings Golden Tests
- Fleet Lifecycle & Installation Guides
- Protocol Integration Guides
- TrustTunnel Integration and Deployment
- Panel Release Notes & History
- Traffic Monitoring and Metrics
- Release Workflow Configuration
- CI Attestation Workflow Job
- Fleet Capacity Distribution Metrics
- MCP Server Main Entrypoint
- Naive Manager Diff Matching
- IPv4 Routing Network Parser
- Fleet Compatibility Validation
- Routing Diff Matching Engine
- Framework Probes Golden Tests
- API Key Authentication Tests
- Routing API Integration Tests
- Docker Container Control Operations
- Panel Session HTTP Client
- Traffic Metrics Live Sampler
- HTTPS Cover Container Setup
- Hysteria2 Service Container Configuration
- NaiveProxy Service Container Configuration
- TeleMT Container Setup
- VLESS TCP Container Setup
- FakePanel Mock Test Client
- AmneziaWG Diff Utilities
- Container Healthcheck Configuration
- Naive Service Environment Variables
- Clients Route Golden Tests
- System Readiness Diagnostic Tests
- Proxy Adapter Smoke Tests
- Container Healthcheck Definition
- Container Healthcheck Parameter Definition
- Service Healthcheck Intervals
- Container Healthcheck Probes
- Healthcheck Interval Settings
- Service Healthcheck Configuration
- Healthcheck Settings Definition
- System Runtimes and Profiles
- AmneziaWG Compose Dependencies
- Bind Mount Volume Configuration
- TrustTunnel Docker Build Arguments
- Volume Mount Definition
- TrustTunnel Manager Compose Dependencies
- Host Bind Volume Mappings
- Healthcheck Periodic Parameters
- Xray Router Compose Secrets
- UI Screenshots and Layouts
- Reproducible Build CI Job
- Publishing Workflow CI Job
- JSON Serialization Golden Tests
- Routing Stringprep Tables
- Client Labeling Test Suite
- Routing Client Probes
- Xray Router State Setup
- Deployment CLI Tests
- AmneziaWG Compose Configuration
- Container Health Check
- AmneziaWG Volume Configuration
- Docker Volume Bind Mounts
- AmneziaWG Environment Settings
- Service Health Checks
- Health Check Settings
- TrustTunnel Compose Configuration
- TrustTunnel Volume Configuration
- TrustTunnel Environment Settings
- Container Health Check Configuration
- Routing Control Panel UI
- Monitoring Dashboard UI Screenshots
- Proxy Control Release Features
- Release Updates and Guides
- GitHub Issue Configuration
- Argparse Verification Tests
- Node Heartbeat Error Handling
- HTTP Request Parsing
- Client Listing API Tests
- Host Installation Profiles
- Container Matrix Tests
- Mock Time Utility
- TrustTunnel Metrics Collection
- HTTPS Fetch Client
- Architecture Decision Records
- MCP Tooling and Reporting
- Protocol Manager Egress Routing
- Fleet API Management
- Traffic Accounting Database Schema
- Scalar Type Definitions
- Proxy Control MCP Skills
- Installer Wizard Profiles
- Core VPN Protocols Integration
- AmneziaWG Protocol Documentation
- Proxy Secret Environment Variables
- Docker Build Configuration
- Xray Router Architecture
- Russian Deployment Guides
- Installer Auditor Tooling
- Live Monitoring System Releases
- Monitoring Service Components
- ASCII CRLF Trimming
- Character Classification Tables
- Probe Installation Script
- MTProxy Compose Versions
- Service Environment Secrets
- Service Environment Secrets Config
- Service TLS Secrets Configuration
- Proxy Environment Credentials
- Protocol Environment Secrets
- Manager Environment Secrets
- API Token Environment Config
- Host Wizard CLI Options
- Artifact Download Client
- MTProxy Routing Release
- Docker Build Directives
- Dockerfile Build Context
- Docker Container Build Spec
- Mieru Configuration Sharing
- Dashboard UI Screenshots
- Routing Configuration UI Screenshots
- AmneziaWG Releases
- Traffic Lanes and Chains
- Routing Policy Specifications
- Manager Version Rebuilding
- Installer Application Entrypoint
- Traffic Accounting Tables
- Web Server Entrypoint
- Telemt Container Entrypoint
- Branding and Login UI
- Host Golden Fixtures
- Core Wizard Output Fixtures
- Wizard Golden Fixtures
- Telemt Entrypoint Script
- Telemt MTProto Deployment
- AmneziaWG Release Features
- Xray Router Geodata
- Router Ingress Migration
- MTProxy Client Links
- Mieru User Management
- Installation Scripts
- Terminal IO Utilities
- Observed State Resources
- Apply Record Creation
- Naive Caddy Build Check
- JS Syntax Validation
- Artifact Description Service
- Host Teardown Script
- Kitchen Sink Installation Status
- X-UI Service Script
- 3X-UI Mode Selection
- Core Apply Plan Verification
- Host Transition Smoke Tests
- Screenshot Guidelines
- Mieru Manager Service
- Database Migrations
- MTProxy Protocol
- Release 3.3.0 Notes
- Release 1.0.0 Notes
- Release 1.2.0 Notes
- Release 1.2.1 Notes
- Local HTTP Panel Client
- Code of Conduct
- Panel Transport API ADR
- Mieru MSS Clamping
- TrustTunnel Screen UI
- Dashboard Overview UI
- Login Screen UI
- Proxy Control Login UI
- WARP Egress Routing
- AmneziaWG Access Management
- AmneziaWG Manager Service
- Client Access Renaming
- Client Import Service
- Dashboard Overview Component
- Database Migrations
- Installer Verification Matrix
- Mita Version Support
- Client Monitoring
- Connection Monitoring
- Naive User Management
- One-Time Secret Reveal
- Real Client Profiles
- Secret Store Management
- Subscription Events
- TrustTunnel Access Management
- Accounting State Table
- Transcript Test Manifests
- Panel Development Dependencies
- Proxy Control Interface
- Mieru Client Probe
- MTProxy Control Bridge
- System Backup Process
- MCP Server AI Tools
- System Monitoring Service
- Workspace Landing Page
- Default Welcome Page
- AmneziaWG Status Record
- Workspace Panel Management
- Welcome Page Interface
- Core Mieru Install Status
- Edge Welcome Page
- Workspace Panel Page
- Relay Welcome Page
- Core Installation Status
- Panel Workspace View
- Relay Host Welcome Page
- Golden Core Install Status
- Panel Workspace Landing
- Portal Welcome Page
- TrustTunnel Installation Status
- Workspace Index Template
- Relay Server Welcome Page
- Existing 3X-UI Status
- Edge Node Welcome Page
- Workspace Dashboard Page
- Service Welcome Page
- Full 3X-UI Install Status
- Edge Gateway Welcome Page
- Web Workspace Page
- User Welcome Page
- Edge Endpoint Welcome Page
- Workspace Index Dashboard
- Relay Node Welcome Index
- Managed 3X-UI Status Fixture
- Ingress Coexistence Plan
- AmneziaWG Deployment Plan
- Mieru Deployment Plan
- NaiveProxy Deployment Plan
- TrustTunnel Deployment Plan
- Existing 3X-UI Plan
- Full 3X-UI Deployment Plan

## God Nodes (most connected - your core abstractions)
1. `Value` - 2732 edges
2. `Map` - 576 edges
3. `AdapterError` - 345 edges
4. `ManagerResult` - 245 edges
5. `CheckpointData` - 220 edges
6. `AppState` - 213 edges
7. `ClientsError` - 194 edges
8. `query()` - 173 edges
9. `LocItem` - 168 edges
10. `Output` - 167 edges

## Surprising Connections (you probably didn't know these)
- `Proxy Control Cover Illustration (Anime style clashing unicorn and girl with war hammer)` --conceptually_related_to--> `Proxy Control`  [INFERRED]
  assets/proxy-control-cover.png → README.md
- `parse_tokens()` --calls--> `accepts()`  [INFERRED]
  installer_core/src/nginx_topology.rs → mcp_server/src/transport.rs
- `OverviewFixture` --uses--> `MemoryNaive`  [INFERRED]
  scripts/lab/ui_protocol_dialog_check.py → panel/tests/harness/memories/naive.py
- `OverviewFixture` --uses--> `MemoryTelemt`  [INFERRED]
  scripts/lab/ui_protocol_dialog_check.py → panel/tests/harness/memories/telemt.py
- `OverviewFixture` --uses--> `MemoryTrusttunnel`  [INFERRED]
  scripts/lab/ui_protocol_dialog_check.py → panel/tests/harness/memories/trusttunnel.py

## Import Cycles
- 1-file cycle: `installer_core/src/planner.rs -> installer_core/src/planner.rs`
- 1-file cycle: `naive_manager/src/fsops.rs -> naive_manager/src/fsops.rs`
- 1-file cycle: `naive_manager/src/tests.rs -> naive_manager/src/tests.rs`
- 1-file cycle: `panel/crates/managers/src/uds.rs -> panel/crates/managers/src/uds.rs`
- 1-file cycle: `panel/crates/metrics/src/sources.rs -> panel/crates/metrics/src/sources.rs`
- 1-file cycle: `panel/crates/model/src/common.rs -> panel/crates/model/src/common.rs`
- 1-file cycle: `panel/crates/web/src/routes/subscriptions_admin.rs -> panel/crates/web/src/routes/subscriptions_admin.rs`
- 2-file cycle: `panel/crates/subscriptions/src/apps.rs -> panel/crates/web/src/routes/subscriptions_admin.rs -> panel/crates/subscriptions/src/apps.rs`
- 2-file cycle: `panel/crates/routing/src/compiler.rs -> panel/crates/routing/src/intent.rs -> panel/crates/routing/src/compiler.rs`
- 2-file cycle: `panel/crates/core/src/pytext/ip.rs -> panel/crates/core/src/pytext/mod.rs -> panel/crates/core/src/pytext/ip.rs`
- 2-file cycle: `mcp_server/src/curated.rs -> mcp_server/src/tools.rs -> mcp_server/src/curated.rs`
- 2-file cycle: `panel/crates/clients/src/lib.rs -> panel/crates/clients/src/service.rs -> panel/crates/clients/src/lib.rs`
- 2-file cycle: `panel/crates/clients/src/facade.rs -> panel/crates/clients/src/lib.rs -> panel/crates/clients/src/facade.rs`
- 2-file cycle: `installer/src/adapters/three_xui.rs -> installer/src/adapters/three_xui/runtime.rs -> installer/src/adapters/three_xui.rs`
- 2-file cycle: `panel/crates/core/src/migrations/list.rs -> panel/crates/core/src/migrations/mod.rs -> panel/crates/core/src/migrations/list.rs`
- 2-file cycle: `pc_host/src/runner/fake.rs -> pc_host/src/runner/mod.rs -> pc_host/src/runner/fake.rs`
- 2-file cycle: `pc_host/src/runner/mod.rs -> pc_host/src/runner/system.rs -> pc_host/src/runner/mod.rs`
- 2-file cycle: `installer_core/src/toml.rs -> mcp_server/src/py.rs -> installer_core/src/toml.rs`
- 3-file cycle: `panel/crates/subscriptions/src/apps.rs -> panel/crates/web/src/routes/subscriptions_admin.rs -> panel/crates/subscriptions/src/service.rs -> panel/crates/subscriptions/src/apps.rs`
- 3-file cycle: `mieru_manager/src/service.rs -> mieru_manager/src/validate.rs -> mieru_manager/src/tests.rs -> mieru_manager/src/service.rs`

## Hyperedges (group relationships)
- **Client and Subscription Lifecycle Verification** — docs_verification_matrix_clients_and_grants, docs_verification_matrix_provisioning_saga, docs_verification_matrix_subscriptions, docs_verification_matrix_client_placement_matrix, docs_verification_matrix_client_delete [EXTRACTED 0.90]
- **Host Golden Installer Plans** — tests_fixtures_host_golden_plans_core, tests_fixtures_host_golden_plans_coexist_ingress, tests_fixtures_host_golden_plans_core_amneziawg, tests_fixtures_host_golden_plans_core_mieru, tests_fixtures_host_golden_plans_core_naive, tests_fixtures_host_golden_plans_core_trusttunnel, tests_fixtures_host_golden_plans_existing_three_xui, tests_fixtures_host_golden_plans_full_three_xui [EXTRACTED 0.90]
- **Release Installer Verification Flow** — docs_installer_reference_en_md_installer_reference, scripts_install_release, install_bootstrap, docs_installer_reference_en_md_installer_wizard [EXTRACTED 0.90]
- **Client Grant Escrow and Subscription Distribution Flow** — docs_guides_panel_en_md_clients_grants, docs_guides_panel_en_md_subscriptions, docs_guides_panel_en_md_master_key [EXTRACTED 0.90]
- **Manager Egress Ownership Enforcement** — docs_routing_ru_md_naive_manager, docs_routing_ru_md_mieru_manager, docs_routing_ru_md_trusttunnel_manager, docs_upgrading_xray_router [EXTRACTED 0.90]
- **Protocol Managers Verification** — docs_verification_matrix_mita_any_version, docs_verification_matrix_amneziawg_manager, docs_routing_ru_md_trusttunnel_manager, docs_verification_matrix_amneziawg_access, docs_verification_matrix_trusttunnel_access [EXTRACTED 0.90]
- **Upgrade Automation and Release Verification Workflow** — docs_upgrading_md, scripts_install_release, scripts_update_host, system_version_agent [EXTRACTED 0.90]
- **Validation Lab Gate Automation** — docs_validation_md, scripts_dev_remote_gate, scripts_lab_docker_lab, scripts_lab_guest_runner, scripts_lab_fleet_acceptance [EXTRACTED 0.90]
- **Supported VPN and Ingress Protocols** — readme_amneziawg, docs_upgrading_trusttunnel, readme_three_xui, readme_warp [EXTRACTED 0.90]
- **Agent Governance Framework** — agents_working_protocol, agents_operational_protocol, agents_md [EXTRACTED 0.95]
- **AmneziaWG Feature Evolution** — docs_releases_v1_4_0_release, docs_releases_v1_5_0_release, docs_releases_v1_5_1_release [EXTRACTED 0.95]
- **Fleet Synchronization and Protocol Loop** — docs_guides_fleet_en_generation_document, docs_guides_fleet_en_heartbeat_delivery, docs_guides_fleet_en_node_api_v2, docs_guides_fleet_en_user_import_lifecycle [EXTRACTED 0.95]
- **Fleet v2 Panel-to-Panel Wire Contracts** — docs_compatibility_md_panel_to_panel_contract, docs_compatibility_md_fleet_v2_api, docs_compatibility_md_generation_document, docs_compatibility_md_observed_generation [EXTRACTED 0.95]
- **Fleet v2 Node Management Flow** — docs_guides_fleet_ru_md_fleet_heartbeat, docs_guides_fleet_ru_md_fleet_delivery, docs_guides_fleet_ru_md_fleet_import, docs_guides_fleet_ru_md_fleet_lifecycle [EXTRACTED 0.95]
- **Installation and Verification Flow** — scripts_install_release, install_bootstrap, readme_install_sh [EXTRACTED 0.95]
- **Installer Protocol Adapters** — docs_installer_reference_ru_adapter_xray_router, docs_installer_reference_ru_adapter_amneziawg, docs_installer_reference_ru_adapter_trusttunnel [EXTRACTED 0.95]
- **Installer Release Bootstrap Flow** — scripts_install_release, install_bootstrap, proxy_control_installer [EXTRACTED 0.95]
- **Installer Bootstrap & Verification Pipeline** — docs_guides_install_en_md_install_release_sh, docs_guides_install_en_md_proxy_control_installer, docs_guides_install_en_md_mtproto_probe, docs_guides_install_en_md_installer_lifecycle [EXTRACTED 0.95]
- **QEMU and Stand Lab Acceptance Scripts** — scripts_lab_qemu_lab, scripts_lab_managed_xui_acceptance, scripts_lab_managed_xui_clients, scripts_lab_guest_runner [EXTRACTED 0.95]
- **MCP Architecture Components** — docs_mcp_en_proxy_control_mcp, docs_mcp_en_curated_tools, docs_mcp_en_confirm_rule [EXTRACTED 0.95]
- **Metrics Collection and Serving Pipeline** — docs_upgrading_version_agent, docs_guides_monitoring_ru_nftables_metrics, docs_guides_monitoring_ru_panel_collector, docs_guides_monitoring_ru_table_metric_rollups, docs_guides_monitoring_ru_api_metrics_stream [EXTRACTED 0.95]
- **Mieru/Mita Lifecycle and Containment** — mieru_manager, mita, scripts_prepare_mieru_token, scripts_prepare_mieru_state [EXTRACTED 0.95]
- **Host to Panel Monitoring Pipeline** — docs_guides_monitoring_en_md_version_agent, docs_guides_monitoring_en_md_nftables_metrics, docs_guides_monitoring_ru_panel_collector, docs_guides_monitoring_en_md_metrics_api [EXTRACTED 0.95]
- **Monitoring Subsystem Verification** — docs_verification_matrix_monitoring_live, docs_verification_matrix_monitoring_stream, docs_verification_matrix_monitoring_history, docs_verification_matrix_monitoring_clients, docs_verification_matrix_monitoring_connections [EXTRACTED 0.95]
- **Node State and Generation Architecture** — docs_adr_001_pull_only_node_transport_md_adr_001, docs_adr_002_declarative_generations_md_adr_002, docs_adr_003_one_writer_per_resource_md_adr_003 [EXTRACTED 0.95]
- **Protocol Accounting and Usage Tracking Group** — docs_accounting_accounting_semantics, readme_telemt, readme_naiveproxy, readme_mieru [EXTRACTED 0.95]
- **Proxy Control Managed Components** — skills_proxy_control_updating_components_telemt, skills_proxy_control_updating_components_mita, docs_upgrading_xray_router, skills_proxy_control_updating_components_naive, skills_proxy_control_updating_components_amneziawg, skills_proxy_control_updating_components_trusttunnel, skills_proxy_control_updating_components_panel [EXTRACTED 0.95]
- **Proxy Protocols and Supervised Runtimes** — docs_architecture_telemt, docs_architecture_naiveproxy, docs_architecture_mieru, docs_architecture_amneziawg, docs_architecture_trusttunnel [EXTRACTED 0.95]
- **Routing Architecture and Investigations** — docs_routing_en, docs_adr_006_routing_policy_ir, docs_spikes_vnext_routing_engine, docs_spikes_xray_egress_router, docs_routing_en_egress_policy [EXTRACTED 0.95]
- **Routing Enforcement Subsystem** — docs_adr_006_routing_policy_ir_md_adr_006, docs_xray_router_ru_md_xray_router, docs_xray_router_ru_md_xray_router_manager, docs_xray_router_ru_md_mtproxy_bridge [EXTRACTED 0.95]
- **Routing Configuration Interface Views** — docs_releases_assets_v1_0_0_routing_image, docs_releases_assets_v1_0_0_routing_en_image, docs_releases_assets_v1_0_0_routing_guide_image [EXTRACTED 0.95]
- **Proxy Control Routing Architecture** — docs_upgrading_xray_router, docs_routing_ru_md_lanes, docs_routing_ru_md_chains, docs_routing_ru_md_relay, docs_routing_ru_md_custom_exits [EXTRACTED 0.95]
- **Supported Proxy Protocols Acceptance Group** — docs_operations_ru_mtproxy_telemt, docs_operations_ru_naiveproxy, docs_operations_ru_mieru, docs_operations_ru_trusttunnel [EXTRACTED 0.95]
- **TrustTunnel Integration Subsystem** — docs_guides_trusttunnel_ru_trusttunnel, docs_guides_trusttunnel_ru_trusttunnel_manager, docs_guides_trusttunnel_ru_trusttunnel_endpoint, docs_guides_trusttunnel_ru_xray_router_integration [EXTRACTED 0.95]
- **Upgrade Process Flow** — scripts_install_release, scripts_update_host, docs_upgrading_ru_migrate_agent, docs_upgrading_version_agent [EXTRACTED 0.95]
- **Version Agent State and Config Pipeline** — docs_upgrading_ru_md_version_agent, docs_upgrading_ru_md_versions_catalog, docs_upgrading_ru_md_agent_state, docs_upgrading_ru_md_compose_versions_override [EXTRACTED 0.95]
- **v2.0.0 Observability Pipeline** — docs_releases_v2_0_0_release, docs_releases_v2_0_0_live_monitoring, docs_releases_v2_0_0_mcp_metrics_tools [EXTRACTED 0.95]
- **v2.2.1 Monitoring UI Views** — docs_releases_assets_v2_2_1_monitoring_nodes_image, docs_releases_assets_v2_2_1_monitoring_now_en_image, docs_releases_assets_v2_2_1_monitoring_now_image, docs_releases_assets_v2_2_1_monitoring_now_phone_image, docs_releases_assets_v2_2_1_monitoring_traffic_image [EXTRACTED 0.95]
- **Verification Matrix Pipeline** — docs_verification_matrix_md, scripts_dev_verification_matrix, scripts_dev_route_coverage, tests_test_verification_matrix [EXTRACTED 0.95]
- **vNext Control Plane Core Architecture** — docs_vnext_architecture_vnext, docs_architecture_fleet_v2, docs_vnext_architecture_secret_boundaries, docs_vnext_architecture_subscription_compatibility [EXTRACTED 0.95]
- **AI Agent Operational Protocol Algorithms** — agents_algorithm_a, agents_algorithm_b, agents_algorithm_c, agents_algorithm_d, agents_algorithm_e, agents_algorithm_f [EXTRACTED 1.00]
- **Backup Protocol Boundaries** — docs_backup_restore_ru_md_naive_generation, docs_backup_restore_ru_md_mieru_generation, docs_backup_restore_ru_md_xray_router_generation, docs_backup_restore_ru_md_amneziawg_generation, docs_backup_restore_ru_md_trusttunnel_generation [EXTRACTED 1.00]
- **Sequential Database Migrations** — changelog_migration_21, changelog_migration_22, changelog_migration_23 [EXTRACTED 1.00]
- **Fleet Verification Suite** — docs_verification_matrix_fleet_subsystem, docs_verification_matrix_fleet_v2_link, docs_verification_matrix_fleet_v2_generations, docs_verification_matrix_fleet_v2_node_api [EXTRACTED 1.00]
- **Full Profile Runtime Services** — tests_fixtures_host_golden_wizard_en_full_quit_at_digest_stdout_txt_xray_router_runtime, tests_fixtures_host_golden_wizard_en_full_quit_at_digest_stdout_txt_amneziawg_runtime, tests_fixtures_host_golden_wizard_en_full_quit_at_digest_stdout_txt_trusttunnel_runtime, tests_fixtures_host_golden_wizard_en_full_quit_at_digest_stdout_txt_mieru_runtime, tests_fixtures_host_golden_wizard_en_full_quit_at_digest_stdout_txt_naive_runtime [EXTRACTED 1.00]
- **Installer Adapters Sequence and Boundaries** — adapter_packages, adapter_nginx, adapter_certificates, adapter_firewall, adapter_core, docs_installer_reference_ru_adapter_trusttunnel, adapter_warp, docs_installer_reference_ru_adapter_xray_router, docs_installer_reference_ru_adapter_amneziawg, adapter_naive, adapter_mieru, docs_installer_reference_en_md_adapter_three_xui, docs_installer_reference_en_md_adapter_mcp, adapter_version_agent [EXTRACTED 1.00]
- **Installer Ownership Adapters** — adapter_packages, adapter_nginx, adapter_certificates, adapter_firewall, adapter_core, docs_installer_reference_ru_adapter_amneziawg, docs_installer_reference_ru_adapter_trusttunnel, adapter_warp, docs_installer_reference_ru_adapter_xray_router, adapter_naive, adapter_mieru, adapter_three_xui, docs_installer_reference_en_md_adapter_mcp, adapter_version_agent [EXTRACTED 1.00]
- **Kitchen Sink Plan Integrated Proxy Services** — docs_adr_007_routing_enforcement_ownership_xray_router, proxy_control_service_naive, proxy_control_service_mieru, proxy_control_service_amneziawg, proxy_control_service_trusttunnel [EXTRACTED 1.00]
- **Managed Proxy and VPN Protocols** — readme_telemt, readme_naiveproxy, readme_mieru, readme_amneziawg, docs_upgrading_trusttunnel [EXTRACTED 1.00]
- **Manager Egress Ownership** — docs_routing_en_naive_manager, docs_routing_en_mieru_manager, docs_routing_en_trusttunnel_manager [EXTRACTED 1.00]
- **Naive Manager Traffic Accounting Schema** — naive_manager_src_testdata_python_schema_txt_accounting_state, naive_manager_src_testdata_python_schema_txt_traffic_archives, naive_manager_src_testdata_python_schema_txt_traffic_counters, naive_manager_src_testdata_python_schema_txt_traffic_files [EXTRACTED 1.00]
- **Proxy Control Operator MCP Skills Suite** — skills_readme_skills, skills_proxy_control_changing_routing_skill, skills_proxy_control_diagnosing_access_skill, skills_proxy_control_granting_access_skill, skills_proxy_control_morning_overview_skill [EXTRACTED 1.00]
- **Release Chain v2.0.1 to v2.2.1** — docs_releases_v201_release_v2_0_1, docs_releases_v210_release_v2_1_0, docs_releases_v220_release_v2_2_0, docs_releases_v221_release_v2_2_1 [EXTRACTED 1.00]
- **Proxy Control v1.0.2 to v1.1.3 Release Progression** — docs_releases_v1_0_2_release, docs_releases_v1_0_3_release, docs_releases_v1_1_0_release, docs_releases_v1_1_2_release, docs_releases_v1_1_3_release [EXTRACTED 1.00]
- **Version 3.x Milestones** — changelog_ru_version_3_0_1, changelog_ru_version_3_1_0, changelog_ru_version_3_2_0, changelog_ru_version_3_2_1, changelog_ru_version_3_3_0 [EXTRACTED 1.00]
- **Proxy Control Release Lineage (v3.2.1 -> v3.3.0 -> v4.0.0)** — docs_releases_v3_2_1_md, docs_releases_v3_3_0_md, docs_releases_v4_0_0_md [EXTRACTED 1.00]
- **Router Verification Suite** — docs_verification_matrix_router_subsystem, docs_verification_matrix_router_runtime, docs_verification_matrix_router_attach_detach, docs_verification_matrix_router_policies [EXTRACTED 1.00]
- **Routing Verification Suite** — docs_verification_matrix_routing_subsystem, docs_verification_matrix_routing_policy_model, docs_verification_matrix_routing_apply_rollback_local, docs_verification_matrix_routing_lanes, docs_verification_matrix_routing_chains [EXTRACTED 1.00]
- **Supported Proxy Protocols under Proxy Control** — readme_telemt, readme_en_naiveproxy, readme_en_mieru, readme_amneziawg, docs_upgrading_trusttunnel [EXTRACTED 1.00]
- **Supported Proxy Protocols** — changelog_protocol_mtproxy, readme_en_md_naiveproxy, readme_en_md_mieru, readme_en_md_amneziawg, docs_releases_v1_6_0_trusttunnel_protocol [EXTRACTED 1.00]
- **Supported Proxy Protocols** — readme_en_md_mtproxy_telemt, readme_en_md_naiveproxy, readme_en_md_mieru, readme_en_md_amneziawg, docs_releases_v1_6_0_trusttunnel_protocol [EXTRACTED 1.00]
- **Version 3.x Release Sequence** — docs_releases_v300_md_release_v3_0_0, docs_releases_v301_md_release_v3_0_1, docs_releases_v310_md_release_v3_1_0, docs_releases_v320_md_release_v3_2_0 [EXTRACTED 1.00]
- **Host Wizard Interactive Prompts** — tests_fixtures_host_golden_wizard_en_eof_stdout_txt_host_mode, tests_fixtures_host_golden_wizard_en_eof_stdout_txt_proxy_control_profile, tests_fixtures_host_golden_wizard_en_eof_stdout_txt_threex_ui_mode [EXTRACTED 1.00]
- **Host Wizard Russian Localization Golden Fixtures** — tests_fixtures_host_golden_wizard_ru_invalid_config_stdout_txt, tests_fixtures_host_golden_wizard_ru_invalid_inputs_stdout_txt, tests_fixtures_host_golden_wizard_ru_managed_three_xui_save_stdout_txt [EXTRACTED 1.00]
- **Xray Egress Router Architecture** — docs_upgrading_xray_router, docs_xray_router_en_xray_router_manager, docs_xray_router_en_xray_router_ingress_bridge, docs_xray_router_en_xray_router_lanes [EXTRACTED 1.00]
- **AmneziaWG Protocol Support and Host Integration** — docs_releases_v130_release_v1_3_0, docs_releases_v132_release_v1_3_2, docs_releases_v133_release_v1_3_3, deploy_awg_forward_service, scripts_enable_amneziawg [INFERRED 0.85]
- **Client Access Provisioning & Subscription Flow** — panel_static_index_client_modal, panel_static_index_subscription_modal, panel_static_index_mieru_modal [INFERRED 0.85]
- **Protocol Node Managers and Routers** — changelog_awg_manager, changelog_mieru_manager, changelog_xray_router [INFERRED 0.85]
- **Operational Runbook Ecosystem** — docs_operations_en_md, guides_fleet_en_md, routing_en_md, upgrading_md, guides_monitoring_en_md [INFERRED 0.85]
- **Control Panel Security & Isolation Architecture** — docs_guides_panel_en_md_control_panel, docs_guides_panel_en_md_api_keys, docs_guides_panel_en_md_master_key, docs_guides_panel_en_md_naive_manager [INFERRED 0.85]
- **Routing & Outbound Egress Configuration** — panel_static_index_rule_modal, panel_static_index_exit_modal, panel_static_index_geodata_modal [INFERRED 0.85]
- **Routing Enforcement and Multi-hop Fleet Architecture** — docs_adr_007_routing_enforcement_ownership_adr007, docs_adr_007_routing_enforcement_ownership_xray_router, docs_adr_008_panel_to_panel_transport_adr008, docs_adr_009_lanes_and_chains_adr009 [INFERRED 0.85]
- **TrustTunnel Protocol Integration Flow** — docs_releases_v1_6_0_trusttunnel_protocol, docs_guides_trusttunnel_en_md_trusttunnel_manager, docs_guides_trusttunnel_en_md_singbox_feed, docs_guides_trusttunnel_en_md_routing_integration [INFERRED 0.85]
- **Wizard Runtime Services and Extensible Protocols** — wizard_amneziawg, wizard_trusttunnel, wizard_xray_router, wizard_warp_routing [INFERRED 0.85]
- **Fleet Protocol Architecture** — fleet_v2_api, fleet_generation_document, fleet_node_sync_key, fleet_managed_resources [INFERRED 0.90]
- **Protocol Managers Cluster** — changelog_ru_mieru_manager, changelog_ru_naive_manager, changelog_ru_trusttunnel_manager, changelog_ru_awg_warp [INFERRED 0.90]
- **Routing Subsystem Evolution and Architecture** — docs_spikes_vnext_routing_engine_md, docs_spikes_xray_egress_router_md, docs_spikes_chains_per_client_md, docs_releases_assets_v221_routing_en_png [INFERRED 0.90]
- **v1.0.2 UI Screenshots** — docs_releases_assets_v1_0_2_clients_screenshot, docs_releases_assets_v1_0_2_grant_window_screenshot, docs_releases_assets_v1_0_2_grant_window_phone_screenshot [INFERRED 0.90]
- **v2.2.1 UI Screenshots** — docs_releases_assets_v2_2_1_clients_screenshot, docs_releases_assets_v2_2_1_clients_phone_screenshot, docs_releases_assets_v2_2_1_dashboard_en_screenshot, docs_releases_assets_v2_2_1_dashboard_phone_screenshot [INFERRED 0.90]
- **Wizard Configuration Prompts Flow** — tests_fixtures_host_golden_wizard_ru_eof_stdout_txt_server_modes, tests_fixtures_host_golden_wizard_ru_eof_stdout_txt_proxy_profiles, tests_fixtures_host_golden_wizard_ru_eof_stdout_txt_threex_ui_modes [INFERRED 0.90]

## Communities (775 total, 169 thin omitted)

### Community 0 - "Data Types and Validation"
Cohesion: 0.03
Nodes (103): Value, Array, Boolean, Date, Float, String, Table, bounded_list() (+95 more)

### Community 1 - "Installation Filesystem Engine"
Cohesion: 0.03
Nodes (92): InstallPlan, AGENT_MANAGED_PATHS, drifted(), exists_or_symlink(), persist(), read_matching_plan(), TransactionEngine, AGENT_ACTION (+84 more)

### Community 2 - "Audit Evidence Checkpoints"
Cohesion: 0.03
Nodes (63): AuditFacts, Evidence, Stale, Adapter, compose_plan(), PlanBridge, AmneziaWgAdapter, assert_free() (+55 more)

### Community 3 - "CLI and Code Generation"
Cohesion: 0.02
Nodes (104): table(), create(), test_create_honours_expires_days(), test_create_prints_one_json_line_with_the_plaintext(), test_create_refuses_a_name_that_is_still_enabled(), test_revoke_deletes_every_key_of_that_name(), _node(), test_import_still_offers_clients_outside_the_current_page() (+96 more)

### Community 4 - "UI and Audit Tests"
Cohesion: 0.02
Nodes (75): _report(), test_every_button_class_is_centred_in_stretching_containers(), test_the_phone_bar_items_are_equal_and_centred_in_both_languages(), test_the_screen_buttons_and_the_phone_bar_are_centred(), clients_browser(), test_deleting_a_grant_whose_user_is_already_gone_succeeds(), chooser_browser(), _assert_native_routing_geometry() (+67 more)

### Community 5 - "Client Models and Validation"
Cohesion: 0.02
Nodes (104): ClientCreate, .TITLE, ClientImport, .TITLE, ClientRename, .TITLE, ClientStateBody, .TITLE (+96 more)

### Community 6 - "Central Routing Generation"
Cohesion: 0.03
Nodes (64): CentralResult, compile(), compile_applies_states_capabilities_options_and_relay(), DesiredGeneration, DesiredRouting, DesiredStore, egress_section(), egress_sections_follow_every_node_capability() (+56 more)

### Community 7 - "Client Error Handling"
Cohesion: 0.04
Nodes (66): ClientsError, Conflict, Db, Injected, Internal, Invalid, ManagedByCentral, NotFound (+58 more)

### Community 8 - "AmneziaWG Manager API"
Cohesion: 0.04
Nodes (13): AmneziawgApi, AmneziawgClient, ManagerResult, mieru_user(), MieruApi, MieruClient, NaiveApi, NaiveClient (+5 more)

### Community 9 - "Client Adapter Mock Testing"
Cohesion: 0.04
Nodes (21): FakeAdapter, FakeUser, Fault, Dishonest, Fail, LoseResponse, AdapterError, AppliedGrant (+13 more)

### Community 10 - "Xray Router Intent Configuration"
Cohesion: 0.03
Nodes (133): published_digest(), ACTIONS, CAPABILITIES, CHAIN_EXITS, chain_ids(), check_reachable(), cidr(), DEFAULT_ACTIONS (+125 more)

### Community 11 - "Host Binary Release Builder"
Cohesion: 0.04
Nodes (86): archive_names(), assert_clean(), build_host_binaries(), build_release(), builder_image(), BuiltRelease, _canonical(), commit_epoch() (+78 more)

### Community 12 - "Node HTTP Hooks Client"
Cohesion: 0.03
Nodes (41): PublishForClient, NodeHttpFactory, factory_error(), Active, Counters, EDGE, Factory, KEY (+33 more)

### Community 13 - "Service Status Dashboard"
Cohesion: 0.03
Nodes (109): amneziawg(), dashboard_reports_mieru_disabled_ready_and_degraded(), dashboard_summarizes_both_protocols_without_naive_traffic_invention(), disabled(), mieru(), mieru_degraded(), mtproxy(), naive() (+101 more)

### Community 14 - "Localization and Translation Catalog"
Cohesion: 0.05
Nodes (71): catalog(), catalogue_is_sorted_and_complete(), EN, format(), Locale, .ALL, En, locale_from_environment() (+63 more)

### Community 15 - "Mieru Proxy Acceptance Tests"
Cohesion: 0.05
Nodes (98): CLIENT_IMAGE, acceptance(), cleanup(), client_config_for(), decode(), login(), MieruAdapter, NaiveAdapter (+90 more)

### Community 16 - "Audit Context and Event Bus"
Cohesion: 0.02
Nodes (70): Audit, AuditContext, ApiKey, .COLUMNS, ApiKeyError, Db, .EXPIRED, Invalid (+62 more)

### Community 17 - "Installer Audit Verification"
Cohesion: 0.04
Nodes (105): alive(), applicable_caa(), ascii_digits(), assignment_tail(), assignment_value(), Audit, audit(), audit_host() (+97 more)

### Community 18 - "Egress Memory Manager"
Cohesion: 0.03
Nodes (36): MemoryNaive, NaiveError, access_from_user(), MemoryTelemt, TelemtError, TelemtIndeterminate, canonical(), document_digest() (+28 more)

### Community 19 - "Client Subscription Management"
Cohesion: 0.03
Nodes (42): SubscriptionIssuer, Conn, DbError, Io, Sqlite, WalLocked, DEFAULT_TIMEOUT, finish() (+34 more)

### Community 20 - "Naive Manager Integration Tests"
Cohesion: 0.04
Nodes (105): accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(), adapted_semantic_drift_makes_health_unready(), Adapter, Egress, Lanes, Users, additional_basic_auth_outside_managed_block_makes_health_unready(), an_operation_record_is_written_with_the_state_it_describes() (+97 more)

### Community 21 - "Address Policy Resolution"
Cohesion: 0.03
Nodes (43): address_policy_rejects_the_entire_answer(), AddressPolicyError, AddressResolver, checked_addresses(), find_header_end(), fingerprint(), fingerprint_addresses(), fingerprint_addresses_with_resolver() (+35 more)

### Community 22 - "Fleet Delivery Interoperability Tests"
Cohesion: 0.03
Nodes (37): LegacyPanel, main(), start_legacy(), verify_source(), certificate(), delivery(), main(), request() (+29 more)

### Community 23 - "Document Validation and Ports"
Cohesion: 0.05
Nodes (28): py_truthy(), direct_document(), is_uuid(), NOAUTH_SERVICES, TUN_SERVICES, uses_provider(), config_bytes(), generation_digest() (+20 more)

### Community 24 - "Database Clock Testing Mock"
Cohesion: 0.04
Nodes (35): SharedClock, Database, Agent, AgentState, FIXTURES, NodeLifecycleService, NOW, table() (+27 more)

### Community 25 - "Planner Adapter Configuration"
Cohesion: 0.05
Nodes (63): Action, ACTION_FIELDS, ADAPTER_NAMES, adapter_requires(), adapters_for(), assert_secret_free(), build_plan(), Fact (+55 more)

### Community 26 - "Audit CLI Error Handling"
Cohesion: 0.04
Nodes (62): blocked_message(), check_accepted_digest(), check_archive_digest(), CliError, is_full_digest(), plan_summary_lines(), release_identity(), render_report_written() (+54 more)

### Community 27 - "Access Reconciliation Enforcement"
Cohesion: 0.04
Nodes (25): AccessEnforcer, INTERVAL, PendingReconciler, Adapter, escaped_manager_failures_answer_like_the_app_handlers(), panel_managers_error(), runtime_answer(), DomainFacade (+17 more)

### Community 28 - "Runtime Fleet Routing"
Cohesion: 0.03
Nodes (19): Any, FleetRouter, ManagerRuntime, NodeRuntime, ok(), RouterAdapter<C>, VersionAgent, VersionClient (+11 more)

### Community 29 - "Caddyfile Accounting Configuration"
Cohesion: 0.04
Nodes (92): ACCOUNTING_BEGIN, ACCOUNTING_END, accounting_lines(), ACCOUNTING_WRITER, accounting_writer_options_derive_from_the_rotation_constants(), assert_accounting_config(), BEGIN, credential_lines() (+84 more)

### Community 30 - "Routing Egress Verification"
Cohesion: 0.06
Nodes (34): ParsedEgress, assert_regular(), exists(), read_text(), backup_stamp(), is_bare_name(), now_parts(), field() (+26 more)

### Community 31 - "Protocol Chain Actions"
Cohesion: 0.07
Nodes (78): a_service_without_lanes_or_node_exits_still_compiles_to_schema_1(), compiling_a_lane_policy_folds_the_service_and_the_other_lanes(), explain_walks_a_lanes_rules_for_a_destination(), lanes_and_node_exits_need_the_router_and_the_attachment(), lanes_fold_into_one_schema_2_intent_with_the_service_lane_and_chains(), node_exit_refusals_are_named(), this_nodes_warp_is_only_needed_by_lanes_that_use_it(), compile_capability_missing_from_target() (+70 more)

### Community 32 - "Installer Domain Configuration Validation"
Cohesion: 0.05
Nodes (80): blocked_line(), awg_host(), boolean(), ConfigError, domain(), domain_shape_ok(), email_ok(), enumeration() (+72 more)

### Community 33 - "Egress View Artifacts"
Cohesion: 0.04
Nodes (60): intent(), intent_on(), GrantIntent, .TITLE, TrusttunnelOptions, .TITLE, AccessArtifact, ObservedGrant (+52 more)

### Community 34 - "Service Policy Router Tests"
Cohesion: 0.07
Nodes (56): ERROR_STATUS, AdapterState, apply(), apply_io_outside_transaction(), apply_local_calls_manager_and_records_applied(), apply_manager_conflict_marks_failed(), apply_native_policy_on_attached_service_is_422(), apply_router_failure_marks_failed_and_maps_codes() (+48 more)

### Community 35 - "Firewall Rule Enforcement"
Cohesion: 0.07
Nodes (68): action_enable(), action_ipv6_enabled(), action_rules(), action_ssh_port(), action_value(), allow_argv(), assert_foreign_preserved(), assert_owned_rules_recognized() (+60 more)

### Community 36 - "Panel Test Fixtures"
Cohesion: 0.04
Nodes (32): anyio_backend(), _close_fake_managers(), login_user(), mieru(), naive(), pair(), pair_factory(), make() (+24 more)

### Community 37 - "TrustTunnel Configuration Parsing"
Cohesion: 0.06
Nodes (64): Config, config_defaults_and_required_values(), ConfigError, from_env(), int_value(), is_hostname(), loopback_address(), make_env() (+56 more)

### Community 38 - "CLI Argument Parser"
Cohesion: 0.04
Nodes (62): Action, action_name(), actions_usage(), Arg, Bool, None, Str, argument_error() (+54 more)

### Community 39 - "Password Hashing and Querying"
Cohesion: 0.03
Nodes (24): Formatter, AuditQuery, list(), ListError, Db, Detail, CHEAP, dummy_hash_has_the_policy_parameters() (+16 more)

### Community 40 - "Fake Caddy HTTP Server"
Cohesion: 0.05
Nodes (61): Admin, answer(), cover(), forward_proxy_handlers(), watch_parent(), write_json(), leaf_fingerprint(), assert_port_free() (+53 more)

### Community 41 - "Frontend Audit UI Components"
Cohesion: 0.05
Nodes (87): ADR-0008, accessRow(), ago(), egressCard(), handleAmneziawgClick(), renderAmneziawg(), STATUS, versionCard() (+79 more)

### Community 42 - "Mieru Manager Service Journal"
Cohesion: 0.07
Nodes (26): cli_slot_factory(), contains(), expected_readback(), get(), get_str(), hash_value(), is_operation_id(), JOURNAL_FIELDS (+18 more)

### Community 43 - "AmneziaWG Manager Lifecycle Tests"
Cohesion: 0.07
Nodes (75): b64(), a_control_socket_that_is_not_ready_at_first_is_configured_while_waiting(), a_fresh_node_is_direct_with_both_capabilities_and_no_tunnel(), a_malformed_egress_section_is_refused(), a_node_without_the_router_device_refuses_the_router_provider(), a_refused_registration_changes_nothing(), Api, api() (+67 more)

### Community 44 - "TLS Certificate Inspection"
Cohesion: 0.06
Nodes (41): a_fullchain_file_is_read_by_its_leaf_and_counts_as_trusted(), BEGIN, CertInfo, days_from_civil(), Element, element(), END, hex() (+33 more)

### Community 45 - "AmneziaWG Client UI Modals"
Cohesion: 0.06
Nodes (86): bindAmneziawg(), openAwgModal(), paintVersions(), syncAwgCreate(), api(), handleAuditClick(), bindClients(), collectDecisions() (+78 more)

### Community 46 - "Xray Test Mocks and Probes"
Cohesion: 0.04
Nodes (34): key(), add(), json_post(), req(), b64(), _clamp(), generate_private(), hexkey() (+26 more)

### Community 47 - "MCP Adapter Composition"
Cohesion: 0.04
Nodes (29): compose_file_list(), ENV, INITIALIZE, KEY, MARKER, McpAdapter, plaintext_of(), PROJECT (+21 more)

### Community 48 - "UI Metrics and Monitoring"
Cohesion: 0.07
Nodes (89): alignSeries(), areaChart(), barChart(), formatBytes(), formatPercent(), lineChart(), sparkline(), stackedAreaChart() (+81 more)

### Community 49 - "Access Enforcement Tests"
Cohesion: 0.06
Nodes (63): test_protocol_enable_cannot_bypass_a_suspended_known_grant(), test_suspension_reaches_remote_runtime_and_resume_preserves_disabled_grant(), _render(), _seed(), test_a_locally_imported_mtproxy_user_renders_with_telemts_link_host(), test_a_remotely_imported_mtproxy_user_renders_with_the_nodes_telemt_link_host(), test_a_username_the_runtime_already_uses_is_refused_before_anything_is_written(), test_adopt_batch_reports_what_it_could_not_take() (+55 more)

### Community 50 - "Grant and Credential State"
Cohesion: 0.05
Nodes (32): changed_lines(), Matcher, Matcher<'a>, SettingsHosts, confirm(), ImportDecision, ImportResult, integer() (+24 more)

### Community 51 - "Routing Regression Tests"
Cohesion: 0.06
Nodes (42): a_lane_the_manager_refuses_fails_its_resource_and_leaves_the_router_clean(), a_mieru_lane_teaches_the_slot_ports_link_template_and_the_service_one_on_return(), a_node_without_warp_carries_the_direct_account_and_reports_only_what_it_carries(), a_resource_with_its_own_lane_gets_a_router_account_and_a_manager_lane_before_the_egress(), apply(), block(), direct(), egress() (+34 more)

### Community 52 - "Acceptance Test Suite"
Cohesion: 0.05
Nodes (6): Acceptance, Api, Browser, CDP, _recv_exact(), redact()

### Community 53 - "Protocol Configuration Options"
Cohesion: 0.03
Nodes (40): AmneziawgOptions, .TITLE, finish_check(), MtproxyOptions, .TITLE, NaiveOptions, .TITLE, ProtocolOptions (+32 more)

### Community 54 - "Central Routing Policy"
Cohesion: 0.10
Nodes (14): router_direct_intent(), RoutingPolicy, .TITLE, NodeRow, runtime_failure(), adapter_code(), adapter_refusal(), CentralManagement (+6 more)

### Community 55 - "Client Protocol Adapters"
Cohesion: 0.05
Nodes (58): awg_manager_contract(), bin(), fake(), geodata(), mieru_manager_contract(), naive_manager_contract(), Running, sha256_hex() (+50 more)

### Community 56 - "State Persistence and Backups"
Cohesion: 0.05
Nodes (56): MAX_OPERATIONS, SCHEMA, BACKUPS, BINARY, CODE, copy_tree(), healthy(), migrate() (+48 more)

### Community 57 - "Route Document Compilation"
Cohesion: 0.06
Nodes (55): AppliedDocument, RouterTarget, document_digest(), Compiled, exit_hops(), is_custom_exit(), is_node_exit(), Reason (+47 more)

### Community 58 - "Xray Router Mock Tests"
Cohesion: 0.06
Nodes (29): client(), MemoryXrayRouter, XrayRouterError, attach_document(), csrf(), document_digest(), linked(), refuse() (+21 more)

### Community 59 - "Mieru Manager Tests"
Cohesion: 0.08
Nodes (75): a_caller_password_is_validated_and_operations_are_pruned(), a_failed_probe_rolls_the_section_back(), a_rollback_that_does_not_restore_the_snapshot_is_not_reported_as_rolled_back(), addresses_networks_and_domains_match_python(), apply_conflicts_and_refusals_leave_mita_untouched(), apply_is_idempotent_by_operation_id(), apply_replaces_only_the_egress_section_with_a_restart(), apply_router_unreachable_refuses() (+67 more)

### Community 60 - "Grant Context and Intents"
Cohesion: 0.06
Nodes (59): is_node_id(), ctx(), a_grant_round_trips_through_the_database_with_its_typed_options(), a_state_change_notifies_subscribers_inside_the_transaction(), archive_refuses_while_grants_are_not_deleted(), client_ids_are_uuids_and_grants_belong_to_one_client_and_node(), delete_client_refuses_an_operation_needing_manual_intervention(), delete_client_refuses_an_unfinished_provisioning_operation() (+51 more)

### Community 61 - "Metrics Collector Configuration"
Cohesion: 0.05
Nodes (27): AGENT_TIMEOUT, CADENCE, cadence(), CollectorConfig, dict_items(), Entry, FLUSH_SECONDS, HANDSHAKE_FRESH_SECONDS (+19 more)

### Community 62 - "Node Inventory Reconciliation"
Cohesion: 0.08
Nodes (30): Latest, Applied, bounded(), COLLISION, decode(), get(), LANE_PROTOCOLS, learned_from() (+22 more)

### Community 63 - "TOML Parsing Utilities"
Cohesion: 0.09
Nodes (27): tuple_repr(), append_nest_to_list(), arrays_of_tables(), DatetimeMatch, days_in_month(), DecodeError, error(), EXPLICIT_NEST (+19 more)

### Community 64 - "Client Dialog UI Tests"
Cohesion: 0.05
Nodes (51): main(), rust_name(), clients_named(), grant_mtproxy(), open_clients(), open_dialog(), test_account_name_follows_the_display_name_typed_after_the_ticks(), test_an_archived_client_is_deleted_from_its_menu_after_a_confirm() (+43 more)

### Community 65 - "Routing Policy UI Editor"
Cohesion: 0.07
Nodes (77): attachment(), BACKEND_NAMES, cardActions(), codeOptions(), currentLane(), currentTarget(), customExitsPanel(), draftFromPolicy() (+69 more)

### Community 66 - "AmneziaWG Python Driver"
Cohesion: 0.05
Nodes (24): AmneziawgError, MemoryAmneziawg, FakeClock, MemoryAgentMetrics, build(), Rig, rig(), test_disabled_monitoring_answers_404() (+16 more)

### Community 67 - "Atomic State Store"
Cohesion: 0.06
Nodes (20): operations_keep_order_and_the_oldest_are_pruned(), state_is_atomic_private_and_schema_checked(), StateError, StateStore, tempdir(), Map, attach_document(), telemt_direct_document() (+12 more)

### Community 68 - "Fleet Node Management"
Cohesion: 0.05
Nodes (17): Accepted, APPLY_DEADLINE, Audited, conflict(), FleetNode, GEODATA_REFUSALS, HistoryQuery, Inner (+9 more)

### Community 69 - "Mieru Adapter Management"
Cohesion: 0.05
Nodes (36): BINARY, BOOTSTRAP, checked_extracted(), CLIENT_DIGEST, CLIENT_EXECUTABLE, CLIENT_URL, CONFIG, copy_probe_sources() (+28 more)

### Community 70 - "Metrics Time Series Store"
Cohesion: 0.06
Nodes (38): trunc(), add_points(), blocking(), bucket(), CPU_AVG, DISK, EPS, first_max() (+30 more)

### Community 71 - "Fleet Central Cryptography Errors"
Cohesion: 0.05
Nodes (44): CentralError, Clients, Db, Internal, Invalid, Json, LinkConflict, Node (+36 more)

### Community 72 - "AmneziaWG Service Manager"
Cohesion: 0.08
Nodes (21): interface_name(), hex(), hexkey(), AwgManager, backoff(), Clock, DEVICE_READY_SECONDS, FULL_RECONCILE_SECONDS (+13 more)

### Community 73 - "Exit Routing Configuration"
Cohesion: 0.05
Nodes (42): invalid_cursors_are_refused_like_python(), unquote(), b64(), b64decode_lenient(), EXIT_COLUMNS, EXIT_NETWORKS, EXIT_PROTOCOLS, EXIT_PURPOSE (+34 more)

### Community 74 - "Logging Utilities"
Cohesion: 0.04
Nodes (34): Logger, atomic_json(), atomic_write(), days_from_civil(), days_in_month(), fromisoformat_timestamp(), hash(), hex() (+26 more)

### Community 75 - "Panel Lifecycle Tests"
Cohesion: 0.11
Nodes (62): join(), a_background_rebuild_answers_first_and_records_its_verdict(), a_changed_agent_binary_restarts_the_agent(), a_host_not_moved_to_the_new_project_is_updated_in_its_old_one(), a_pc_common_change_rebuilds_every_rust_manager(), a_second_panel_update_is_refused_while_one_is_running(), a_version_file_ahead_of_the_running_panel_does_not_hide_the_update(), auto_rebuild_can_be_switched_off() (+54 more)

### Community 76 - "Safe Archive Extraction"
Cohesion: 0.07
Nodes (54): is_member_name(), resolve_symlink_target(), absolute_components(), Anchor, anonymous_file(), ArchiveEntry, ArchiveManifest, best_effort_remove_tree_at() (+46 more)

### Community 77 - "Version Agent Server"
Cohesion: 0.07
Nodes (30): AgentError, Catalog, Conflict, Internal, Invalid, Update, metrics_response(), Api (+22 more)

### Community 78 - "Node Metrics Source Tests"
Cohesion: 0.06
Nodes (41): ActiveCall, AnswerKind, History, Live, Summary, cancelling_one_caller_does_not_cancel_the_shared_request(), completed_shared_future_is_retired_before_immediate_same_key_reentry(), concurrent_identical_history_calls_share_one_request() (+33 more)

### Community 79 - "Node System Audit Tests"
Cohesion: 0.09
Nodes (54): ResolveResult, a_non_x86_host_is_refused_by_name(), Absolute, argv(), audit_facts_cover_all_categories_and_are_deterministic(), audit_names_a_foreign_holder_of_every_reserved_identity(), audit_uses_authoritative_ufw_ipv6_mode_not_observed_rules(), audit_uses_only_read_only_commands_and_coexist_never_inspects_firewall_mutably() (+46 more)

### Community 80 - "Router Configuration State Management"
Cohesion: 0.09
Nodes (63): a_malformed_credential_is_a_manual_intervention_not_a_new_one(), a_manager_without_the_socket_does_not_know_mtproxy(), a_node_updated_from_a_router_without_mtproxy_rerenders_it_pass_through(), a_pin_nobody_ever_chose_moves_to_loyalsoldier_but_a_chosen_one_stays(), a_policy_for_trusttunnel_routes_only_its_own_inbound(), a_stale_socket_is_removed_before_xray_starts(), amneziawg(), apply_conflict_on_stale_revision() (+55 more)

### Community 81 - "Routing Lanes and Relays"
Cohesion: 0.07
Nodes (29): RelayConfirmation, blocking(), AdapterFailure, api_error(), audit(), ChainResolver, DEFAULT_RELAY_PORT, EXITS (+21 more)

### Community 82 - "Healthcheck Verification CLI"
Cohesion: 0.05
Nodes (50): int(), check(), healthcheck_relay_flags_post_and_get(), healthcheck_status_flag_prints_the_manager_status(), main(), request(), run(), serve() (+42 more)

### Community 83 - "Client Bundle Protocol Adapters"
Cohesion: 0.07
Nodes (62): BUNDLE_PROTOCOLS, bundleArtifact(), filename(), jsonConfig(), karingVariant(), mieruNative(), naiveNative(), naiveNekobox() (+54 more)

### Community 84 - "Container Integration Test Runner"
Cohesion: 0.05
Nodes (47): add_hosts(), CASE_STATUS, client_probe(), container_audit(), container_cmd(), container_nginx_multi_map(), container_setup(), container_uninstall_foreign_identity() (+39 more)

### Community 85 - "Database Schema Migrations"
Cohesion: 0.07
Nodes (45): MIGRATIONS, apply(), apply_migrations(), Migration, migration_status(), MigrationError, ChecksumMismatch, Database (+37 more)

### Community 86 - "AmneziaWG Configuration Models"
Cohesion: 0.04
Nodes (48): AmneziaWgConfig, AWG_DEFAULT_DNS, AWG_DEFAULT_MTU, AWG_DEFAULT_SUBNETS, awg_interface(), AWG_VERSIONS, DEFAULT_LANE_SLOTS, DEFAULT_RELAY_PORT (+40 more)

### Community 87 - "Config Migration and Rollback"
Cohesion: 0.08
Nodes (59): agent_managed_paths(), assert_owned(), write_rebased(), already_approved_proxy_semantics_keep_the_original_plan_digest(), between(), cli_inspection_prints_one_python_json_line(), client_ip_backend(), edited_owned_config_is_refused_and_foreign_missing_is_skipped() (+51 more)

### Community 88 - "AmneziaWG Egress Adapter"
Cohesion: 0.07
Nodes (17): applied_egress_from_view(), AppliedEgress, AmneziawgAdapter<C>, learned_options(), public_key_of(), py_list(), crash(), learned_options() (+9 more)

### Community 89 - "Access Artifact Manifest Generation"
Cohesion: 0.09
Nodes (45): Manifest, ManifestGrant, DeepLink, display_text(), grant_names(), Artifacts, check(), credential_reason() (+37 more)

### Community 90 - "Tun Device Process Runner"
Cohesion: 0.05
Nodes (25): a_missing_binary_does_not_start(), a_real_process_starts_and_stops(), free_port(), Handle, IFF_NO_PI, IFF_TUN, key_line(), open_tun() (+17 more)

### Community 91 - "Subprocess Runner Execution"
Cohesion: 0.06
Nodes (38): os_error_class(), text_mode(), capture_text(), capture_unavailable(), CLEANUP_UNCONFIRMED, CORE_TIMEOUT, interrupt_flag(), INTERRUPTED (+30 more)

### Community 92 - "Routing Spike Proxy Handlers"
Cohesion: 0.06
Nodes (33): adapt(), admin(), curl_socks(), forward_proxy_handler(), walk(), load(), main(), apply_mita() (+25 more)

### Community 93 - "Upstream Release Asset Verification"
Cohesion: 0.08
Nodes (58): check_all(), check_component(), a_digest(), a_trusttunnel_asset_outside_its_repository_is_refused(), a_trusttunnel_release_without_a_digest_is_visible_but_not_installable(), amneziawg_and_trusttunnel_keep_the_installed_release(), amneziawg_offers_tags_with_their_commits_newest_first_and_keeps_the_installed_one(), an_older_image_the_registry_does_not_answer_for_is_skipped() (+50 more)

### Community 94 - "Installer CLI Commands"
Cohesion: 0.05
Nodes (50): Namespace, Args, CheckpointView, Command, command(), Install, Plan, ReconcilePanelUpdate (+42 more)

### Community 95 - "Manager Egress Error Codes"
Cohesion: 0.04
Nodes (26): constructors_filter_codes_like_python(), EGRESS_REASON_CODES, handlers_answer_like_the_python_app(), is_naive_reason(), Manager, Amneziawg, Mieru, Naive (+18 more)

### Community 96 - "Tunnel Lifecycle Integration Tests"
Cohesion: 0.03
Nodes (65): a_bridge_down_refuses_attach(), a_client_holds_every_version_and_each_gets_its_own_config(), a_credential_plan_must_match_the_protocol_mieru(), a_credential_plan_must_match_the_protocol_naive(), a_custom_unmanaged_egress_has_no_applied_document_naive(), a_failed_warp_apply_leaves_the_tunnel_direct(), a_lost_reply_is_replayed_without_a_second_client(), a_native_policy_other_than_direct_must_attach_first() (+57 more)

### Community 97 - "Node Tunnel Reconciliation Tests"
Cohesion: 0.03
Nodes (66): a_bridge_that_does_not_answer_leaves_telemt_untouched(), a_certificate_the_system_does_not_trust_is_learned_but_a_trusted_one_is_not(), a_custom_unmanaged_egress_has_no_applied_document_mieru(), a_fresh_telemt_is_direct_and_offers_the_router(), a_linked_node_applies_the_access_and_the_central_learns_its_details(), a_lost_patch_reply_is_decided_by_reading_back(), a_lost_reply_is_replayed_without_a_second_peer(), a_manager_credential_is_refused() (+58 more)

### Community 98 - "Agent Binary Update Rollback"
Cohesion: 0.10
Nodes (59): AgentConfig, consumer_overlays(), archive_member_hash_is_checked_against_the_archive_not_the_file(), BINARY, binary_rollback_restart_is_not_success_without_health(), binary_update_records_the_pin_the_unit_check_reads(), binary_update_restores_the_previous_pin_when_the_service_fails(), binary_update_rolls_back_when_service_restart_fails() (+51 more)

### Community 99 - "Client Request API Models"
Cohesion: 0.09
Nodes (37): issues(), adapters(), adopt(), adopt_batch(), adopt_one(), adopt_refusal(), ADOPT_RULES, audit_context() (+29 more)

### Community 100 - "MCP Server Client Placement"
Cohesion: 0.10
Nodes (44): Full, a_confirmed_call_reaches_the_panel_and_its_error_comes_back_as_tool_text(), a_host_outside_the_allowlist_is_refused(), amneziawg_versions_are_separate_accesses_in_a_placement(), background(), Call, call(), client_subscription_reveals_the_url_again() (+36 more)

### Community 101 - "Python-Compatible URL Parser"
Cohesion: 0.05
Nodes (43): PyValueError, check_bracketed_host(), check_bracketed_netloc(), check_netloc(), SCHEME_CHARS, SplitResult, urlsplit(), AMNEZIAWG_WHOLE_ONLY (+35 more)

### Community 102 - "Version Agent Release Checker"
Cohesion: 0.07
Nodes (25): AgentLock, ALL_COMPONENTS, Applied, BASE_COMPONENTS, Checker, Clock, COMPOSE_PROJECT, days_from_civil() (+17 more)

### Community 103 - "Xray Router Manager Tests"
Cohesion: 0.06
Nodes (55): with(), a_chain_for_mtproxy_renders_like_any_service(), a_failed_registration_refuses_the_apply_and_changes_nothing(), a_router_that_does_not_come_back_after_the_swap_is_recorded(), Api, artifact(), automatic_updates_run_at_the_interval_from_the_watchdog(), block_document_still_applies_after_an_update() (+47 more)

### Community 104 - "Upstream Version Parsing"
Cohesion: 0.09
Nodes (56): is_dotted(), amneziawg(), AMNEZIAWG_REPOSITORY, asset_url(), BinarySource, candidate_version(), compare_versions(), COMPONENTS (+48 more)

### Community 105 - "Frontend API Error Formatter"
Cohesion: 0.06
Nodes (60): API_REASONS, cookie(), DETAIL_TEXT, DETAIL_WORTH_SHOWING, detailText(), problemText(), registerReasons(), formatDay() (+52 more)

### Community 106 - "Go Runtime Packages"
Cohesion: 0.08
Nodes (34): bridge, credential, halfCloser, outcome, refused, secret, seenRequest, check() (+26 more)

### Community 107 - "AmneziaWG Wizard Configuration Tests"
Cohesion: 0.12
Nodes (56): pinned_version(), amneziawg_answers_are_validated_with_localized_feedback(), amneziawg_defaults_are_all_versions_and_the_panel_domain(), amneziawg_port_that_collides_is_reported_by_the_review_loop(), amneziawg_ports_default_to_the_random_free_ones_and_enter_accepts_them(), awg_and_tt_prompts_are_short_with_the_explanation_as_a_help_line(), awg_root(), awg_tt_answers() (+48 more)

### Community 108 - "Node Traffic Counters"
Cohesion: 0.05
Nodes (33): eq(), counter(), envelope(), is_username(), MAX, naive(), naive_traffic_keeps_only_consistent_rows(), py_int() (+25 more)

### Community 109 - "AwgManager Egress Management"
Cohesion: 0.09
Nodes (32): account(), AwgManager, BLACKHOLE_METRIC, bump_revision(), CAPABILITIES, check_revision(), direct(), document() (+24 more)

### Community 110 - "Candidate Update Verification Tests"
Cohesion: 0.08
Nodes (44): a_failed_source_keeps_its_previous_candidates_next_to_the_error(), a_rebuild_marker_counts_for_half_an_hour(), agent_in(), an_unverified_rollback_blocks_updates_and_a_failed_rollback_is_recorded(), Answer, cached_upstream_telemt_build_candidate_is_installable_and_listed(), card_drops_managers_whose_container_image_is_newer_than_the_panel_update(), check_upstream_caches_candidates_and_lists_them_after_the_catalog() (+36 more)

### Community 111 - "File Acceptance Markers"
Cohesion: 0.04
Nodes (49): acceptance_name(), ACCEPTANCE_OWNER, ACCEPTANCE_PENDING, ACCEPTANCE_PREFIX, add_owned_directories(), ADJACENT_CREDENTIALS, ADJACENT_SERVICES, base64_encode() (+41 more)

### Community 112 - "Proxy Ownership Acceptance"
Cohesion: 0.09
Nodes (15): clear_directory(), command_failure(), evidence(), Host, identity_from_entry(), is_hex(), loopback(), mutations() (+7 more)

### Community 113 - "Traffic Accounting Storage"
Cohesion: 0.08
Nodes (23): now_iso(), total(), ACCOUNTING_MAX_VERIFY_BYTES, ACCOUNTING_RETAINED_BYTES, ACCOUNTING_ROLL_KEEP, ADDED_COLUMNS, as_i64(), assert_safe_parent_chain() (+15 more)

### Community 114 - "Isolated VPN Smoke Tests"
Cohesion: 0.05
Nodes (32): Cleanup, IsolatedRunner, real_isolated_engine_install_repair_rollback(), NativeRunner, Bounded, .AUDIT, .CERTIFICATES, .FIREWALL (+24 more)

### Community 115 - "Operator Credentials Validation"
Cohesion: 0.08
Nodes (37): anchor(), CredentialError, credentials_path(), discard_staged_credentials(), fail(), FIELDS, MAXIMUM_PASSWORD, MINIMUM_PASSWORD (+29 more)

### Community 116 - "Metrics Route Endpoints"
Cohesion: 0.12
Nodes (39): Caller, check_node(), check_range(), clients(), clients_route(), enabled(), envelope(), error_response() (+31 more)

### Community 117 - "Client Management UI Actions"
Cohesion: 0.07
Nodes (58): acceptPage(), actions(), adopt(), adoptNote(), archiveClient(), byProtocol(), byState(), CLIENT_FILTER_DEFAULT (+50 more)

### Community 118 - "Client Dispatch Replay"
Cohesion: 0.10
Nodes (4): dispatch(), none(), pair(), Replay

### Community 119 - "Ordered JSON Deserialization"
Cohesion: 0.05
Nodes (22): Ordered, Array, Object, Scalar, canonical(), CANONICAL, canonical_digest(), check_integer_range() (+14 more)

### Community 120 - "Server-Sent Events Streams"
Cohesion: 0.06
Nodes (22): Alive, Build, EventStream, frame(), GLOBAL, Lease, MAX_AGE_SECONDS, PER_SESSION (+14 more)

### Community 121 - "Python-Compatible JSON Serialization"
Cohesion: 0.05
Nodes (28): canonical(), CANONICAL, plain(), state(), as_int(), canonical(), dumps(), eq() (+20 more)

### Community 122 - "Adapter Context Registry"
Cohesion: 0.09
Nodes (44): AdapterContext, mcp_handoff(), registry(), atomic(), capture(), checked(), compose(), ensure_archive() (+36 more)

### Community 123 - "Agent Service Lifecycle Tests"
Cohesion: 0.13
Nodes (50): action_from_golden(), agent_checkpoint_validation_and_marker_drift_prevent_mutation(), agent_engine_fresh_repair_and_uninstall_own_the_complete_tree(), agent_env_fresh_is_byte_exact_python_golden(), agent_preflight_refuses_foreign_installation_and_unsafe_sources(), agent_preserves_catalog_state_and_rejects_foreign_tree_files(), agent_purge_removes_only_owned_code_and_persistent_data(), agent_rejects_nonexecutable_binary_before_starting_service() (+42 more)

### Community 124 - "JSON-RPC Tool Invocation"
Cohesion: 0.07
Nodes (12): Handler, handler_error(), INSTRUCTIONS, KEEP_ALIVE, LOG, MAX_BODY, method_not_found(), SERVER_NAME (+4 more)

### Community 125 - "HTTP Request Extractors"
Cohesion: 0.06
Nodes (18): BodyInput, Bytes, Json, Missing, Call, content_type(), cookies_parse_like_starlette(), header() (+10 more)

### Community 126 - "Policy Routing Route Handlers"
Cohesion: 0.13
Nodes (38): ANYONE, apply(), attach(), audit_context(), delete_policy(), detach(), escaped_manager_errors_keep_protocol_http_answers(), exits_action() (+30 more)

### Community 127 - "Atomic Binary Execution Script"
Cohesion: 0.12
Nodes (38): run.sh script, CatalogEntry, atomic_write(), assert_generation(), assert_pin(), build_caddy(), fetch_binary(), read_pin() (+30 more)

### Community 128 - "Mita Process Execution Tests"
Cohesion: 0.09
Nodes (30): cli_eof_before_child_exit_is_sanitized_and_reaps_child(), cli_hashes_an_unchanged_executable_once_and_any_change_again(), cli_kills_child_during_execution_when_either_output_stream_exceeds_cap(), cli_parses_official_exact_status_grammar(), cli_passes_complete_config_through_anonymous_fd_and_bounds_output(), cli_reads_cumulative_per_user_bytes_from_mita_get_metrics(), cli_refuses_unpinned_or_changed_executable_before_launch(), cli_rejects_ambiguous_or_noncanonical_status() (+22 more)

### Community 129 - "Safe Archive Extraction Tests"
Cohesion: 0.13
Nodes (49): an_architecture_this_release_does_not_build_for_is_refused(), archive_digest_is_verified_before_tar_processing(), archive_path_swap_cannot_change_verified_bytes(), backup_cleanup_failure_does_not_report_failed_install(), compressed_archive_bytes_have_a_hard_bound(), contains(), decompressed_tar_and_extension_metadata_are_bounded(), destination_parent_swap_is_detected_at_mutation_boundary() (+41 more)

### Community 130 - "AwgManager Service Daemon"
Cohesion: 0.05
Nodes (25): env(), fetch_health(), healthcheck(), main(), print_health(), probe(), run(), serve() (+17 more)

### Community 131 - "Proxy Process Child Isolation"
Cohesion: 0.13
Nodes (35): BoundaryError, checked_fd(), child(), children(), cli(), cstring(), directory(), Entry (+27 more)

### Community 132 - "Fleet Central Certificate Validation"
Cohesion: 0.10
Nodes (33): audit_context(), blocking(), CentralDomain, client_for(), domain(), force_query(), linked(), node_failure() (+25 more)

### Community 133 - "ACME Certificate Management"
Cohesion: 0.11
Nodes (20): acme_vhost_matches_python_golden(), action(), address_facts(), certificate_action(), certificate_checkpoint(), certificate_groups(), certificate_sans(), certificate_vhost_path() (+12 more)

### Community 134 - "Version Agent Client"
Cohesion: 0.06
Nodes (13): Result, VersionClient, .DEFAULT_TIMEOUT, LocalName, ManagerMeters, MeterSources, missing(), POLLED (+5 more)

### Community 135 - "Component Release Catalog"
Cohesion: 0.07
Nodes (42): alnum(), archive(), Catalog, COMPONENTS, entry(), entry_from_value(), ENTRY_KEYS, https_artifact() (+34 more)

### Community 136 - "Nginx Topology Parser"
Cohesion: 0.10
Nodes (47): parse_nginx_observation(), nginx_observation_reports_routes_http_names_and_errors(), EFFECTIVE, fail(), fnmatchcase(), glob(), glob_items(), glob_path_matches() (+39 more)

### Community 137 - "X25519 Cryptographic Keys"
Cohesion: 0.06
Nodes (36): cli(), generate_private(), generated_private_key_is_clamped_and_base64_is_strict(), KeyError, public_key(), random_bytes(), unb64(), x25519() (+28 more)

### Community 138 - "Three-XUI Adapter Integration"
Cohesion: 0.09
Nodes (20): fail(), safe(), tags(), ThreeXuiAdapter, walk(), bootstrap_dialogue(), copy_tree(), DATABASE (+12 more)

### Community 139 - "Relay Lane Policies"
Cohesion: 0.07
Nodes (30): lane_policies(), a_grant_on_a_linked_node_gets_its_lane_through_the_generation(), a_linked_nodes_relay_is_enabled_through_its_generation_and_a_chain_follows_its_report(), a_v06_node_refuses_lanes_and_relay_by_code(), compile_includes_only_desired_sections_for_an_egress_v1_node(), exits_crud_import_test_and_the_policy_that_uses_one(), identity_reports_the_lanes_and_relay_capabilities_and_the_relays_public_part(), pusher_marks_policy_failed_with_the_node_error() (+22 more)

### Community 140 - "GeoData Asset Fetcher"
Cohesion: 0.06
Nodes (42): advance(), answer(), as_float(), corrupt(), DEFAULT_INTERVAL_HOURS, DEFAULT_SOURCE, DEFAULT_UPDATE_HOUR, download_pair() (+34 more)

### Community 141 - "Keyring Key Management"
Cohesion: 0.07
Nodes (21): debug_never_shows_material(), generated_keyring_has_one_active_key_with_python_id_shape(), io(), Key, Keyring, KeyringError, .ACTIVE_NOT_ACTIVE, .BAD_MODE (+13 more)

### Community 142 - "Web Request Infrastructure"
Cohesion: 0.07
Nodes (20): latin1(), RequestMeta, run(), settings_from_env(), TEST_HOOKS, Conn, Tcp, Unix (+12 more)

### Community 143 - "Configuration Obfuscation Generator"
Cohesion: 0.09
Nodes (39): allowed(), apply_overrides(), client_view(), COMMON, default_i1(), digits(), err(), extra_keys() (+31 more)

### Community 144 - "Managed Node Storage Store"
Cohesion: 0.09
Nodes (19): AcceptError, Conflict, Store, EgressUpdate, Key, LANES_KEY, loads(), ManagedStore (+11 more)

### Community 145 - "TeleMT Metrics Dashboard Tasks"
Cohesion: 0.10
Nodes (34): GatherError, Call, Task, gathering(), add_user(), amneziawg_snapshot(), audit_context(), dashboard_route() (+26 more)

### Community 146 - "Fleet Metrics Source Aggregator"
Cohesion: 0.08
Nodes (17): CALL_TIMEOUT, CAPABILITY, CONCURRENCY, FleetMetricsSource, FlightKey, History, Live, Summary (+9 more)

### Community 147 - "Nginx Route Configuration Adapter"
Cohesion: 0.17
Nodes (22): action_specification(), checkpoint_identity(), derive_owned_route_variable(), desired_content(), ensure_stream_context(), has_stream_context(), nginx_runtime_prefix(), NginxAdapter (+14 more)

### Community 148 - "Host Process Command Runner"
Cohesion: 0.07
Nodes (29): CORE_ACTION, read_active_state(), check_version(), cli(), lines(), migrate(), Model, NEW (+21 more)

### Community 149 - "AmneziaWG Management Client"
Cohesion: 0.06
Nodes (19): AmneziawgClient, EGRESS_TIMEOUT, listed(), Result, httpx_target(), Numeric, Float, Int (+11 more)

### Community 150 - "HTTP Boundary Regression Tests"
Cohesion: 0.08
Nodes (31): exchange(), test_body_limit_stops_consuming_oversize_stream(), test_bounded_body_preserves_bytes_for_handler(), test_incomplete_body_never_dispatches_or_becomes_server_error(), _connect_through(), _echo(), _load(), _refuses() (+23 more)

### Community 151 - "Bounded HTTP Client Operations"
Cohesion: 0.08
Nodes (26): AGENT_USER_AGENT, check_host(), ClientOptions, copy_bounded(), DEFAULT_TIMEOUT, Head, head_of(), hop_allowed() (+18 more)

### Community 152 - "External Link Chooser Tests"
Cohesion: 0.06
Nodes (21): load_env(), main(), chooser_text(), client_with_trusttunnel(), key(), open_clients(), open_href(), pick() (+13 more)

### Community 153 - "Host Handoff Ownership Verification"
Cohesion: 0.12
Nodes (44): JournalFile, Ownership, Plan, Report, State, host(), owned_host(), OwnedHost (+36 more)

### Community 154 - "Naive Caddy Deployment Adapter"
Cohesion: 0.08
Nodes (25): BOOTSTRAP_PASSWORD, BOOTSTRAP_USER, CADDY_BINARY, CADDY_VERSION, CADDYFILE, DATA_DIR, decode_adjacent(), deploy_hook_text() (+17 more)

### Community 155 - "Client App Deep Links"
Cohesion: 0.08
Nodes (33): App, AppEntry, APPS, apps_for(), by_id(), catalogue(), deep_link(), download_links_are_https() (+25 more)

### Community 156 - "AwgManager Process Supervision"
Cohesion: 0.07
Nodes (16): Egress, a_real_child_is_polled_terminated_and_reaped(), AMNEZIAWG_BINARY, ChildProc, COMMAND_TIMEOUT, Host, HostError, NFT_TABLE (+8 more)

### Community 157 - "HTTPS Certificate Validation"
Cohesion: 0.09
Nodes (29): AnyCertificate, check_hop_reachable(), connect(), connect_error(), Failure, Open, Read, handshake() (+21 more)

### Community 158 - "Acceptance and Handoff Reporting"
Cohesion: 0.07
Nodes (30): bounded_text(), AcceptanceReport, ALLOWED_FACTS, assert_public(), CredentialHandoff, CREDENTIALS_DIR, CREDENTIALS_NAME, encode() (+22 more)

### Community 159 - "In-Memory TeleMT Management"
Cohesion: 0.09
Nodes (7): MemoryTelemt, TelemtState, TelemtAccess, TelemtApi, TelemtClient, TelemtResult, access_of()

### Community 160 - "TeleMT Proxy Manager"
Cohesion: 0.09
Nodes (13): parse_qs_first(), access_from_user(), access_is_read_from_the_first_tls_link(), api_secret(), BatchState, classify(), FAKE_TLS_PREFIX, http_client() (+5 more)

### Community 162 - "Naive Manager CLI"
Cohesion: 0.08
Nodes (26): args(), healthcheck(), main(), parse_args(), run(), USAGE, check_token(), constant_time_eq() (+18 more)

### Community 163 - "Traffic Accounting Tests"
Cohesion: 0.13
Nodes (44): tempdir(), active_hardlink_alias_counts_once_and_does_not_consume_rotation_or_verify_budget(), aggregate_counter_never_exceeds_signed_sqlite_integer(), append(), archiving_deleted_user_removes_live_counter_without_losing_history(), collector(), consumed_prefix_larger_than_request_budget_fails_closed(), contract_is_secret_free_and_documents_accounting_limits() (+36 more)

### Community 164 - "Host Updater Service"
Cohesion: 0.10
Nodes (28): manager_services(), pending_list(), AGENT_RESTART, block_header(), compose_command(), compose_up(), display(), Downloader (+20 more)

### Community 165 - "APT Package Management"
Cohesion: 0.14
Nodes (28): action_packages(), apt_runner(), assert_added_unchanged(), assert_preexisting_unchanged(), checkpoint_packages(), config(), DEFAULT_PACKAGES, explicit_uninstall_purge_is_the_only_package_purge() (+20 more)

### Community 166 - "Mieru Egress Management"
Cohesion: 0.09
Nodes (41): ACTIONS, both(), CAPABILITIES, check_reachable(), cidr(), Credential, credential(), direct_doc() (+33 more)

### Community 167 - "HTTP Request Router"
Cohesion: 0.08
Nodes (20): find_user(), PathParams, Bound, Handler, Static, compile(), Dispatcher, DispatcherInner (+12 more)

### Community 168 - "Client Account Provisioning"
Cohesion: 0.14
Nodes (41): account(), arg(), arg_or(), audit_tail(), client_subscription(), create_client(), derive_username(), grants_body() (+33 more)

### Community 169 - "Runtime Geodata Management"
Cohesion: 0.07
Nodes (10): GeodataAction, Codes, Restore, Settings, Update, View, Managers, Managers<N, M> (+2 more)

### Community 170 - "Node Link Management"
Cohesion: 0.10
Nodes (14): validate_panel_url(), connection(), context(), FailingFactory, flag(), heartbeat_records_good_reports_and_only_transition_events(), KEY_PURPOSE, NodeLinkService (+6 more)

### Community 171 - "Fleet Reconciliation Tests"
Cohesion: 0.15
Nodes (43): a_missing_row_lingers_for_repeat_reports_and_never_claims_a_new_local_user(), a_regrant_under_a_new_ref_is_owned_under_that_ref_after_the_apply(), a_regrant_under_a_new_ref_retires_the_missing_row_and_still_respects_a_local_user(), accept(), accept_records_master_and_rejects_lower_same_digest_and_foreign(), apply(), apply_is_idempotent_and_survives_a_restart_mid_apply(), apply_of_an_older_generation_is_superseded() (+35 more)

### Community 172 - "Client Attention Dashboard UI"
Cohesion: 0.11
Nodes (44): showClientIssue(), paintClientsCount(), plural(), attentionBlock(), attentionLine(), bindAttention(), CLIENT_ATTENTION, cpuDetail() (+36 more)

### Community 173 - "Lane and Route Validation"
Cohesion: 0.09
Nodes (36): chars_in(), handler_lines(), invalid(), is_account_password(), is_account_user(), is_forward_proxy(), is_lane_id(), is_route_open() (+28 more)

### Community 174 - "Routing Protocol Error Handling"
Cohesion: 0.07
Nodes (20): NodeClientProvider, ProtocolSwitch, Refusal, Result, RoutingFailure, Adapter, Internal, Manager (+12 more)

### Community 175 - "Node Management Routes"
Cohesion: 0.14
Nodes (27): authorized(), blocking(), disable(), enable(), error_response(), finish(), get_node(), json_response() (+19 more)

### Community 176 - "Node Administration UI"
Cohesion: 0.09
Nodes (44): nodeOptions(), esc(), versionOptions(), actions(), bindLinkDialog(), certificateLine(), COMPONENT_NAMES, COMPONENT_SHORT (+36 more)

### Community 177 - "Host Metrics Collection Tests"
Cohesion: 0.17
Nodes (29): amneziawg_from_interface_counters(), connections_count_established_on_protocol_ports_only(), connections_tolerate_missing_ipv6_and_garbage(), connections_zero_when_files_readable_and_null_without_tcp_ports_or_files(), CONTAINER_IDS, containers_from_cgroup_and_docker_ps(), cpu_percent_exact(), docker_failure_gives_empty_containers() (+21 more)

### Community 178 - "Warp Adapter Package Management"
Cohesion: 0.10
Nodes (12): DIRECTORY, KEY, KEY_SHA256, OWNER, PACKAGE_SHA256, PACKAGE_URL, REPO, REPO_PATH (+4 more)

### Community 179 - "API Key Management Routes"
Cohesion: 0.15
Nodes (28): Handled, create_key(), delete_key(), key_error(), list_keys(), set_enabled(), capture(), check_versions() (+20 more)

### Community 180 - "In-Memory Protocol Node Mocks"
Cohesion: 0.09
Nodes (8): Hosts, Node, NodeOptions, StaticVersions, table(), TempDir, TestRuntime, unavailable()

### Community 181 - "State Probe and Rollback"
Cohesion: 0.10
Nodes (25): a_failed_slot_probe_restores_the_slot_and_keeps_the_state(), Api, bootstrap_resyncs_the_slots_from_the_state(), call(), call_with(), failed_probe_rolls_back_full_snapshot_and_restarts(), Fake, FakeMita (+17 more)

### Community 182 - "Routing Policy Backend Store"
Cohesion: 0.10
Nodes (36): backend_for(), backends_for(), PolicyOwn, ROUTER_BACKEND, apply_row(), apply_rows(), ApplyRecord, delete() (+28 more)

### Community 183 - "Chart Value Formatting Utilities"
Cohesion: 0.11
Nodes (42): BYTE_UNITS, byteTicks(), decimal(), defaultGap(), describe(), digits(), finite(), formatClock() (+34 more)

### Community 184 - "QEMU Test Platform Automation"
Cohesion: 0.10
Nodes (29): acceleration(), allocate_port(), _archive(), cleanup(), finalize_results(), full_egress_policy(), guest_remote(), junit_xml() (+21 more)

### Community 185 - "Architecture Documentation and Protocols"
Cohesion: 0.07
Nodes (36): Algorithm A (Deploy Node Non-interactively), Algorithm B (Prepare Node for Central), Algorithm C (Link Node to Central), Algorithm D (Issue Client Access on Node), Algorithm E (Egress Routing & Lanes), Algorithm F (Upgrade, Rollback, Backup), Refusal Code Decision Matrix, AI Agent Operational Protocol (+28 more)

### Community 186 - "Mieru Quota Models"
Cohesion: 0.06
Nodes (27): INT64_MAX, kinds(), MieruQuota, .TITLE, MieruQuotaUpdate, .TITLE, MieruRevision, .TITLE (+19 more)

### Community 187 - "VPN Runtime Management"
Cohesion: 0.13
Nodes (6): hex(), OVERRIDE, PROJECT, Runtime, without_override_service(), is_in_band_failure()

### Community 188 - "Cursor and Value Serialization"
Cohesion: 0.07
Nodes (28): a2b_base64(), cursors_round_trip_and_match_python_bytes(), decode(), encode(), json_loads(), sextet(), is_uuid(), py_eq_int() (+20 more)

### Community 189 - "Installer CLI Test Suite"
Cohesion: 0.15
Nodes (30): a_failed_install_rolls_back_and_a_crash_is_resumed(), a_missing_adapter_is_blocked(), a_report_needs_an_active_installation_and_its_mcp_handoff(), audit_failure_is_blocked_without_a_traceback(), config_errors_are_blocked_like_python(), config_path(), core_toml(), Fixture (+22 more)

### Community 190 - "Installation Transaction Lifecycle"
Cohesion: 0.17
Nodes (38): plan_for(), a_completed_rollback_does_not_block_the_next_attempt(), a_completed_uninstall_does_not_block_the_next_install(), a_file_the_version_agent_manages_is_not_foreign_drift(), a_rollback_failure_is_recorded_and_resumable(), a_runtime_v2_journal_is_refused_by_name(), a_service_rewritten_owned_file_is_not_foreign_drift(), an_interrupted_transaction_still_blocks_a_fresh_start() (+30 more)

### Community 191 - "GitHub Actions CI Workflows"
Cohesion: 0.07
Nodes (40): runs-on, steps, timeout-minutes, concurrency, cancel-in-progress, group, runs-on, steps (+32 more)

### Community 192 - "HTTP Server Endpoint Tests"
Cohesion: 0.12
Nodes (25): Answer, Counting, counting(), get(), host_endpoint_is_read_only_and_rejects_writes(), http_endpoints(), post(), raw() (+17 more)

### Community 193 - "Test Fixtures and RBAC"
Cohesion: 0.08
Nodes (15): Gate, Current, Roles, OWNER, fixture_database(), fixture_json(), fixture_path(), TempDir (+7 more)

### Community 194 - "Fleet Verification Claims"
Cohesion: 0.05
Nodes (40): amneziawg-fleet Claim, egress-api-managers Claim, fleet-native-legacy-33 Claim, Fleet Verification Subsystem, fleet-v2-auto-import Claim, fleet-v2-generations Claim, fleet-v2-geodata-and-exits Claim, fleet-v2-import-and-grants Claim (+32 more)

### Community 195 - "Fleet Metrics Aggregation"
Cohesion: 0.07
Nodes (14): FleetMeters, Metrics, HOST_SERIES, is_series(), LOCAL_NODE, NodeMetricsSource, POINTS_DEFAULT, POINTS_MAX (+6 more)

### Community 196 - "Core Adapter Lifecycle Automation"
Cohesion: 0.14
Nodes (6): core(), CoreAdapter, decode_routes(), domain(), valid_backend(), validate_users()

### Community 197 - "Nginx Stream Configuration Rendering"
Cohesion: 0.07
Nodes (31): active_sni_routes(), byte_offsets(), client_ip_backend(), DEFAULT_FRESH_PATH, effective_source_sections(), ensure_stream_context_matches_goldens_atomically(), fixture(), fresh_renderers_match_python_goldens() (+23 more)

### Community 198 - "Python JSON Test Generator"
Cohesion: 0.11
Nodes (22): main(), random_float(), random_string(), random_value(), structures(), tie_floats(), cumulative(), day_factor() (+14 more)

### Community 199 - "Subscription Service Test Suite"
Cohesion: 0.14
Nodes (31): FixedHosts, BumpGeneration, a_client_and_its_subscription_are_born_in_one_transaction(), a_pending_credential_version_is_not_rendered(), a_second_active_subscription_cannot_exist(), a_subscription_issued_before_escrow_is_a_conflict_not_a_crash(), a_suspended_client_renders_nothing_as_enabled(), create_with_client_without_a_subscription_domain_makes_only_the_client() (+23 more)

### Community 200 - "Database Schema Migrations"
Cohesion: 0.08
Nodes (39): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+31 more)

### Community 201 - "Static Files and MIME Handling"
Cohesion: 0.10
Nodes (29): ENCODINGS_MAP, SUFFIX_MAP, TYPES_MAP, civil_from_days(), DAYS, detail(), etag(), file_response() (+21 more)

### Community 202 - "Geodata Scheduled Updates"
Cohesion: 0.13
Nodes (14): Clock, clocked(), daily_updates_wait_for_the_update_hour_and_the_view_says_when(), GeodataStore, parse_source(), sha256_path(), Source, StagedPair (+6 more)

### Community 203 - "HTTP Transport Channel Handling"
Cohesion: 0.10
Nodes (22): accepts(), ChannelBody, edit_json(), event_stream(), HANDLED_METHODS, HANDSHAKE_VERSIONS, INVALID_REQUEST, jsonrpc_error() (+14 more)

### Community 204 - "Web Admin CLI Commands"
Cohesion: 0.21
Nodes (30): py_path(), api_key_create(), api_key_revoke(), call(), COMMANDS, create_admin(), create_admin_and_key_like_the_installer(), database_key_and_node_commands_match_python_stdout() (+22 more)

### Community 205 - "MCP Docker Compose Configuration"
Cohesion: 0.05
Nodes (38): context, dockerfile, panel, MCP_ALLOWED_HOSTS, MCP_BIND, MCP_PANEL_HOST, MCP_PANEL_KEY_FILE, MCP_PANEL_URL (+30 more)

### Community 206 - "Fake Manager Server Tests"
Cohesion: 0.07
Nodes (11): assertion_failures(), _body(), close_all(), _egress_quartet(), FakeManagerServer, _lanes(), _read_chunked(), Route (+3 more)

### Community 207 - "Secrets Keyring Fixture Tests"
Cohesion: 0.09
Nodes (21): casefold_matches_python_wherever_the_fold_contains_ascii(), detail_json_and_digests_are_byte_identical_to_python(), forbidden_keys_are_the_ones_python_forbids(), database_bytes(), fixture_json(), fixture_path(), private_copy(), TempDir (+13 more)

### Community 208 - "API Tool Schema Validation"
Cohesion: 0.09
Nodes (29): Curated, curated(), odd_schemas_fail_with_the_python_messages(), tool_names_follow_the_rule(), BODY_METHODS, body_schema(), build(), build_operations() (+21 more)

### Community 209 - "Quota Enforcer Server Handler"
Cohesion: 0.09
Nodes (17): body(), dispatch(), Enforce, error_response(), handler(), json_response(), MAX_BODY, optional_text() (+9 more)

### Community 210 - "Metrics Route Integration Tests"
Cohesion: 0.11
Nodes (20): a_node_metrics_source_serves_the_linked_nodes(), Answer, answer(), client_rates_of_one_protocol_for_the_protocol_pages(), disabled_monitoring_answers_404(), every_metrics_route_needs_a_session(), every_recorded_answer_of_the_main_app_is_identical(), get() (+12 more)

### Community 211 - "Egress and Geodata Management"
Cohesion: 0.11
Nodes (4): refusals_carry_the_bounded_codes_and_geodata_its_own(), Refusing, RouterAdapter<C>, targets_name_why_the_router_cannot_serve()

### Community 212 - "Router Policy Apply Workflow"
Cohesion: 0.12
Nodes (8): redact(), lane_built(), slot_learned(), warp_reachable(), settled(), settled(), settled(), settled()

### Community 213 - "QR Code Generation"
Cohesion: 0.09
Nodes (28): qr(), qr(), ALPHANUMERIC, best_fit(), capacity(), clear_information(), data_bits(), data_uri() (+20 more)

### Community 214 - "3X-UI API Integration Tests"
Cohesion: 0.10
Nodes (27): ApiResponse, csrf_meta_and_cookie_are_sent_before_login(), csrf_missing_fails_before_credentials_are_sent(), Fixture, inbound_view_drops_credentials(), leaf_pin_accepts_installed_leaf_before_credentials(), leaf_pin_mismatch_sends_no_request_bytes(), login_response() (+19 more)

### Community 215 - "Python Compatibility Helpers"
Cohesion: 0.10
Nodes (23): awg_version(), ALWAYS_SAFE, contains(), dict_set(), dict_update(), dumps(), get(), get_or() (+15 more)

### Community 216 - "Database Schema Snapshot V19"
Cohesion: 0.09
Nodes (37): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+29 more)

### Community 217 - "Database Schema Snapshot V21"
Cohesion: 0.09
Nodes (37): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+29 more)

### Community 218 - "Database Schema Snapshot V23"
Cohesion: 0.09
Nodes (37): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+29 more)

### Community 219 - "Database Schema Snapshot V24"
Cohesion: 0.09
Nodes (37): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+29 more)

### Community 220 - "Host Update Script Tests"
Cohesion: 0.11
Nodes (26): Agent, host(), _run(), _serve(), _answer(), do_GET(), do_POST(), get_request() (+18 more)

### Community 221 - "Client Audit Golden Tests"
Cohesion: 0.15
Nodes (27): golden_path(), assert_same(), client_create_digests_match_the_recordings(), client_row(), client_state_rows_match_the_fleet_recording(), context(), golden(), grant_disable_row_matches_the_recording() (+19 more)

### Community 222 - "Proxy Smoke Docker Tests"
Cohesion: 0.11
Nodes (12): checked_output(), docker(), execute(), identity(), ProbeContainer, ProbeOrigin, Processes, real_proxy_engine_install_repair_and_rollback() (+4 more)

### Community 223 - "Egress Configuration Tests"
Cohesion: 0.19
Nodes (36): a_failed_reload_restores_the_previous_bytes(), a_readback_mismatch_rolls_back_with_its_own_code(), apply_conflicts_on_a_stale_revision_without_touching_anything(), apply_is_idempotent_by_operation_id(), apply_keeps_every_other_line_byte_for_byte(), apply_refuses_an_unreachable_provider_and_an_unconfigured_one(), apply_rejects_an_invalid_document_before_any_io(), apply_router_unreachable_refuses_without_changes() (+28 more)

### Community 224 - "Database Schema Snapshot v16"
Cohesion: 0.09
Nodes (36): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+28 more)

### Community 225 - "VPN Protocol Transcripts"
Cohesion: 0.09
Nodes (27): access_grant(), Built, Amneziawg, Mieru, Naive, Router, Telemt, Trusttunnel (+19 more)

### Community 226 - "Test Mocking and Recording"
Cohesion: 0.12
Nodes (19): Call, CallKind, Bounded, Capture, CaptureChecked, Run, every_contract_has_a_fake_answer(), owned() (+11 more)

### Community 227 - "Python Compatibility Testing"
Cohesion: 0.13
Nodes (24): loads(), CHARS, json_writers_match_the_python_writers(), Lcg, listing(), malicious_archives_are_refused_like_python(), python(), python_lock_holder_excludes_rust() (+16 more)

### Community 228 - "Backup and File Management"
Cohesion: 0.17
Nodes (31): optional_overlay(), argv(), copy2(), is_symlink(), Backups, chown(), copy_db_file(), copy_entry() (+23 more)

### Community 229 - "Network Egress and Relays"
Cohesion: 0.07
Nodes (16): strings(), within_validity(), without_lane(), compiled_from(), compiled_previews_and_policy_helpers_match_python(), constants_match_python(), deliberate_difference(), egress_document_helpers_match_python() (+8 more)

### Community 231 - "Python JSON Serialization"
Cohesion: 0.10
Nodes (27): ascii_string(), canonical(), compact(), compact_utf8(), default_separators_depend_on_indent(), dumps(), dumps_default(), float_repr() (+19 more)

### Community 232 - "Agent Monitoring Scenarios"
Cohesion: 0.11
Nodes (33): a_failing_manager_marks_only_its_protocol_unavailable(), a_silent_agent_raises_a_stale_alert_after_a_minute(), alerts_follow_the_plan_thresholds(), an_old_mieru_manager_without_the_route_leaves_the_rest_untouched(), an_unreachable_agent_makes_the_node_stale_with_its_age_and_records_nothing(), connections_come_from_the_agent_next_to_the_manager_sessions(), cpu_rows(), flush_writes_all_three_resolutions_in_one_pass_and_merges_the_next_flush() (+25 more)

### Community 233 - "API Error Handling"
Cohesion: 0.12
Nodes (23): NodesError, Conflict, Db, Json, NotFound, active_grants(), AuditContext, checked_display_name() (+15 more)

### Community 234 - "Trust Tunnel Egress Management"
Cohesion: 0.12
Nodes (4): egress_revision(), MemoryTrusttunnel, TrusttunnelError, tunnel_panel()

### Community 235 - "Node Certificate Management"
Cohesion: 0.11
Nodes (17): CertificateInfo, LOCAL_NODE_ID, NodeView, list(), to_value(), a_link_without_auto_import_column_defaults_to_on(), cert(), derive() (+9 more)

### Community 236 - "Release and Artifact Management"
Cohesion: 0.16
Nodes (26): load_manifest(), ArtifactPin, DEFAULT_MAX_MEMBER_SIZE, has_architecture_token(), Identity, is_name(), is_repository(), is_semver() (+18 more)

### Community 237 - "Client Management and Access Control"
Cohesion: 0.10
Nodes (34): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+26 more)

### Community 238 - "Client Authentication and Access Management"
Cohesion: 0.10
Nodes (34): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+26 more)

### Community 239 - "Client Access Dialog Management"
Cohesion: 0.11
Nodes (34): createAccessDialogs(), bind(), bindClientDialog(), clearBundleSubscription(), clearClientDialog(), closeBundle(), openOperationBundle(), renderVariant() (+26 more)

### Community 240 - "Mieru SOCKS Client Tests"
Cohesion: 0.10
Nodes (20): ClientCommand, command_cleanup_kills_and_reaps_a_live_client_on_early_return(), COMMAND_TIMEOUT, DEADLINE, Destination, drain_socks_reply(), fragmented_socks_addresses_are_drained_before_reading_http(), Fragments (+12 more)

### Community 241 - "Fleet Host Rollback Engine"
Cohesion: 0.15
Nodes (24): a_failed_move_restores_the_journal_and_the_files(), a_modified_owned_overlay_is_refused_as_drift(), agent_runner(), compose_migration_copies_only_project_scoped_data_volumes(), failed_owned_agent_swap_restores_both_journals_and_owned_files(), failed_start_restores_old_unit_code_and_tmpfiles(), fleet_model(), fleet_overlays_in_use_are_never_retired() (+16 more)

### Community 242 - "Runtime Testkit Evidence"
Cohesion: 0.13
Nodes (8): action_for(), evidence(), Failure, Crash, Runtime, RecordingAdapter, release(), TempDir

### Community 243 - "3x-ui API Client"
Cohesion: 0.14
Nodes (12): CONTRACT, failure(), form_value(), LIMIT, parse_csrf_token(), python_repr(), safe_path(), Socket (+4 more)

### Community 244 - "Background Lifespan Tasks"
Cohesion: 0.11
Nodes (10): BackgroundLoop, BoxFuture, Counting, Lifespan, loops_stop_on_signal_and_stragglers_are_cancelled(), paused_loops_do_not_run_but_tick_on_demand(), StartupHook, STOP_GRACE (+2 more)

### Community 245 - "Central Process Manager"
Cohesion: 0.09
Nodes (6): central_environment(), CentralProcess, native_panel(), NodeB, Stub, _terminate()

### Community 246 - "Port Metrics Discovery"
Cohesion: 0.11
Nodes (26): Options, DEFAULT_MTPROXY_PORT, DEFAULT_NAIVE_PORT, DEFAULT_TRUSTTUNNEL_PORT, discover(), discover_ports(), EnvReader, KNOWN_PROTOCOLS (+18 more)

### Community 247 - "Version Agent Errors"
Cohesion: 0.11
Nodes (15): Cause, failure_line(), failure_line_has_the_chain_and_the_stderr_tail(), link(), UpdateError, UpdateState, RollbackFailed, RolledBack (+7 more)

### Community 248 - "Mieru Quotas and Routes"
Cohesion: 0.20
Nodes (23): dump_quotas(), access(), audit_context(), create(), delete(), domain_created(), domain_failure(), escrow() (+15 more)

### Community 249 - "Xray Router Adapter"
Cohesion: 0.14
Nodes (12): ARCHIVE, BIN, checkpoint_rejects_missing_unknown_and_wrong_typed_fields(), ENV, env_bytes_match_python_kitchen_sink_golden(), HELPERS, MARKER, SECRETS (+4 more)

### Community 250 - "Python String Compatibility Utilities"
Cohesion: 0.09
Nodes (17): ALWAYS_SAFE, collapse_whitespace(), decimal(), float_from_str(), in_table(), int_from_str(), is_ascii_space(), is_printable_char() (+9 more)

### Community 251 - "Naive Manager Memory Mock"
Cohesion: 0.15
Nodes (4): canonical_sha(), MemoryNaive, naive_error(), NaiveState

### Community 252 - "Proxy Control Panel Documentation"
Cohesion: 0.08
Nodes (32): Proxy Control Cover Illustration (Anime style clashing unicorn and girl with war hammer), Accounting Semantics, NaiveProxy Caddy Manager, Proxy Control Panel, Telemt MTProto Integration, TrustTunnel, Pull Request Template, AmneziaWG (+24 more)

### Community 253 - "Host Network Test Device"
Cohesion: 0.11
Nodes (9): api_socket_mode_and_healthcheck_probe(), Device, FakeHost, FakePeer, FakeProc, health_degrades_without_ip_forward_or_with_a_dead_instance(), HostState, ProcState (+1 more)

### Community 254 - "Release Notes and Changelog"
Cohesion: 0.07
Nodes (26): CHANGELOG.md, Database Migration 21, Release 3.0.1, Telemt (MTProto), Version Agent, Xray-router, AmneziaWG WARP routing, proxy_panel_by_dubr1k stack (+18 more)

### Community 255 - "Wizard Engine Golden Tests"
Cohesion: 0.12
Nodes (19): EngineError, Blocked, Fatal, Interrupted, WizardEngine, command(), engine(), golden() (+11 more)

### Community 256 - "Live Xray Router Tests"
Cohesion: 0.12
Nodes (26): ARCHIVE, assert_runtime(), authenticate(), BIN, checked(), credential_and_connect_proof(), docker(), engine() (+18 more)

### Community 257 - "HTTP API Response Rendering"
Cohesion: 0.12
Nodes (15): ApiFailure, Cookie, empty(), Failure, Api, Internal, html(), json() (+7 more)

### Community 258 - "Manifest Grant Subscription Renderers"
Cohesion: 0.15
Nodes (27): a_body_over_the_size_limit_is_refused_not_truncated(), a_hostile_uri_artifact_gets_no_link_only_copyable_text(), canonically_equivalent_unicode_names_get_unique_suffixes(), clash_group_references_node_qualified_names(), clash_lists_mieru_and_trusttunnel_with_quoted_scalars(), disabled_and_credential_less_grants_never_become_links(), duplicate_access_labels_get_order_independent_suffixes(), duplicate_node_names_get_stable_unique_suffixes() (+19 more)

### Community 259 - "TrustTunnel Memory Mock"
Cohesion: 0.14
Nodes (6): lock(), MemoryTrusttunnel, obfuscation(), PERIOD_START, TrusttunnelState, tt_error()

### Community 260 - "Release Verification Matrix"
Cohesion: 0.09
Nodes (10): Release Gate & Verification Matrix, check_names(), load(), main(), proof_problem(), render(), route_problems(), row_problems() (+2 more)

### Community 261 - "Manager Client Egress Tests"
Cohesion: 0.09
Nodes (15): a_request_that_never_left_is_a_plain_failure_not_indeterminate(), check_bodies(), current_access_reads_the_live_link_from_the_user_listing(), golden(), handler(), journal_is_written_byte_identical_to_python(), manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes_mieru(), manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes_naive() (+7 more)

### Community 262 - "Mieru Validation Rules"
Cohesion: 0.13
Nodes (29): with(), bounded_int(), dns_host_ok(), DUAL_STACK, FRACTION_DIGITS, FRACTION_ONE, go_duration_ns(), invalid() (+21 more)

### Community 263 - "Routing Coverage and Capabilities"
Cohesion: 0.18
Nodes (23): a_grant_on_a_linked_node_gets_its_lane_through_the_generation(), a_linked_nodes_chain_waits_for_its_report_and_uses_the_confirmed_direct_account(), a_v06_node_refuses_lanes_and_relay_and_never_receives_schema_two(), AdaptersOnly, advertised(), block(), capabilities(), compile_includes_only_desired_sections_for_an_egress_v1_node() (+15 more)

### Community 264 - "Container Metrics Sampler"
Cohesion: 0.15
Nodes (4): Deltas, MetricsSampler, monotonic(), State

### Community 265 - "Linux Process Host Runner"
Cohesion: 0.13
Nodes (14): alive(), bounded_classifies_start_failures(), bounded_deadline_and_output_limit_kill_the_group(), children_start_in_their_own_session(), cleanup(), interrupt_stops_the_process_group(), pid_of(), run_suppresses_stdout_preserves_stderr_stdin_and_env() (+6 more)

### Community 266 - "Mieru Lanes Configuration"
Cohesion: 0.10
Nodes (25): binding_query(), bindings_of(), empty_config(), is_account_password(), is_account_user(), is_lane_id(), LaneRequest, lanes_invalid() (+17 more)

### Community 267 - "Python Datetime Compatibility Utilities"
Cohesion: 0.11
Nodes (18): civil(), compare_digest(), days_from_civil(), days_in_month(), digits(), fromisoformat_matches_python_313(), fromisoformat_timestamp(), hex() (+10 more)

### Community 268 - "Database Schema Snapshot V11"
Cohesion: 0.11
Nodes (29): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+21 more)

### Community 269 - "Database Schema Snapshot V12"
Cohesion: 0.11
Nodes (29): access_grants, access_grants_client, admins, api_keys, api_keys_prefix, audit_log, audit_log_request, client_subscriptions (+21 more)

### Community 270 - "Exit and Geodata Request Models"
Cohesion: 0.07
Nodes (18): ExitCreateBody, .TITLE, ExitImportBody, .TITLE, ExplainBody, .TITLE, GeodataSettingsBody, .TITLE (+10 more)

### Community 271 - "Authentication and Session Flows"
Cohesion: 0.14
Nodes (26): admin_key_reads_and_mutates_without_a_session(), audit_cursor_and_filters_are_backward_compatible(), authenticated_login_page_preserves_session_csrf(), bad_missing_or_disabled_key_is_401(), body_limit_and_validation(), concurrent_login_batch_reserves_attempts_and_bounds_argon2(), create_key(), csrf_required_for_login_and_authenticated_mutations() (+18 more)

### Community 272 - "Panel Archive Extraction"
Cohesion: 0.11
Nodes (20): extract_panel_archive(), archive_errors_name_the_problem(), extracts_files_directories_and_modes(), member(), members_can_be_read_without_extracting(), panel_preflight_refuses_an_unsafe_archive_before_touching_anything(), PANEL_SYNC_330, preflight_refuses_everything_outside_the_release_tree() (+12 more)

### Community 273 - "IPv4 Network Utilities"
Cohesion: 0.13
Nodes (17): format_v4(), ip_network(), Ipv4Net, is_ip_address(), membership_overlap_and_hosts(), Network, V4, V6 (+9 more)

### Community 274 - "TrustTunnel and Routing Documentation"
Cohesion: 0.08
Nodes (28): Release 1.6.0, Release 3.0.0, Release 3.2.0, trusttunnel-manager, TrustTunnel Protocol, trusttunnel-manager, TrustTunnel Endpoint, Relay and Lane Slots (+20 more)

### Community 275 - "Multi-Protocol Project Changelog"
Cohesion: 0.08
Nodes (28): CHANGELOG.md, Release 3.1.0, Release 3.2.0, Release 3.2.1, Release 3.3.0, Release 4.0.0, AmneziaWG (awg-manager), Clients and State Domain (+20 more)

### Community 276 - "AmneziaWG Routes and Errors"
Cohesion: 0.11
Nodes (9): holders(), overview(), page_failure(), all(), DOCUMENT, openapi_schema(), holders(), overview() (+1 more)

### Community 277 - "Secret Staging Helper"
Cohesion: 0.12
Nodes (25): EXIT_FAILURE, main(), MAX_BYTES, MIN_BYTES, open_source(), SOURCE_GID, SOURCE_MODE, SOURCE_UID (+17 more)

### Community 278 - "QEMU Lab Test Suite"
Cohesion: 0.08
Nodes (3): FakeClock, QemuLabTests, probe()

### Community 279 - "AmneziaWG Configuration Validation"
Cohesion: 0.12
Nodes (19): boolean(), Config, config_defaults(), config_messages_quote_the_bad_value(), config_partial_override_and_subset(), ConfigError, DEFAULT_PORTS, DEFAULT_SUBNETS (+11 more)

### Community 280 - "Version Agent Command Runner"
Cohesion: 0.11
Nodes (13): Command, CommandError, Failed, Os, Other, Timeout, CommandRunner, DEFAULT_TIMEOUT (+5 more)

### Community 281 - "Proxy Control Installer Guides"
Cohesion: 0.08
Nodes (27): Installer Configuration Schema, Interactive Release Installer Reference, Installer Wizard, state.json, version-overrides/compose.versions.yaml, install.sh, version-agent, versions.json (Catalog) (+19 more)

### Community 282 - "Public Client Format Negotiation"
Cohesion: 0.10
Nodes (8): ACCEPT_FORMATS, FETCHES_PER_MINUTE, FORK_AGENTS, answer(), blocking(), not_found(), refuse(), subscription()

### Community 283 - "JSON Load and Parser"
Cohesion: 0.19
Nodes (15): decode_detected(), decode(), decode_error(), duplicate_keys_keep_the_first_position_and_the_last_value(), is_digit(), loads(), LoadsError, Decode (+7 more)

### Community 284 - "JSON Number Serialization Modes"
Cohesion: 0.15
Nodes (19): is_float(), dumps(), float_repr(), FloatMode, Python, RustShortest, historical_number_modes_keep_distinct_persisted_bytes(), increment() (+11 more)

### Community 285 - "HTTP Parsing and Decoding"
Cohesion: 0.12
Nodes (14): Body, Invalid, Read, decode(), form_decode(), hex(), json_headers(), json_object_accepts_objects_and_empty_bodies_only() (+6 more)

### Community 286 - "Mieru Docker Compose Setup"
Cohesion: 0.07
Nodes (27): cap_drop, command, image, network_mode, read_only, restart, security_opt, volumes (+19 more)

### Community 287 - "Egress Migration Support"
Cohesion: 0.11
Nodes (14): ChainHop, migration_21_widens_the_checks(), count(), database(), GUID_B, GUID_C, hop_b(), hop_c() (+6 more)

### Community 288 - "Component Integration Guides"
Cohesion: 0.08
Nodes (27): AmneziaWG WARP Egress, docs/guides/MONITORING.ru.md, docs/guides/TRUSTTUNNEL.ru.md, AmneziaWG Support, Release 1.3.0, Mieru Manager, Metrics Monitoring Engine, mtproxy-bridge (+19 more)

### Community 289 - "File Directory Descriptor Operations"
Cohesion: 0.20
Nodes (20): check(), create_file_at(), cstr(), DIRECTORY_FLAGS, dup(), fchmod(), fstat(), fsync() (+12 more)

### Community 290 - "Web Test Client Helpers"
Cohesion: 0.13
Nodes (9): Answer, Client, exchange(), header(), Panel, parse(), start(), start_with() (+1 more)

### Community 291 - "Naive Routes and Escrow"
Cohesion: 0.23
Nodes (18): access(), audit_context(), create(), delete(), domain_failure(), escrow(), escrow_error(), facade() (+10 more)

### Community 292 - "Caddy Reverse Proxy Client"
Cohesion: 0.13
Nodes (20): Admin, ADMIN_ADDRESS, admin_requests_are_byte_identical_to_urllib(), ADMIN_TIMEOUT, caddy_adapt_unwraps_caddy_211_envelope(), cover_probe_accepts_a_locally_untrusted_cover_certificate(), dechunk(), finish() (+12 more)

### Community 293 - "PyText Test Data Generator"
Cohesion: 0.15
Nodes (18): decimal_ranges(), ip_facts(), is_surrogate(), main(), nfc_inputs(), py_float(), py_int(), random_ips() (+10 more)

### Community 294 - "Protocol Golden Config Tests"
Cohesion: 0.19
Nodes (26): amneziawg_configs_are_byte_exact(), amneziawg_credentials_and_learned_options_match_python(), amneziawg_public_keys_match_python(), an_oversized_config_has_no_qr(), artifacts_value(), bytes(), cases(), check_adapter_error() (+18 more)

### Community 295 - "User Adapter UI Tests"
Cohesion: 0.07
Nodes (5): test_access_returns_sanitized_conflict_for_malformed_upstream_url(), test_created_and_rotated_reveals_carry_the_qr_the_access_dialog_requires(), test_the_domain_writer_adopts_a_user_it_did_not_create(), test_the_domain_writer_records_a_client_and_grant_for_every_protocol(), test_user_crud_rotate_and_one_time_reveal()

### Community 296 - "Host Hardware Metrics Reader"
Cohesion: 0.14
Nodes (13): cpu_utilisation_is_a_delta_between_two_samples(), cpu_with(), disk_reports_space_an_operator_can_actually_write(), HostReader, MEMINFO, memory_counts_reclaimable_cache_as_available(), missing_proc_files_degrade_each_section_independently(), reader() (+5 more)

### Community 297 - "Host Metrics Collection Timer"
Cohesion: 0.10
Nodes (20): Clock, CONTAINER_NAMES_TTL, counter_name(), cpu_count(), DISCOVERY_INTERVAL, float(), INTERVAL, is_protocol_name() (+12 more)

### Community 298 - "TLS Network Client"
Cohesion: 0.14
Nodes (14): ALLOWED, certificates(), client(), header_value(), hosts_tls_and_timeouts(), https_client_contract(), openssl(), redirects_are_checked_on_every_hop() (+6 more)

### Community 299 - "IP Address Normalization"
Cohesion: 0.14
Nodes (19): ip_address(), ipv4_address(), ipv4_int(), ipv6_address(), ipv6_int(), ipv6_str(), parse_hextet(), parse_octet() (+11 more)

### Community 300 - "Core Acceptance Engine Tests"
Cohesion: 0.14
Nodes (14): core_action(), core_engine_preserves_credentials_and_refuses_foreign_drift(), core_rollback_preserves_credentials_and_neighboring_project_files_unless_purged(), core_vhosts_match_python_goldens(), corrupt_core_checkpoint_refuses_lifecycle_without_mutating_generation_or_foreign_file(), failed_temporary_cleanup_retains_owned_tombstone_until_success_or_explicit_purge(), forged_checkpoint_ownership_refuses_foreign_project_file_and_off_domain_cover_before_mutation(), owned_core() (+6 more)

### Community 301 - "WARP and TrustTunnel Smoke Tests"
Cohesion: 0.14
Nodes (13): certificate_action(), checked(), Cleanup, mount_directory(), namespace(), native_trusttunnel_fresh_upgrade_private_ca_san_and_sni(), native_warp_shipped_pin_download_install_and_egress(), plan() (+5 more)

### Community 302 - "Router Lifecycle Smoke Tests"
Cohesion: 0.18
Nodes (18): bad_pinned_zip_member_prevents_commands_and_install(), FixtureState, Io, managed_three_xui_real_tls_engine_apply_and_rollback(), pin_tree(), plan(), real_hidden_bootstrap_cli_rotates_and_rejects_default_credential(), real_zip_engine_apply_and_purge_rollback() (+10 more)

### Community 303 - "MCP HTTP Forwarding Router"
Cohesion: 0.22
Nodes (8): App, Body, full(), header_text(), json_response(), listed(), serve(), text_response()

### Community 304 - "Node Capture and Reconciliation"
Cohesion: 0.14
Nodes (13): a_push_landing_during_unlink_cannot_resurrect_managed_rows(), a_slow_reconcile_is_answered_202_and_keeps_running(), capture_is_audited_and_answers_local_users_only_for_an_import(), capture_unlink_and_versions_update(), central_owned_users_refuse_local_mutation_and_leave_local_inventory(), code(), MASTER, NODE (+5 more)

### Community 305 - "Core Checkpoint Validation"
Cohesion: 0.22
Nodes (10): core_or_acceptance(), CoreCheckpoint, is_symlink(), lexists(), mode(), names(), path_sha256(), acceptance() (+2 more)

### Community 306 - "Xray Router Manager Client"
Cohesion: 0.14
Nodes (5): GEODATA_SOURCE_KINDS, Result, ROUTER_CAPABILITIES, ROUTER_SERVICES, XrayRouterClient

### Community 307 - "Panel Archive Extraction Helpers"
Cohesion: 0.17
Nodes (16): AGENT_ROOT, anonymous_file(), DECOMPRESSED_SLACK, handoff_allows(), MAX_PANEL_TREE, not_targz(), PANEL_AGENT_DIR, PANEL_ARCHIVE_PREFIX (+8 more)

### Community 308 - "Service Adapters Installer Reference"
Cohesion: 0.14
Nodes (22): Certificates Adapter, Core Adapter, Firewall Adapter, Mieru Adapter, Naive Adapter, Nginx Adapter, Packages Adapter, 3x-ui Adapter (+14 more)

### Community 309 - "Secrets Store Encryption Tests"
Cohesion: 0.17
Nodes (16): copied_ciphertext_under_another_row_fails(), database_without_key_holds_no_recognisable_secret(), disabled_store_refuses_and_transition_needs_no_key(), every_python_row_decrypts_and_re_encrypts_identically(), fresh(), golden(), golden_rows(), GoldenRow (+8 more)

### Community 310 - "Nginx and VPN Smoke Tests"
Cohesion: 0.14
Nodes (15): NginxProcess, real_nginx_engine_install_repair_uninstall(), action(), agent_managed_vpn_pins_survive_installer_apply_and_repair_without_becoming_owned(), failed_health_rolls_back_through_engine(), golden_renders_and_engine_install_repair_uninstall(), helper_derivation_pins_and_negatives(), legacy_python_checkpoints_remain_usable_without_guessing_forwarding() (+7 more)

### Community 311 - "Mieru Manager Memory Mock"
Cohesion: 0.19
Nodes (3): MemoryMieru, mieru_error(), MieruState

### Community 312 - "HTTP Mock Server Testkit"
Cohesion: 0.16
Nodes (9): FakeServer, Recorded, Reply, Answer, Close, Hang, Script, serve() (+1 more)

### Community 313 - "ISO Datetime Parsing"
Cohesion: 0.20
Nodes (19): Bytes, days_before_year(), days_in_month(), find_separator(), fromisoformat(), Invalid, is_leap(), iso_to_ymd() (+11 more)

### Community 314 - "Application State Authentication"
Cohesion: 0.21
Nodes (6): AppState, blocking(), Principal, Via, ApiKey, Session

### Community 315 - "Metrics API Routes"
Cohesion: 0.19
Nodes (8): AppState, caller(), clients(), history(), live(), MetricsLoop, stream(), summary()

### Community 316 - "Admin Subscription Management"
Cohesion: 0.22
Nodes (15): audit_context(), blocking(), compatibility(), create(), events(), issue(), OWNER_ADMIN, read() (+7 more)

### Community 317 - "Rust Cargo Workspace Crates"
Cohesion: 0.26
Nodes (24): awg-manager, installer, installer-core, mcp-server, mieru-manager, naive-manager, panel-clients, panel-core (+16 more)

### Community 318 - "TDLib Node Dependencies"
Cohesion: 0.11
Nodes (18): dependencies, prebuilt-tdlib@0.1008066.0, tdl@8.1.0, description, engines, node, license, name (+10 more)

### Community 319 - "Drill API Integration Client"
Cohesion: 0.19
Nodes (4): Api, Drill, sha256(), sqlite_online_backup()

### Community 320 - "Fleet Metrics System"
Cohesion: 0.09
Nodes (23): Fleet v2 Architecture, Release 2.0.0, Release 4.0.0, Mita (Mieru Service), Metrics API & SSE Stream, nftables Metrics Table, Version Agent (Host Metrics Agent), GET /api/metrics/live (+15 more)

### Community 321 - "Web Assets and CSP"
Cohesion: 0.10
Nodes (8): ASCII_FOLDS, PYTHON_CSP, SCRIPT, STYLE, additive_4_0_keys(), binaries_are_checked_after_extraction(), golden_release(), reads_the_identity_build_py_stamps()

### Community 322 - "Naive Manager Errors"
Cohesion: 0.11
Nodes (13): Error, Conflict, EgressInvalid, EgressUnreachable, Key, LanesInvalid, NotFound, Os (+5 more)

### Community 323 - "Application Settings Management"
Cohesion: 0.15
Nodes (9): debug_hides_tokens(), DEFAULT_VERSION_FILE, Env, Lookup, Settings, SettingsError, Invalid, NotUnicode (+1 more)

### Community 324 - "NaiveProxy Client Management"
Cohesion: 0.15
Nodes (6): egress_direct(), NAIVE_EGRESS_CAPABILITIES, NaiveClient, optional(), Result, segment_slash()

### Community 325 - "Admin Authentication Routes"
Cohesion: 0.21
Nodes (16): add_cookie(), add_admin(), admins(), audit_log(), edit_admin(), favicon(), healthz(), index() (+8 more)

### Community 326 - "TLS Certificate Issuance Tests"
Cohesion: 0.26
Nodes (14): action(), completed_interrupted_issuance_is_reused_and_partial_issuance_replaced(), Faults, foreign_incomplete_lineage_and_post_prepare_appearance_are_never_adopted(), Host, ineffective_or_drifted_owned_vhost_never_verifies_or_is_deleted(), invalid_private_key_or_certificate_contract_never_verifies(), renewal_failure_is_fatal_and_diagnostics_do_not_leak_acme_output() (+6 more)

### Community 327 - "Node Management Routes"
Cohesion: 0.21
Nodes (10): answer(), AppState, audit_context(), disable(), enable(), failure(), list(), one() (+2 more)

### Community 328 - "IP Address Utilities"
Cohesion: 0.24
Nodes (8): IpAddress, V4, V6, v4(), v4_in(), v4_is_global(), v4_is_private(), v6_in()

### Community 329 - "Process Supervision"
Cohesion: 0.15
Nodes (7): shutdown_signal(), ProcessSupervisor, signal(), starts_reloads_and_stops_a_real_process(), STOP_TIMEOUT, Supervisor, wait_for()

### Community 330 - "Node Import Models"
Cohesion: 0.10
Nodes (14): NodeFingerprint, .TITLE, NodeImport, .TITLE, NodeImportItem, .TITLE, NodeLinkCreate, .TITLE (+6 more)

### Community 332 - "Fleet Acceptance Testing"
Cohesion: 0.10
Nodes (5): _run(), test_naive_probe_retries_a_cut_connection_but_not_a_refusal(), test_routing_scenarios_are_opt_in_and_sit_after_the_grants(), test_scenario_report_is_secret_free_and_stops_the_central_on_failure(), test_scenario_runs_all_eleven_steps_on_fakes()

### Community 333 - "Operations Documentation"
Cohesion: 0.10
Nodes (21): Accounting Documentation, AI Agent Working Protocol, Backup Contract, Caddy NaiveProxy Build, Proxy Control Operations Runbook (English), Proxy Control Operations Runbook (Russian), Fleet v2 Sync Architecture, Fleet Guide (v2) (+13 more)

### Community 334 - "AmneziaWG Port Allocation"
Cohesion: 0.19
Nodes (16): bound_ports(), derive_port(), derive_port_matches_python(), ENV_OVERLAY, hostname(), installed_ports(), machine_id(), MAX_ATTEMPTS (+8 more)

### Community 335 - "Naive Manager State"
Cohesion: 0.14
Nodes (17): conflict(), encode_state(), equals_one(), exact_int(), is_operation_id(), is_quota(), normalise(), OPERATION_RETENTION_SECONDS (+9 more)

### Community 336 - "Binary Identity Verification"
Cohesion: 0.16
Nodes (14): AGENT_BINARY, binaries(), Builder, builder(), IDENTITY_PATH, IdentityError, Incomplete, Invalid (+6 more)

### Community 337 - "Client Rate Limiting"
Cohesion: 0.19
Nodes (11): a_windowed_rate_spreads_a_burst_over_the_window_and_decays_to_zero(), bools_strings_and_negatives_are_not_counters(), client_rates_baseline_reset_and_forgetting(), ClientRate, ClientRates, fold(), Key, Last (+3 more)

### Community 338 - "AmneziaWG Acceptance Script"
Cohesion: 0.20
Nodes (19): AMNEZIAWG_PUBLIC_HOST, api(), AWG_MANAGER_STATE_DIR, AWG_MANAGER_TOKEN_FILE, bad(), body_of(), check(), cleanup() (+11 more)

### Community 339 - "AmneziaWG Panel E2E Tests"
Cohesion: 0.20
Nodes (19): AMNEZIAWG_PUBLIC_HOST, api(), AWG_MANAGER_STATE_DIR, AWG_MANAGER_TOKEN_FILE, bad(), body_of(), check(), cleanup() (+11 more)

### Community 340 - "Archive Extraction Utilities"
Cohesion: 0.20
Nodes (16): ArtifactError, error(), escaping_members_unknown_formats_and_garbage_are_refused(), extract_member(), from_tar(), from_zip(), MAX_MEMBER, normalized() (+8 more)

### Community 341 - "Operational Runbooks and Contracts"
Cohesion: 0.11
Nodes (20): Accounting Contract, Backup and Restore Contract (RU), Proxy Control Operations Runbook (EN), Proxy Control Operations Runbook (RU), Egress Policy Management, Fleet v2 Node Operations, Mieru Protocol Operations, Telemt MTProxy Acceptance (+12 more)

### Community 342 - "Routing Presets Service"
Cohesion: 0.19
Nodes (11): a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset(), every_preset_is_a_valid_rule_and_the_ids_are_distinct(), preset(), preset_ids(), presets(), regional_presets_name_the_geodata_source_their_codes_need(), rule_for(), a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset() (+3 more)

### Community 343 - "Updater Integration Tests"
Cohesion: 0.15
Nodes (7): Answer, Host, read(), sha(), tail(), text(), version_text()

### Community 344 - "Panel Client Integration"
Cohesion: 0.16
Nodes (7): compact(), CONNECT_TIMEOUT, failure_name(), PanelError, present(), TIMEOUT, unreachable()

### Community 345 - "Installer Error Handling"
Cohesion: 0.17
Nodes (9): class_names_and_fatality(), Error, Fatal, Other, Plan, Tx, libc_enoent(), ownership() (+1 more)

### Community 346 - "Fleet Architecture Specifications"
Cohesion: 0.12
Nodes (18): 003-one-writer-per-resource.md, BACKUP_RESTORE.en.md, Central API (/api/nodes/*), Proxy Control Fleet v2 Overview, Fleet Security & Scoping Model, Generation Document Synchronization, Heartbeat and Health Delivery Loop, Node API v2 (/api/fleet/v2/*) (+10 more)

### Community 347 - "Core Services Acceptance"
Cohesion: 0.12
Nodes (9): acceptance_checks_every_fact(), CoreAcceptance, healthy_services(), probe_key(), require_acceptance(), collision(), TestAcceptance, AcceptanceMock (+1 more)

### Community 348 - "In-Memory AmneziaWG State"
Cohesion: 0.27
Nodes (3): AmneziawgState, awg_error(), MemoryAmneziawg

### Community 349 - "Manager Golden Tests"
Cohesion: 0.18
Nodes (14): agent(), agent_error(), cases(), dispatch(), every_python_case_gives_the_same_outcome_and_request(), manager_error(), ok(), python_crash_expectation() (+6 more)

### Community 350 - "Routing Lanes Route Tests"
Cohesion: 0.19
Nodes (12): _attach(), _csrf(), _grant(), router(), _subscription(), test_a_grant_gets_its_own_lane_and_loses_it_again(), test_a_lane_policy_with_rules_applies_as_one_intent_with_the_service(), test_deleting_a_laned_grant_drops_the_lane_first() (+4 more)

### Community 352 - "TrustTunnel Manager State"
Cohesion: 0.19
Nodes (12): Client, corrupt_or_foreign_state_is_refused(), Document, Egress, EgressDocument, MAX_OPERATIONS, Operation, operations_keep_order_and_the_oldest_are_pruned() (+4 more)

### Community 353 - "Environment File Parser"
Cohesion: 0.19
Nodes (14): append(), decodes_quoted_paths_continuations_and_literal_shell_characters(), horizontal(), invalid(), key_is_valid(), malformed_values_fail_without_echoing_the_secret(), Mode, Double (+6 more)

### Community 354 - "MTProxy Dockerfile Setup"
Cohesion: 0.11
Nodes (18): context, dockerfile, mtproxy, condition, build, cap_add, cap_drop, container_name (+10 more)

### Community 355 - "Monitoring Live Checks"
Cohesion: 0.24
Nodes (13): agent_metrics(), check(), info(), main(), panel_db(), panel_host(), phase_agent(), phase_degraded() (+5 more)

### Community 356 - "Credential and Report Testing"
Cohesion: 0.20
Nodes (12): CLIENT_UUID, fact_map(), handoff_with_secrets(), MANAGER_TOKEN, PANEL_PASSWORD, public_report_and_credential_handoff_are_schema_disjoint(), public_report_is_world_readable_and_the_handoff_directory_is_not(), public_report_keeps_only_named_acceptance_facts() (+4 more)

### Community 357 - "Core Adapter Acceptance"
Cohesion: 0.27
Nodes (3): CoreAdapter, PanelSession, trim_ascii_whitespace()

### Community 358 - "Nginx Regression Tests"
Cohesion: 0.27
Nodes (11): active_route_topology_drift_blocks_verify_and_rollback(), coexist_replay_and_rollback_preserve_adjacent_routes_and_symlink_metadata(), corrupt_or_unbound_checkpoint_never_mutates_selected_file(), failed_validation_restores_exact_bytes_without_reload(), Host, interrupted_apply_recovers_backup_but_refuses_a_missing_backup(), ORIGINAL, path_identity_changes_refuse_before_apply_verify_or_rollback() (+3 more)

### Community 359 - "Mieru Manager Service"
Cohesion: 0.16
Nodes (8): env(), env_optional(), health_probe(), healthcheck(), main(), MITA, run(), Mita

### Community 360 - "Protocol Egress Targets"
Cohesion: 0.21
Nodes (10): EGRESS_ERROR_CODES, egress_target_from_view(), EgressTarget, providers(), revision_of(), router_target_from_view(), strings(), attached_to_router() (+2 more)

### Community 361 - "IDNA Domain Processing"
Cohesion: 0.18
Nodes (9): check_length(), encode(), IdnaError, in_table(), is_digit(), nameprep(), to_ascii(), NameCollision (+1 more)

### Community 363 - "Metrics Port Discovery"
Cohesion: 0.15
Nodes (7): discover_in(), env_reader_is_injectable(), files(), mieru_ports_from_mita_config_and_lane_slots(), naive_and_trusttunnel_only_with_their_overlay(), override_replaces_and_adds(), sources()

### Community 364 - "Installer Audit Tests"
Cohesion: 0.21
Nodes (9): config_of(), golden(), read_json(), recorded_install_audits_are_reproduced(), recorded_plan_audits_are_reproduced(), Replay, replay(), SimResolver (+1 more)

### Community 365 - "AmneziaWG Forwarding Service"
Cohesion: 0.13
Nodes (16): deploy/awg-forward.service, Release v1.1.4, Release v1.2.0, Release v1.2.1, Release v1.3.0, Release v1.3.1, Release v1.3.2, Release v1.3.3 (+8 more)

### Community 367 - "Mieru Setup and Operations"
Cohesion: 0.17
Nodes (12): mieru-manager, mita, check_rule(), mieru-mss-clamp.sh script, usage(), fail(), MIERU_GID, MIERU_MODE (+4 more)

### Community 368 - "Issue Template Configuration"
Cohesion: 0.12
Nodes (16): description, label, options, value, body, attributes, id, type (+8 more)

### Community 369 - "MCP Server Configuration"
Cohesion: 0.15
Nodes (13): Config, config_reads_secrets_from_files_and_requires_allowed_hosts(), DEFAULT_BIND, DEFAULT_PANEL_KEY_FILE, DEFAULT_PANEL_URL, DEFAULT_TOKEN_FILE, MIN_TOKEN_LENGTH, PANEL_HOST (+5 more)

### Community 370 - "Python Compatible IP Parser"
Cohesion: 0.22
Nodes (13): address_version(), ascii_digits(), is_address(), is_network(), network_str(), parse_hextet(), parse_v4(), parse_v6() (+5 more)

### Community 371 - "MTProxy Container Specification"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 372 - "MTProxy Container Configuration"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 373 - "MTProxy Service Configuration"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 374 - "MTProxy Compose Configuration"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 375 - "MTProxy Container Deployment"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 376 - "MTProxy Compose Specification"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 377 - "MTProxy Container Settings"
Cohesion: 0.12
Nodes (17): context, mtproxy, condition, build, cap_add, cap_drop, container_name, depends_on (+9 more)

### Community 378 - "Compose Migration Tests"
Cohesion: 0.26
Nodes (13): host(), _nothing_stopped(), _run(), _set(), _state(), test_a_bind_source_the_host_lacks_refuses_before_anything_stops(), test_a_failed_start_brings_the_old_project_back_and_drops_the_copies(), test_a_missing_compose_file_refuses_before_anything_stops() (+5 more)

### Community 379 - "Version Agent Golden Tests"
Cohesion: 0.21
Nodes (13): golden(), golden_agent(), golden_bytes(), golden_json(), NOW, recorded_calls(), Simulated, simulated_host() (+5 more)

### Community 380 - "Panel File Ownership"
Cohesion: 0.17
Nodes (11): collect_owned_files(), compose_publishes_telemt_api(), cover_text(), owned_path_in_scope(), ownership_entry(), panel_vhost(), rebased_panel_path(), rendered_env() (+3 more)

### Community 382 - "Core API Errors"
Cohesion: 0.17
Nodes (8): ApiError, Coded, Detail, Routing, Validation, bodies_have_the_four_shapes(), error_codes!, validation_issues_match_fastapi()

### Community 383 - "Python Text Parsing Tests"
Cohesion: 0.29
Nodes (13): fixture(), int_and_float_parsing(), ip_address_parsing_text_and_tables(), isprintable(), len_and_slices(), nfc_and_nfkc(), quote_quote_plus_and_unquote(), repr_and_lower() (+5 more)

### Community 384 - "Service Golden Comparison Tests"
Cohesion: 0.23
Nodes (12): view_to_value(), bytes(), cli_node_list_is_byte_identical(), context(), Golden, golden(), mutations_inserts_and_their_rows_match(), node_ids() (+4 more)

### Community 385 - "Subscription Format Converters"
Cohesion: 0.14
Nodes (9): truthy(), Format, .ALL, Clash, Html, Manifest, Raw, Singbox (+1 more)

### Community 386 - "Installation Hook Handlers"
Cohesion: 0.16
Nodes (14): Failure, Io, Release, Hook, AfterAnchor, AfterVerifiedCopy, CopyMember, RemoveTree (+6 more)

### Community 387 - "QEMU Release Artifact Tests"
Cohesion: 0.17
Nodes (4): _passing_report(), ReleaseArtifactTests, ReleaseMatrixTests, report_without()

### Community 388 - "Managed X-UI Client Tests"
Cohesion: 0.17
Nodes (8): test_cleanup_signals_process_group_even_if_leader_exited(), test_hysteria_requires_lazy_auth_in_both_variants(), test_preflight_refuses_unrelated_route_or_noncredential_change(), test_preflight_requires_all_positive_negative_configs_and_distinct_ports(), test_preflight_requires_root_private_manifest_and_configs(), test_run_reports_per_case_differential_without_credentials(), test_vless_wrong_credential_must_remain_valid_uuid(), _valid_manifest()

### Community 389 - "Nftables Counter Parsing"
Cohesion: 0.15
Nodes (8): F, Nft, NftUnavailable, parse_counters(), SystemNft, FakeNft, FakeNftState, golden_parse_counters()

### Community 390 - "Xray Router IP Handling"
Cohesion: 0.23
Nodes (11): HEX_DIGITS, is_ip_address(), mask_v6(), network(), parse_hextet(), parse_v4(), parse_v6(), prefix_from_string() (+3 more)

### Community 391 - "Web Health Check Probes"
Cohesion: 0.16
Nodes (6): exchange(), probe(), run(), std::os::unix::net::UnixStream, TIMEOUT, Timeouts

### Community 392 - "Docker Container Hardening"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 393 - "Xray Router Environment Variables"
Cohesion: 0.13
Nodes (15): TMPDIR, XRAY_ROUTER_BIN_DIR, XRAY_ROUTER_EGRESS_WARP, XRAY_ROUTER_GEOIP_SHA256, XRAY_ROUTER_GEOSITE_SHA256, XRAY_ROUTER_INGRESS_MIERU_FILE, XRAY_ROUTER_INGRESS_NAIVE_FILE, XRAY_ROUTER_MANAGER_TOKEN_FILE (+7 more)

### Community 394 - "Node Lifecycle Tests"
Cohesion: 0.33
Nodes (12): migrated(), service_at(), a_failed_mutation_leaves_neither_row_nor_audit(), a_linked_panel_is_paused_not_disabled(), add_node(), count(), ctx(), disable_refuses_while_commands_are_pending() (+4 more)

### Community 395 - "Database Snapshot v0.4"
Cohesion: 0.21
Nodes (14): admins, audit_log, audit_log_request, fleet_certificates, fleet_commands, fleet_commands_node_sequence, fleet_nodes, login_attempts (+6 more)

### Community 396 - "Database Snapshot v0.5"
Cohesion: 0.21
Nodes (14): admins, audit_log, audit_log_request, fleet_certificates, fleet_commands, fleet_commands_node_sequence, fleet_nodes, login_attempts (+6 more)

### Community 397 - "Credential Reconciliation State"
Cohesion: 0.15
Nodes (13): credentials(), delete_refuses_provisioned_and_pending_deleted_grants_before_any_unlink(), deletion_report_after_202_purges_tombstone_and_frees_name_for_regrant(), drift_report_does_not_infer_runtime_from_the_centrals_clock(), empty_publish_is_durable_and_older_ack_never_clears_newer_dirty_intent(), old_or_applying_report_never_escrows_or_confirms_rotated_version(), report(), report_for_previous_credential_reference_cannot_resurrect_retiring_version() (+5 more)

### Community 398 - "Query Parameter Parsing"
Cohesion: 0.25
Nodes (11): bounded_int(), last_value_wins_and_blank_values_are_kept(), loc(), parse_digits(), Parsed, Big, Int, Query (+3 more)

### Community 399 - "Local Manager State Registry"
Cohesion: 0.15
Nodes (8): LocalManager, .ALL, Amneziawg, Mieru, Naive, Telemt, Trusttunnel, NodesState

### Community 400 - "Compatibility Matrix Specification"
Cohesion: 0.20
Nodes (14): cell(), CLIENTS, compatibility_matrix_follows_the_fixture_and_never_claims_telegram_auto_refresh(), fixture(), MATRIX, matrix_json(), note(), NOTES (+6 more)

### Community 401 - "Live Connection Management"
Cohesion: 0.38
Nodes (14): backoffDelay(), connectLive(), clearTimers(), deliver(), fallToPolling(), guard(), onVisibility(), openStream() (+6 more)

### Community 402 - "Client Link Reveal Tests"
Cohesion: 0.24
Nodes (9): _client_with_grants(), _reveal(), test_a_clients_mtproxy_grants_come_back_as_links_with_a_qr(), test_a_deleted_grant_is_not_handed_out_again(), test_a_grant_of_another_client_is_not_revealed(), test_one_grant_is_revealed_alone_with_a_qr_for_its_link(), test_only_the_protocol_the_screen_shows_is_decrypted(), test_showing_the_links_is_audited_without_the_secret() (+1 more)

### Community 403 - "Version Update Agent Tests"
Cohesion: 0.22
Nodes (11): test_host_resources_are_polled_alone_and_follow_the_agent(), test_host_resources_report_a_reason_when_the_agent_is_silent(), test_overview_degrades_to_a_reason_when_the_host_agent_is_silent(), test_overview_reports_host_resources_from_the_agent(), test_owner_checks_upstream_and_sees_the_candidate(), test_owner_rebuilds_pending_managers_viewer_cannot_and_a_running_update_is_409(), test_owner_updates_the_panel_itself_and_the_answer_is_async(), test_version_update_rejects_viewer() (+3 more)

### Community 404 - "Secret Scrubbing Validator"
Cohesion: 0.19
Nodes (5): assert_secret_free(), walk(), mtproxy_secret(), Check, Panel

### Community 405 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 406 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 407 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 408 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 409 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 410 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 411 - "Container Service Configuration"
Cohesion: 0.13
Nodes (15): mask, condition, cap_drop, container_name, depends_on, entrypoint, expose, image (+7 more)

### Community 412 - "Manager Build Host"
Cohesion: 0.22
Nodes (12): a_failed_build_restores_the_override_and_the_image_and_proves_the_old_version(), a_rebuild_that_reports_another_version_is_rolled_back(), a_trusttunnel_update_needs_an_x86_64_host(), an_update_rebuilds_the_manager_with_build_args_and_keeps_the_other_overrides(), BuildHost, Built, compose_commands_carry_the_mcp_overlay_and_the_panel_sync_ships_its_file(), manager_agent() (+4 more)

### Community 413 - "Xray Router Manager Errors"
Cohesion: 0.15
Nodes (11): Error, ArtifactMismatch, Conflict, EgressInvalid, EgressUnreachable, Geodata, Internal, Manual (+3 more)

### Community 414 - "Naive Manager Configuration"
Cohesion: 0.21
Nodes (8): build_manager(), Config, defaults_and_optional_providers(), from_env(), get(), optional(), QUOTA_INTERVAL_SECONDS, QUOTA_MAX_BACKOFF_SECONDS

### Community 415 - "Xray Router Ingress Service"
Cohesion: 0.14
Nodes (14): XRAY_ROUTER_BRIDGE_LISTEN, XRAY_ROUTER_INGRESS_MTPROXY_SOCKET, xray-router-ingress, cap_drop, container_name, entrypoint, environment, expose (+6 more)

### Community 416 - "Version Management API Routes"
Cohesion: 0.24
Nodes (5): agent_failure(), check_versions(), list_versions(), rebuild_managers(), update_version()

### Community 417 - "Secret Staging CLI Tests"
Cohesion: 0.21
Nodes (5): is_root(), stage_secret_rejects_invalid_source_without_creating_destination(), stage_secret_stages_real_file_with_private_metadata(), the_command_prints_python_messages_and_exits_64(), write_source()

### Community 419 - "Mieru Manager Errors"
Cohesion: 0.19
Nodes (9): Error, Conflict, EgressInvalid, EgressUnreachable, Internal, LanesInvalid, Mita, Validation (+1 more)

### Community 421 - "IP Address Parsing Utilities"
Cohesion: 0.21
Nodes (12): format_v4(), format_v6_hextets(), ip_address(), parse_hextet(), parse_octet(), parse_v4(), parse_v6(), V4_PRIVATE (+4 more)

### Community 422 - "Frontend Internationalization System"
Cohesion: 0.29
Nodes (12): applyLanguage(), ATTRIBUTES, compile(), escapeRegExp(), LANGS, observe(), paintSwitch(), remember() (+4 more)

### Community 423 - "Panel Host Mocking"
Cohesion: 0.16
Nodes (8): answer(), hex_id(), Intercept, iso(), now(), panel_image_id(), PanelHost, State

### Community 424 - "Protocol Route Audit Tests"
Cohesion: 0.18
Nodes (7): golden(), manager_error_bodies_and_down_overviews_match_python(), OWNER_PASSWORD, audit_registered_route_gates_over_http(), concrete_path(), observed(), PUBLIC

### Community 425 - "Core Compose Base Config"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 426 - "Security Hardened Container Options"
Cohesion: 0.15
Nodes (13): cap_add, cap_drop, container_name, devices, network_mode, pids_limit, read_only, restart (+5 more)

### Community 427 - "AmneziaWG Environment Variables"
Cohesion: 0.15
Nodes (13): environment, AWG_DNS, AWG_EGRESS_ROUTER_TUN, AWG_EGRESS_ROUTER_UID, AWG_LOG_LEVEL, AWG_MANAGER_SOCKET_MODE, AWG_MANAGER_TOKEN_FILE, AWG_MTU (+5 more)

### Community 428 - "MTProxy Container Configuration"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 429 - "Xray Router Panel Compose"
Cohesion: 0.15
Nodes (13): xray-router, PANEL_SUPPLEMENTARY_GROUPS, XRAY_ROUTER_ENABLED, XRAY_ROUTER_MANAGER_SOCKET, XRAY_ROUTER_MANAGER_TOKEN_SOURCE, depends_on, environment, group_add (+5 more)

### Community 430 - "Client Verification Matrix"
Cohesion: 0.15
Nodes (13): auth-session, client-delete, client-placement-matrix, clients-and-grants, health-and-static, Verification Matrix, provisioning-saga, readiness-diagnostic (+5 more)

### Community 431 - "GitHub Security Form Schema"
Cohesion: 0.15
Nodes (12): label, options, value, body, attributes, id, type, description (+4 more)

### Community 432 - "Release Workflow Inputs"
Cohesion: 0.15
Nodes (13): description, required, type, expected_sha256, version, tags, True, push (+5 more)

### Community 433 - "Mieru Manager HTTP Server"
Cohesion: 0.29
Nodes (10): body(), conflict_code(), error_response(), exact(), handler(), MAX_BODY, not_found(), route() (+2 more)

### Community 434 - "Mock Time Clock"
Cohesion: 0.26
Nodes (3): fake_clock_moves_only_when_told(), FakeClock, .MONOTONIC_OFFSET

### Community 435 - "Managed Route Guard Middleware"
Cohesion: 0.21
Nodes (7): GuardError, Db, Managed, MANAGED_DETAIL, MANAGED_REASON, REASON_HEADER, require_unmanaged()

### Community 436 - "Python-Compatible Float Math"
Cohesion: 0.15
Nodes (5): float(), floordiv(), int(), opt_int(), truthy()

### Community 438 - "Process Execution Utilities"
Cohesion: 0.23
Nodes (8): captures_output_and_stdin(), kills_at_the_deadline(), run(), run_command(), RunError, Io, Spawn, Timeout

### Community 439 - "URL Parsing Utilities"
Cohesion: 0.26
Nodes (6): C0_CONTROL_OR_SPACE, join(), remove_dot_segments(), split(), split_matches_urllib(), SplitResult

### Community 440 - "Panel Performance Profiling"
Cohesion: 0.18
Nodes (6): cpu_ticks(), Panel, phase_perf(), sse(), hold(), reveal()

### Community 441 - "Coexist Ingress Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 442 - "Coexist MTProxy Service Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 443 - "Coexist Ingress Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 444 - "Direct Core Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 445 - "Direct MTProxy Service Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 446 - "Direct Core Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 447 - "Egress Swapped Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 448 - "Egress Swapped MTProxy Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 449 - "Egress Swapped Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 450 - "Existing 3X-UI Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 451 - "Existing 3X-UI MTProxy Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 452 - "Existing 3X-UI Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 453 - "Kitchen Sink Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 454 - "Kitchen Sink MTProxy Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 455 - "Kitchen Sink Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 456 - "Managed 3X-UI Compose Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 457 - "Managed 3X-UI MTProxy Config"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 458 - "Managed 3X-UI Panel Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 459 - "Managed 3X-UI Warp Deployment"
Cohesion: 0.15
Nodes (12): file, name, file, secrets, mtproxy-secrets, panel-master-key, telemt-api-token, services (+4 more)

### Community 460 - "Managed 3X-UI Warp MTProxy"
Cohesion: 0.15
Nodes (13): aliases, MTPROXY_DOMAIN, container_name, environment, image, init, networks, read_only (+5 more)

### Community 461 - "Managed 3X-UI Warp Environment"
Cohesion: 0.15
Nodes (13): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+5 more)

### Community 462 - "Panel Service Core Environment"
Cohesion: 0.17
Nodes (12): PANEL_ALLOWED_HOSTS, PANEL_COOKIE_SECURE, PANEL_DATABASE, PANEL_HEALTHCHECK_HOST, PANEL_SINGBOX_FORK_CLIENTS, PANEL_SUBSCRIPTION_HOST, PANEL_SUBSCRIPTION_URL, PANEL_SUPPLEMENTARY_GROUPS (+4 more)

### Community 463 - "Mieru Compose Volume Secrets"
Cohesion: 0.17
Nodes (11): device, o, type, driver_opts, file, name, secrets, mieru-manager-token (+3 more)

### Community 464 - "Mieru Panel Compose Integration"
Cohesion: 0.17
Nodes (12): mieru-manager, MIERU_ENABLED, MIERU_MANAGER_SOCKET, MIERU_MANAGER_TOKEN_SOURCE, PANEL_SUPPLEMENTARY_GROUPS, condition, depends_on, environment (+4 more)

### Community 465 - "Mieru Manager Container Spec"
Cohesion: 0.17
Nodes (12): cap_drop, container_name, group_add, network_mode, pids_limit, read_only, restart, secrets (+4 more)

### Community 466 - "Naive Compose Volume Secrets"
Cohesion: 0.17
Nodes (11): device, o, type, driver_opts, file, name, secrets, naive-manager-token (+3 more)

### Community 467 - "Xray Router Container Spec"
Cohesion: 0.17
Nodes (12): xray-router, cap_drop, container_name, devices, network_mode, pids_limit, read_only, restart (+4 more)

### Community 468 - "GitHub Actions Release Step"
Cohesion: 0.17
Nodes (12): with, draft, fetch-depth, files, if-no-files-found, name, path, persist-credentials (+4 more)

### Community 469 - "Naive Manager IP Network"
Cohesion: 0.33
Nodes (10): ip_network(), parse_hextet(), parse_octet(), parse_v4(), parse_v6(), prefix_digits(), prefix_of_mask(), v4_network() (+2 more)

### Community 470 - "System Clock Utilities"
Cohesion: 0.20
Nodes (4): Arc<C>, Clock, system_clock_is_sane(), SystemClock

### Community 472 - "Client Grant Model Tests"
Cohesion: 0.23
Nodes (5): a_grant_round_trips_through_its_dump_with_typed_options(), client(), grant(), grants_check_their_label_and_options(), suspended_client_compiles_every_grant_as_disabled()

### Community 473 - "HTTP Client Utilities"
Cohesion: 0.33
Nodes (8): ClientResponse, dechunk(), health_probe(), parse_response(), request(), serve_once(), tcp_get(), tcp_get_reads_plain_and_chunked_bodies()

### Community 474 - "Common Python Text Helpers"
Cohesion: 0.18
Nodes (4): ascii_int_parts(), repr_with_printable(), strip(), printable()

### Community 475 - "3X-UI Lab Acceptance Scripts"
Cohesion: 0.26
Nodes (8): fail(), main(), provision(), require_clean_host(), managed-xui-acceptance.sh script, wait_for_port(), tests/lab/fixtures/nginx-multi-map.conf, three-xui-existing.sh script

### Community 479 - "Mieru Manager Environment Config"
Cohesion: 0.18
Nodes (11): MIERU_EGRESS_ROUTER, MIERU_EGRESS_ROUTER_CREDENTIAL_FILE, MIERU_EGRESS_WARP, MIERU_LANE_SLOTS, MIERU_MANAGER_TOKEN_FILE, MIERU_MITA_SHA256, MIERU_PUBLIC_HOST, MIERU_SOCKET_MODE (+3 more)

### Community 480 - "Naive Manager Service Configuration"
Cohesion: 0.18
Nodes (11): naive-manager, NAIVE_ENABLED, NAIVE_MANAGER_SOCKET, NAIVE_MANAGER_TOKEN_SOURCE, NAIVE_PUBLIC_HOST, condition, depends_on, environment (+3 more)

### Community 481 - "Naive Manager Container Hardening"
Cohesion: 0.18
Nodes (11): cap_drop, container_name, group_add, network_mode, read_only, restart, security_opt, tmpfs (+3 more)

### Community 482 - "TrustTunnel Environment Variables"
Cohesion: 0.18
Nodes (11): TT_BINARY, TT_CERT, TT_HOSTNAME, TT_KEY, TT_LISTEN, TT_MANAGER_SOCKET, TT_MANAGER_SOCKET_MODE, TT_MANAGER_TOKEN_FILE (+3 more)

### Community 483 - "TrustTunnel Manager Security Settings"
Cohesion: 0.18
Nodes (11): trusttunnel-manager, cap_drop, container_name, network_mode, pids_limit, read_only, restart, secrets (+3 more)

### Community 484 - "System Compatibility & Contracts"
Cohesion: 0.18
Nodes (11): Compatibility Policy, Fleet v2 API (/api/fleet/v2/*), GenerationDocument (schema_version: 1), Lanes and Chains Contract, Monitoring (v2.0), MTProxy Routing (v1.1), ObservedGeneration, Panel-to-Panel Contract (Frozen) (+3 more)

### Community 485 - "Feature Releases and Integrations"
Cohesion: 0.20
Nodes (11): Client Search & Filters, Grant Link API Endpoint, Access Grant Window, Release v1.0.2, Self-Verifying Release Install Script, Installation Wizard Defaults & Fixes, Release v1.0.3, MTProxy Xray-Router Integration (+3 more)

### Community 486 - "CI Workflow Step Definition"
Cohesion: 0.25
Nodes (11): steps, steps, steps, GH_TOKEN, steps, steps, env, id (+3 more)

### Community 487 - "Network CIDR Matching Utilities"
Cohesion: 0.25
Nodes (3): membership_ignores_the_scope(), Network, PRIVATE_NETWORKS

### Community 488 - "Database Schema Snapshot"
Cohesion: 0.27
Nodes (10): admins, audit_log, fleet_certificates, fleet_commands, fleet_commands_node_sequence, fleet_nodes, login_attempts, login_attempts_scope_time (+2 more)

### Community 489 - "Web UI Dialogs & Interfaces"
Cohesion: 0.22
Nodes (11): Administrator Management Dialog, Client Creation Dialog, Custom Outbound Exit Dialog, Geodata Configuration Dialog, API Key Creation Dialog, Node Linking Dialog, Mieru Access Dialog, Panel Web UI (index.html) (+3 more)

### Community 491 - "Environment Preflight Diagnostics"
Cohesion: 0.27
Nodes (11): archive_integrity(), case_run(), case_skip(), container_environment_preflight(), emit(), emit_plan_digest(), host_diagnostics(), host_environment_preflight() (+3 more)

### Community 492 - "Ingress Secret Rotation Scripts"
Cohesion: 0.27
Nodes (10): compose(), fail(), MIERU_MANAGER_UID, NAIVE_MANAGER_GID, NAIVE_MANAGER_UID, random_hex(), random_password(), ROUTER_GID (+2 more)

### Community 494 - "Xray Router Diff Engine"
Cohesion: 0.24
Nodes (4): changed_lines(), GOLDEN, Matcher, Matcher<'a>

### Community 495 - "Routing Architecture Documentation"
Cohesion: 0.22
Nodes (10): ADR 006: Routing Policy IR, Fleet Guide, Proxy Control Documentation Index, Release v4.0.0, Proxy Control Routing Guide (English), Egress Policy Engine, Xray-router Backend, Spike: vNext Routing Engine (+2 more)

### Community 496 - "Python Web Golden Tests"
Cohesion: 0.27
Nodes (4): file_response_stat_headers_match_python(), fixture(), json_loads_matches_python(), mimetypes_match_the_image()

### Community 497 - "GitHub Workflow Permissions Setup"
Cohesion: 0.20
Nodes (10): permissions, permissions, needs, permissions, runs-on, timeout-minutes, draft-release, attestations (+2 more)

### Community 498 - "Fleet Wire Replay Tests"
Cohesion: 0.40
Nodes (6): node_side_refusals_answer_the_recorded_bodies(), push(), render(), replay_node(), the_recorded_wire_replays_byte_for_byte(), golden()

### Community 499 - "Cryptographic Token & ID Helpers"
Cohesion: 0.36
Nodes (7): hex(), random_bytes(), sha256_hex(), token_hex(), token_urlsafe(), uuid4(), uuid4_has_python_shape()

### Community 500 - "Python Number Compatibility Parser"
Cohesion: 0.31
Nodes (6): compare(), compare_keeps_python_number_types_and_order(), or_zero(), PyNum, Float, Int

### Community 501 - "Secure Zip Archive Extraction"
Cohesion: 0.40
Nodes (9): MemberPin, safe_extract_zip_default(), pins(), safe_extract_zip_extracts_named_members_only(), safe_extract_zip_rejects_member_digest_mismatch(), safe_extract_zip_rejects_missing_member_and_bad_names(), safe_extract_zip_rejects_oversized_and_undersized_members(), safe_extract_zip_replaces_a_previous_install_atomically() (+1 more)

### Community 502 - "Wizard Setup and Profiles"
Cohesion: 0.20
Nodes (9): AmneziaWG, TrustTunnel, invalid-inputs.stdout.txt fixture, Proxy Control Wizard CLI, Wizard Configurable Fields, Wizard Domain Uniqueness Validation, Host Mode (fresh / coexist), Proxy Control Profiles (core / core-naive / core-mieru / full) (+1 more)

### Community 504 - "AmneziaWG Server API Handlers"
Cohesion: 0.33
Nodes (4): handler(), MAX_BODY, route(), TOKEN_HEADER

### Community 505 - "Xray Router Compose Service"
Cohesion: 0.22
Nodes (8): device, o, type, name, services, volumes, xray-router-run, driver_opts

### Community 506 - "Runtime Settings Golden Tests"
Cohesion: 0.28
Nodes (3): as_python(), every_python_environment_gives_the_same_settings(), token_dir()

### Community 507 - "Fleet Lifecycle & Installation Guides"
Cohesion: 0.22
Nodes (9): Fleet Delivery & Backoff, Fleet Heartbeat Cycle, Existing Users Import, Fleet Access Lifecycle (Rotation, Unlink, Delete), Fleet Security Model, install-release.sh Bootstrap Script, Installer Lifecycle Phases, External MTProto TDLib Probe (+1 more)

### Community 508 - "Protocol Integration Guides"
Cohesion: 0.28
Nodes (7): Multi-protocol Access Grant Operation, Nodes Screen, Routing Screen, Subscription Endpoint (/s/{token}), User Guides README, TrustTunnel Routing Integration, Sing-box TrustTunnel Subscription Feed

### Community 509 - "TrustTunnel Integration and Deployment"
Cohesion: 0.25
Nodes (8): sing-box Forks with TrustTunnel Outbound, TrustTunnel VPN Protocol, trusttunnel_endpoint, trusttunnel-manager, TrustTunnel Xray-Router Integration, v1.6.0 Release, enable-trusttunnel.sh script, usage()

### Community 510 - "Panel Release Notes & History"
Cohesion: 0.22
Nodes (9): Clients UI Screenshot (v1.0.0), Release Notes v3.2.1, NekoBox Subscription Profile, Client Permanent Deletion Flow, Release Notes v3.3.0, Subscription Web Page (/s/{token}), Fleet v1 Deprecation and Removal, Release Notes v4.0.0 (+1 more)

### Community 511 - "Traffic Monitoring and Metrics"
Cohesion: 0.22
Nodes (9): Monitor Connection Counters, Release v2.0.1, Release v2.1.0, TrustTunnel Sing-Box Fork Subscription, Mieru Per-Client Traffic Monitoring, NaiveProxy Per-Client Traffic Monitoring, Release v2.2.0, Release v2.2.1 (+1 more)

### Community 512 - "Release Workflow Configuration"
Cohesion: 0.22
Nodes (8): concurrency, cancel-in-progress, group, env, EXPECTED_SHA256, RELEASE_VERSION, name, permissions

### Community 513 - "CI Attestation Workflow Job"
Cohesion: 0.22
Nodes (9): needs, runs-on, timeout-minutes, jobs, attest, quality, permissions, runs-on (+1 more)

### Community 514 - "Fleet Capacity Distribution Metrics"
Cohesion: 0.28
Nodes (3): distribution(), main(), measure()

### Community 515 - "MCP Server Main Entrypoint"
Cohesion: 0.39
Nodes (6): BLOCKING_THREADS, environment(), Exit, healthcheck(), main(), run()

### Community 516 - "Naive Manager Diff Matching"
Cohesion: 0.31
Nodes (3): changed_lines(), Matcher, Matcher<'a>

### Community 517 - "IPv4 Routing Network Parser"
Cohesion: 0.39
Nodes (6): contiguous_prefix(), ip_network(), ipv4_address(), parse_octet(), prefix_length(), v4_prefix()

### Community 518 - "Fleet Compatibility Validation"
Cohesion: 0.22
Nodes (6): INVENTORY_KEYS, is_operation(), NODE_PATTERN, OPERATIONS, PENDING_COMMAND_STATUSES, valid_node_id()

### Community 519 - "Routing Diff Matching Engine"
Cohesion: 0.31
Nodes (3): changed_lines(), Matcher, Matcher<'a>

### Community 520 - "Framework Probes Golden Tests"
Cohesion: 0.36
Nodes (7): cookie_token(), framework_probes_match_python(), known_difference(), mask_json(), normalise(), render(), VOLATILE_JSON_KEYS

### Community 521 - "API Key Authentication Tests"
Cohesion: 0.39
Nodes (7): _key(), test_admin_key_reads_and_mutates_without_a_session(), test_bad_missing_or_disabled_key_is_401(), test_key_management_is_owner_only_and_never_lists_plaintext(), test_key_rate_limit_answers_429(), test_monitor_key_is_read_only(), test_node_sync_key_reaches_only_the_fleet_api()

### Community 522 - "Routing API Integration Tests"
Cohesion: 0.36
Nodes (6): _csrf(), test_apply_rollback_delete_and_history(), test_malformed_manager_answer_remains_bare_500_without_failed_policy(), test_preview_of_a_draft_does_not_save(), test_put_upserts_with_expected_revision_and_keeps_rule_ids(), test_viewer_reads_and_previews_but_never_mutates()

### Community 525 - "Traffic Metrics Live Sampler"
Cohesion: 0.22
Nodes (4): cum(), run_traffic(), Sampler, window_stats()

### Community 526 - "HTTPS Cover Container Setup"
Cohesion: 0.22
Nodes (9): cap_drop, command, image, network_mode, read_only, restart, security_opt, volumes (+1 more)

### Community 527 - "Hysteria2 Service Container Configuration"
Cohesion: 0.22
Nodes (9): cap_drop, command, image, network_mode, read_only, restart, security_opt, volumes (+1 more)

### Community 528 - "NaiveProxy Service Container Configuration"
Cohesion: 0.22
Nodes (9): cap_drop, command, image, network_mode, read_only, restart, security_opt, volumes (+1 more)

### Community 529 - "TeleMT Container Setup"
Cohesion: 0.22
Nodes (9): telemt, cap_drop, command, image, network_mode, read_only, restart, security_opt (+1 more)

### Community 530 - "VLESS TCP Container Setup"
Cohesion: 0.22
Nodes (9): vless-tcp, cap_drop, command, image, network_mode, read_only, restart, security_opt (+1 more)

### Community 532 - "AmneziaWG Diff Utilities"
Cohesion: 0.39
Nodes (7): changed_lines(), diff_of_the_egress_documents_matches_difflib(), lines(), longest_match(), matching_blocks(), separate_runs_and_pure_insertions(), plan_diff()

### Community 533 - "Container Healthcheck Configuration"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 534 - "Naive Service Environment Variables"
Cohesion: 0.25
Nodes (8): NAIVE_EGRESS_ROUTER, NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE, NAIVE_EGRESS_WARP, NAIVE_MANAGER_TOKEN_FILE, NAIVE_SOCKET_MODE, NAIVE_TRAFFIC_DATABASE, NAIVE_TRAFFIC_LOG, environment

### Community 535 - "Clients Route Golden Tests"
Cohesion: 0.39
Nodes (5): clients_are_created_renamed_labelled_and_listed(), golden(), OWNER_PASSWORD, recorded_refusals_are_byte_identical(), signed_in()

### Community 536 - "System Readiness Diagnostic Tests"
Cohesion: 0.29
Nodes (3): login(), test_node_state_uses_actual_applied_timestamp(), test_readiness_requires_owner_or_admin_and_does_not_change_healthz()

### Community 537 - "Proxy Adapter Smoke Tests"
Cohesion: 0.25
Nodes (6): CARGO_INCREMENTAL, CARGO_PROFILE_DEV_DEBUG, CARGO_TARGET_DIR, PC_PROXY_SMOKE_IMAGE, PC_PROXY_SMOKE_NETWORK, smoke-proxy-adapters.sh script

### Community 538 - "Container Healthcheck Definition"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 539 - "Container Healthcheck Parameter Definition"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 540 - "Service Healthcheck Intervals"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 541 - "Container Healthcheck Probes"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 542 - "Healthcheck Interval Settings"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 543 - "Service Healthcheck Configuration"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 544 - "Healthcheck Settings Definition"
Cohesion: 0.50
Nodes (8): interval, retries, start_period, test, timeout, healthcheck, healthcheck, healthcheck

### Community 545 - "System Runtimes and Profiles"
Cohesion: 0.25
Nodes (8): AmneziaWG Runtime, Host Golden Wizard (Full Profile, Quit at Digest), Mieru Runtime, NaiveProxy Runtime, Proxy Control Full Profile Plan, TrustTunnel Runtime, Version Agent Runtime, Xray-router Runtime

### Community 546 - "AmneziaWG Compose Dependencies"
Cohesion: 0.29
Nodes (7): condition, awg-manager, depends_on, group_add, secrets, volumes, panel

### Community 547 - "Bind Mount Volume Configuration"
Cohesion: 0.29
Nodes (7): create_host_path, volumes, bind, read_only, source, target, type

### Community 548 - "TrustTunnel Docker Build Arguments"
Cohesion: 0.29
Nodes (7): TT_SHA256_AARCH64, TT_SHA256_X86_64, TT_VERSION, args, context, dockerfile, build

### Community 549 - "Volume Mount Definition"
Cohesion: 0.29
Nodes (7): create_host_path, volumes, bind, read_only, source, target, type

### Community 550 - "TrustTunnel Manager Compose Dependencies"
Cohesion: 0.29
Nodes (7): trusttunnel-manager, depends_on, group_add, secrets, volumes, panel, condition

### Community 551 - "Host Bind Volume Mappings"
Cohesion: 0.29
Nodes (7): create_host_path, bind, read_only, source, target, type, volumes

### Community 552 - "Healthcheck Periodic Parameters"
Cohesion: 0.48
Nodes (7): interval, retries, start_period, test, timeout, healthcheck, healthcheck

### Community 553 - "Xray Router Compose Secrets"
Cohesion: 0.29
Nodes (7): secrets, xray-router-ingress-mieru, xray-router-ingress-naive, xray-router-manager-token, file, file, file

### Community 554 - "UI Screenshots and Layouts"
Cohesion: 0.29
Nodes (7): Clients List Desktop UI (v1.0.2), Access Grant Details Mobile Modal UI (v1.0.2), Access Grant Details Desktop Modal UI (v1.0.2), Clients List Mobile UI (v2.2.1), Clients List Desktop UI (v2.2.1), Overview Dashboard Desktop UI English (v2.2.1), Overview Dashboard Mobile UI Russian (v2.2.1)

### Community 555 - "Reproducible Build CI Job"
Cohesion: 0.29
Nodes (7): needs, outputs, runs-on, timeout-minutes, build-twice-and-compare, archive-sha256, version

### Community 556 - "Publishing Workflow CI Job"
Cohesion: 0.29
Nodes (7): name, publish, environment, needs, permissions, runs-on, timeout-minutes

### Community 557 - "JSON Serialization Golden Tests"
Cohesion: 0.43
Nodes (5): fixture(), floats_are_written_like_python_repr_and_pydantic(), options(), strings_are_escaped_like_python(), structures_match_every_variant()

### Community 558 - "Routing Stringprep Tables"
Cohesion: 0.29
Nodes (6): B1, B2_EXCEPTIONS, BIDI_L, DIGIT_NOT_DECIMAL, PROHIBITED, RAND_AL

### Community 559 - "Client Labeling Test Suite"
Cohesion: 0.48
Nodes (5): _client_with_grant(), test_a_client_is_renamed_and_the_rename_is_audited(), test_a_grant_label_is_set_shown_and_reset(), test_a_grant_label_refuses_too_long_unknown_and_deleted(), test_renaming_a_client_refuses_blank_missing_and_needs_csrf()

### Community 561 - "Xray Router State Setup"
Cohesion: 0.43
Nodes (6): fail(), ROUTER_GID, ROUTER_MODE, ROUTER_UID, prepare-xray-router-state.sh script, verify_regular_file()

### Community 563 - "AmneziaWG Compose Configuration"
Cohesion: 0.33
Nodes (5): file, name, secrets, awg-manager-token, services

### Community 564 - "Container Health Check"
Cohesion: 0.33
Nodes (6): healthcheck, interval, retries, start_period, test, timeout

### Community 565 - "AmneziaWG Volume Configuration"
Cohesion: 0.33
Nodes (6): driver_opts, device, o, type, volumes, awg-manager-run

### Community 566 - "Docker Volume Bind Mounts"
Cohesion: 0.33
Nodes (6): volumes, create_host_path, bind, source, target, type

### Community 567 - "AmneziaWG Environment Settings"
Cohesion: 0.33
Nodes (6): AMNEZIAWG_ENABLED, AMNEZIAWG_PUBLIC_HOST, AWG_MANAGER_SOCKET, AWG_MANAGER_TOKEN_SOURCE, PANEL_SUPPLEMENTARY_GROUPS, environment

### Community 568 - "Service Health Checks"
Cohesion: 0.33
Nodes (6): interval, retries, start_period, test, timeout, healthcheck

### Community 569 - "Health Check Settings"
Cohesion: 0.33
Nodes (6): interval, retries, start_period, test, timeout, healthcheck

### Community 570 - "TrustTunnel Compose Configuration"
Cohesion: 0.33
Nodes (5): name, secrets, trusttunnel-manager-token, services, file

### Community 571 - "TrustTunnel Volume Configuration"
Cohesion: 0.33
Nodes (6): device, o, type, driver_opts, volumes, trusttunnel-manager-run

### Community 572 - "TrustTunnel Environment Settings"
Cohesion: 0.33
Nodes (6): PANEL_SUPPLEMENTARY_GROUPS, TRUSTTUNNEL_ENABLED, TRUSTTUNNEL_MANAGER_SOCKET, TRUSTTUNNEL_MANAGER_TOKEN_SOURCE, TRUSTTUNNEL_PUBLIC_HOST, environment

### Community 573 - "Container Health Check Configuration"
Cohesion: 0.33
Nodes (6): interval, retries, start_period, test, timeout, healthcheck

### Community 574 - "Routing Control Panel UI"
Cohesion: 0.40
Nodes (6): UI Screenshot: Routing Control Panel (English), UI Screenshot: Routing Guide Modal (Russian), UI Screenshot: Routing Control Panel (Russian), Chains and Per-Client Lanes Spike (v0.7), Routing Engine Spike (v0.4), Xray Egress-Router Spike (v0.5)

### Community 575 - "Monitoring Dashboard UI Screenshots"
Cohesion: 0.33
Nodes (6): UI Screenshot: Proxy Control Dashboard Overview, UI Screenshot: Proxy Control Monitoring Nodes View, UI Screenshot: Proxy Control Real-Time Monitoring (English), UI Screenshot: Proxy Control Real-Time Monitoring (Russian), UI Screenshot: Proxy Control Real-Time Monitoring (Mobile View), UI Screenshot: Proxy Control Monitoring Traffic View

### Community 576 - "Proxy Control Release Features"
Cohesion: 0.33
Nodes (6): Mieru Key Persistence, Proxy Control v1.0.0, Throne Client Support, Mieru/mita Generic Version Compatibility, Regional Geodata Auto-update, Proxy Control v1.0.1

### Community 577 - "Release Updates and Guides"
Cohesion: 0.40
Nodes (6): AI Agent Installation Guide, Release v1.1.2, Safe Uninstallation Behavior, Subscription ETag Cache Invalidation, Release v1.1.3, Differentiated Subscription Naming

### Community 578 - "GitHub Issue Configuration"
Cohesion: 0.33
Nodes (5): blank_issues_enabled, contact_links, about, name, url

### Community 579 - "Argparse Verification Tests"
Cohesion: 0.67
Nodes (4): check(), corpus(), installer_command_lines_match_python(), verify_release_command_lines_match_verify_py()

### Community 580 - "Node Heartbeat Error Handling"
Cohesion: 0.33
Nodes (6): bare_gateway_404_and_oversized_heartbeat_are_offline_once(), failed_capture_timeout_or_500_keeps_manager_version_pending_and_node_online(), import_capture_failure_and_mid_transaction_failure_leave_no_partial_clients_or_secrets(), refused_heartbeat_is_not_offline_and_cannot_deliver_until_recovered(), rejected(), unlink_rejection_is_audited_without_remote_detail_or_credentials()

### Community 582 - "Client Listing API Tests"
Cohesion: 0.47
Nodes (3): test_client_api_keeps_legacy_full_list_and_exposes_validated_pages(), test_client_delete_route_is_closed_to_viewers(), test_client_delete_route_refuses_then_removes_and_the_token_stops_resolving()

### Community 583 - "Host Installation Profiles"
Cohesion: 0.33
Nodes (6): AmneziaWG Integration, Host Mode Configuration, Core Profile, proxy-control.toml, TrustTunnel Integration, Host Installer Wizard (Core Save Flow)

### Community 586 - "TrustTunnel Metrics Collection"
Cohesion: 0.47
Nodes (4): a_lower_reading_without_restart_is_a_counter_reset(), aggregate(), fetch_clients(), Reading

### Community 587 - "HTTPS Fetch Client"
Cohesion: 0.33
Nodes (3): F, Fetched, fetch_https_refuses_hosts_outside_the_allowlist()

### Community 588 - "Architecture Decision Records"
Cohesion: 0.40
Nodes (5): ADR 001: Pull-only node transport, ADR 002: Declarative immutable generations, ADR 003: One writer per resource, ADR 004: Client, AccessGrant and subscription as a projection, ADR 005: Secrets travel as references

### Community 589 - "MCP Tooling and Reporting"
Cohesion: 0.40
Nodes (5): Report and Handoff Generation, MCP Confirm Rule, MCP Curated Tools, proxy-control-mcp, Proxy Control Skills

### Community 590 - "Protocol Manager Egress Routing"
Cohesion: 0.40
Nodes (5): ADR 007: Routing Enforcement Ownership, Mieru Manager Egress, Naive Manager Egress, TrustTunnel Manager Egress, TrustTunnel via Xray-router

### Community 591 - "Fleet API Management"
Cohesion: 0.40
Nodes (5): ClientService.notify, Generation Document, managed_resources Registry, API Key scope: node-sync, Fleet API v2

### Community 592 - "Traffic Accounting Database Schema"
Cohesion: 0.40
Nodes (5): accounting_state table, Legacy Migrated Accounting Schema, traffic_archives table, traffic_counters table, traffic_files table

### Community 594 - "Scalar Type Definitions"
Cohesion: 0.50
Nodes (4): Scalar, Bool, Int, Str

### Community 595 - "Proxy Control MCP Skills"
Cohesion: 0.40
Nodes (5): Skill: Changing Routing, Skill: Diagnosing Access, Skill: Granting Access, Skill: Morning Overview, Proxy Control MCP Skills Documentation

### Community 596 - "Installer Wizard Profiles"
Cohesion: 0.40
Nodes (5): Wizard Russian EOF Stdout Golden Test Fixture, INSTALLER_REFERENCE, Proxy Control Profiles (core / core-naive / core-mieru / full), Server Modes (fresh / coexist), 3x-ui Modes (none / existing / managed-new)

### Community 597 - "Core VPN Protocols Integration"
Cohesion: 0.50
Nodes (5): full-quit-at-digest.stdout.txt fixture, AmneziaWG Obfuscated WireGuard Integration, TrustTunnel HTTP/2 VPN Integration, Cloudflare WARP Egress Routing, Xray Router Runtime Component

### Community 599 - "AmneziaWG Protocol Documentation"
Cohesion: 0.50
Nodes (4): AmneziaWG Protocol Support, awg-manager, docs/guides/AMNEZIAWG.en.md, Database Migration 23

### Community 600 - "Proxy Secret Environment Variables"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 601 - "Docker Build Configuration"
Cohesion: 0.67
Nodes (4): context, dockerfile, build, build

### Community 602 - "Xray Router Architecture"
Cohesion: 0.50
Nodes (4): ADR 006: Engine-neutral routing policy IR, mtproxy-bridge, Xray Router, Xray Router Manager

### Community 603 - "Russian Deployment Guides"
Cohesion: 0.67
Nodes (3): Nginx SNI Router Deployment, Telemt MTProto Data Plane, TRUSTTUNNEL.ru.md

### Community 605 - "Live Monitoring System Releases"
Cohesion: 0.67
Nodes (4): Live Monitoring System, Manager Auto-Rebuild, MCP Metrics Tools, v2.0.0 Release

### Community 606 - "Monitoring Service Components"
Cohesion: 0.50
Nodes (4): monitoring-history, monitoring-live, monitoring-mcp, monitoring-stream

### Community 608 - "Character Classification Tables"
Cohesion: 0.50
Nodes (3): DECIMAL, NON_PRINTABLE, WHITESPACE

### Community 609 - "Probe Installation Script"
Cohesion: 0.50
Nodes (3): DESTINATION, IMAGE, install.sh script

### Community 610 - "MTProxy Compose Versions"
Cohesion: 0.50
Nodes (3): image, services, mtproxy

### Community 611 - "Service Environment Secrets"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 612 - "Service Environment Secrets Config"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 613 - "Service TLS Secrets Configuration"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 614 - "Proxy Environment Credentials"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 615 - "Protocol Environment Secrets"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 616 - "Manager Environment Secrets"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 617 - "API Token Environment Config"
Cohesion: 0.50
Nodes (4): API_TOKEN_FILE, FAKE_TLS_DOMAIN, SECRETS_FILE, environment

### Community 618 - "Host Wizard CLI Options"
Cohesion: 0.50
Nodes (4): Host Wizard EOF Test Output (EN), Host Mode Option (fresh / coexist), Proxy Control Profile Option (core / core-naive / core-mieru / full), 3x-ui Mode Option (none / existing / managed-new)

### Community 619 - "Artifact Download Client"
Cohesion: 0.83
Nodes (4): download_artifact(), DownloadError, Refused, Unreachable

### Community 620 - "MTProxy Routing Release"
Cohesion: 0.67
Nodes (3): MTProxy Routing via Xray-router, Release 1.1.0, docs/releases/v1.1.0.md

### Community 621 - "Docker Build Directives"
Cohesion: 0.67
Nodes (3): build, context, dockerfile

### Community 622 - "Dockerfile Build Context"
Cohesion: 0.67
Nodes (3): context, dockerfile, build

### Community 623 - "Docker Container Build Spec"
Cohesion: 0.67
Nodes (3): context, dockerfile, build

### Community 624 - "Mieru Configuration Sharing"
Cohesion: 0.67
Nodes (3): Mieru Configuration Sharing, QR Security Contract, Выдача конфигураций Mieru

### Community 625 - "Dashboard UI Screenshots"
Cohesion: 0.67
Nodes (3): Desktop Dashboard UI Screenshot, Mobile Dashboard UI Screenshot, Mobile Clients Management UI Screenshot

### Community 626 - "Routing Configuration UI Screenshots"
Cohesion: 1.00
Nodes (3): Routing Configuration UI Screenshot (English), Routing Guide Modal UI Screenshot, Routing Configuration UI Screenshot (Russian)

### Community 627 - "AmneziaWG Releases"
Cohesion: 0.67
Nodes (3): AmneziaWG Random Ports, v1.5.0 Release, v1.5.1 Release

### Community 628 - "Traffic Lanes and Chains"
Cohesion: 0.67
Nodes (3): ADR 009: Lanes and Chains, Chains and Lanes, Egress Relay

### Community 629 - "Routing Policy Specifications"
Cohesion: 0.67
Nodes (3): ADR 006: Routing Policy IR, MTProxy via Xray-router, Routing Policy Overview

### Community 630 - "Manager Version Rebuilding"
Cohesion: 0.67
Nodes (3): versions-agent, versions-managers-rebuild, versions-protocol-managers

### Community 632 - "Traffic Accounting Tables"
Cohesion: 0.67
Nodes (3): traffic_archives (table), traffic_counters (table), traffic_files (table)

### Community 636 - "Branding and Login UI"
Cohesion: 0.67
Nodes (3): Proxy Control Logo 64px Icon (isometric proxy routing diagram), Proxy Control Logo Icon (isometric proxy routing diagram with port 443, mieru, naive, mtproxy), Proxy Control Login Page

### Community 638 - "Host Golden Fixtures"
Cohesion: 0.67
Nodes (3): Plan: core, Host-side golden fixtures README, scripts/dev/record-host-goldens.py

### Community 640 - "Wizard Golden Fixtures"
Cohesion: 0.67
Nodes (3): invalid-config.stdout.txt (ru wizard golden fixture), invalid-inputs.stdout.txt (ru wizard golden fixture), managed-three-xui-save.stdout.txt (ru wizard golden fixture)

## Knowledge Gaps
- **795 isolated node(s):** `Array`, `Boolean`, `Date`, `Float`, `String` (+790 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 5438 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **169 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Value` connect `Data Types and Validation` to `Installation Filesystem Engine`, `Audit Evidence Checkpoints`, `Client Models and Validation`, `Central Routing Generation`, `Client Error Handling`, `AmneziaWG Manager API`, `Client Adapter Mock Testing`, `Framework Probes Golden Tests`, `Xray Router Intent Configuration`, `Node HTTP Hooks Client`, `Service Status Dashboard`, `Localization and Translation Catalog`, `Mieru Proxy Acceptance Tests`, `Audit Context and Event Bus`, `Installer Audit Verification`, `Client Subscription Management`, `AmneziaWG Diff Utilities`, `Naive Manager Integration Tests`, `Address Policy Resolution`, `Document Validation and Ports`, `Database Clock Testing Mock`, `Planner Adapter Configuration`, `Audit CLI Error Handling`, `Access Reconciliation Enforcement`, `Runtime Fleet Routing`, `Caddyfile Accounting Configuration`, `Routing Egress Verification`, `Protocol Chain Actions`, `Installer Domain Configuration Validation`, `Egress View Artifacts`, `Service Policy Router Tests`, `Firewall Rule Enforcement`, `TrustTunnel Configuration Parsing`, `Password Hashing and Querying`, `Mieru Manager Service Journal`, `AmneziaWG Manager Lifecycle Tests`, `TLS Certificate Inspection`, `JSON Serialization Golden Tests`, `MCP Adapter Composition`, `Grant and Credential State`, `Routing Regression Tests`, `Protocol Configuration Options`, `Central Routing Policy`, `Client Protocol Adapters`, `State Persistence and Backups`, `Route Document Compilation`, `Mieru Manager Tests`, `Grant Context and Intents`, `Metrics Collector Configuration`, `Node Inventory Reconciliation`, `TOML Parsing Utilities`, `Atomic State Store`, `Argparse Verification Tests`, `Mieru Adapter Management`, `Fleet Node Management`, `HTTP Request Parsing`, `AmneziaWG Service Manager`, `Metrics Time Series Store`, `Logging Utilities`, `Exit Routing Configuration`, `TrustTunnel Metrics Collection`, `Version Agent Server`, `Node Metrics Source Tests`, `Node System Audit Tests`, `Panel Lifecycle Tests`, `Routing Lanes and Relays`, `Healthcheck Verification CLI`, `Router Configuration State Management`, `Database Schema Migrations`, `AmneziaWG Configuration Models`, `Config Migration and Rollback`, `AmneziaWG Egress Adapter`, `Access Artifact Manifest Generation`, `Tun Device Process Runner`, `Subprocess Runner Execution`, `Upstream Release Asset Verification`, `Installer CLI Commands`, `Manager Egress Error Codes`, `Agent Binary Update Rollback`, `Client Request API Models`, `MCP Server Client Placement`, `Python-Compatible URL Parser`, `Version Agent Release Checker`, `Xray Router Manager Tests`, `Upstream Version Parsing`, `Node Traffic Counters`, `AwgManager Egress Management`, `Candidate Update Verification Tests`, `File Acceptance Markers`, `Proxy Ownership Acceptance`, `Traffic Accounting Storage`, `Operator Credentials Validation`, `Metrics Route Endpoints`, `Client Dispatch Replay`, `Ordered JSON Deserialization`, `Server-Sent Events Streams`, `Python-Compatible JSON Serialization`, `Adapter Context Registry`, `Agent Service Lifecycle Tests`, `HTTP Request Extractors`, `Policy Routing Route Handlers`, `Atomic Binary Execution Script`, `Mita Process Execution Tests`, `Safe Archive Extraction Tests`, `AwgManager Service Daemon`, `Fleet Central Certificate Validation`, `ACME Certificate Management`, `Version Agent Client`, `Clients Route Golden Tests`, `Nginx Topology Parser`, `X25519 Cryptographic Keys`, `Three-XUI Adapter Integration`, `Relay Lane Policies`, `Component Release Catalog`, `Keyring Key Management`, `GeoData Asset Fetcher`, `Configuration Obfuscation Generator`, `Managed Node Storage Store`, `TeleMT Metrics Dashboard Tasks`, `Fleet Metrics Source Aggregator`, `Nginx Route Configuration Adapter`, `Host Process Command Runner`, `AmneziaWG Management Client`, `Naive Caddy Deployment Adapter`, `Client App Deep Links`, `AwgManager Process Supervision`, `HTTPS Certificate Validation`, `Acceptance and Handoff Reporting`, `In-Memory TeleMT Management`, `TeleMT Proxy Manager`, `Traffic Accounting Tests`, `Host Updater Service`, `APT Package Management`, `Mieru Egress Management`, `HTTP Request Router`, `Client Account Provisioning`, `Runtime Geodata Management`, `Node Link Management`, `Fleet Reconciliation Tests`, `Lane and Route Validation`, `Routing Protocol Error Handling`, `Node Management Routes`, `Host Metrics Collection Tests`, `Warp Adapter Package Management`, `API Key Management Routes`, `In-Memory Protocol Node Mocks`, `State Probe and Rollback`, `Routing Policy Backend Store`, `Mieru Quota Models`, `VPN Runtime Management`, `Cursor and Value Serialization`, `Installer CLI Test Suite`, `HTTP Server Endpoint Tests`, `Test Fixtures and RBAC`, `Fleet Metrics Aggregation`, `Nginx Stream Configuration Rendering`, `Subscription Service Test Suite`, `Geodata Scheduled Updates`, `HTTP Transport Channel Handling`, `Web Admin CLI Commands`, `Secrets Keyring Fixture Tests`, `API Tool Schema Validation`, `Quota Enforcer Server Handler`, `Metrics Route Integration Tests`, `Egress and Geodata Management`, `QR Code Generation`, `3X-UI API Integration Tests`, `Python Compatibility Helpers`, `Client Audit Golden Tests`, `Proxy Smoke Docker Tests`, `Egress Configuration Tests`, `VPN Protocol Transcripts`, `Test Mocking and Recording`, `Python Compatibility Testing`, `Backup and File Management`, `Network Egress and Relays`, `Python JSON Serialization`, `Agent Monitoring Scenarios`, `API Error Handling`, `Node Certificate Management`, `Release and Artifact Management`, `Fleet Host Rollback Engine`, `Runtime Testkit Evidence`, `3x-ui API Client`, `Background Lifespan Tasks`, `Port Metrics Discovery`, `Mieru Quotas and Routes`, `Xray Router Adapter`, `Naive Manager Memory Mock`, `Host Network Test Device`, `Wizard Engine Golden Tests`, `Live Xray Router Tests`, `HTTP API Response Rendering`, `Manifest Grant Subscription Renderers`, `TrustTunnel Memory Mock`, `Manager Client Egress Tests`, `Mieru Validation Rules`, `Routing Coverage and Capabilities`, `Container Metrics Sampler`, `Mieru Lanes Configuration`, `Exit and Geodata Request Models`, `Authentication and Session Flows`, `AmneziaWG Routes and Errors`, `AmneziaWG Configuration Validation`, `JSON Load and Parser`, `JSON Number Serialization Modes`, `HTTP Parsing and Decoding`, `Egress Migration Support`, `Web Test Client Helpers`, `Naive Routes and Escrow`, `Caddy Reverse Proxy Client`, `Protocol Golden Config Tests`, `Host Hardware Metrics Reader`, `Host Metrics Collection Timer`, `IP Address Normalization`, `Router Lifecycle Smoke Tests`, `Node Capture and Reconciliation`, `Core Checkpoint Validation`, `Xray Router Manager Client`, `Secrets Store Encryption Tests`, `Nginx and VPN Smoke Tests`, `Mieru Manager Memory Mock`, `HTTP Mock Server Testkit`, `Application State Authentication`, `Metrics API Routes`, `Admin Subscription Management`, `NaiveProxy Client Management`, `Admin Authentication Routes`, `Node Management Routes`, `Node Import Models`, `AmneziaWG Port Allocation`, `Naive Manager State`, `Binary Identity Verification`, `Client Rate Limiting`, `Routing Presets Service`, `Panel Client Integration`, `Core Services Acceptance`, `In-Memory AmneziaWG State`, `Manager Golden Tests`, `Credential and Report Testing`, `Core Adapter Acceptance`, `Mieru Manager Service`, `Protocol Egress Targets`, `Metrics Port Discovery`, `Installer Audit Tests`, `Python Compatible IP Parser`, `Version Agent Golden Tests`, `Panel File Ownership`, `Core API Errors`, `Python Text Parsing Tests`, `Service Golden Comparison Tests`, `Subscription Format Converters`, `Query Parameter Parsing`, `Compatibility Matrix Specification`, `Version Management API Routes`, `Protocol Route Audit Tests`, `Mieru Manager HTTP Server`, `Python-Compatible Float Math`, `HTTP Client Utilities`, `Runtime Hook Tests`, `Python Web Golden Tests`, `Fleet Wire Replay Tests`, `Python Number Compatibility Parser`, `Runtime Settings Golden Tests`?**
  _High betweenness centrality (0.288) - this node is a cross-community bridge._
- **What connects `Array`, `Boolean`, `Date` to the rest of the system?**
  _795 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Data Types and Validation` be split into smaller, more focused modules?**
  _Cohesion score 0.030448999683555432 - nodes in this community are weakly interconnected._
- **Why does `Map` connect `Atomic State Store` to `Data Types and Validation`, `Installation Filesystem Engine`, `Audit Evidence Checkpoints`, `Client Models and Validation`, `Central Routing Generation`, `Client Error Handling`, `Client Adapter Mock Testing`, `Xray Router Intent Configuration`, `Node HTTP Hooks Client`, `Service Status Dashboard`, `Localization and Translation Catalog`, `Audit Context and Event Bus`, `Installer Audit Verification`, `Client Subscription Management`, `Naive Manager Integration Tests`, `Address Policy Resolution`, `Document Validation and Ports`, `Database Clock Testing Mock`, `Planner Adapter Configuration`, `Audit CLI Error Handling`, `Access Reconciliation Enforcement`, `Caddyfile Accounting Configuration`, `Routing Egress Verification`, `Protocol Chain Actions`, `Egress View Artifacts`, `Service Policy Router Tests`, `TrustTunnel Configuration Parsing`, `Password Hashing and Querying`, `Mieru Manager Service Journal`, `AmneziaWG Manager Lifecycle Tests`, `TLS Certificate Inspection`, `MCP Adapter Composition`, `Grant and Credential State`, `Routing Regression Tests`, `Central Routing Policy`, `State Persistence and Backups`, `Route Document Compilation`, `Mieru Manager Tests`, `Metrics Collector Configuration`, `Node Inventory Reconciliation`, `Fleet Node Management`, `AmneziaWG Service Manager`, `Exit Routing Configuration`, `Logging Utilities`, `Node Metrics Source Tests`, `Routing Lanes and Relays`, `Healthcheck Verification CLI`, `AmneziaWG Egress Adapter`, `Access Artifact Manifest Generation`, `Upstream Release Asset Verification`, `MCP Server Client Placement`, `Python-Compatible URL Parser`, `Version Agent Release Checker`, `Upstream Version Parsing`, `AwgManager Egress Management`, `Candidate Update Verification Tests`, `File Acceptance Markers`, `Proxy Ownership Acceptance`, `Metrics Route Endpoints`, `Agent Service Lifecycle Tests`, `HTTP Request Extractors`, `Policy Routing Route Handlers`, `Atomic Binary Execution Script`, `Mita Process Execution Tests`, `Component Release Catalog`, `X25519 Cryptographic Keys`, `GeoData Asset Fetcher`, `Managed Node Storage Store`, `Client App Deep Links`, `Mieru Egress Management`, `Client Account Provisioning`, `Node Link Management`, `Fleet Reconciliation Tests`, `Lane and Route Validation`, `Routing Protocol Error Handling`, `Node Management Routes`, `State Probe and Rollback`, `Routing Policy Backend Store`, `Mieru Quota Models`, `Subscription Service Test Suite`, `Geodata Scheduled Updates`, `HTTP Transport Channel Handling`, `API Tool Schema Validation`, `Quota Enforcer Server Handler`, `Python Compatibility Helpers`, `Client Audit Golden Tests`, `VPN Protocol Transcripts`, `API Error Handling`, `Node Certificate Management`, `Release and Artifact Management`, `Runtime Testkit Evidence`, `3x-ui API Client`, `Mieru Validation Rules`, `Container Metrics Sampler`, `Mieru Lanes Configuration`, `Exit and Geodata Request Models`, `JSON Load and Parser`, `JSON Number Serialization Modes`, `HTTP Parsing and Decoding`, `Egress Migration Support`, `Host Metrics Collection Timer`, `Core Checkpoint Validation`, `Application State Authentication`, `NaiveProxy Client Management`, `AmneziaWG Port Allocation`, `Naive Manager State`, `Binary Identity Verification`, `Core Services Acceptance`, `Mieru Manager Service`, `Protocol Egress Targets`, `Panel File Ownership`, `Core API Errors`, `Mieru Manager HTTP Server`, `Runtime Settings Golden Tests`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **Should `Installation Filesystem Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.02511294180175392 - nodes in this community are weakly interconnected._
- **Why does `GeodataAction` connect `Runtime Geodata Management` to `Egress View Artifacts`, `VPN Protocol Transcripts`, `Service Policy Router Tests`, `Fleet Node Management`, `Routing Protocol Error Handling`, `Routing Regression Tests`, `Egress and Geodata Management`, `API Key Management Routes`, `Runtime Fleet Routing`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Should `Audit Evidence Checkpoints` be split into smaller, more focused modules?**
  _Cohesion score 0.02506265664160401 - nodes in this community are weakly interconnected._