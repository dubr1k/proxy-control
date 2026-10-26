//! The composition root (`create_app`, `app.py:92-319`): what is built, in which order, and what
//! refuses to start.
//!
//! 1. the settings checks of `create_app` and Starlette's `allowed_hosts` pattern rule;
//! 2. the database (WAL) and the schema migrations (Python's `Store`/`FleetStore` constructors ran
//!    them; here once);
//! 3. the master keyring — or, without `PANEL_MASTER_KEY_FILE`, the refusal when `secret_versions`
//!    holds rows;
//! 4. the identity stores, the manager clients, the in-memory state (reveals, the API-key limiter,
//!    the login semaphore), the panel GUID and version;
//! 5. the services of the other packages ([`services`]) and their background loops and startup
//!    work ([`register_lifespan`]), in `create_app`'s order.

use std::path::PathBuf;
use std::sync::Arc;

use panel_core::clock::SharedClock;
use panel_core::db::Database;
use panel_core::settings::Settings;
use panel_metrics::sources::LocalName;
use panel_metrics::{ManagerMeters, Metrics};
use panel_nodes::NodeLifecycleService;
use panel_secrets::api_keys::ApiKeyService;
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::SecretStore;
use panel_secrets::store::Store;
use tokio::sync::Semaphore;

use crate::lifespan::Lifespan;
use crate::state::{
    AppState, BackgroundWork, Core, KeyRateLimiter, Managers, PanelClock, Reveals, Services, TestState,
};

/// Where the JS app lives in the image (`Path(__file__).parent / "static"`).
pub const DEFAULT_STATIC_DIR: &str = "/app/panel/static";

/// Builds the state, or the reason the panel refuses to start.
pub fn build(settings: Settings, static_dir: PathBuf) -> Result<AppState, String> {
    settings.validate().map_err(|error| error.to_string())?;
    crate::server::check_allowed_hosts(&settings.allowed_hosts)?;
    let panel_clock = Arc::new(PanelClock::default());
    let clock: SharedClock = panel_clock.clone();
    let database = Database::open(&settings.database_path).map_err(|error| error.to_string())?;
    panel_core::migrations::apply_migrations(&database).map_err(|error| error.to_string())?;
    let secrets =
        SecretStore::open(&database, settings.master_key_file.as_deref()).map_err(|error| error.to_string())?;
    let store = Arc::new(Store::new(database.clone()));
    let api_keys = ApiKeyService::with_clock(database.clone(), clock.clone());
    let events =
        Arc::new(EventBus::with_options(database.clone(), panel_secrets::events::DEFAULT_CAPACITY, clock.clone()));
    let managers = Managers::from_settings(&settings);
    let panel_guid = panel_secrets::identity::ensure_guid(&database).map_err(|error| error.to_string())?;
    let panel_version = panel_secrets::identity::read_panel_version(&settings.panel_version_file);
    let core = Arc::new(Core {
        key_rate: KeyRateLimiter::new(settings.api_key_rate_per_minute, clock.clone()),
        login_slots: Semaphore::new(usize::try_from(settings.login_verify_concurrency).unwrap_or(1).max(1)),
        reveals: Reveals::new(settings.reveal_ttl_seconds, clock.clone()),
        settings,
        database,
        clock,
        panel_clock,
        store,
        api_keys,
        secrets,
        events,
        managers,
        panel_guid,
        panel_version,
        static_dir,
        openapi: bytes::Bytes::from_static(crate::routes::openapi::DOCUMENT),
        lifespan: Lifespan::default(),
        background: Arc::new(BackgroundWork::default()),
        test: TestState::default(),
    });
    let state = AppState::new(core.clone(), services(&core)?);
    register_lifespan(&state);
    Ok(state)
}

/// The other packages' services, in `create_app`'s order (`app.py:146-252`): protocol adapters
/// (WP6), clients/provisioning/facade/lifecycle (WP7), subscriptions (WP9), versions (WP8), the
/// fleet (WP11/WP12), routing and lanes (WP10), metrics (WP13). Each adds `services.insert(…)`.
pub fn services(core: &Arc<Core>) -> Result<Services, String> {
    let mut services = Services::new();
    // `app.state.nodes = NodeLifecycleService(...)` (WP11, `app.py:130`), on the panel's clock.
    let nodes = NodeLifecycleService::new(core.database.clone(), core.clock.clone());
    services.insert(nodes.clone());
    // `app.state.adapters` and `app.state.router` (`app.py:150-171`): one adapter set for the whole
    // panel (WP12a builds it; the clients and routing packages take their adapters from it).
    let runtime = Arc::new(panel_fleet::node::ManagerRuntime::from_settings(&core.settings, bridge_probe(core)));
    // The node side of fleet v2 (`ManagedStore`, `Reconciler`, `app.py:174,206-209`).
    let node = panel_fleet::node::FleetNode::new(
        core.database.clone(),
        core.secrets.clone(),
        runtime.clone(),
        Arc::new(core.managers.versions.clone()),
        panel_fleet::node::NodeConfig::from_settings(&core.settings),
        core.panel_guid.clone(),
        core.panel_version.clone(),
        core.clock.clone(),
    );
    // The WP7 clients domain over that adapter set, its enforcer ticking the node's reconciler.
    crate::routes::clients::wire(core, &mut services, &runtime, &node);
    services.insert(runtime);
    services.insert(node);
    // `setup_metrics(app, settings, source=build_fleet_metrics_source(app))` (WP13, `app.py:252`):
    // the collector reads the host agent and the five protocol managers; the local node's name
    // comes from the node store. The fleet source (WP12b) is plugged in with
    // `Metrics::set_source`; until then linked nodes answer `unsupported`.
    let managers = &core.managers;
    let local_name: LocalName = Arc::new(move || nodes.local().ok().map(|view| view.display_name));
    let meters = ManagerMeters {
        versions: Some(Arc::new(managers.versions.clone())),
        trusttunnel: Some(Arc::new(managers.trusttunnel.clone())),
        amneziawg: Some(Arc::new(managers.amneziawg.clone())),
        telemt: Some(managers.telemt.clone()),
        mieru: Some(Arc::new(managers.mieru.clone())),
        naive: Some(Arc::new(managers.naive.clone())),
        local_name: Some(local_name),
    };
    let metrics: Arc<Metrics> =
        Metrics::setup(&core.settings, core.database.clone(), Arc::new(meters), core.clock.clone());
    services.insert(metrics);
    Ok(services)
}

/// The MTProxy ingress probe: the real one, unless a `test-hooks` build was told the answer
/// (`POST /__test/probe-bridge`).
fn bridge_probe(core: &Arc<Core>) -> Option<panel_protocols::telemt::BridgeProbe> {
    if !crate::TEST_HOOKS {
        return None;
    }
    let core = Arc::downgrade(core);
    let real = panel_protocols::telemt::default_bridge_probe();
    Some(Arc::new(move |ingress| {
        let forced = core.upgrade().and_then(|core| core.test.bridge_answer());
        match forced {
            Some(answer) => Box::pin(async move { answer }),
            None => real(ingress),
        }
    }))
}

/// Background loops and pre-serve work (`_lifespan`, `app.py:70-89`): the access enforcer's
/// `tick(force=True)` before serving (WP7), then the loops `pusher` (WP12), `enforcer` (WP7) and
/// `metrics` (WP13, only when `PANEL_METRICS_ENABLED`), registered in that order.
pub fn register_lifespan(state: &AppState) {
    // (pusher: WP12) — the enforcer's pre-serve tick and loop (WP7).
    crate::routes::clients::register_lifespan(state);
    // `metrics`: `collector.run_forever()` when metrics are on (no startup work of its own).
    if let Some(collector) = state.service::<Arc<Metrics>>().collector() {
        state.lifespan.register_loop(Arc::new(crate::routes::metrics::MetricsLoop(collector.clone())));
    }
}
