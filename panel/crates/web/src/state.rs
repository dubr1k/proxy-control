//! The application state every handler receives (`app.state` of the Python panel).
//!
//! [`AppState`] is cheap to clone: a [`Core`] this package owns (settings, database, the identity
//! stores, the manager clients, the in-memory state of `create_app`, the clock, the background
//! registry) plus [`Services`], a type map the other work packages fill with their own service
//! objects (`ClientService`, `RoutingService`, the fleet pusher, …) in `crate::wiring`, in the
//! order of `create_app` (`app.py:118-252`). A handler reads one with `state.service::<T>()`.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use panel_core::clock::{Clock, SharedClock, SystemClock};
use panel_core::db::Database;
use panel_core::settings::Settings;
use panel_managers::{
    AmneziawgClient, MieruClient, NaiveClient, TelemtClient, TelemtEgressJournal, TrusttunnelClient, VersionClient,
    XrayRouterClient,
};
use panel_secrets::api_keys::ApiKeyService;
use panel_secrets::events::EventBus;
use panel_secrets::secrets_store::SecretStore;
use panel_secrets::store::Store;
use serde_json::Value;
use tokio::sync::{Notify, Semaphore};

use crate::http::response::Failure;
use crate::lifespan::Lifespan;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The panel's clock: the real one, or — once a test hook set it — one fake time feeding wall and
/// monotonic time (`monotonic = time - 1.7e9`, as `FakeClock`). Release builds never set it.
#[derive(Debug, Default)]
pub struct PanelClock {
    fake: Mutex<Option<f64>>,
}

impl PanelClock {
    /// Sets the fake wall time.
    pub fn set(&self, time: f64) {
        *lock(&self.fake) = Some(time);
    }

    /// Moves the fake time (starting from the real time on first use).
    pub fn advance(&self, seconds: f64) {
        let mut fake = lock(&self.fake);
        let now = fake.unwrap_or_else(|| SystemClock.time());
        *fake = Some(now + seconds);
    }
}

impl Clock for PanelClock {
    fn time(&self) -> f64 {
        lock(&self.fake).unwrap_or_else(|| SystemClock.time())
    }

    fn monotonic(&self) -> f64 {
        match *lock(&self.fake) {
            Some(time) => time - panel_core::clock::FakeClock::MONOTONIC_OFFSET,
            None => SystemClock.monotonic(),
        }
    }
}

/// `KeyRateLimiter(limit)`: per API key, a sliding 60 s window on the monotonic clock, in memory.
pub struct KeyRateLimiter {
    limit: usize,
    window: f64,
    clock: SharedClock,
    hits: Mutex<HashMap<i64, VecDeque<f64>>>,
}

impl std::fmt::Debug for KeyRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRateLimiter").field("limit", &self.limit).finish_non_exhaustive()
    }
}

impl KeyRateLimiter {
    pub fn new(limit: i64, clock: SharedClock) -> Self {
        Self { limit: limit.max(0) as usize, window: 60.0, clock, hits: Mutex::new(HashMap::new()) }
    }

    /// `allow(key_id)`: drops hits older than the window, refuses at the limit, else records one.
    pub fn allow(&self, key_id: i64) -> bool {
        let now = self.clock.monotonic();
        let mut hits = lock(&self.hits);
        let window = hits.entry(key_id).or_default();
        while window.front().is_some_and(|first| now - first > self.window) {
            window.pop_front();
        }
        if window.len() >= self.limit {
            return false;
        }
        window.push_back(now);
        true
    }
}

/// One pending reveal: deadline (monotonic), owner (session token hash or `key:<id>`), payload.
type Reveal = (f64, String, Value);

/// `app.state.reveals`: one-time plaintext payloads bound to the session or key that created them.
pub struct Reveals {
    ttl: f64,
    clock: SharedClock,
    items: Mutex<HashMap<String, Reveal>>,
}

impl std::fmt::Debug for Reveals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reveals").field("ttl", &self.ttl).finish_non_exhaustive()
    }
}

impl Reveals {
    pub fn new(ttl_seconds: i64, clock: SharedClock) -> Self {
        Self { ttl: ttl_seconds as f64, clock, items: Mutex::new(HashMap::new()) }
    }

    /// `create_reveal(data, owner)`: sweeps expired entries, stores the payload for the TTL, and
    /// answers its token (`token_urlsafe(32)`).
    pub fn create(&self, data: Value, owner_token_hash: &str) -> String {
        let now = self.clock.monotonic();
        let mut items = lock(&self.items);
        items.retain(|_, (deadline, _, _)| *deadline >= now);
        let token = panel_core::ids::token_urlsafe(32);
        items.insert(token.clone(), (now + self.ttl, owner_token_hash.to_string(), data));
        token
    }

    /// `consume_reveal(token, user)`: 410 when unknown or expired (and dropped), 403 when another
    /// session owns it (kept), else the payload (dropped).
    pub fn consume(&self, token: &str, owner_token_hash: &str) -> Result<Value, Failure> {
        let now = self.clock.monotonic();
        let mut items = lock(&self.items);
        let live = items.get(token).is_some_and(|(deadline, _, _)| *deadline >= now);
        if !live {
            items.remove(token);
            return Err(Failure::detail(410, "reveal expired or consumed"));
        }
        let (_, owner, _) = &items[token];
        if !panel_secrets::compare_digest(owner, owner_token_hash) {
            return Err(Failure::detail(403, "reveal belongs to another session"));
        }
        Ok(items.remove(token).map(|(_, _, data)| data).unwrap_or(Value::Null))
    }
}

/// Work a request leaves running after its answer (a node's apply after a 202); the
/// `/__test/settle` hook waits for it.
#[derive(Debug, Default)]
pub struct BackgroundWork {
    running: AtomicUsize,
    idle: Notify,
}

impl BackgroundWork {
    /// Spawns `work` on the runtime and tracks it.
    pub fn spawn<F>(self: &Arc<Self>, work: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.running.fetch_add(1, Ordering::SeqCst);
        let tracker = Arc::clone(self);
        tokio::spawn(async move {
            work.await;
            if tracker.running.fetch_sub(1, Ordering::SeqCst) == 1 {
                tracker.idle.notify_waiters();
            }
        });
    }

    /// Waits until no tracked work runs.
    pub async fn settle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.running.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// The outbound clients (`app.py:136-164`).
#[derive(Debug, Clone)]
pub struct Managers {
    pub telemt: Arc<TelemtClient>,
    pub naive: NaiveClient,
    pub mieru: MieruClient,
    pub amneziawg: AmneziawgClient,
    pub trusttunnel: TrusttunnelClient,
    /// Only when `XRAY_ROUTER_ENABLED` (the overlay is part of the stack).
    pub router: Option<XrayRouterClient>,
    pub versions: VersionClient,
    /// The Telemt egress journal next to the database.
    pub telemt_journal: Arc<TelemtEgressJournal>,
}

impl Managers {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            telemt: Arc::new(TelemtClient::new(&settings.telemt_url, settings.telemt_token.clone())),
            naive: NaiveClient::new(&settings.naive_socket, settings.naive_token.clone()),
            mieru: MieruClient::new(&settings.mieru_socket, settings.mieru_token.clone()),
            amneziawg: AmneziawgClient::new(&settings.amneziawg_socket, settings.amneziawg_token.clone()),
            trusttunnel: TrusttunnelClient::new(&settings.trusttunnel_socket, settings.trusttunnel_token.clone()),
            router: settings
                .xray_router_enabled
                .then(|| XrayRouterClient::new(&settings.xray_router_socket, settings.xray_router_token.clone())),
            versions: VersionClient::new(&settings.version_agent_socket),
            telemt_journal: Arc::new(TelemtEgressJournal::new(Some(settings.telemt_egress_journal()))),
        }
    }
}

/// What the test hooks change (`test-hooks` builds only; inert otherwise).
#[derive(Debug, Default)]
pub struct TestState {
    /// `/__test/probe-bridge`: what the MTProxy ingress probe answers instead of dialling.
    bridge_answer: Mutex<Option<bool>>,
}

impl TestState {
    pub fn set_bridge_answer(&self, answer: bool) {
        *lock(&self.bridge_answer) = Some(answer);
    }

    /// The forced answer of the bridge probe, if a test set one (always `None` in release builds).
    pub fn bridge_answer(&self) -> Option<bool> {
        if cfg!(feature = "test-hooks") {
            *lock(&self.bridge_answer)
        } else {
            None
        }
    }
}

/// Everything this package owns in the state.
pub struct Core {
    pub settings: Settings,
    pub database: Database,
    /// The panel's clock (switchable by the test hooks) as a [`SharedClock`].
    pub clock: SharedClock,
    pub panel_clock: Arc<PanelClock>,
    /// Admins, sessions, login limiter, audit — on the system clock, like Python's `Store`.
    pub store: Arc<Store>,
    pub api_keys: ApiKeyService,
    pub secrets: SecretStore,
    pub events: Arc<EventBus>,
    pub managers: Managers,
    pub key_rate: KeyRateLimiter,
    /// `login_verify_slots`: at most `login_verify_concurrency` argon2 verifications at once.
    pub login_slots: Semaphore,
    pub reveals: Reveals,
    pub panel_guid: String,
    pub panel_version: String,
    /// `panel/static` (`PANEL_STATIC_DIR`, default `/app/panel/static`).
    pub static_dir: PathBuf,
    /// The OpenAPI document served at `/api/openapi.json`.
    pub openapi: bytes::Bytes,
    pub lifespan: Lifespan,
    pub background: Arc<BackgroundWork>,
    pub test: TestState,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core").field("database", &self.database.path()).finish_non_exhaustive()
    }
}

/// Service objects of the other work packages, by type.
#[derive(Default)]
pub struct Services {
    map: http::Extensions,
}

impl Services {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) the service of type `T`.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, service: T) {
        self.map.insert(service);
    }

    pub fn get<T: Clone + Send + Sync + 'static>(&self) -> Option<&T> {
        self.map.get::<T>()
    }
}

/// The state handlers receive.
#[derive(Clone)]
pub struct AppState {
    core: Arc<Core>,
    services: Arc<Services>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.core.fmt(f)
    }
}

impl std::ops::Deref for AppState {
    type Target = Core;

    fn deref(&self) -> &Core {
        &self.core
    }
}

impl AppState {
    pub fn new(core: Arc<Core>, services: Services) -> Self {
        Self { core, services: Arc::new(services) }
    }

    pub fn core(&self) -> &Arc<Core> {
        &self.core
    }

    /// The service of type `T`; a missing one is a wiring bug (panics, answered as a bare 500).
    pub fn service<T: Clone + Send + Sync + 'static>(&self) -> &T {
        self.services.get::<T>().unwrap_or_else(|| panic!("service {} is not wired", std::any::type_name::<T>()))
    }

    /// The service of type `T`, if wired.
    pub fn try_service<T: Clone + Send + Sync + 'static>(&self) -> Option<&T> {
        self.services.get::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_core::clock::FakeClock;

    #[test]
    fn key_rate_limiter_slides_its_window() {
        let clock = Arc::new(FakeClock::default());
        let limiter = KeyRateLimiter::new(2, clock.clone());
        assert!(limiter.allow(1) && limiter.allow(1));
        assert!(!limiter.allow(1));
        assert!(limiter.allow(2));
        clock.advance(60.0);
        assert!(!limiter.allow(1), "exactly 60 s later the first hit still counts");
        clock.advance(0.5);
        assert!(limiter.allow(1));
    }

    #[test]
    fn reveals_are_one_time_and_owned() {
        let clock = Arc::new(FakeClock::default());
        let reveals = Reveals::new(60, clock.clone());
        let token = reveals.create(serde_json::json!({"secret": "s"}), "owner");
        assert!(matches!(reveals.consume(&token, "other"), Err(Failure::Api(_))));
        assert_eq!(reveals.consume(&token, "owner").unwrap()["secret"], "s");
        assert!(reveals.consume(&token, "owner").is_err());
        let late = reveals.create(Value::Null, "owner");
        clock.advance(61.0);
        assert!(reveals.consume(&late, "owner").is_err());
    }

    #[test]
    fn panel_clock_switches_to_the_fake_time() {
        let clock = PanelClock::default();
        assert!(clock.time() > 1_700_000_000.0);
        clock.set(1_800_000_000.0);
        assert_eq!(clock.monotonic(), 100_000_000.0);
        clock.advance(1.5);
        assert_eq!(clock.time(), 1_800_000_001.5);
    }
}
