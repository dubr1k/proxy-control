//! `panel healthcheck`: healthy only on a 200 from `/healthz` with the configured Host.

mod common;

use panel_web::server::Listen;

#[test]
fn healthcheck_needs_an_allowed_host_and_a_200() {
    let panel = common::start(&[]);
    let listen = Listen::Unix(panel.socket.clone());
    assert!(panel_web::healthcheck::probe(&listen, "testserver").unwrap());
    assert!(!panel_web::healthcheck::probe(&listen, "evil.example").unwrap(), "400 Invalid host header");
    assert!(panel_web::healthcheck::probe(&Listen::Unix(panel.dir.join("missing.sock")), "testserver").is_err());
}
