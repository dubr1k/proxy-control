//! The change hooks `create_app` hangs on [`crate::ClientService`] (`app.py:194`, `:221-230`).

use std::sync::Arc;

use panel_core::db::Conn;
use panel_core::rusqlite::params;
use panel_model::seams::{ClientChangeHook, GenerationPublisher, SeamError};

/// `publish_for_client(db, client_id)`: every grant mutation funnels through
/// `ClientService.notify`; the next generation of each linked node the client touches is
/// published inside the same transaction (spec §6).
pub struct PublishForClient {
    publisher: Arc<dyn GenerationPublisher>,
}

impl PublishForClient {
    pub fn new(publisher: Arc<dyn GenerationPublisher>) -> Self {
        Self { publisher }
    }
}

impl ClientChangeHook for PublishForClient {
    fn on_change(&self, db: &Conn, client_id: &str) -> Result<(), SeamError> {
        let nodes: Vec<String> = {
            let mut statement = db.prepare(
                "SELECT DISTINCT g.node_id FROM access_grants g JOIN node_links l ON l.node_id=g.node_id
                             WHERE g.client_id=?",
            )?;
            let rows = statement.query_map(params![client_id], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for node_id in nodes {
            self.publisher.publish(db, &node_id)?;
        }
        Ok(())
    }
}
