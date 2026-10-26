//! `panel/trusttunnel_routes.py`: the read-only, secret-free local TrustTunnel overview. Passwords,
//! share links and certificates never leave through this projection; access changes use grants.

use std::collections::HashMap;

use axum::extract::State;
use panel_clients::store::{self, GrantFilter};
use panel_clients::ClientsError;
use panel_model::clients::{GrantDesiredState, ProtocolOptions};
use panel_model::Protocol;
use panel_pages::overview::{self, Holders};
use panel_pages::Fault;

use super::clients::ClientsDomain;
use super::gather::{gathering, GatherError};
use crate::http::request::Call;
use crate::http::response::{self, Failure, Handled};
use crate::http::router::Routes;
use crate::state::AppState;

pub fn routes() -> Routes {
    Routes::new().get("/api/trusttunnel/overview", overview)
}

fn page_failure(fault: Fault) -> Failure {
    match fault {
        Fault::Api(error) => Failure::from(*error),
        Fault::Manager(error) => match error.app_error() {
            Some(api) => Failure::from(api),
            None => Failure::internal(error),
        },
        Fault::Crash(message) => Failure::internal(message),
    }
}

/// `_holders()`: local, non-deleted TrustTunnel grants by runtime username. Of the typed options,
/// only the display name is public here; hostname material and certificate DER stay out.
async fn holders(app: &AppState) -> Result<Holders, Failure> {
    let clients = app.service::<ClientsDomain>().clients.clone();
    let database = app.database.clone();
    tokio::task::spawn_blocking(move || {
        let all_clients = clients.list_clients()?;
        let names: HashMap<&str, &str> =
            all_clients.iter().map(|client| (client.id.as_str(), client.display_name.as_str())).collect();
        let grants = database.with_connection(|db| {
            store::grants(db, &GrantFilter { node_id: Some("local"), ..GrantFilter::default() })
        })?;
        let mut holders = Holders::new();
        for grant in grants {
            if grant.protocol != Protocol::Trusttunnel || grant.desired_state == GrantDesiredState::Deleted {
                continue;
            }
            let ProtocolOptions::Trusttunnel(options) = &grant.options else {
                unreachable!("stored grant options match their protocol")
            };
            holders.insert(
                grant.runtime_username.clone(),
                serde_json::json!({
                    "grant_id": &grant.id,
                    "client_id": &grant.client_id,
                    "client_name": names.get(grant.client_id.as_str()).copied().unwrap_or(""),
                    "desired_state": grant.desired_state.as_str(),
                    "name": &options.name,
                }),
            );
        }
        Ok::<Holders, ClientsError>(holders)
    })
    .await
    .map_err(Failure::internal)?
    .map_err(Failure::internal)
}

async fn overview(State(app): State<AppState>, call: Call) -> Handled {
    app.current(&call).await?;
    if !app.settings.trusttunnel_enabled {
        return Err(Failure::detail(404, "feature unavailable"));
    }
    let public_host = if app.settings.trusttunnel_public_host.is_empty() {
        app.settings.naive_public_host.as_str()
    } else {
        app.settings.trusttunnel_public_host.as_str()
    };
    let holders = holders(&app).await?;
    let manager = app.managers.trusttunnel.clone();
    let health = tokio::spawn({
        let client = manager.clone();
        async move { client.health().await }
    });
    let endpoint = tokio::spawn({
        let client = manager.clone();
        async move { client.endpoint().await }
    });
    let clients = tokio::spawn(async move { manager.clients().await });
    let (health, endpoint, clients) = match tokio::try_join!(gathering(health), gathering(endpoint), gathering(clients))
    {
        Ok(values) => values,
        Err(GatherError::Call(_)) => {
            return Ok(response::json(200, &overview::trusttunnel_down(public_host, &holders)));
        }
        Err(GatherError::Task(error)) => return Err(error),
    };
    let answer = overview::trusttunnel(public_host, &health, &endpoint, &clients, &holders).map_err(page_failure)?;
    Ok(response::json(200, &answer))
}
