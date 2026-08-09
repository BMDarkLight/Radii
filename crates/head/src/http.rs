use crate::decision::{DecisionEngine, DecisionInput, DecisionReason, Protocol};
use axum::extract::{ConnectInfo, Host, State};
use axum::http::StatusCode;
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    decision: DecisionEngine,
    protocol: Protocol,
}

#[derive(Serialize)]
struct HeadResponse {
    source_ip: String,
    host: Option<String>,
    backend: String,
    decision_reason: String,
}

pub fn router(decision: DecisionEngine) -> Router {
    let state = AppState {
        decision,
        protocol: Protocol::Http,
    };

    Router::new()
        .route("/health", get(health))
        .fallback(any(handle_request))
        .with_state(state)
}

pub async fn serve_http(bind: &str, decision: DecisionEngine) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    serve_http_on(listener, decision).await
}

pub async fn serve_http_on(listener: TcpListener, decision: DecisionEngine) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "head http listening");

    axum::serve(
        listener,
        router(decision).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn handle_request(
    State(state): State<AppState>,
    connect: ConnectInfo<SocketAddr>,
    host: Option<Host>,
) -> Result<Json<HeadResponse>, StatusCode> {
    let host_value = host.as_ref().map(|value| value.0.clone());
    let decision = state.decision.decide(DecisionInput {
        protocol: state.protocol,
        protocol_label: None,
        host: host_value.as_deref(),
        source: Some(connect.0),
        destination_port: None,
        attributes: &[],
    });

    tracing::info!(
        source = %connect.0,
        host = ?host_value,
        backend = %decision.backend,
        reason = ?decision.reason,
        "head received request"
    );

    let reason = match decision.reason {
        DecisionReason::HostMatch => "host_map",
        DecisionReason::Default => "default",
    };

    Ok(Json(HeadResponse {
        source_ip: connect.0.to_string(),
        host: host_value,
        backend: decision.backend,
        decision_reason: reason.to_string(),
    }))
}
