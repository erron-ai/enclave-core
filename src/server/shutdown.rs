//! Graceful-shutdown signal handling.

#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl+c handler");
    };
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm => {}
    }
    tracing::info!(event = "graceful_shutdown_initiated");
}

#[cfg(not(unix))]
pub async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl+c handler");
    tracing::info!(event = "graceful_shutdown_initiated");
}
