//! Harmless DNS resolution and loopback TCP ping/ack simulator.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};

use super::types::DnsTcpOutcome;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves `domain:port` and connects briefly over TCP, falling back to an in-process
/// loopback TCP listener when `--loopback` is requested or the host is offline.
pub async fn run_dns_tcp_scenario(
    domain: &str,
    port: u16,
    force_loopback: bool,
) -> Result<DnsTcpOutcome> {
    run_dns_tcp_scenario_with_hold(domain, port, force_loopback, 0).await
}

/// Like [`run_dns_tcp_scenario`], holding the process alive for `hold_ms` milliseconds
/// after closing the TCP connection so asynchronous ETW + WFP containment can be observed.
pub async fn run_dns_tcp_scenario_with_hold(
    domain: &str,
    port: u16,
    force_loopback: bool,
    hold_ms: u64,
) -> Result<DnsTcpOutcome> {
    if force_loopback {
        let outcome = run_loopback_tcp_exchange("forced --loopback mode").await?;
        wait_hold_ms(hold_ms).await;
        return Ok(outcome);
    }

    let lookup_res = tokio::time::timeout(NETWORK_TIMEOUT, lookup_host((domain, port))).await;
    let addrs: Vec<SocketAddr> = match lookup_res {
        Ok(Ok(iter)) => iter.collect(),
        Ok(Err(err)) => {
            let outcome = run_loopback_tcp_exchange(&format!(
                "DNS lookup for `{domain}:{port}` unavailable ({err}); fell back to loopback"
            ))
            .await?;
            wait_hold_ms(hold_ms).await;
            return Ok(outcome);
        }
        Err(_) => {
            let outcome = run_loopback_tcp_exchange(&format!(
                "DNS lookup for `{domain}:{port}` timed out; fell back to loopback"
            ))
            .await?;
            wait_hold_ms(hold_ms).await;
            return Ok(outcome);
        }
    };

    let mut resolved_ips = Vec::new();
    for addr in &addrs {
        if !resolved_ips.contains(&addr.ip()) {
            resolved_ips.push(addr.ip());
        }
    }

    for addr in addrs {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(NETWORK_TIMEOUT, TcpStream::connect(addr)).await
        {
            let _ = stream.shutdown().await;
            drop(stream);
            wait_hold_ms(hold_ms).await;
            return Ok(DnsTcpOutcome {
                domain: domain.to_string(),
                resolved_ips,
                connected_addr: Some(addr.to_string()),
                used_loopback: false,
                connected: true,
                note: "DNS resolution and TCP connect completed".to_string(),
            });
        }
    }

    let outcome = run_loopback_tcp_exchange(&format!(
        "TCP connect to `{domain}:{port}` unreachable offline; fell back to loopback"
    ))
    .await?;
    wait_hold_ms(hold_ms).await;
    Ok(outcome)
}

async fn wait_hold_ms(hold_ms: u64) {
    if hold_ms == 0 {
        return;
    }
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(hold_ms)) => {}
        _ = ctrl_c => {}
    }
}

/// Runs a self-contained loopback TCP listener + client exchange for offline validation.
pub async fn run_loopback_tcp_exchange(reason: &str) -> Result<DnsTcpOutcome> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind loopback TCP listener")?;
    let bound_addr = listener.local_addr()?;

    let mut resolved_ips = Vec::new();
    if let Ok(iter) = lookup_host(("localhost", bound_addr.port())).await {
        for addr in iter {
            if !resolved_ips.contains(&addr.ip()) {
                resolved_ips.push(addr.ip());
            }
        }
    }
    if resolved_ips.is_empty() {
        resolved_ips.push(bound_addr.ip());
    }

    let server_task = tokio::spawn(async move {
        if let Ok((mut sock, _peer)) = listener.accept().await {
            let _ = handle_ping_server(&mut sock).await;
        }
    });

    let mut client = match TcpStream::connect(bound_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            server_task.abort();
            return Err(err).context("failed to connect to loopback TCP listener");
        }
    };
    let _ = exchange_ping_ack(&mut client).await?;
    let _ = server_task.await;

    Ok(DnsTcpOutcome {
        domain: "localhost".to_string(),
        resolved_ips,
        connected_addr: Some(bound_addr.to_string()),
        used_loopback: true,
        connected: true,
        note: reason.to_string(),
    })
}

pub(crate) async fn handle_ping_server<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<String> {
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await?;
    stream.write_all(b"LocalEDR-Sim-Ack\n").await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

pub(crate) async fn exchange_ping_ack<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<String> {
    stream.write_all(b"LocalEDR-Sim-Ping\n").await?;
    stream.flush().await?;
    let mut ack = [0u8; 64];
    let n = match tokio::time::timeout(NETWORK_TIMEOUT, stream.read(&mut ack)).await {
        Ok(Ok(count)) => count,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => 0,
    };
    let _ = stream.shutdown().await;
    Ok(String::from_utf8_lossy(&ack[..n]).into_owned())
}
