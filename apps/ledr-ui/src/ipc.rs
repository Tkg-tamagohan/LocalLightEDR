//! Named Pipe IPC client communicating with `ledr-daemon` over `\\.\pipe\localedr-ipc`.

use ledr_proto::{
    AlertDecision, AlertRecord, AlertStatus, AllowlistRuleRecord, FlightRecorderSnapshot,
    IPC_PIPE_NAME, IpcRequest, IpcResponse, PipelineMetrics, RuleScope, read_ipc_frame,
    write_ipc_frame,
};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::thread;
use std::time::Duration;

/// Optional environment variable overriding the Named Pipe path for testing.
pub const IPC_PIPE_OVERRIDE_ENV: &str = "LEDR_IPC_PIPE";

const ERROR_PIPE_BUSY_CODE: i32 = 231;
const PIPE_BUSY_MAX_RETRIES: usize = 3;
const PIPE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(20);

/// Resolves the Named Pipe endpoint from `LEDR_IPC_PIPE` or [`IPC_PIPE_NAME`].
pub fn resolve_ipc_pipe_name() -> String {
    std::env::var(IPC_PIPE_OVERRIDE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| IPC_PIPE_NAME.to_string())
}

/// Client for exchanging 4-byte little-endian length-prefixed JSON frames with `ledr-daemon`.
#[derive(Debug, Clone)]
pub struct IpcClient {
    pipe_name: String,
}

impl IpcClient {
    /// Creates an IPC client targeting `pipe_name`.
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    /// Creates an IPC client targeting `LEDR_IPC_PIPE` if set, otherwise [`IPC_PIPE_NAME`].
    pub fn default_endpoint() -> Self {
        Self::new(resolve_ipc_pipe_name())
    }

    /// Returns the configured Named Pipe endpoint path.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Sends one [`IpcRequest`] over any bidirectional byte stream and reads one [`IpcResponse`].
    pub fn send_request_over_stream<S: Read + Write>(
        stream: &mut S,
        request: &IpcRequest,
    ) -> Result<IpcResponse, String> {
        write_ipc_frame(stream, request).map_err(|err| format!("IPC frame write error: {err}"))?;
        read_ipc_frame::<S, IpcResponse>(stream)
            .map_err(|err| format!("IPC frame read error: {err}"))
    }

    /// Opens the configured Named Pipe and performs a single request/response round-trip.
    pub fn send_request(&self, request: &IpcRequest) -> Result<IpcResponse, String> {
        let mut attempt = 0;
        let mut pipe = loop {
            match OpenOptions::new().read(true).write(true).open(&self.pipe_name) {
                Ok(file) => break file,
                Err(err)
                    if err.raw_os_error() == Some(ERROR_PIPE_BUSY_CODE)
                        && attempt < PIPE_BUSY_MAX_RETRIES =>
                {
                    attempt += 1;
                    thread::sleep(PIPE_BUSY_RETRY_DELAY);
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    return Err(format!(
                        "ledr-daemon is offline (IPC pipe '{}' not found: {err})",
                        self.pipe_name
                    ));
                }
                Err(err) => {
                    return Err(format!(
                        "failed to connect to IPC pipe '{}': {err}",
                        self.pipe_name
                    ));
                }
            }
        };

        Self::send_request_over_stream(&mut pipe, request)
    }

    /// Sends `IpcRequest::Ping` and returns a formatted daemon handshake summary.
    pub fn ping(&self) -> Result<String, String> {
        parse_ping_response(self.send_request(&IpcRequest::Ping)?)
    }

    /// Fetches a [`FlightRecorderSnapshot`] from `ledr-daemon`.
    pub fn get_flight_recorder(
        &self,
        limit: usize,
        process_instance_id: Option<String>,
    ) -> Result<FlightRecorderSnapshot, String> {
        let req = IpcRequest::GetFlightRecorder {
            limit,
            process_instance_id,
        };
        parse_flight_recorder_response(self.send_request(&req)?)
    }

    /// Fetches [`PipelineMetrics`] from `ledr-daemon`.
    pub fn get_pipeline_metrics(&self) -> Result<PipelineMetrics, String> {
        parse_metrics_response(self.send_request(&IpcRequest::GetPipelineMetrics)?)
    }

    /// Fetches persisted alerts from `ledr-daemon`, optionally filtered by [`AlertStatus`].
    pub fn get_alerts(
        &self,
        status: Option<AlertStatus>,
        limit: usize,
    ) -> Result<Vec<AlertRecord>, String> {
        let req = IpcRequest::GetAlerts { status, limit };
        parse_alerts_response(self.send_request(&req)?)
    }

    /// Resolves an alert with the given [`AlertDecision`] (`L-07`).
    pub fn resolve_alert(
        &self,
        alert_id: String,
        decision: AlertDecision,
    ) -> Result<String, String> {
        let req = IpcRequest::ResolveAlert { alert_id, decision };
        parse_ack_response(self.send_request(&req)?)
    }

    /// Lists allowlist/blocklist policy rules from `ledr-daemon`, optionally filtered by [`RuleScope`].
    pub fn list_rules(
        &self,
        scope: Option<RuleScope>,
    ) -> Result<Vec<AllowlistRuleRecord>, String> {
        let req = IpcRequest::ListRules { scope };
        parse_rules_response(self.send_request(&req)?)
    }
}

pub(crate) fn parse_ping_response(response: IpcResponse) -> Result<String, String> {
    match response {
        IpcResponse::Pong {
            daemon_version,
            protocol_version,
        } => Ok(format!(
            "ledr-daemon v{daemon_version} (proto v{protocol_version})"
        )),
        other => Err(unexpected_or_daemon_error(other, "Pong")),
    }
}

pub(crate) fn parse_flight_recorder_response(
    response: IpcResponse,
) -> Result<FlightRecorderSnapshot, String> {
    match response {
        IpcResponse::FlightRecorder(snapshot) => Ok(snapshot),
        other => Err(unexpected_or_daemon_error(other, "FlightRecorder")),
    }
}

pub(crate) fn parse_metrics_response(response: IpcResponse) -> Result<PipelineMetrics, String> {
    match response {
        IpcResponse::Metrics(metrics) => Ok(metrics),
        other => Err(unexpected_or_daemon_error(other, "Metrics")),
    }
}

pub(crate) fn parse_alerts_response(response: IpcResponse) -> Result<Vec<AlertRecord>, String> {
    match response {
        IpcResponse::Alerts(alerts) => Ok(alerts),
        other => Err(unexpected_or_daemon_error(other, "Alerts")),
    }
}

pub(crate) fn parse_ack_response(response: IpcResponse) -> Result<String, String> {
    match response {
        IpcResponse::Ack { message } => Ok(message),
        other => Err(unexpected_or_daemon_error(other, "Ack")),
    }
}

pub(crate) fn parse_rules_response(
    response: IpcResponse,
) -> Result<Vec<AllowlistRuleRecord>, String> {
    match response {
        IpcResponse::Rules(rules) => Ok(rules),
        other => Err(unexpected_or_daemon_error(other, "Rules")),
    }
}

fn unexpected_or_daemon_error(response: IpcResponse, expected: &str) -> String {
    match response {
        IpcResponse::Error { code, message } => format!("daemon error [{code}]: {message}"),
        other => format!("unexpected IPC response (expected {expected}): {other:?}"),
    }
}
