use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{AttestationError, Result};
use crate::utils::pad_report_data;

use super::evidence::DstackEvidence;

const DEFAULT_DSTACK_SOCKET: &str = "/var/run/dstack.sock";

/// Check if dstack guest agent is available via its Unix socket.
pub fn is_available() -> bool {
    let socket_path = std::env::var("DSTACK_SOCKET")
        .unwrap_or_else(|_| DEFAULT_DSTACK_SOCKET.to_string());
    Path::new(&socket_path).exists()
}

/// Generate TDX attestation evidence via dstack's guest agent.
///
/// Sends report_data to dstack's `/GetQuote` endpoint over the Unix socket.
/// dstack forwards it to the TDX hardware and returns a standard TDX v4/v5 quote.
pub async fn generate_evidence(report_data: &[u8]) -> Result<DstackEvidence> {
    let padded = pad_report_data(report_data, 64)?;

    let socket_path = std::env::var("DSTACK_SOCKET")
        .unwrap_or_else(|_| DEFAULT_DSTACK_SOCKET.to_string());

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        get_quote_via_socket(&socket_path, &padded),
    )
    .await
    .map_err(|_| {
        AttestationError::HardwareAccessFailed(
            "dstack GetQuote timed out after 30s".to_string(),
        )
    })??;

    // dstack returns the quote as a hex string; convert to base64
    // since the TDX verifier expects base64-encoded quote bytes.
    let quote_bytes = response.decode_quote()?;
    let quote_b64 = BASE64.encode(&quote_bytes);

    Ok(DstackEvidence {
        quote: quote_b64,
        event_log: non_empty(response.event_log),
        vm_config: non_empty(response.vm_config),
    })
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Response from dstack's GetQuote endpoint.
#[derive(Debug, Deserialize)]
struct GetQuoteResponse {
    /// Hex-encoded TDX quote bytes.
    quote: String,
    /// Event log entries (JSON string).
    #[serde(default)]
    event_log: String,
    /// VM configuration.
    #[serde(default)]
    vm_config: String,
}

impl GetQuoteResponse {
    /// Decode the quote field from hex to raw bytes.
    fn decode_quote(&self) -> Result<Vec<u8>> {
        hex::decode(&self.quote).map_err(|e| {
            AttestationError::HardwareAccessFailed(format!(
                "failed to decode dstack quote hex: {e}"
            ))
        })
    }
}

/// POST to dstack's GetQuote endpoint over a Unix domain socket.
///
/// Uses raw HTTP/1.1 framing to avoid additional dependencies.
async fn get_quote_via_socket(socket_path: &str, report_data: &[u8]) -> Result<GetQuoteResponse> {
    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        AttestationError::HardwareAccessFailed(format!(
            "failed to connect to dstack socket {}: {}",
            socket_path, e
        ))
    })?;

    // dstack expects report_data as hex in the JSON body
    let report_data_hex = hex::encode(report_data);
    let body = format!(r#"{{"reportData":"{}"}}"#, report_data_hex);
    let body_bytes = body.as_bytes();

    let request = format!(
        "POST /GetQuote HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body_bytes.len()
    );

    // Send request
    stream.write_all(request.as_bytes()).await.map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to write to dstack socket: {e}"))
    })?;
    stream.write_all(body_bytes).await.map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to write body to dstack socket: {e}"))
    })?;

    // Read response (bounded to 10 MiB to prevent memory exhaustion)
    const MAX_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;
    let mut response = Vec::with_capacity(8192);
    stream
        .take(MAX_RESPONSE_SIZE)
        .read_to_end(&mut response)
        .await
        .map_err(|e| {
            AttestationError::HardwareAccessFailed(format!(
                "failed to read from dstack socket: {e}"
            ))
        })?;

    // Parse HTTP response — split headers from body
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            AttestationError::HardwareAccessFailed(
                "malformed HTTP response from dstack: no header/body separator".to_string(),
            )
        })?;

    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("invalid HTTP headers from dstack: {e}"))
    })?;

    // Check status code
    let status_line = headers.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if status_code != 200 {
        return Err(AttestationError::HardwareAccessFailed(format!(
            "dstack returned HTTP {}: {}",
            status_code,
            String::from_utf8_lossy(&response[header_end + 4..])
        )));
    }

    let body = &response[header_end + 4..];

    let parsed: GetQuoteResponse = serde_json::from_slice(body).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("failed to parse dstack response: {e}"))
    })?;

    // Validate the quote can be decoded
    let _ = parsed.decode_quote()?;

    Ok(parsed)
}
