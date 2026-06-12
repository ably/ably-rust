//! The production WebSocket transport (tokio-tungstenite), implementing the
//! `Transport` trait. Protocol messages travel as JSON text frames or msgpack
//! binary frames depending on the configured format (RTN2a).

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::ProtocolMessage;
use crate::rest::Format;
use crate::transport::{Transport, TransportConnection, TransportEvent};

pub(crate) struct WsTransport {
    format: Format,
    logger: crate::options::Logger,
}

impl WsTransport {
    pub fn new(format: Format, logger: crate::options::Logger) -> Self {
        Self { format, logger }
    }
}

#[async_trait]
impl Transport for WsTransport {
    async fn connect(&self, url: &str) -> Result<Box<dyn TransportConnection>> {
        let (stream, _response) = tokio_tungstenite::connect_async(url).await.map_err(|e| {
            ErrorInfo::with_status(
                ErrorCode::ConnectionFailed.code(),
                400,
                format!("WebSocket connect failed: {}", e),
            )
        })?;
        Ok(Box::new(WsConnection {
            stream,
            format: self.format,
            logger: self.logger.clone(),
        }))
    }
}

struct WsConnection {
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    format: Format,
    logger: crate::options::Logger,
}

#[async_trait]
impl TransportConnection for WsConnection {
    async fn send(&mut self, msg: ProtocolMessage) -> Result<()> {
        let frame = match self.format {
            Format::JSON => WsMessage::Text(serde_json::to_string(&msg)?),
            Format::MessagePack => WsMessage::Binary(rmp_serde::to_vec_named(&msg)?),
        };
        self.stream.send(frame).await.map_err(|e| {
            ErrorInfo::new(
                ErrorCode::Disconnected.code(),
                format!("WebSocket send failed: {}", e),
            )
        })
    }

    async fn recv(&mut self) -> Option<TransportEvent> {
        loop {
            match self.stream.next().await? {
                Ok(WsMessage::Text(text)) => match serde_json::from_str(&text) {
                    Ok(pm) => return Some(TransportEvent::Message(pm)),
                    Err(e) => {
                        // tolerated, but never silently (observability policy)
                        self.logger.error(|| {
                            format!(
                                "Discarding undecodable JSON frame ({} bytes): {}",
                                text.len(),
                                e
                            )
                        });
                        continue;
                    }
                },
                Ok(WsMessage::Binary(bytes)) => match decode_msgpack_tolerant(&bytes) {
                    Some(pm) => return Some(TransportEvent::Message(pm)),
                    None => {
                        self.logger.error(|| {
                            format!(
                                "Discarding undecodable msgpack frame ({} bytes) — failed even tolerant decode",
                                bytes.len()
                            )
                        });
                        continue;
                    }
                },
                Ok(WsMessage::Close(_)) => return Some(TransportEvent::Disconnected),
                Ok(_) => continue, // ping/pong/frame are transport-level
                Err(_) => return Some(TransportEvent::Disconnected),
            }
        }
    }

    async fn close(&mut self) {
        let _ = self.stream.close(None).await;
    }
}

/// Decode a msgpack frame into a ProtocolMessage. The realtime service has
/// been observed emitting DUPLICATE map keys in msgpack frames (e.g.
/// `messages` twice in a MESSAGE); serde rejects those, so per RTF1
/// (deserialization must be tolerant) we dedup keys — last occurrence wins —
/// and retry. Re-encoding (rather than a JSON round-trip) preserves binary
/// payloads.
fn decode_msgpack_tolerant(bytes: &[u8]) -> Option<ProtocolMessage> {
    match rmp_serde::from_slice(bytes) {
        Ok(pm) => Some(pm),
        Err(_) => {
            let value = rmpv::decode::read_value(&mut &bytes[..]).ok()?;
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &dedup_map_keys(value)).ok()?;
            rmp_serde::from_slice(&out).ok()
        }
    }
}

fn dedup_map_keys(value: rmpv::Value) -> rmpv::Value {
    match value {
        rmpv::Value::Map(entries) => {
            let mut deduped: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();
            for (k, v) in entries {
                let v = dedup_map_keys(v);
                if let Some(slot) = deduped.iter_mut().find(|(ek, _)| ek == &k) {
                    slot.1 = v;
                } else {
                    deduped.push((k, v));
                }
            }
            rmpv::Value::Map(deduped)
        }
        rmpv::Value::Array(items) => {
            rmpv::Value::Array(items.into_iter().map(dedup_map_keys).collect())
        }
        other => other,
    }
}
