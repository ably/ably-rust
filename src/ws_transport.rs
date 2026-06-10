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
}

impl WsTransport {
    pub fn new(format: Format) -> Self {
        Self { format }
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
        }))
    }
}

struct WsConnection {
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    format: Format,
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
                    Err(_) => continue, // unparseable frame: skip (RTN19-shaped tolerance)
                },
                Ok(WsMessage::Binary(bytes)) => match rmp_serde::from_slice(&bytes) {
                    Ok(pm) => return Some(TransportEvent::Message(pm)),
                    Err(_) => continue,
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
