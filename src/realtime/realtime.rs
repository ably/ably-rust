use std::sync::Arc;

use futures::future::select;
use futures::stream::{SplitSink, SplitStream};
use futures::{select, FutureExt, SinkExt};
use futures_util::{future, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{Mutex, MutexGuard, RwLock};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::realtime::protocol_message::{AttatchMessage, ProtocolMessage};
use crate::realtime::Channels;

use super::MessageMessage;

type WebSocketWrite = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WebSocketRead = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub enum ConnectionState {
    Initialized,
    Connecting,
    Connected,
    Disconnected,
    Suspended,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
    send:  Sender<ProtocolMessage>,
}

struct ConnectionInner {
    state: Mutex<ConnectionState>,
    recv:  Mutex<Receiver<ProtocolMessage>>,
}

impl Connection {
    fn new() -> Self {
        let (send, recv) = channel(1);
        Connection {
            inner: Arc::new(ConnectionInner {
                state: Mutex::new(ConnectionState::Initialized),
                recv:  Mutex::new(recv),
            }),

            send,
        }
    }

    async fn connect(&self) {
        loop {
            let state = self.inner.state.lock().await;
            match &*state {
                ConnectionState::Initialized => {
                    drop(state);
                    self.establish_connection().await
                }
                ConnectionState::Connecting => panic!(),
                ConnectionState::Connected => panic!(),
                ConnectionState::Disconnected => todo!(),
                ConnectionState::Suspended => todo!(),
                ConnectionState::Closing => todo!(),
                ConnectionState::Closed => todo!(),
                ConnectionState::Failed => todo!(),
            }
        }
    }

    async fn sockets(&self) -> WebSocket {
        let key = std::env::var("ABLY_KEY").unwrap();
        let mut url = url::Url::parse("wss://realtime.ably.io").unwrap();
        url.query_pairs_mut()
            .append_pair(
                "key",
                &key,
            )
            .append_pair("protocol", "json")
            .append_pair("echo", "true");

        let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
        println!("socket connected");
        let (write, read) = ws_stream.split();
        WebSocket { read, write }
    }

    async fn establish_connection(&self) {
        let mut ws = self.sockets().await;
        *self.inner.state.lock().await = ConnectionState::Connecting;

        loop {
            let msg = ws.read.next().await.unwrap().unwrap().into_data();
            if let Ok(ProtocolMessage::Connected(_)) = ProtocolMessage::from_json(&msg) {
                *self.inner.state.lock().await = ConnectionState::Connected;
                println!("connected");
                break;
            }
        }

        let f1 = self.read_loop(&mut ws.write).fuse();
        let f2 = self.message_loop(&mut ws.read).fuse();
        pin_mut!(f1, f2);

        select! {
            () = f1 => (),
            () = f2 => (),
        };
        panic!();
    }

    async fn read_loop(&self, ws: &mut WebSocketWrite) {
        loop {
            let msg = self.inner.recv.lock().await.recv().await.unwrap();
            match msg {
                ProtocolMessage::Heartbeat => (),
                ProtocolMessage::Ack => todo!(),
                ProtocolMessage::Nack => todo!(),
                ProtocolMessage::Connect => todo!(),
                ProtocolMessage::Connected(_) => todo!(),
                ProtocolMessage::Disconnect => todo!(),
                ProtocolMessage::Disconnected => todo!(),
                ProtocolMessage::Close => todo!(),
                ProtocolMessage::Closed => todo!(),
                ProtocolMessage::Error(_) => todo!(),
                ProtocolMessage::Attatch(_) => self.send(ws, msg).await,
                ProtocolMessage::Attatched(_) => todo!(),
                ProtocolMessage::Detatch => todo!(),
                ProtocolMessage::Detatched => todo!(),
                ProtocolMessage::Presence => todo!(),
                ProtocolMessage::Message(_) => self.send(ws, msg).await,
                ProtocolMessage::Sync(_) => todo!(),
                ProtocolMessage::Auth => todo!(),
            }
        }
    }

    async fn attatch(&self, name: &str) {
        self.send
            .send(ProtocolMessage::Attatch(AttatchMessage {
                channel: name.to_string(),
            }))
            .await
            .unwrap();
    }

    async fn publish(&self, channel: &str, name: &str, data: &str) {
        let message = crate::realtime::Message {
            id:            None,
            name:          Some(name.to_string()),
            client_id:     None,
            timestamp:     None,
            data:          data.to_string(),
            encoding:      None,
            connection_id: None,
        };
        let message = MessageMessage {
            id:                "".to_string(),
            connection_id:     "".to_string(),
            connection_serial: 999,
            msg_serial:        Some(999),
            channel:           channel.to_string(),
            channel_serial:    "1".to_string(),
            timestamp:         None,
            messages:          vec![message],
        };

        self.send
            .send(ProtocolMessage::Message(message))
            .await
            .unwrap();
    }

    async fn send(&self, ws: &mut WebSocketWrite, msg: ProtocolMessage) {
        let msg = msg.to_json().unwrap();
        ws.send(Message::Binary(msg.into_bytes())).await.unwrap();
    }

    async fn message_loop(&self, ws: &mut WebSocketRead) {
        loop {
            let msg = ws.next().await.unwrap().unwrap().into_data();
            let msg = match ProtocolMessage::from_json(&msg) {
                Ok(msg) => msg,
                Err(err) => {
                    continue;
                }
            };
            println!("\n\nMESSAGE:\n{:#?}", msg);
            match msg {
                ProtocolMessage::Heartbeat => (),
                ProtocolMessage::Ack => (),
                ProtocolMessage::Nack => todo!(),
                ProtocolMessage::Connect => todo!(),
                ProtocolMessage::Connected(_) => todo!(),
                ProtocolMessage::Disconnect => todo!(),
                ProtocolMessage::Disconnected => todo!(),
                ProtocolMessage::Close => todo!(),
                ProtocolMessage::Closed => todo!(),
                ProtocolMessage::Error(_) => todo!(),
                ProtocolMessage::Attatch(_) => todo!(),
                ProtocolMessage::Attatched(msg) => (),
                ProtocolMessage::Detatch => todo!(),
                ProtocolMessage::Detatched => (),
                ProtocolMessage::Presence => todo!(),
                ProtocolMessage::Message(msg) => (),
                ProtocolMessage::Sync(msg) => (),
                ProtocolMessage::Auth => todo!(),
            }
        }
    }
}

struct WebSocket {
    write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    read:  SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

pub struct RealtimeInner {
    channels:   Mutex<Channels>,
    connection: Mutex<Connection>,
}

#[derive(Clone)]
pub struct Realtime {
    inner: Arc<RealtimeInner>,
}

impl Realtime {
    fn new() -> Realtime {
        let realtime = Realtime {
            inner: Arc::new(RealtimeInner {
                channels:   Mutex::new(Channels::new()),
                connection: Mutex::new(Connection::new()),
            }),
        };

        realtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_realtime() {
        let con = Connection::new();
        let send_con = con.clone();
        let join = tokio::spawn(async move { send_con.clone().connect().await });

        con.attatch("chan1").await;

        con.publish("chan1", "hello", "world").await;

        join.await.unwrap();
    }
}
