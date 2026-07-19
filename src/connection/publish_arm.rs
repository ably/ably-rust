//! The publish-ACK arm of the connection loop: the RTL6 publish
//! pipeline (send/queue per connection state), the RTN19a resend on
//! reconnect, and ACK/NACK resolution (TR4s/RTL6j) for messages,
//! presence and annotations alike via `PendingPublish`. State types
//! are defined in the parent module; only behaviour lives here.

use tokio::sync::oneshot;

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{action, ChannelState, ConnectionState, ProtocolMessage};

use super::*;

impl ConnectionCtx {
    /// RTL6c: the publish state table. Channel SUSPENDED/FAILED and terminal
    /// connection states fail immediately (RTL6c4); CONNECTED sends now
    /// (RTL6c1, regardless of channel attach state, no implicit attach
    /// RTL6c5); anything else queues per queueMessages (RTL6c2).
    pub(crate) fn handle_publish(
        &mut self,
        name: String,
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
        reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
    ) {
        // RTL6c4: channel state gate
        if let Some(ch) = self.channels.get(&name) {
            if matches!(ch.state, ChannelState::Suspended | ChannelState::Failed) {
                let _ = reply.send(Err(ch.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot publish on a {:?} channel", ch.state),
                    )
                })));
                return;
            }
        }
        match self.state {
            ConnectionState::Connected => self.send_publish(name, messages, params, reply),
            // RTL6c2: queue while a connection is plausible
            ConnectionState::Initialized
            | ConnectionState::Connecting
            | ConnectionState::Disconnected => {
                if self.rest.inner.opts.queue_messages {
                    self.queued_publishes.push(QueuedPublish {
                        channel: name,
                        messages,
                        params,
                        reply,
                    });
                } else {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::Disconnected.code(),
                        "Cannot publish: not connected and queueMessages is disabled",
                    )));
                }
            }
            // RTL6c4: terminal connection states
            _ => {
                let _ = reply.send(Err(self.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ConnectionFailed.code(),
                        format!("Cannot publish in connection state {:?}", self.state),
                    )
                })));
            }
        }
    }
    /// Encode for the wire (RSL4/RSL5 with the channel cipher), assign the
    /// next msgSerial (RTN7b), send, and register the pending ACK (RTN7a).
    pub(crate) fn send_publish(
        &mut self,
        name: String,
        messages: Vec<crate::rest::Message>,
        params: Option<serde_json::Value>,
        reply: oneshot::Sender<Result<crate::rest::PublishResult>>,
    ) {
        let cipher = self
            .channels
            .get(&name)
            .and_then(|ch| ch.options.cipher.clone());
        let format = self.rest.inner.opts.format;
        let mut wire_messages = Vec::with_capacity(messages.len());
        for mut msg in messages {
            let (data, encoding) = match crate::rest::encode_data_for_wire(
                msg.data,
                msg.encoding,
                format,
                cipher.as_ref(),
            ) {
                Ok(de) => de,
                Err(e) => {
                    let _ = reply.send(Err(e));
                    return;
                }
            };
            msg.data = data;
            msg.encoding = encoding;
            wire_messages.push(msg);
        }
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::MESSAGE);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.messages = Some(wire_messages.clone());
        pm.params = params.clone();
        self.send_protocol(pm);
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Messages {
                messages: wire_messages,
                params,
            },
            reply: PendingReply::Publish(reply),
        });
    }
    /// Resend a pending publish verbatim (RTN19a) under its (possibly
    /// renumbered) serial.
    pub(crate) fn resend_pending_publishes(&mut self) {
        if !self.pending_publishes.is_empty() {
            self.logger().minor(|| {
                format!(
                    "RTN19a: resending {} pending publish(es) on the new transport",
                    self.pending_publishes.len()
                )
            });
        }
        let resends: Vec<ProtocolMessage> = self
            .pending_publishes
            .iter()
            .map(|p| {
                p.payload
                    .to_protocol_message(p.channel.clone(), p.msg_serial)
            })
            .collect();
        for pm in resends {
            self.send_protocol(pm);
        }
    }
    /// RTL6c2: queued publishes go out in order once CONNECTED.
    pub(crate) fn flush_queued_publishes(&mut self) {
        if !self.queued_publishes.is_empty() {
            self.logger().minor(|| {
                format!(
                    "Flushing {} queued publish(es)",
                    self.queued_publishes.len()
                )
            });
        }
        for q in std::mem::take(&mut self.queued_publishes) {
            self.send_publish(q.channel, q.messages, q.params, q.reply);
        }
    }
    /// RTN7e: fail every pending and queued publish with the given reason.
    pub(crate) fn fail_all_publishes(&mut self, reason: &ErrorInfo) {
        for p in self.pending_publishes.drain(..) {
            p.reply.resolve(Err(reason.clone()));
        }
        for q in self.queued_publishes.drain(..) {
            let _ = q.reply.send(Err(reason.clone()));
        }
    }
    /// TR4s/RTL6j: an ACK resolves pending publishes with serials in
    /// [msgSerial, msgSerial+count), pairing them with `res` entries.
    pub(crate) fn handle_ack(&mut self, pm: ProtocolMessage) {
        let first = pm.msg_serial.unwrap_or(0);
        let count = pm.count.unwrap_or(1) as i64;
        let res = pm.res.unwrap_or_default();
        let acked: Vec<PendingPublish> = {
            let mut acked = Vec::new();
            let mut i = 0;
            while i < self.pending_publishes.len() {
                let serial = self.pending_publishes[i].msg_serial;
                if serial >= first && serial < first + count {
                    acked.push(self.pending_publishes.remove(i));
                } else {
                    i += 1;
                }
            }
            acked
        };
        if acked.is_empty() {
            self.logger().error(|| {
                format!(
                    "ACK for unknown msgSerial range [{}, {}) — no pending operation matches",
                    first,
                    first + count
                )
            });
        }
        for p in acked {
            let idx = (p.msg_serial - first) as usize;
            let result = res
                .get(idx)
                .map(|r| crate::rest::PublishResult {
                    serials: r.serials.clone(),
                    message_id: None,
                })
                .unwrap_or_default();
            p.reply.resolve(Ok(result));
        }
    }
    /// A NACK fails the addressed pending publishes (RTL6j).
    pub(crate) fn handle_nack(&mut self, pm: ProtocolMessage) {
        let first = pm.msg_serial.unwrap_or(0);
        let count = pm.count.unwrap_or(1) as i64;
        let reason = pm.error.unwrap_or_else(|| {
            ErrorInfo::with_status(ErrorCode::InternalError.code(), 500, "Publish rejected")
        });
        let mut i = 0;
        let mut matched = false;
        while i < self.pending_publishes.len() {
            let serial = self.pending_publishes[i].msg_serial;
            if serial >= first && serial < first + count {
                let p = self.pending_publishes.remove(i);
                self.logger()
                    .minor(|| format!("NACK for msgSerial {}: {}", serial, reason));
                p.reply.resolve(Err(reason.clone()));
                matched = true;
            } else {
                i += 1;
            }
        }
        if !matched {
            self.logger().error(|| {
                format!(
                    "NACK for unknown msgSerial range [{}, {}) — no pending operation matches",
                    first,
                    first + count
                )
            });
        }
    }
}
