//! The presence/annotation arm of the connection loop: outbound
//! presence and annotation operations (RTP8/9/10/15, RTAN1/2), the
//! RTP11 get with waitForSync, and inbound PRESENCE/SYNC/ANNOTATION
//! dispatch. State lives in `PresenceCtx` (owned by the loop, defined
//! in the parent module); only behaviour lives here.

use tokio::sync::oneshot;

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{action, ProtocolMessage};
use crate::{ChannelState, ConnectionState};

use super::*;

/// RTP6a/RTP6b: deliver to matching presence subscribers; prune closed.
pub(super) fn deliver_presence(
    subscribers: &mut Vec<PresenceSubscriber>,
    event: &crate::rest::PresenceMessage,
) {
    subscribers.retain(|sub| {
        let matches = match &sub.actions {
            None => true,
            Some(actions) => event.action.map(|a| actions.contains(&a)).unwrap_or(false),
        };
        if !matches {
            return true;
        }
        sub.sender.send(event.clone()).is_ok()
    });
}

/// RTP11: resolve deferred gets now that the sync state is settled.
pub(super) fn resolve_presence_gets(presence: &mut PresenceCtx) {
    for get in std::mem::take(&mut presence.pending_get) {
        let members = presence_members(presence, &get.client_id, &get.connection_id);
        let _ = get.reply.send(Ok(members));
    }
}

/// RTP11c2/c3: the members list with optional clientId/connectionId filters.
pub(super) fn presence_members(
    presence: &PresenceCtx,
    client_id: &Option<String>,
    connection_id: &Option<String>,
) -> Vec<crate::rest::PresenceMessage> {
    presence
        .map
        .values()
        .into_iter()
        .filter(|m| {
            client_id
                .as_ref()
                .map(|c| m.client_id.as_deref() == Some(c.as_str()))
                .unwrap_or(true)
                && connection_id
                    .as_ref()
                    .map(|c| m.connection_id.as_deref() == Some(c.as_str()))
                    .unwrap_or(true)
        })
        .cloned()
        .collect()
}

impl ConnectionCtx {
    /// RTP8/9/10: a presence operation per the RTP16 connection/channel
    /// state table: send when ATTACHED, queue while ATTACHING (or implicit
    /// attach from INITIALIZED, RTP8d), error otherwise (RTP8g/RTP16c).
    pub(crate) fn handle_presence_op(
        &mut self,
        name: String,
        message: crate::rest::PresenceMessage,
        reply: oneshot::Sender<Result<()>>,
    ) {
        let connected = self.state == ConnectionState::Connected;
        let _rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Unknown channel",
            )));
            return;
        };
        match ch.state {
            ChannelState::Attached => {
                if connected {
                    self.send_presence(name, message, reply);
                } else if self.rest.inner.opts.queue_messages
                    && matches!(
                        self.state,
                        ConnectionState::Connecting | ConnectionState::Disconnected
                    )
                {
                    ch.presence
                        .queued_ops
                        .push(QueuedPresenceOp { message, reply });
                } else {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::Disconnected.code(),
                        format!("Cannot send presence in connection state {:?}", self.state),
                    )));
                }
            }
            // RTP16b: queued until the attach completes
            ChannelState::Attaching => {
                ch.presence
                    .queued_ops
                    .push(QueuedPresenceOp { message, reply });
            }
            // RTP8d: an INITIALIZED channel is implicitly attached
            ChannelState::Initialized => {
                ch.presence
                    .queued_ops
                    .push(QueuedPresenceOp { message, reply });
                let (attach_reply, _rx) = oneshot::channel();
                self.handle_attach(name, attach_reply);
            }
            // RTP8g/RTP16c: DETACHED/DETACHING/SUSPENDED/FAILED error
            _ => {
                let _ = reply.send(Err(ErrorInfo::with_status(
                    ErrorCode::UnableToEnterPresenceChannelInvalidChannelState.code(),
                    400,
                    format!("Cannot send presence in channel state {:?}", ch.state),
                )));
            }
        }
    }
    /// Send a PRESENCE ProtocolMessage with the next msgSerial; the ACK/NACK
    /// resolves the reply through the pending-publish machinery (RTL11a:
    /// resolution is unaffected by later channel state changes).
    pub(crate) fn send_presence(
        &mut self,
        name: String,
        message: crate::rest::PresenceMessage,
        reply: oneshot::Sender<Result<()>>,
    ) {
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::PRESENCE);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.presence = Some(vec![message.clone()]);
        self.send_protocol(pm);
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Presence(vec![message]),
            reply: PendingReply::Op(reply),
        });
    }
    /// RTP11: presence get with waitForSync semantics.
    pub(crate) fn handle_presence_get(
        &mut self,
        name: String,
        wait_for_sync: bool,
        client_id: Option<String>,
        connection_id: Option<String>,
        reply: oneshot::Sender<Result<Vec<crate::rest::PresenceMessage>>>,
    ) {
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Ok(Vec::new()));
            return;
        };
        // RTP11d: SUSPENDED errors unless waitForSync=false
        if ch.state == ChannelState::Suspended {
            if wait_for_sync {
                let _ = reply.send(Err(ErrorInfo::with_status(
                    ErrorCode::PresenceStateIsOutOfSync.code(),
                    400,
                    "Presence state is out of sync (channel suspended)",
                )));
            } else {
                let _ = reply.send(Ok(presence_members(
                    &ch.presence,
                    &client_id,
                    &connection_id,
                )));
            }
            return;
        }
        if !wait_for_sync || ch.presence.sync_complete {
            let _ = reply.send(Ok(presence_members(
                &ch.presence,
                &client_id,
                &connection_id,
            )));
            return;
        }
        // RTP11a/RTP11b: defer until the sync completes (the implicit attach
        // is issued handle-side)
        ch.presence.pending_get.push(DeferredPresenceGet {
            client_id,
            connection_id,
            reply,
        });
    }
    /// RTAN1b: annotation ops share the message-publish state table; the
    /// wire shape is an ANNOTATION ProtocolMessage resolved via ACK/NACK
    /// (RTAN1d).
    pub(crate) fn handle_annotation_op(
        &mut self,
        name: String,
        annotation: crate::rest::Annotation,
        reply: oneshot::Sender<Result<()>>,
    ) {
        // RTL6c4-shaped channel gate
        if let Some(ch) = self.channels.get(&name) {
            if matches!(ch.state, ChannelState::Suspended | ChannelState::Failed) {
                let _ = reply.send(Err(ch.error_reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot publish an annotation on a {:?} channel", ch.state),
                    )
                })));
                return;
            }
        }
        if self.state != ConnectionState::Connected {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::Disconnected.code(),
                format!(
                    "Cannot publish an annotation in connection state {:?}",
                    self.state
                ),
            )));
            return;
        }
        // RTAN1a/RSAN1c3: annotation data is encoded per RSL4 (annotations
        // are not encrypted, so no cipher applies)
        let mut annotation = annotation;
        let format = self.rest.inner.opts.format;
        match crate::rest::encode_data_for_wire(
            annotation.data.clone(),
            annotation.encoding.clone(),
            format,
            None,
        ) {
            Ok((data, encoding)) => {
                annotation.data = data;
                annotation.encoding = encoding;
            }
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        }
        let serial = self.msg_serial;
        self.msg_serial += 1;
        let mut pm = ProtocolMessage::new(action::ANNOTATION);
        pm.channel = Some(name.clone());
        pm.msg_serial = Some(serial);
        pm.annotations = Some(vec![annotation.clone()]);
        self.send_protocol(pm);
        self.pending_publishes.push(PendingPublish {
            msg_serial: serial,
            channel: name,
            payload: PendingPayload::Annotations(vec![annotation]),
            reply: PendingReply::Op(reply),
        });
    }
    /// RTAN4: inbound ANNOTATION — decode entries and dispatch to matching
    /// subscribers (RTAN4c type filters).
    pub(crate) fn handle_annotation_action(&mut self, pm: ProtocolMessage) {
        self.update_channel_serial(&pm);
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        if ch.state != ChannelState::Attached {
            return;
        }
        let entries = pm.annotations.clone().unwrap_or_default();
        for (index, mut ann) in entries.into_iter().enumerate() {
            if ann.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    ann.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            if ann.timestamp.is_none() {
                ann.timestamp = pm.timestamp;
            }
            // RTAN4b1: annotation data decodes per RSL6 (no cipher —
            // annotations are not encrypted)
            let (data, encoding) = crate::rest::decode_data(ann.data, ann.encoding, None);
            ann.data = data;
            ann.encoding = encoding;
            ch.annotation_subscribers.retain(|sub| {
                let matches = sub
                    .type_filter
                    .as_ref()
                    .map(|t| ann.annotation_type.as_deref() == Some(t.as_str()))
                    .unwrap_or(true);
                if !matches {
                    return true;
                }
                sub.sender.send(ann.clone()).is_ok()
            });
        }
    }
    /// RTP6/RTP17/RTP18/RTP19: inbound PRESENCE or SYNC. Field population
    /// follows TM2 conventions; events are dispatched per RTP2 newness.
    pub(crate) fn handle_presence_action(&mut self, pm: ProtocolMessage, is_sync: bool) {
        // RTL15b: PRESENCE updates the channel serial; SYNC does not — its
        // channelSerial carries the sync cursor ("<sequence>:<cursor>"), which
        // is not a channel serial and would be rejected by the server if sent
        // back in a reattach ATTACH (RTL4c1).
        if !is_sync {
            self.update_channel_serial(&pm);
        }
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let own_connection = self.id.clone();
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };

        if is_sync && !ch.presence.map.sync_in_progress() {
            // RTP18a: a new sync page stream begins
            ch.logger
                .minor(|| format!("Channel '{}': presence SYNC started", name));
            ch.presence.map.start_sync();
            ch.presence.sync_complete = false;
            ch.publish_snapshot();
        }

        let wire = pm.presence.clone().unwrap_or_default();
        for (index, mut msg) in wire.into_iter().enumerate() {
            // TM2-shaped inheritance
            if msg.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    msg.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            if msg.connection_id.is_none() {
                msg.connection_id = pm.connection_id.clone();
            }
            if msg.timestamp.is_none() {
                msg.timestamp = pm.timestamp;
            }
            msg.decode_with_cipher(ch.options.cipher.as_ref());
            // RTP17: members entered through THIS connection feed the
            // internal map
            if own_connection.is_some() && msg.connection_id == own_connection {
                ch.presence.internal.put(&msg);
            }
            if let Some(event) = ch.presence.map.put(&msg) {
                deliver_presence(&mut ch.presence.subscribers, &event);
            }
        }

        // RTP18b/RTP18c: the sync completes when the cursor is exhausted
        if is_sync && !crate::presence::sync_continues(&pm.channel_serial) {
            ch.logger
                .minor(|| format!("Channel '{}': presence SYNC complete", name));
            let leaves = ch.presence.map.end_sync();
            for leave in &leaves {
                deliver_presence(&mut ch.presence.subscribers, leave);
            }
            ch.presence.sync_complete = true;
            ch.publish_snapshot();
            resolve_presence_gets(&mut ch.presence);
        }
    }
}
