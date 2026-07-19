//! The channel arm of the connection loop: channel lifecycle
//! (attach/detach and their server confirmations), connection-state
//! effects on channels, and inbound MESSAGE delivery. State lives in
//! `ChannelCtx` (owned by the loop, defined in the parent module);
//! only behaviour lives here.

use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::protocol::{
    action, flags, ChannelEvent, ChannelMode, ChannelState, ChannelStateChange, ConnectionState,
    ProtocolMessage,
};

use super::presence_arm::{deliver_presence, resolve_presence_gets};
use super::*;

impl ChannelCtx {
    /// Transition the channel state machine: snapshot first, then the event
    /// (DESIGN.md §4 contract). RTL2g: no event when the state is unchanged.
    pub(crate) fn transition(
        &mut self,
        to: ChannelState,
        reason: Option<ErrorInfo>,
        resumed: bool,
        has_backlog: bool,
    ) {
        let previous = self.state;
        if previous != to {
            self.logger.major(|| {
                format!(
                    "Channel '{}': {:?} -> {:?}{}",
                    self.name,
                    previous,
                    to,
                    reason
                        .as_ref()
                        .map(|e| format!(" (reason: {})", e))
                        .unwrap_or_default()
                )
            });
        }
        self.state = to;
        if let Some(err) = &reason {
            self.error_reason = Some(err.clone());
        }
        // RTL15b1: DETACHED/SUSPENDED/FAILED clear the channelSerial
        if matches!(
            to,
            ChannelState::Detached | ChannelState::Suspended | ChannelState::Failed
        ) {
            self.channel_serial = None;
        }
        // RTL19: any move out of ATTACHED invalidates the stored delta base —
        // the server resends a fresh non-delta after (re)attach. Clearing on
        // ATTACHING also covers the RTL18c recovery re-attach.
        if to != ChannelState::Attached {
            self.delta_base_payload = None;
            self.delta_last_message_id = None;
        }
        // RTP5a: DETACHED/FAILED clear both presence maps and fail queued
        // presence ops + deferred gets (RTL11); RTP5f: SUSPENDED keeps the
        // map but the sync state is no longer authoritative
        match to {
            ChannelState::Detached | ChannelState::Failed => {
                self.presence.map.clear();
                self.presence.internal.clear();
                self.presence.sync_complete = false;
                let err = reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Channel became {:?}", to),
                    )
                });
                for op in self.presence.queued_ops.drain(..) {
                    let _ = op.reply.send(Err(err.clone()));
                }
                for get in self.presence.pending_get.drain(..) {
                    let _ = get.reply.send(Err(err.clone()));
                }
            }
            ChannelState::Suspended => {
                self.presence.sync_complete = false;
                let err = reason.clone().unwrap_or_else(|| {
                    ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        "Channel suspended",
                    )
                });
                for op in self.presence.queued_ops.drain(..) {
                    let _ = op.reply.send(Err(err.clone()));
                }
                // RTP11d: a deferred waiting get cannot complete once the
                // presence state is out of sync
                for get in self.presence.pending_get.drain(..) {
                    let _ = get.reply.send(Err(ErrorInfo::with_status(
                        ErrorCode::PresenceStateIsOutOfSync.code(),
                        400,
                        "Presence state is out of sync (channel suspended)",
                    )));
                }
            }
            _ => {}
        }
        self.publish_snapshot();
        if previous != to {
            let _ = self.events_tx.send(ChannelStateChange {
                previous,
                current: to,
                event: channel_state_event(to),
                reason,
                resumed,
                has_backlog,
                retry_in: self.next_retry_in.take(),
            });
        }
    }

    /// RTL2g: an UPDATE event for condition changes without a state change.
    pub(crate) fn emit_update(
        &mut self,
        reason: Option<ErrorInfo>,
        resumed: bool,
        has_backlog: bool,
    ) {
        self.logger.major(|| {
            format!(
                "Channel '{}': UPDATE{}",
                self.name,
                reason
                    .as_ref()
                    .map(|e| format!(" (reason: {})", e))
                    .unwrap_or_default()
            )
        });
        self.publish_snapshot();
        let _ = self.events_tx.send(ChannelStateChange {
            previous: self.state,
            current: self.state,
            event: ChannelEvent::Update,
            reason,
            resumed,
            has_backlog,
            retry_in: None,
        });
    }

    pub(crate) fn publish_snapshot(&self) {
        let _ = self.snapshot_tx.send(ChannelSnapshot {
            state: self.state,
            options: self.options.clone(),
            presence_sync_complete: self.presence.sync_complete,
            error_reason: self.error_reason.clone(),
            channel_serial: self.channel_serial.clone(),
            attach_serial: self.attach_serial.clone(),
            modes: self.attached_modes.clone(),
        });
    }

    /// §8: deliver to matching subscribers; prune closed receivers.
    pub(crate) fn deliver(&mut self, msg: &crate::rest::Message) {
        self.subscribers.retain(|sub| {
            let matches = match &sub.filter {
                SubscriberFilter::All => true,
                SubscriberFilter::Name(n) => msg.name.as_deref() == Some(n.as_str()),
                SubscriberFilter::Filter(f) => f.matches(msg),
            };
            if !matches {
                return true;
            }
            sub.sender.send(msg.clone()).is_ok()
        });
    }

    /// RTL18/RTL19/RTL20/PC3: decode one inbound message, applying vcdiff
    /// delta decoding against the stored base payload when the encoding has a
    /// vcdiff step. On success the decoded message is returned and the stored
    /// base payload (RTL19) and last-message id (RTL20) are updated. Returns
    /// `Err` — always code 40018 — when RTL18 recovery is required (a decode
    /// failure or an RTL20 delta-reference id mismatch); the caller discards
    /// the message (RTL18b) and re-attaches (RTL18c).
    pub(crate) fn decode_message(
        &mut self,
        mut msg: crate::rest::Message,
        decoder: &DeltaDecoder,
    ) -> std::result::Result<crate::rest::Message, ErrorInfo> {
        use crate::rest::Data;
        let recover = |m: String| {
            ErrorInfo::new(ErrorCode::VcdiffDecodeFailure.code(), format!("RTL18: {m}"))
        };

        let mut data = std::mem::take(&mut msg.data);
        let mut parts: Vec<String> = msg
            .encoding
            .take()
            .map(|e| {
                e.split('/')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        // RTL19a: an outermost base64 step is decoded first, for delta and
        // non-delta messages alike, before any base-payload bookkeeping.
        if parts.last().map(|s| s == "base64").unwrap_or(false) {
            let bytes = match &data {
                Data::String(s) => {
                    base64::decode(s).map_err(|e| recover(format!("base64 decode: {e}")))?
                }
                Data::Binary(b) => b.to_vec(),
                _ => return Err(recover("base64 step on non-string data".into())),
            };
            data = Data::Binary(serde_bytes::ByteBuf::from(bytes));
            parts.pop();
        }

        if parts.last().map(|s| s == "vcdiff").unwrap_or(false) {
            // RTL20: the delta reference id must match the stored last id.
            let from = delta_from(&msg);
            if from.as_deref() != self.delta_last_message_id.as_deref() {
                return Err(recover(format!(
                    "RTL20: delta reference id {:?} does not match stored id {:?}",
                    from, self.delta_last_message_id
                )));
            }
            let base = self
                .delta_base_payload
                .as_ref()
                .ok_or_else(|| recover("no base payload available for delta".into()))?;
            // PC3a: a string base is UTF-8 encoded to binary before decode.
            let base_bytes: Vec<u8> = match base {
                Data::String(s) => s.as_bytes().to_vec(),
                Data::Binary(b) => b.to_vec(),
                _ => {
                    return Err(recover(
                        "stored base payload is not string or binary".into(),
                    ))
                }
            };
            let delta_bytes: Vec<u8> = match &data {
                Data::Binary(b) => b.to_vec(),
                Data::String(s) => s.clone().into_bytes(),
                _ => return Err(recover("delta payload is not binary".into())),
            };
            let decoded = decoder(&delta_bytes, &base_bytes)
                .map_err(|e| recover(format!("vcdiff decode failed: {e}")))?;
            // RTL19c: the direct vcdiff result becomes the new base payload,
            // before any further decoding steps.
            self.delta_base_payload =
                Some(Data::Binary(serde_bytes::ByteBuf::from(decoded.clone())));
            data = Data::Binary(serde_bytes::ByteBuf::from(decoded));
            parts.pop();
        } else {
            // RTL19b: for a non-delta message the base payload is the wire
            // form AFTER base64 (RTL19a) but BEFORE json/utf-8 decoding.
            self.delta_base_payload = Some(data.clone());
        }

        // Remaining steps (utf-8, json, cipher) via the standard chain (RSL6).
        let remaining = if parts.is_empty() {
            None
        } else {
            Some(parts.join("/"))
        };
        let (d, e) = crate::rest::decode_data(data, remaining, self.options.cipher.as_ref());
        msg.data = d;
        msg.encoding = e;

        // RTL20: store this message's id as the last received id.
        if let Some(id) = &msg.id {
            self.delta_last_message_id = Some(id.clone());
        }
        // TM2s: version defaulting (otherwise done inside decode_with_cipher).
        msg.default_version();
        Ok(msg)
    }

    /// RTP1/RTP19a: apply an ATTACHED frame's HAS_PRESENCE flag. With the
    /// flag a server sync is incoming; without it the presence set is
    /// authoritatively empty — an empty sync window synthesizes the LEAVEs.
    /// `publish` mirrors the call sites' original snapshot behaviour (the
    /// attach transition publishes one itself; an in-place UPDATE does not).
    pub(crate) fn apply_has_presence(&mut self, has_presence: bool, publish: bool) {
        if has_presence {
            self.presence.map.start_sync();
            self.presence.sync_complete = false;
            if publish {
                self.publish_snapshot();
            }
        } else {
            self.presence.map.start_sync();
            let leaves = self.presence.map.end_sync();
            for leave in &leaves {
                deliver_presence(&mut self.presence.subscribers, leave);
            }
            self.presence.sync_complete = true;
            if publish {
                self.publish_snapshot();
            }
            resolve_presence_gets(&mut self.presence);
        }
    }

    pub(crate) fn resolve_attach(&mut self, result: Result<()>) {
        for replier in self.pending_attach.drain(..) {
            let _ = replier.send(result.clone());
        }
    }

    pub(crate) fn resolve_detach(&mut self, result: Result<()>) {
        for replier in self.pending_detach.drain(..) {
            let _ = replier.send(result.clone());
        }
    }
}

pub(super) fn channel_state_event(state: ChannelState) -> ChannelEvent {
    match state {
        ChannelState::Initialized => ChannelEvent::Initialized,
        ChannelState::Attaching => ChannelEvent::Attaching,
        ChannelState::Attached => ChannelEvent::Attached,
        ChannelState::Detaching => ChannelEvent::Detaching,
        ChannelState::Detached => ChannelEvent::Detached,
        ChannelState::Suspended => ChannelEvent::Suspended,
        ChannelState::Failed => ChannelEvent::Failed,
    }
}

impl ConnectionCtx {
    /// RTL4: attach a channel.
    pub(crate) fn handle_attach(&mut self, name: String, reply: oneshot::Sender<Result<()>>) {
        let conn_state = self.state;
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Err(ErrorInfo::new(
                ErrorCode::ChannelOperationFailed.code(),
                "Channel has been released",
            )));
            return;
        };
        match ch.state {
            // RTL4a: already attached — immediate success
            ChannelState::Attached => {
                let _ = reply.send(Ok(()));
            }
            // RTL4h: attach in progress — share its outcome
            ChannelState::Attaching => {
                ch.pending_attach.push(reply);
            }
            // RTL4h: detaching — attach once the detach completes
            ChannelState::Detaching => {
                ch.attach_pending = true;
                ch.pending_attach.push(reply);
            }
            // RTL4g covers Failed (proceeds, clearing errorReason via RTL4c)
            ChannelState::Initialized
            | ChannelState::Detached
            | ChannelState::Suspended
            | ChannelState::Failed => match conn_state {
                // RTL4b: invalid connection states
                ConnectionState::Closing
                | ConnectionState::Closed
                | ConnectionState::Failed
                | ConnectionState::Suspended => {
                    let _ = reply.send(Err(ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        format!("Cannot attach while the connection is {:?}", conn_state),
                    )));
                }
                // RTL4i: queue until the connection is CONNECTED
                ConnectionState::Initialized
                | ConnectionState::Connecting
                | ConnectionState::Disconnected => {
                    // RTL4c: a new attach clears errorReason
                    ch.error_reason = None;
                    ch.pending_attach.push(reply);
                    ch.attach_pending = true;
                    ch.transition(ChannelState::Attaching, None, false, false);
                }
                ConnectionState::Connected => {
                    ch.error_reason = None;
                    ch.pending_attach.push(reply);
                    ch.transition(ChannelState::Attaching, None, false, false);
                    ch.op_deadline = Some(Instant::now() + rtt);
                    let msg = attach_message(ch);
                    self.send_protocol(msg);
                }
            },
        }
    }
    /// RTL5: detach a channel.
    pub(crate) fn handle_detach(&mut self, name: String, reply: oneshot::Sender<Result<()>>) {
        let conn_state = self.state;
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            let _ = reply.send(Ok(()));
            return;
        };
        match ch.state {
            // RTL5a: nothing to detach
            ChannelState::Initialized | ChannelState::Detached => {
                let _ = reply.send(Ok(()));
            }
            // RTL5b: detach from FAILED is an error
            ChannelState::Failed => {
                let _ = reply.send(Err(ErrorInfo::new(
                    ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                    "Cannot detach a failed channel",
                )));
            }
            // RTL5j: suspended → detached immediately
            ChannelState::Suspended => {
                let _ = reply.send(Ok(()));
                ch.transition(ChannelState::Detached, None, false, false);
            }
            // RTL5i: detach in progress — share its outcome
            ChannelState::Detaching => {
                ch.pending_detach.push(reply);
            }
            // RTL5i: attaching — detach once the attach completes
            ChannelState::Attaching => {
                if conn_state == ConnectionState::Connected {
                    ch.detach_pending = true;
                    ch.pending_detach.push(reply);
                } else {
                    // RTL5l: no live connection — abandon the queued attach
                    // and go straight to DETACHED, nothing on the wire
                    ch.attach_pending = false;
                    ch.op_deadline = None;
                    ch.resolve_attach(Err(ErrorInfo::new(
                        ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                        "Attach superseded by detach",
                    )));
                    let _ = reply.send(Ok(()));
                    ch.transition(ChannelState::Detached, None, false, false);
                }
            }
            ChannelState::Attached => {
                if conn_state == ConnectionState::Connected {
                    // RTL5d: DETACH on the wire, await DETACHED
                    ch.op_revert_state = ch.state;
                    ch.pending_detach.push(reply);
                    ch.transition(ChannelState::Detaching, None, false, false);
                    ch.op_deadline = Some(Instant::now() + rtt);
                    let mut msg = ProtocolMessage::new(action::DETACH);
                    msg.channel = Some(ch.name.clone());
                    self.send_protocol(msg);
                } else {
                    // RTL5l: no live connection — detached immediately
                    let _ = reply.send(Ok(()));
                    ch.transition(ChannelState::Detached, None, false, false);
                }
            }
        }
    }
    /// ATTACHED received from the server.
    /// RTP17i: re-enter the internal presence members after an attach
    /// without continuity, omitting the id when the connectionId changed
    /// (RTP17g1). A failed re-entry surfaces as a channel UPDATE carrying a
    /// 91004 error (RTP17e), via the PresenceReentryFailed command.
    pub(crate) fn reenter_internal_members(&mut self, name: &str) {
        let own = self.id.clone();
        let Some(ch) = self.channels.get_mut(name) else {
            return;
        };
        let mut reentries = Vec::new();
        for member in ch.presence.internal.values() {
            let mut enter = member.clone();
            enter.action = Some(crate::rest::PresenceAction::Enter);
            if enter.connection_id != own {
                enter.id = None; // RTP17g1
            }
            enter.connection_id = None;
            reentries.push(enter);
        }
        for enter in reentries {
            let (reply, rx) = oneshot::channel();
            self.send_presence(name.to_string(), enter, reply);
            let input_tx = self.input_tx.clone();
            let chan = name.to_string();
            tokio::spawn(async move {
                if let Ok(Err(err)) = rx.await {
                    let _ = input_tx.send(LoopInput::Cmd(Command::PresenceReentryFailed {
                        name: chan,
                        error: err,
                    }));
                }
            });
        }
    }
    pub(crate) fn handle_attached(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        let resumed = pm.flags.map(|f| f & flags::RESUMED != 0).unwrap_or(false);
        let has_backlog = pm
            .flags
            .map(|f| f & flags::HAS_BACKLOG != 0)
            .unwrap_or(false);
        match ch.state {
            ChannelState::Attaching => {
                ch.attach_serial = pm.channel_serial.clone();
                ch.channel_serial = pm.channel_serial.clone();
                // RTL4m: modes granted by the server
                ch.attached_modes = pm.flags.map(modes_from_flags);
                ch.has_been_attached = true;
                ch.op_deadline = None;
                // RTL13b: a successful attach ends the retry cycle
                ch.retry_at = None;
                ch.retry_count = 0;
                // RTP1/RTP19a: HAS_PRESENCE announces an incoming sync;
                // without it the presence set is authoritatively empty
                let has_presence = pm
                    .flags
                    .map(|f| f & flags::HAS_PRESENCE != 0)
                    .unwrap_or(false);
                ch.apply_has_presence(has_presence, false);
                ch.resolve_attach(Ok(()));
                ch.transition(ChannelState::Attached, pm.error, resumed, has_backlog);
                // RTP5b: queued presence ops go out now
                let queued: Vec<QueuedPresenceOp> = ch.presence.queued_ops.drain(..).collect();
                let detach_now = std::mem::take(&mut ch.detach_pending);
                for op in queued {
                    self.send_presence(name.clone(), op.message, op.reply);
                }
                // RTP17i: automatic re-entry of internal members on a
                // non-resumed attach
                if !resumed {
                    self.reenter_internal_members(&name);
                }
                // RTL5i: a queued detach proceeds now
                if detach_now {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_detach(name, tx);
                }
            }
            ChannelState::Attached => {
                // RTL12-shaped: an additional ATTACHED is an UPDATE
                ch.attach_serial = pm.channel_serial.clone();
                ch.channel_serial = pm.channel_serial.clone();
                if let Some(f) = pm.flags {
                    ch.attached_modes = Some(modes_from_flags(f));
                }
                // RTL12: RESUMED means continuity was preserved — no UPDATE
                if !resumed {
                    ch.emit_update(pm.error, resumed, has_backlog);
                    // RTP1/RTP19a: the flagless re-ATTACHED makes the
                    // presence set authoritatively empty; with HAS_PRESENCE a
                    // fresh sync follows
                    let has_presence = pm
                        .flags
                        .map(|f| f & flags::HAS_PRESENCE != 0)
                        .unwrap_or(false);
                    ch.apply_has_presence(has_presence, true);
                    // RTP17i: continuity was lost — re-enter internal members
                    self.reenter_internal_members(&name);
                }
            }
            // RTL5k: an ATTACHED while detaching/detached is answered with DETACH
            ChannelState::Detaching | ChannelState::Detached => {
                ch.op_deadline = Some(Instant::now() + rtt);
                let mut msg = ProtocolMessage::new(action::DETACH);
                msg.channel = Some(name);
                self.send_protocol(msg);
            }
            _ => {}
        }
    }
    /// DETACHED received from the server.
    pub(crate) fn handle_detached(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        match ch.state {
            ChannelState::Detaching => {
                ch.op_deadline = None;
                ch.resolve_detach(Ok(()));
                ch.transition(ChannelState::Detached, pm.error, false, false);
                if ch.release_on_detach {
                    if let Some(reply) = ch.release_reply.take() {
                        let _ = reply.send(());
                    }
                    self.channels.remove(&name);
                    return;
                }
                // RTL4h: a queued attach proceeds now
                let attach_now =
                    std::mem::take(&mut self.channels.get_mut(&name).unwrap().attach_pending);
                if attach_now {
                    let (tx, _rx) = oneshot::channel();
                    self.handle_attach(name, tx);
                }
            }
            // RTL13a: server-initiated DETACHED on an ATTACHED or SUSPENDED
            // channel triggers an immediate reattach
            ChannelState::Attached | ChannelState::Suspended => {
                let rtt = self.rest.inner.opts.realtime_request_timeout;
                let Some(ch) = self.channels.get_mut(&name) else {
                    return;
                };
                ch.transition(ChannelState::Attaching, pm.error, false, false);
                ch.op_deadline = Some(Instant::now() + rtt);
                let msg = attach_message(ch);
                self.send_protocol(msg);
            }
            // RTL13b: DETACHED while ATTACHING is a failed (re)attach — go
            // SUSPENDED and schedule a retry
            ChannelState::Attaching => {
                let reason = pm.error.clone();
                if let Some(ch) = self.channels.get_mut(&name) {
                    ch.op_deadline = None;
                    ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                        ErrorInfo::new(
                            ErrorCode::ChannelOperationFailedInvalidChannelState.code(),
                            "Attach rejected by the server",
                        )
                    })));
                }
                self.suspend_channel_with_retry(&name, reason);
            }
            _ => {}
        }
    }
    /// ERROR with a channel set: the attach/detach failed (RTL4e/RTL5e-shaped).
    pub(crate) fn handle_channel_error(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else {
            return;
        };
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        ch.op_deadline = None;
        let err = pm.error.clone().unwrap_or_else(|| {
            ErrorInfo::new(ErrorCode::ChannelOperationFailed.code(), "Channel error")
        });
        ch.resolve_attach(Err(err.clone()));
        ch.resolve_detach(Err(err.clone()));
        ch.transition(ChannelState::Failed, Some(err), false, false);
    }
    /// RTL3: connection-state side effects on channels — applied atomically
    /// with the connection transition (DESIGN.md §7).
    pub(crate) fn apply_connection_effects_to_channels(
        &mut self,
        conn_state: ConnectionState,
        reason: &Option<ErrorInfo>,
    ) {
        match conn_state {
            // RTL3a: FAILED fails attached/attaching channels
            ConnectionState::Failed => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                            ErrorInfo::new(ErrorCode::ConnectionFailed.code(), "Connection failed")
                        })));
                        ch.transition(ChannelState::Failed, reason.clone(), false, false);
                    }
                }
            }
            // RTL3b: CLOSED detaches attached/attaching channels
            ConnectionState::Closed => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(ErrorInfo::new(
                            ErrorCode::ConnectionClosed.code(),
                            "Connection closed",
                        )));
                        ch.transition(ChannelState::Detached, None, false, false);
                    }
                }
            }
            // RTL3c: SUSPENDED suspends attached/attaching channels
            ConnectionState::Suspended => {
                for ch in self.channels.values_mut() {
                    if matches!(ch.state, ChannelState::Attached | ChannelState::Attaching) {
                        ch.op_deadline = None;
                        ch.resolve_attach(Err(reason.clone().unwrap_or_else(|| {
                            ErrorInfo::new(
                                ErrorCode::ConnectionSuspended.code(),
                                "Connection suspended",
                            )
                        })));
                        ch.transition(ChannelState::Suspended, reason.clone(), false, false);
                    }
                }
            }
            // RTL3e: DISCONNECTED leaves channel states untouched
            _ => {}
        }
        // RTL13c: channel reattach retries only run while CONNECTED
        if conn_state != ConnectionState::Connected {
            for ch in self.channels.values_mut() {
                ch.retry_at = None;
            }
        }
    }
    /// RTL13b: transition a channel to SUSPENDED and schedule the next
    /// reattach retry (RTB1 backoff over channelRetryTimeout), provided the
    /// connection is still CONNECTED (RTL13c).
    pub(crate) fn suspend_channel_with_retry(&mut self, name: &str, reason: Option<ErrorInfo>) {
        let connected = self.state == ConnectionState::Connected;
        let base = self.rest.inner.opts.channel_retry_timeout;
        let Some(ch) = self.channels.get_mut(name) else {
            return;
        };
        if connected {
            let delay = retry_delay(base, ch.retry_count);
            ch.retry_count += 1;
            ch.retry_at = Some(Instant::now() + delay);
            ch.next_retry_in = Some(delay);
            ch.logger.minor(|| {
                format!(
                    "Channel '{}': scheduling reattach retry {} in {:?} (RTL13b)",
                    name, ch.retry_count, delay
                )
            });
        }
        ch.transition(ChannelState::Suspended, reason, false, false);
    }
    /// RTL3d: on CONNECTED, (re)attach channels that were attached, attaching,
    /// suspended, or queued (RTL4i).
    pub(crate) fn reattach_channels_on_connected(&mut self) {
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let mut to_send = Vec::new();
        for ch in self.channels.values_mut() {
            let queued = std::mem::take(&mut ch.attach_pending);
            let needs_attach = queued
                || matches!(
                    ch.state,
                    ChannelState::Attached | ChannelState::Attaching | ChannelState::Suspended
                );
            if needs_attach {
                if ch.state != ChannelState::Attaching {
                    ch.transition(ChannelState::Attaching, None, false, false);
                }
                ch.op_deadline = Some(Instant::now() + rtt);
                to_send.push(attach_message(ch));
            } else if ch.state == ChannelState::Detaching {
                // RTN19b: a pending DETACH is resent on the new transport
                ch.op_deadline = Some(Instant::now() + rtt);
                let mut msg = ProtocolMessage::new(action::DETACH);
                msg.channel = Some(ch.name.clone());
                to_send.push(msg);
            }
        }
        for msg in to_send {
            self.send_protocol(msg);
        }
    }
    /// A MESSAGE from the server: TM2 field population, RSL6 decode with the
    /// channel cipher, RTL17 attached-only delivery, subscriber dispatch (§8).
    pub(crate) fn handle_message_action(&mut self, pm: ProtocolMessage) {
        let Some(name) = pm.channel.clone() else {
            return;
        };
        // RTL18c: recovery re-attaches from the serial of the message BEFORE
        // the one that failed, so capture the current serial before RTL15b
        // advances it to this ProtocolMessage's serial.
        let prev_serial = self
            .channels
            .get(&name)
            .and_then(|c| c.channel_serial.clone());
        self.update_channel_serial(&pm);
        let rtt = self.rest.inner.opts.realtime_request_timeout;
        let decoder = self.delta_decoder.clone();
        let Some(ch) = self.channels.get_mut(&name) else {
            return;
        };
        // RTL17: messages are only delivered while ATTACHED. This also means a
        // delta arriving mid-recovery (channel ATTACHING) is dropped, so a
        // second decode failure cannot start a second recovery (RTL18 single).
        if ch.state != ChannelState::Attached {
            ch.logger.minor(|| {
                format!(
                    "RTL17: dropping MESSAGE for channel '{}' in state {:?}",
                    name, ch.state
                )
            });
            return;
        }
        // RTL21: decode in ascending array order; a delta may reference the
        // message immediately before it in the same ProtocolMessage.
        let wire = pm.messages.clone().unwrap_or_default();
        let mut recovery: Option<ErrorInfo> = None;
        for (index, mut msg) in wire.into_iter().enumerate() {
            // TM2a: id defaults to protocolMessage.id + ":" + index
            if msg.id.is_none() {
                if let Some(pm_id) = &pm.id {
                    msg.id = Some(format!("{}:{}", pm_id, index));
                }
            }
            // TM2c: connectionId inherited unless already present
            if msg.connection_id.is_none() {
                msg.connection_id = pm.connection_id.clone();
            }
            // TM2f: timestamp inherited unless already present
            if msg.timestamp.is_none() {
                msg.timestamp = pm.timestamp;
            }
            // RSL6/RTL18/RTL19/RTL20: decode (delta-aware) with the channel
            // cipher; a failure requires RTL18 recovery.
            match ch.decode_message(msg, &decoder) {
                Ok(decoded) => ch.deliver(&decoded),
                Err(reason) => {
                    // RTL18b: discard the failed message and stop processing
                    // the rest of this ProtocolMessage.
                    recovery = Some(reason);
                    break;
                }
            }
        }
        if let Some(reason) = recovery {
            // RTL18a: log the failure at Error.
            ch.logger.error(|| {
                format!(
                    "RTL18: vcdiff decode failed on channel '{}': {} — recovering",
                    name, reason
                )
            });
            // RTL18c: re-attach from the previous message's channelSerial,
            // transitioning to ATTACHING with the 40018 reason and awaiting
            // the server's ATTACHED.
            ch.channel_serial = prev_serial;
            ch.op_deadline = Some(Instant::now() + rtt);
            ch.transition(ChannelState::Attaching, Some(reason), false, false);
            let attach = attach_message(ch);
            self.send_protocol(attach);
        }
    }
    /// RTL15b: MESSAGE/PRESENCE/ANNOTATION carrying a channelSerial update the
    /// channel's serial (SYNC is excluded — see handle_presence_action).
    pub(crate) fn update_channel_serial(&mut self, pm: &ProtocolMessage) {
        let Some(name) = &pm.channel else { return };
        let Some(serial) = &pm.channel_serial else {
            return;
        };
        if let Some(ch) = self.channels.get_mut(name) {
            ch.channel_serial = Some(serial.clone());
            ch.publish_snapshot();
        }
    }
}

/// RTL4c/RTL4c1/RTL4k/RTL4l/RTL4j: build the ATTACH message for a channel.
/// RTL20: the delta reference id from a message's `extras.delta.from`, if any.
fn delta_from(msg: &crate::rest::Message) -> Option<String> {
    msg.extras
        .as_ref()?
        .get("delta")?
        .get("from")?
        .as_str()
        .map(String::from)
}

pub(super) fn attach_message(ch: &ChannelCtx) -> ProtocolMessage {
    let mut msg = ProtocolMessage::new(action::ATTACH);
    msg.channel = Some(ch.name.clone());
    // RTL4c1: include the channelSerial from the previous attachment
    if let Some(serial) = &ch.channel_serial {
        msg.channel_serial = Some(serial.clone());
    }
    // RTL4k: requested channel params
    if !ch.options.params.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = ch
            .options
            .params
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        msg.params = Some(serde_json::Value::Object(map));
    }
    // RTL4l: requested modes as flags; RTL4j: ATTACH_RESUME on reattach
    let mut flag_bits: u64 = ch
        .options
        .modes
        .iter()
        .map(|m| match m {
            ChannelMode::Presence => flags::PRESENCE,
            ChannelMode::Publish => flags::PUBLISH,
            ChannelMode::Subscribe => flags::SUBSCRIBE,
            ChannelMode::PresenceSubscribe => flags::PRESENCE_SUBSCRIBE,
            ChannelMode::AnnotationPublish => flags::ANNOTATION_PUBLISH,
            ChannelMode::AnnotationSubscribe => flags::ANNOTATION_SUBSCRIBE,
        })
        .fold(0, |acc, f| acc | f);
    if ch.has_been_attached {
        flag_bits |= flags::ATTACH_RESUME;
    }
    if flag_bits != 0 {
        msg.flags = Some(flag_bits);
    }
    msg
}

/// RTL4m: decode the mode flags granted in ATTACHED.
pub(super) fn modes_from_flags(f: u64) -> Vec<ChannelMode> {
    let mut modes = Vec::new();
    if f & flags::PRESENCE != 0 {
        modes.push(ChannelMode::Presence);
    }
    if f & flags::PUBLISH != 0 {
        modes.push(ChannelMode::Publish);
    }
    if f & flags::SUBSCRIBE != 0 {
        modes.push(ChannelMode::Subscribe);
    }
    if f & flags::PRESENCE_SUBSCRIBE != 0 {
        modes.push(ChannelMode::PresenceSubscribe);
    }
    if f & flags::ANNOTATION_PUBLISH != 0 {
        modes.push(ChannelMode::AnnotationPublish);
    }
    if f & flags::ANNOTATION_SUBSCRIBE != 0 {
        modes.push(ChannelMode::AnnotationSubscribe);
    }
    modes
}
