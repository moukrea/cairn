//! Channel multiplexing over yamux streams (spec/02-wire-protocol.md section 7).
//!
//! Channels provide named, multiplexed data streams within a session. Each channel
//! maps 1:1 to a yamux stream. The stream ID implicitly identifies the channel.

use crate::error::{CairnError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Prefix for reserved cairn-internal channel names.
pub const RESERVED_CHANNEL_PREFIX: &str = "__cairn_";

/// Reserved channel name for store-and-forward operations.
pub const CHANNEL_FORWARD: &str = "__cairn_forward";

/// Message type code for ChannelInit (first message on a new stream).
pub const CHANNEL_INIT: u16 = 0x0303;

/// Opaque stream identifier (maps to yamux StreamId).
pub type StreamId = u32;

/// Validate that a channel name is not reserved.
///
/// Application code cannot open channels with the `__cairn_` prefix.
pub fn validate_channel_name(name: &str) -> Result<()> {
    if name.starts_with(RESERVED_CHANNEL_PREFIX) {
        return Err(CairnError::Protocol(format!(
            "channel name '{name}' uses reserved prefix '{RESERVED_CHANNEL_PREFIX}'"
        )));
    }
    if name.is_empty() {
        return Err(CairnError::Protocol(
            "channel name must not be empty".to_string(),
        ));
    }
    Ok(())
}

/// Channel lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// ChannelInit sent, waiting for accept/reject from remote peer.
    Opening,
    /// Accepted and active.
    Open,
    /// Remote peer rejected the channel.
    Rejected,
    /// Either side closed the yamux stream.
    Closed,
}

/// A named channel multiplexed over a yamux stream.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Human-readable channel name.
    pub name: String,
    /// The underlying yamux stream identifier.
    pub stream_id: StreamId,
    /// Current channel state.
    pub state: ChannelState,
    /// Application-defined metadata sent with ChannelInit.
    pub metadata: Option<Vec<u8>>,
}

impl Channel {
    /// Create a new channel in the Opening state.
    pub fn new(name: String, stream_id: StreamId, metadata: Option<Vec<u8>>) -> Self {
        Self {
            name,
            stream_id,
            state: ChannelState::Opening,
            metadata,
        }
    }

    /// Transition to the Open state (accepted by remote).
    pub fn accept(&mut self) -> Result<()> {
        if self.state != ChannelState::Opening {
            return Err(CairnError::Protocol(format!(
                "cannot accept channel '{}' in state {:?}",
                self.name, self.state
            )));
        }
        self.state = ChannelState::Open;
        Ok(())
    }

    /// Transition to the Rejected state.
    pub fn reject(&mut self) -> Result<()> {
        if self.state != ChannelState::Opening {
            return Err(CairnError::Protocol(format!(
                "cannot reject channel '{}' in state {:?}",
                self.name, self.state
            )));
        }
        self.state = ChannelState::Rejected;
        Ok(())
    }

    /// Transition to the Closed state.
    pub fn close(&mut self) -> Result<()> {
        if self.state == ChannelState::Closed {
            return Err(CairnError::Protocol(format!(
                "channel '{}' is already closed",
                self.name
            )));
        }
        self.state = ChannelState::Closed;
        Ok(())
    }

    /// Check if the channel is open and ready for data flow.
    pub fn is_open(&self) -> bool {
        self.state == ChannelState::Open
    }
}

/// The first message sent on a newly opened yamux stream.
///
/// Contains the channel name and optional application-defined metadata.
/// Uses message type code 0x0303 (CHANNEL_INIT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInit {
    /// The name of the channel being opened.
    pub channel_name: String,
    /// Optional application-defined metadata.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub metadata: Option<Vec<u8>>,
}

impl ChannelInit {
    /// Encode the ChannelInit to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| CairnError::Protocol(format!("ChannelInit encode error: {e}")))?;
        Ok(buf)
    }

    /// Decode a ChannelInit from CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes)
            .map_err(|e| CairnError::Protocol(format!("ChannelInit decode error: {e}")))
    }
}

/// Application data payload with reliable delivery semantics (0x0300).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMessage {
    /// Unique message identifier (UUID v7).
    pub msg_id: [u8; 16],
    /// Application data payload.
    pub payload: Vec<u8>,
}

impl DataMessage {
    /// Create a new DataMessage with a fresh UUID v7 identifier.
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            msg_id: *uuid::Uuid::now_v7().as_bytes(),
            payload,
        }
    }
}

/// Acknowledges successful receipt of a DataMessage (0x0301).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataAck {
    /// The msg_id of the acknowledged DataMessage.
    pub acked_msg_id: [u8; 16],
}

/// Negative acknowledgment, requesting retransmission (0x0302).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataNack {
    /// The msg_id of the negatively acknowledged DataMessage.
    pub nacked_msg_id: [u8; 16],
    /// Optional reason for the negative acknowledgment.
    pub reason: Option<String>,
}

/// Events emitted by the channel manager.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// A remote peer opened a new channel.
    Opened {
        channel_name: String,
        stream_id: StreamId,
        metadata: Option<Vec<u8>>,
    },
    /// A channel was accepted.
    Accepted { stream_id: StreamId },
    /// A channel was rejected.
    Rejected {
        stream_id: StreamId,
        reason: Option<String>,
    },
    /// Data received on a channel.
    Data {
        stream_id: StreamId,
        message: DataMessage,
    },
    /// A channel was closed.
    Closed { stream_id: StreamId },
}

/// Manages channels within a session.
///
/// Tracks open channels by stream ID and emits events for channel lifecycle changes.
pub struct ChannelManager {
    channels: HashMap<StreamId, Channel>,
    event_tx: mpsc::Sender<ChannelEvent>,
}

impl ChannelManager {
    /// Create a new channel manager.
    ///
    /// Returns the manager and a receiver for channel events.
    pub fn new(buffer_size: usize) -> (Self, mpsc::Receiver<ChannelEvent>) {
        let (event_tx, event_rx) = mpsc::channel(buffer_size);
        let manager = Self {
            channels: HashMap::new(),
            event_tx,
        };
        (manager, event_rx)
    }

    /// Open a new channel on a given stream.
    ///
    /// Validates the channel name, creates the channel in Opening state,
    /// and returns the ChannelInit payload to send on the stream.
    pub fn open_channel(
        &mut self,
        name: &str,
        stream_id: StreamId,
        metadata: Option<Vec<u8>>,
    ) -> Result<ChannelInit> {
        validate_channel_name(name)?;

        if self.channels.contains_key(&stream_id) {
            return Err(CairnError::Protocol(format!(
                "stream {stream_id} already has a channel"
            )));
        }

        let channel = Channel::new(name.to_string(), stream_id, metadata.clone());
        self.channels.insert(stream_id, channel);

        Ok(ChannelInit {
            channel_name: name.to_string(),
            metadata,
        })
    }

    /// Handle an incoming ChannelInit from a remote peer.
    ///
    /// Creates the channel and emits an Opened event. The application should
    /// call `accept_channel` or `reject_channel` in response.
    pub async fn handle_channel_init(
        &mut self,
        stream_id: StreamId,
        init: ChannelInit,
    ) -> Result<()> {
        if self.channels.contains_key(&stream_id) {
            return Err(CairnError::Protocol(format!(
                "stream {stream_id} already has a channel"
            )));
        }

        let channel = Channel::new(init.channel_name.clone(), stream_id, init.metadata.clone());
        self.channels.insert(stream_id, channel);

        let _ = self
            .event_tx
            .send(ChannelEvent::Opened {
                channel_name: init.channel_name,
                stream_id,
                metadata: init.metadata,
            })
            .await;

        Ok(())
    }

    /// Accept an incoming channel.
    pub async fn accept_channel(&mut self, stream_id: StreamId) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&stream_id)
            .ok_or_else(|| CairnError::Protocol(format!("no channel on stream {stream_id}")))?;

        channel.accept()?;

        let _ = self
            .event_tx
            .send(ChannelEvent::Accepted { stream_id })
            .await;

        Ok(())
    }

    /// Reject an incoming channel.
    pub async fn reject_channel(
        &mut self,
        stream_id: StreamId,
        reason: Option<String>,
    ) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&stream_id)
            .ok_or_else(|| CairnError::Protocol(format!("no channel on stream {stream_id}")))?;

        channel.reject()?;

        let _ = self
            .event_tx
            .send(ChannelEvent::Rejected { stream_id, reason })
            .await;

        Ok(())
    }

    /// Handle incoming data on a channel.
    pub async fn handle_data(&self, stream_id: StreamId, message: DataMessage) -> Result<()> {
        let channel = self
            .channels
            .get(&stream_id)
            .ok_or_else(|| CairnError::Protocol(format!("no channel on stream {stream_id}")))?;

        if !channel.is_open() {
            return Err(CairnError::Protocol(format!(
                "channel '{}' is not open (state: {:?})",
                channel.name, channel.state
            )));
        }

        let _ = self
            .event_tx
            .send(ChannelEvent::Data { stream_id, message })
            .await;

        Ok(())
    }

    /// Close a channel.
    pub async fn close_channel(&mut self, stream_id: StreamId) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&stream_id)
            .ok_or_else(|| CairnError::Protocol(format!("no channel on stream {stream_id}")))?;

        channel.close()?;

        let _ = self.event_tx.send(ChannelEvent::Closed { stream_id }).await;

        Ok(())
    }

    /// Get a channel by stream ID.
    pub fn get_channel(&self, stream_id: StreamId) -> Option<&Channel> {
        self.channels.get(&stream_id)
    }

    /// Get the number of tracked channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
}

/// Helper module for serde_bytes on Option<Vec<u8>>.
mod serde_bytes_opt {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Vec<u8>>, D::Error> {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|bb| bb.into_vec()))
    }

    use serde::Deserialize;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Reserved name validation ---

    #[test]
    fn test_validate_channel_name_valid() {
        assert!(validate_channel_name("my-channel").is_ok());
        assert!(validate_channel_name("data").is_ok());
        assert!(validate_channel_name("chat_room_1").is_ok());
    }

    #[test]
    fn test_validate_channel_name_reserved_prefix_rejected() {
        assert!(validate_channel_name("__cairn_forward").is_err());
        assert!(validate_channel_name("__cairn_custom").is_err());
        assert!(validate_channel_name("__cairn_").is_err());
    }

    #[test]
    fn test_validate_channel_name_empty_rejected() {
        assert!(validate_channel_name("").is_err());
    }

    #[test]
    fn test_reserved_constants() {
        assert_eq!(RESERVED_CHANNEL_PREFIX, "__cairn_");
        assert_eq!(CHANNEL_FORWARD, "__cairn_forward");
        assert!(CHANNEL_FORWARD.starts_with(RESERVED_CHANNEL_PREFIX));
    }

    // --- Channel state transitions ---

    #[test]
    fn test_channel_new_is_opening() {
        let ch = Channel::new("test".into(), 1, None);
        assert_eq!(ch.state, ChannelState::Opening);
        assert_eq!(ch.name, "test");
        assert_eq!(ch.stream_id, 1);
        assert!(!ch.is_open());
    }

    #[test]
    fn test_channel_accept() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.accept().unwrap();
        assert_eq!(ch.state, ChannelState::Open);
        assert!(ch.is_open());
    }

    #[test]
    fn test_channel_reject() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.reject().unwrap();
        assert_eq!(ch.state, ChannelState::Rejected);
        assert!(!ch.is_open());
    }

    #[test]
    fn test_channel_close_from_open() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.accept().unwrap();
        ch.close().unwrap();
        assert_eq!(ch.state, ChannelState::Closed);
        assert!(!ch.is_open());
    }

    #[test]
    fn test_channel_close_from_opening() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.close().unwrap();
        assert_eq!(ch.state, ChannelState::Closed);
    }

    #[test]
    fn test_channel_double_accept_rejected() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.accept().unwrap();
        assert!(ch.accept().is_err());
    }

    #[test]
    fn test_channel_accept_after_reject_rejected() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.reject().unwrap();
        assert!(ch.accept().is_err());
    }

    #[test]
    fn test_channel_double_close_rejected() {
        let mut ch = Channel::new("test".into(), 1, None);
        ch.close().unwrap();
        assert!(ch.close().is_err());
    }

    #[test]
    fn test_channel_with_metadata() {
        let meta = vec![0xCA, 0xFE];
        let ch = Channel::new("test".into(), 1, Some(meta.clone()));
        assert_eq!(ch.metadata, Some(meta));
    }

    // --- ChannelInit serialization ---

    #[test]
    fn test_channel_init_roundtrip() {
        let init = ChannelInit {
            channel_name: "my-channel".to_string(),
            metadata: None,
        };
        let encoded = init.encode().unwrap();
        let decoded = ChannelInit::decode(&encoded).unwrap();
        assert_eq!(init, decoded);
    }

    #[test]
    fn test_channel_init_with_metadata_roundtrip() {
        let init = ChannelInit {
            channel_name: "data-stream".to_string(),
            metadata: Some(vec![0x01, 0x02, 0x03]),
        };
        let encoded = init.encode().unwrap();
        let decoded = ChannelInit::decode(&encoded).unwrap();
        assert_eq!(init, decoded);
    }

    #[test]
    fn test_channel_init_decode_invalid() {
        assert!(ChannelInit::decode(&[0xFF, 0xFF]).is_err());
    }

    // --- DataMessage / DataAck / DataNack ---

    #[test]
    fn test_data_message_new() {
        let msg = DataMessage::new(vec![0xDE, 0xAD]);
        assert_eq!(msg.payload, vec![0xDE, 0xAD]);
        assert_eq!(msg.msg_id.len(), 16);
    }

    #[test]
    fn test_data_message_unique_ids() {
        let msg1 = DataMessage::new(vec![]);
        let msg2 = DataMessage::new(vec![]);
        assert_ne!(msg1.msg_id, msg2.msg_id);
    }

    #[test]
    fn test_data_ack() {
        let msg = DataMessage::new(vec![0x01]);
        let ack = DataAck {
            acked_msg_id: msg.msg_id,
        };
        assert_eq!(ack.acked_msg_id, msg.msg_id);
    }

    #[test]
    fn test_data_nack() {
        let msg = DataMessage::new(vec![0x01]);
        let nack = DataNack {
            nacked_msg_id: msg.msg_id,
            reason: Some("checksum mismatch".into()),
        };
        assert_eq!(nack.nacked_msg_id, msg.msg_id);
        assert_eq!(nack.reason.as_deref(), Some("checksum mismatch"));
    }

    #[test]
    fn test_data_nack_no_reason() {
        let nack = DataNack {
            nacked_msg_id: [0; 16],
            reason: None,
        };
        assert!(nack.reason.is_none());
    }

    // --- ChannelManager ---

    #[tokio::test]
    async fn test_channel_manager_open() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        let init = mgr.open_channel("chat", 1, None).unwrap();
        assert_eq!(init.channel_name, "chat");
        assert!(init.metadata.is_none());
        assert_eq!(mgr.channel_count(), 1);

        let ch = mgr.get_channel(1).unwrap();
        assert_eq!(ch.state, ChannelState::Opening);
    }

    #[tokio::test]
    async fn test_channel_manager_open_reserved_rejected() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        let result = mgr.open_channel("__cairn_forward", 1, None);
        assert!(result.is_err());
        assert_eq!(mgr.channel_count(), 0);
    }

    #[tokio::test]
    async fn test_channel_manager_open_duplicate_stream_rejected() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        mgr.open_channel("chat", 1, None).unwrap();
        let result = mgr.open_channel("other", 1, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_manager_handle_init() {
        let (mut mgr, mut rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "remote-channel".into(),
            metadata: Some(vec![0xAB]),
        };
        mgr.handle_channel_init(5, init).await.unwrap();

        assert_eq!(mgr.channel_count(), 1);
        let ch = mgr.get_channel(5).unwrap();
        assert_eq!(ch.name, "remote-channel");
        assert_eq!(ch.state, ChannelState::Opening);

        let event = rx.try_recv().unwrap();
        match event {
            ChannelEvent::Opened {
                channel_name,
                stream_id,
                metadata,
            } => {
                assert_eq!(channel_name, "remote-channel");
                assert_eq!(stream_id, 5);
                assert_eq!(metadata, Some(vec![0xAB]));
            }
            _ => panic!("expected Opened event"),
        }
    }

    #[tokio::test]
    async fn test_channel_manager_accept() {
        let (mut mgr, mut rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "ch".into(),
            metadata: None,
        };
        mgr.handle_channel_init(1, init).await.unwrap();
        let _ = rx.try_recv(); // consume Opened event

        mgr.accept_channel(1).await.unwrap();

        let ch = mgr.get_channel(1).unwrap();
        assert_eq!(ch.state, ChannelState::Open);

        let event = rx.try_recv().unwrap();
        matches!(event, ChannelEvent::Accepted { stream_id: 1 });
    }

    #[tokio::test]
    async fn test_channel_manager_reject() {
        let (mut mgr, mut rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "ch".into(),
            metadata: None,
        };
        mgr.handle_channel_init(1, init).await.unwrap();
        let _ = rx.try_recv();

        mgr.reject_channel(1, Some("not allowed".into()))
            .await
            .unwrap();

        let ch = mgr.get_channel(1).unwrap();
        assert_eq!(ch.state, ChannelState::Rejected);

        let event = rx.try_recv().unwrap();
        match event {
            ChannelEvent::Rejected { stream_id, reason } => {
                assert_eq!(stream_id, 1);
                assert_eq!(reason.as_deref(), Some("not allowed"));
            }
            _ => panic!("expected Rejected event"),
        }
    }

    #[tokio::test]
    async fn test_channel_manager_data_on_open_channel() {
        let (mut mgr, mut rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "data".into(),
            metadata: None,
        };
        mgr.handle_channel_init(1, init).await.unwrap();
        let _ = rx.try_recv();
        mgr.accept_channel(1).await.unwrap();
        let _ = rx.try_recv();

        let msg = DataMessage::new(vec![0x42]);
        let msg_id = msg.msg_id;
        mgr.handle_data(1, msg).await.unwrap();

        let event = rx.try_recv().unwrap();
        match event {
            ChannelEvent::Data { stream_id, message } => {
                assert_eq!(stream_id, 1);
                assert_eq!(message.msg_id, msg_id);
                assert_eq!(message.payload, vec![0x42]);
            }
            _ => panic!("expected Data event"),
        }
    }

    #[tokio::test]
    async fn test_channel_manager_data_on_non_open_rejected() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "data".into(),
            metadata: None,
        };
        mgr.handle_channel_init(1, init).await.unwrap();
        // Channel is still in Opening state, not Open
        let msg = DataMessage::new(vec![0x42]);
        let result = mgr.handle_data(1, msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_manager_data_on_unknown_stream_rejected() {
        let (mgr, _rx) = ChannelManager::new(16);
        let msg = DataMessage::new(vec![0x42]);
        let result = mgr.handle_data(99, msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_manager_close() {
        let (mut mgr, mut rx) = ChannelManager::new(16);
        let init = ChannelInit {
            channel_name: "ch".into(),
            metadata: None,
        };
        mgr.handle_channel_init(1, init).await.unwrap();
        let _ = rx.try_recv();
        mgr.accept_channel(1).await.unwrap();
        let _ = rx.try_recv();

        mgr.close_channel(1).await.unwrap();

        let ch = mgr.get_channel(1).unwrap();
        assert_eq!(ch.state, ChannelState::Closed);

        let event = rx.try_recv().unwrap();
        matches!(event, ChannelEvent::Closed { stream_id: 1 });
    }

    #[tokio::test]
    async fn test_channel_manager_open_with_metadata() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        let meta = vec![0x01, 0x02];
        let init = mgr.open_channel("meta-ch", 1, Some(meta.clone())).unwrap();
        assert_eq!(init.metadata, Some(meta.clone()));

        let ch = mgr.get_channel(1).unwrap();
        assert_eq!(ch.metadata, Some(meta));
    }

    #[tokio::test]
    async fn test_channel_manager_multiple_channels() {
        let (mut mgr, _rx) = ChannelManager::new(16);
        mgr.open_channel("ch1", 1, None).unwrap();
        mgr.open_channel("ch2", 2, None).unwrap();
        mgr.open_channel("ch3", 3, None).unwrap();
        assert_eq!(mgr.channel_count(), 3);

        assert_eq!(mgr.get_channel(1).unwrap().name, "ch1");
        assert_eq!(mgr.get_channel(2).unwrap().name, "ch2");
        assert_eq!(mgr.get_channel(3).unwrap().name, "ch3");
        assert!(mgr.get_channel(4).is_none());
    }
}
