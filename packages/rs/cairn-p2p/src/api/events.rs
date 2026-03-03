use serde::{Deserialize, Serialize};

/// Connection state for a peer session (spec section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Connected,
    Unstable,
    Disconnected,
    Reconnecting,
    Suspended,
    Reconnected,
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Unstable => write!(f, "Unstable"),
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Reconnecting => write!(f, "Reconnecting"),
            ConnectionState::Suspended => write!(f, "Suspended"),
            ConnectionState::Reconnected => write!(f, "Reconnected"),
            ConnectionState::Failed => write!(f, "Failed"),
        }
    }
}

/// Events delivered to the application via tokio mpsc channel.
#[derive(Debug, Clone)]
pub enum Event {
    /// Connection state changed for a peer.
    StateChanged {
        peer_id: String,
        state: ConnectionState,
    },
    /// Data received on a channel.
    MessageReceived {
        peer_id: String,
        channel: String,
        data: Vec<u8>,
    },
    /// Pairing completed successfully.
    PairingCompleted { peer_id: String },
    /// Pairing failed.
    PairingFailed { peer_id: String, error: String },
    /// A channel was opened.
    ChannelOpened {
        peer_id: String,
        channel_name: String,
    },
    /// A channel was closed.
    ChannelClosed {
        peer_id: String,
        channel_name: String,
    },
    /// An error occurred.
    Error { error: String },
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::StateChanged { peer_id, state } => {
                write!(f, "StateChanged({peer_id}, {state})")
            }
            Event::MessageReceived {
                peer_id,
                channel,
                data,
            } => {
                write!(
                    f,
                    "MessageReceived({peer_id}, {channel}, {} bytes)",
                    data.len()
                )
            }
            Event::PairingCompleted { peer_id } => {
                write!(f, "PairingCompleted({peer_id})")
            }
            Event::PairingFailed { peer_id, error } => {
                write!(f, "PairingFailed({peer_id}, {error})")
            }
            Event::ChannelOpened {
                peer_id,
                channel_name,
            } => {
                write!(f, "ChannelOpened({peer_id}, {channel_name})")
            }
            Event::ChannelClosed {
                peer_id,
                channel_name,
            } => {
                write!(f, "ChannelClosed({peer_id}, {channel_name})")
            }
            Event::Error { error } => write!(f, "Error({error})"),
        }
    }
}

/// Network diagnostic information (spec section 7).
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub nat_type: crate::transport::nat::NatType,
    pub external_addr: Option<std::net::SocketAddr>,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            nat_type: crate::transport::nat::NatType::Unknown,
            external_addr: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Unstable.to_string(), "Unstable");
        assert_eq!(ConnectionState::Disconnected.to_string(), "Disconnected");
        assert_eq!(ConnectionState::Reconnecting.to_string(), "Reconnecting");
        assert_eq!(ConnectionState::Suspended.to_string(), "Suspended");
        assert_eq!(ConnectionState::Reconnected.to_string(), "Reconnected");
        assert_eq!(ConnectionState::Failed.to_string(), "Failed");
    }

    #[test]
    fn connection_state_serde_roundtrip() {
        let state = ConnectionState::Connected;
        let json = serde_json::to_string(&state).unwrap();
        let restored: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn event_display() {
        let e = Event::StateChanged {
            peer_id: "abc".into(),
            state: ConnectionState::Connected,
        };
        assert!(e.to_string().contains("abc"));
        assert!(e.to_string().contains("Connected"));

        let e = Event::MessageReceived {
            peer_id: "x".into(),
            channel: "data".into(),
            data: vec![1, 2, 3],
        };
        assert!(e.to_string().contains("3 bytes"));
    }

    #[test]
    fn network_info_default() {
        let info = NetworkInfo::default();
        assert_eq!(info.nat_type, crate::transport::nat::NatType::Unknown);
        assert!(info.external_addr.is_none());
    }

    #[test]
    fn all_seven_connection_states() {
        let states = [
            ConnectionState::Connected,
            ConnectionState::Unstable,
            ConnectionState::Disconnected,
            ConnectionState::Reconnecting,
            ConnectionState::Suspended,
            ConnectionState::Reconnected,
            ConnectionState::Failed,
        ];
        assert_eq!(states.len(), 7);
        for (i, s) in states.iter().enumerate() {
            for (j, t) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(s, t);
                }
            }
        }
    }
}
