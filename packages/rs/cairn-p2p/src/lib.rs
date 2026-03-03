pub mod api;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod mesh;
pub mod pairing;
pub mod protocol;
pub mod server;
pub mod session;
pub mod traits;
pub mod transport;

pub use config::{
    CairnConfig, CairnConfigBuilder, InfrastructureManifest, ManifestConfig, MeshSettings,
    ReconnectionPolicy, StorageBackend, TransportType, TurnServer,
};
pub use error::{CairnError, ErrorBehavior, Result};
pub use identity::{
    IdentityError, InMemoryTrustStore, LocalIdentity, PairedPeerInfo, PeerId, TrustStore,
};

// Public API types (spec section 3.1-3.5).
pub use api::{
    ApiChannel, ApiNode, ApiSession, ConnectionState, Event, LinkPairingData, NetworkInfo,
    PinPairingData, QrPairingData,
};
pub use transport::NatType;

/// Convenience type alias: `Node` is the public-facing name for [`ApiNode`].
pub type Node = ApiNode;

/// Convenience type alias: `Session` is the public-facing name for [`ApiSession`].
pub type Session = ApiSession;

/// Convenience type alias: `Channel` is the public-facing name for [`ApiChannel`].
pub type Channel = ApiChannel;

// Factory functions (spec section 3.2).
pub use config::{create, create_server, create_server_with_config, create_with_config};
