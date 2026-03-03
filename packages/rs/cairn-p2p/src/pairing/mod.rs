pub mod mechanisms;
pub mod messages;
pub mod rate_limit;
pub mod state_machine;
pub mod unpairing;

pub use mechanisms::{
    AdapterError, ConnectionHint, CustomMechanism, CustomPairingAdapter, CustomPayload,
    MechanismError, MechanismType, PairingLinkMechanism, PairingMechanism, PairingPayload,
    PinCodeMechanism, PskError, PskMechanism, QrCodeMechanism,
};
pub use messages::{
    PairChallenge, PairConfirm, PairReject, PairRejectReason, PairRequest, PairResponse,
    PairRevoke, PairingFlowType, PairingMessage,
};
pub use rate_limit::{RateLimitError, RateLimiter};
pub use state_machine::{
    PairingError, PairingRole, PairingSession, PairingState, DEFAULT_PAIRING_TIMEOUT,
};
pub use unpairing::{UnpairingError, UnpairingEvent};
