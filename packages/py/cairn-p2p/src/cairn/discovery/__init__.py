"""Discovery backends: mDNS, DHT, trackers, signaling, rendezvous."""

from cairn.discovery.mdns import (
    DhtBackend,
    DiscoveryBackend,
    DiscoveryCoordinator,
    MdnsBackend,
    PeerInfo,
    SignalingBackend,
    TrackerBackend,
)
from cairn.discovery.rendezvous import (
    RendezvousId,
    RotationConfig,
    active_rendezvous_ids,
    active_rendezvous_ids_at,
    compute_epoch,
    current_epoch,
    derive_pairing_rendezvous_id,
    derive_rendezvous_id,
)

__all__ = [
    "DhtBackend",
    "DiscoveryBackend",
    "DiscoveryCoordinator",
    "MdnsBackend",
    "PeerInfo",
    "RendezvousId",
    "RotationConfig",
    "SignalingBackend",
    "TrackerBackend",
    "active_rendezvous_ids",
    "active_rendezvous_ids_at",
    "compute_epoch",
    "current_epoch",
    "derive_pairing_rendezvous_id",
    "derive_rendezvous_id",
]
