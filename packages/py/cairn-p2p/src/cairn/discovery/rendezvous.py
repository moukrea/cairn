"""Rendezvous ID derivation and rotation system."""

from __future__ import annotations

import time
from dataclasses import dataclass

from cairn.crypto.kdf import hkdf_sha256

HKDF_INFO_RENDEZVOUS: bytes = b"cairn-rendezvous-v1"
HKDF_INFO_PAIRING_RENDEZVOUS: bytes = (
    b"cairn-pairing-rendezvous-v1"
)
HKDF_INFO_EPOCH_OFFSET: bytes = b"cairn-epoch-offset-v1"


class RendezvousId:
    """A 32-byte opaque rendezvous identifier."""

    def __init__(self, data: bytes) -> None:
        if len(data) != 32:
            raise ValueError(
                f"RendezvousId must be 32 bytes, got {len(data)}"
            )
        self._data = data

    @property
    def data(self) -> bytes:
        return self._data

    def to_hex(self) -> str:
        return self._data.hex()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RendezvousId):
            return self._data == other._data
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._data)

    def __repr__(self) -> str:
        return f"RendezvousId({self.to_hex()[:16]}...)"


@dataclass
class RotationConfig:
    """Configuration for rendezvous ID rotation."""

    rotation_interval: float = 86400.0  # 24 hours
    overlap_window: float = 3600.0  # 1 hour
    clock_tolerance: float = 300.0  # 5 minutes


def derive_rendezvous_id(
    pairing_secret: bytes, epoch: int
) -> RendezvousId:
    """Derive a rendezvous ID from pairing secret and epoch number."""
    salt = epoch.to_bytes(8, "big")
    data = hkdf_sha256(
        pairing_secret, salt, HKDF_INFO_RENDEZVOUS, 32
    )
    return RendezvousId(data)


def derive_pairing_rendezvous_id(
    pake_credential: bytes, nonce: bytes
) -> RendezvousId:
    """Derive a pairing-bootstrapped rendezvous ID.

    Used for initial discovery before a pairing secret exists.
    """
    data = hkdf_sha256(
        pake_credential, nonce, HKDF_INFO_PAIRING_RENDEZVOUS, 32
    )
    return RendezvousId(data)


def _derive_epoch_offset(pairing_secret: bytes) -> int:
    """Derive epoch offset from pairing secret."""
    offset_bytes = hkdf_sha256(
        pairing_secret, b"", HKDF_INFO_EPOCH_OFFSET, 8
    )
    return int.from_bytes(offset_bytes, "big")


def compute_epoch(
    pairing_secret: bytes,
    rotation_interval: float,
    timestamp_secs: float,
) -> int:
    """Compute epoch number for a given pairing secret and time."""
    if rotation_interval <= 0:
        raise ValueError("rotation interval must be > 0")
    offset = _derive_epoch_offset(pairing_secret)
    interval = int(rotation_interval)
    adjusted = (int(timestamp_secs) + offset) & 0xFFFFFFFFFFFFFFFF
    return adjusted // interval


def current_epoch(
    pairing_secret: bytes, rotation_interval: float
) -> int:
    """Compute current epoch using system clock."""
    return compute_epoch(
        pairing_secret, rotation_interval, time.time()
    )


def active_rendezvous_ids_at(
    pairing_secret: bytes,
    config: RotationConfig,
    timestamp_secs: float,
) -> list[RendezvousId]:
    """Determine active rendezvous IDs at a given timestamp.

    Returns 1 ID normally, 2 IDs during the overlap window.
    """
    interval = int(config.rotation_interval)
    if interval <= 0:
        raise ValueError("rotation interval must be > 0")

    offset = _derive_epoch_offset(pairing_secret)
    adjusted = (int(timestamp_secs) + offset) & 0xFFFFFFFFFFFFFFFF
    epoch = adjusted // interval
    position = adjusted % interval

    half_overlap = int(
        config.overlap_window / 2 + config.clock_tolerance
    )

    current_id = derive_rendezvous_id(pairing_secret, epoch)

    near_start = position < half_overlap
    near_end = position > interval - half_overlap

    if (near_start or near_end) and epoch > 0:
        if near_start:
            other_epoch = epoch - 1
        else:
            other_epoch = epoch + 1
        other_id = derive_rendezvous_id(
            pairing_secret, other_epoch
        )
        return [current_id, other_id]

    return [current_id]


def active_rendezvous_ids(
    pairing_secret: bytes,
    config: RotationConfig | None = None,
) -> list[RendezvousId]:
    """Determine active rendezvous IDs using system clock."""
    cfg = config or RotationConfig()
    return active_rendezvous_ids_at(
        pairing_secret, cfg, time.time()
    )
