"""QR code pairing mechanism."""

from __future__ import annotations

import os
import time

import qrcode
import qrcode.constants

from cairn.pairing.payload import PairingPayload

MAX_QR_PAYLOAD_SIZE: int = 256
DEFAULT_TTL_SECS: int = 300


def pair_generate_qr(
    peer_id: bytes,
    pake_credential: bytes,
    hints: list | None = None,
    ttl: int = DEFAULT_TTL_SECS,
) -> tuple[PairingPayload, bytes]:
    """Generate a QR-encodable pairing payload.

    Returns (payload, cbor_bytes).
    """
    nonce = os.urandom(16)
    now = int(time.time())
    payload = PairingPayload(
        peer_id=peer_id,
        nonce=nonce,
        pake_credential=pake_credential,
        connection_hints=hints,
        created_at=now,
        expires_at=now + ttl,
    )
    cbor_bytes = payload.to_cbor()
    if len(cbor_bytes) > MAX_QR_PAYLOAD_SIZE:
        raise ValueError(
            f"payload too large: {len(cbor_bytes)} bytes "
            f"(max {MAX_QR_PAYLOAD_SIZE})"
        )
    return payload, cbor_bytes


def render_qr(cbor_bytes: bytes) -> qrcode.QRCode:
    """Render CBOR bytes as a QR code with EC Level M."""
    if len(cbor_bytes) > MAX_QR_PAYLOAD_SIZE:
        raise ValueError(
            f"payload too large: {len(cbor_bytes)} bytes "
            f"(max {MAX_QR_PAYLOAD_SIZE})"
        )
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
    )
    qr.add_data(cbor_bytes)
    qr.make(fit=True)
    return qr


def pair_scan_qr(cbor_bytes: bytes) -> PairingPayload:
    """Parse a QR code payload and validate it.

    Raises ValueError if expired or oversized.
    """
    if len(cbor_bytes) > MAX_QR_PAYLOAD_SIZE:
        raise ValueError(
            f"payload too large: {len(cbor_bytes)} bytes "
            f"(max {MAX_QR_PAYLOAD_SIZE})"
        )
    payload = PairingPayload.from_cbor(cbor_bytes)
    if payload.is_expired():
        raise ValueError("pairing payload has expired")
    return payload
