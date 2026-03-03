"""Pairing link/URI mechanism."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import base58
import cbor2

from cairn.crypto.identity import PeerId
from cairn.pairing.payload import ConnectionHint, PairingPayload

DEFAULT_SCHEME: str = "cairn"
DEFAULT_TTL_SECS: int = 300


def pair_generate_link(
    payload: PairingPayload,
    scheme: str = DEFAULT_SCHEME,
) -> str:
    """Generate a cairn://pair?... pairing URI from a payload."""
    pid = base58.b58encode(payload.peer_id).decode("ascii")
    nonce = payload.nonce.hex()
    pake = payload.pake_credential.hex()

    uri = (
        f"{scheme}://pair?pid={pid}&nonce={nonce}&pake={pake}"
    )

    if payload.connection_hints:
        hints_cbor = cbor2.dumps([
            [h.hint_type, h.value]
            for h in payload.connection_hints
        ])
        hints_b64 = base64.urlsafe_b64encode(hints_cbor).rstrip(
            b"="
        ).decode("ascii")
        uri += f"&hints={hints_b64}"

    uri += f"&t={payload.created_at}&x={payload.expires_at}"
    return uri


def pair_from_link(
    uri: str,
    scheme: str = DEFAULT_SCHEME,
) -> PairingPayload:
    """Parse a pairing URI and return the payload.

    Raises ValueError if the URI is invalid or expired.
    """
    parsed = urlparse(uri)
    if parsed.scheme != scheme:
        raise ValueError(
            f"expected scheme '{scheme}', got '{parsed.scheme}'"
        )
    if parsed.hostname != "pair":
        raise ValueError(
            f"expected host 'pair', got '{parsed.hostname}'"
        )

    params = parse_qs(parsed.query)

    def get_param(name: str) -> str:
        vals = params.get(name)
        if not vals:
            raise ValueError(f"missing '{name}' parameter")
        return vals[0]

    pid_str = get_param("pid")
    pid_bytes = base58.b58decode(pid_str)
    # Validate PeerId structure
    PeerId(pid_bytes)

    nonce = bytes.fromhex(get_param("nonce"))
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")

    pake = bytes.fromhex(get_param("pake"))

    hints = None
    hints_vals = params.get("hints")
    if hints_vals:
        hints_b64 = hints_vals[0]
        # Add back padding
        padding = 4 - len(hints_b64) % 4
        if padding != 4:
            hints_b64 += "=" * padding
        hints_cbor = base64.urlsafe_b64decode(hints_b64)
        raw_hints = cbor2.loads(hints_cbor)
        hints = [
            ConnectionHint(hint_type=h[0], value=h[1])
            for h in raw_hints
        ]

    t_vals = params.get("t")
    created_at = int(t_vals[0]) if t_vals else 0
    x_vals = params.get("x")
    expires_at = int(x_vals[0]) if x_vals else 0

    payload = PairingPayload(
        peer_id=pid_bytes,
        nonce=nonce,
        pake_credential=pake,
        connection_hints=hints,
        created_at=created_at,
        expires_at=expires_at,
    )

    if payload.is_expired():
        raise ValueError("pairing link has expired")

    return payload
