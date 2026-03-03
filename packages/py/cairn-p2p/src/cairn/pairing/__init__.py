"""Pairing mechanisms: QR, PIN, link, SAS, adapter, rate limiting."""

from cairn.pairing.adapter import PairingAdapter
from cairn.pairing.link import pair_from_link, pair_generate_link
from cairn.pairing.payload import ConnectionHint, PairingPayload
from cairn.pairing.pin import (
    decode_crockford,
    derive_pin_rendezvous_id,
    encode_crockford,
    format_pin,
    normalize_pin,
    pair_enter_pin,
    pair_generate_pin,
)
from cairn.pairing.qr import (
    pair_generate_qr,
    pair_scan_qr,
    render_qr,
)
from cairn.pairing.rate_limit import (
    AutoInvalidatedError,
    RateLimiter,
    RateLimitError,
    WindowExceededError,
)
from cairn.pairing.sas import (
    derive_emoji_sas,
    derive_numeric_sas,
    verify_emoji_sas,
    verify_numeric_sas,
)

__all__ = [
    "AutoInvalidatedError",
    "ConnectionHint",
    "PairingAdapter",
    "PairingPayload",
    "RateLimitError",
    "RateLimiter",
    "WindowExceededError",
    "decode_crockford",
    "derive_emoji_sas",
    "derive_numeric_sas",
    "derive_pin_rendezvous_id",
    "encode_crockford",
    "format_pin",
    "normalize_pin",
    "pair_enter_pin",
    "pair_from_link",
    "pair_generate_link",
    "pair_generate_pin",
    "pair_generate_qr",
    "pair_scan_qr",
    "render_qr",
    "verify_emoji_sas",
    "verify_numeric_sas",
]
