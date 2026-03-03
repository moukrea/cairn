"""PIN code pairing mechanism (Crockford Base32)."""

from __future__ import annotations

import os

from cairn.crypto.kdf import hkdf_sha256

CROCKFORD_ALPHABET: str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PIN_LENGTH: int = 8
HKDF_INFO_PIN_RENDEZVOUS: bytes = b"cairn-pin-rendezvous-v1"


def encode_crockford(data: bytes) -> str:
    """Encode 5 bytes (40 bits) to 8 Crockford Base32 characters."""
    bits = int.from_bytes(data, "big")
    chars = []
    for i in range(7, -1, -1):
        idx = (bits >> (i * 5)) & 0x1F
        chars.append(CROCKFORD_ALPHABET[idx])
    return "".join(chars)


def decode_crockford(s: str) -> bytes:
    """Decode 8 Crockford Base32 characters to 5 bytes."""
    if len(s) != PIN_LENGTH:
        raise ValueError(
            f"expected {PIN_LENGTH} characters, got {len(s)}"
        )
    bits = 0
    for ch in s:
        idx = CROCKFORD_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid Crockford character: '{ch}'")
        bits = (bits << 5) | idx
    return bits.to_bytes(5, "big")


def normalize_pin(raw: str) -> str:
    """Normalize pin input: uppercase, strip separators, Crockford subs."""
    result = []
    for ch in raw:
        if ch in ("-", " "):
            continue
        c = ch.upper()
        if c == "U":
            continue
        if c in ("I", "L"):
            c = "1"
        elif c == "O":
            c = "0"
        result.append(c)
    return "".join(result)


def format_pin(pin: str) -> str:
    """Format an 8-char pin as XXXX-XXXX."""
    if len(pin) == PIN_LENGTH:
        return f"{pin[:4]}-{pin[4:]}"
    return pin


def pair_generate_pin() -> str:
    """Generate a random 8-char Crockford Base32 pin, formatted."""
    raw_bytes = os.urandom(5)  # 40 bits
    pin = encode_crockford(raw_bytes)
    return format_pin(pin)


def pair_enter_pin(user_input: str) -> str:
    """Normalize and validate user-entered pin. Returns raw 8-char pin."""
    normalized = normalize_pin(user_input)
    if len(normalized) != PIN_LENGTH:
        raise ValueError(
            f"normalized pin has {len(normalized)} characters, "
            f"expected {PIN_LENGTH}"
        )
    decode_crockford(normalized)  # validate characters
    return normalized


def derive_pin_rendezvous_id(pin_bytes: bytes) -> bytes:
    """Derive a 32-byte rendezvous ID from a pin code."""
    return hkdf_sha256(pin_bytes, b"", HKDF_INFO_PIN_RENDEZVOUS, 32)
