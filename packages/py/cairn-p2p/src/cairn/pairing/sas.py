"""SAS (Short Authentication String) verification for pairing."""

from __future__ import annotations

from cairn.crypto.noise import (
    EMOJI_TABLE,
    derive_emoji_sas,
    derive_numeric_sas,
)

__all__ = [
    "EMOJI_TABLE",
    "derive_emoji_sas",
    "derive_numeric_sas",
    "verify_numeric_sas",
    "verify_emoji_sas",
]


def verify_numeric_sas(
    local_transcript: bytes,
    remote_code: str,
) -> bool:
    """Verify a numeric SAS code against a local transcript hash.

    Both peers derive a 6-digit code from their handshake transcript.
    The user visually confirms they match. This function automates the
    comparison side.
    """
    local_code = derive_numeric_sas(local_transcript)
    return local_code == remote_code


def verify_emoji_sas(
    local_transcript: bytes,
    remote_emoji: list[str],
) -> bool:
    """Verify an emoji SAS against a local transcript hash.

    Both peers derive 4 emoji from their handshake transcript.
    The user visually confirms they match.
    """
    local_emoji = derive_emoji_sas(local_transcript)
    return local_emoji == remote_emoji
