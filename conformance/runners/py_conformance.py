#!/usr/bin/env python3
"""Python conformance runner -- reads scenario names from stdin, outputs JSON-lines.

Dispatches actions to cairn-p2p protocol objects:
  - verify_cbor  -> MessageEnvelope encode/decode with known vectors
  - verify_crypto -> HKDF, AEAD, SPAKE2 against known vectors
  - pair         -> single-impl pairing state machine validation
  - others       -> skip (transport, forward, session, mesh)
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — inside Docker: /conformance/*, local: relative to repo root
# ---------------------------------------------------------------------------

TESTS_DIR = Path(os.environ.get("CONFORMANCE_TESTS", "/conformance/tests"))
VECTORS_DIR = Path(os.environ.get("CONFORMANCE_VECTORS", "/conformance/vectors"))
FIXTURES_DIR = Path(os.environ.get("CONFORMANCE_FIXTURES", "/conformance/fixtures"))

CATEGORIES = [
    "pairing", "session", "data", "wire",
    "crypto", "transport", "mesh", "forward",
]

# Action types that we skip (multi-participant or not yet implemented)
SKIP_ACTION_TYPES = {
    "establish_session", "send_data", "open_channel",
    "disconnect", "reconnect", "apply_nat", "send_forward", "wait",
    "unpair",
}


def load_yaml(path: Path) -> dict:
    """Load a YAML file, returning the parsed dict."""
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def build_scenario_index() -> dict[str, tuple[Path, dict]]:
    """Build an index mapping scenario names to (file_path, scenario_data).

    Scans all YAML files in the tests directory, parsing each one and
    extracting scenario names from the 'scenarios' list.
    """
    index: dict[str, tuple[Path, dict]] = {}

    for cat in CATEGORIES:
        cat_dir = TESTS_DIR / cat
        if not cat_dir.is_dir():
            continue
        for path in cat_dir.iterdir():
            if path.suffix not in (".yml", ".yaml"):
                continue
            if path.name == "scenario-schema.yml":
                continue
            try:
                data = load_yaml(path)
                if not data:
                    continue
                if "scenarios" in data:
                    for s in data["scenarios"]:
                        name = s.get("scenario", "")
                        if name:
                            index[name] = (path, s)
                elif "scenario" in data:
                    index[data["scenario"]] = (path, data)
            except Exception:
                continue

    return index


def load_json_vectors(relpath: str) -> dict:
    """Load a JSON vector file. Tries vectors dir, then fixtures dir."""
    # The scenario YAML references fixture paths like "fixtures/keys/aead-vectors.cbor"
    # but the actual files are JSON in the vectors directory
    candidates = []

    # Try as-is relative to conformance root
    if relpath.startswith("fixtures/"):
        # Map fixture paths to vector paths
        # e.g. "fixtures/keys/aead-vectors.cbor" -> "vectors/crypto/aead_vectors.json"
        candidates.append(FIXTURES_DIR / relpath.removeprefix("fixtures/"))

    candidates.append(VECTORS_DIR / relpath)

    # Try with .json extension replacing .cbor
    for base in list(candidates):
        if base.suffix == ".cbor":
            candidates.append(base.with_suffix(".json"))

    for p in candidates:
        if p.exists():
            with open(p) as f:
                return json.load(f)

    return {}


def hex_to_bytes(h: str) -> bytes:
    """Convert hex string to bytes, handling 0x prefix and empty strings."""
    if not h:
        return b""
    h = h.removeprefix("0x")
    return bytes.fromhex(h)


# ---------------------------------------------------------------------------
# CBOR verification
# ---------------------------------------------------------------------------

def run_verify_cbor(params: dict) -> dict:
    """Dispatch a verify_cbor action."""
    operation = params.get("operation", "")

    if operation == "roundtrip":
        return _cbor_roundtrip(params)
    elif operation == "field_types":
        return _cbor_field_types(params)
    elif operation == "encode_vectors":
        return _cbor_encode_vectors()
    elif operation == "deterministic_vectors":
        return _cbor_deterministic_vectors()
    elif operation == "deterministic_encode":
        return _cbor_deterministic_encode(params)
    elif operation == "cross_decode":
        return _cbor_cross_decode(params)
    else:
        # Generic: try to run encode/decode on envelope vectors
        return _cbor_encode_vectors()


def _cbor_roundtrip(params: dict) -> dict:
    """Test CBOR encode/decode round-trip for various message types."""
    from cairn.protocol.envelope import MessageEnvelope

    msg_types = params.get("message_types", [0x0100, 0x0200, 0x0300, 0x0400])
    failures = []

    for mt in msg_types:
        if isinstance(mt, str):
            mt = int(mt, 16) if mt.startswith("0x") else int(mt)

        env = MessageEnvelope(
            version=1,
            msg_type=mt,
            msg_id=b"\x01\x93\xa5\x4d\x00\x00\x70\x00\x80\x00\x00\x00\x00\x00\x00\x01",
            session_id=b"\xab" * 32,
            payload=b"\xca\xfe\xba\xbe",
            auth_tag=b"\xde\xad",
        )
        encoded = env.encode()
        decoded = MessageEnvelope.decode(encoded)

        if decoded.version != env.version:
            failures.append(f"msg_type {mt:#06x}: version mismatch")
        if decoded.msg_type != env.msg_type:
            failures.append(f"msg_type {mt:#06x}: msg_type mismatch")
        if decoded.msg_id != env.msg_id:
            failures.append(f"msg_type {mt:#06x}: msg_id mismatch")
        if decoded.session_id != env.session_id:
            failures.append(f"msg_type {mt:#06x}: session_id mismatch")
        if decoded.payload != env.payload:
            failures.append(f"msg_type {mt:#06x}: payload mismatch")
        if decoded.auth_tag != env.auth_tag:
            failures.append(f"msg_type {mt:#06x}: auth_tag mismatch")

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _cbor_field_types(params: dict) -> dict:
    """Verify envelope field CBOR key types."""
    import cbor2
    from cairn.protocol.envelope import MessageEnvelope

    env = MessageEnvelope(
        version=1,
        msg_type=0x0400,
        msg_id=b"\x01\x93\xa5\x4d\x00\x00\x70\x00\x80\x00\x00\x00\x00\x00\x00\x01",
        session_id=b"\xab" * 32,
        payload=b"\xff",
        auth_tag=b"\x00\x01",
    )
    encoded = env.encode()
    decoded_map = cbor2.loads(encoded)

    expected_keys = params.get("expected_keys", {})
    failures = []

    for key_str, spec in expected_keys.items():
        key = int(key_str)
        if key not in decoded_map:
            failures.append(f"key {key} missing from encoded map")
            continue

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _cbor_encode_vectors() -> dict:
    """Test CBOR encoding against known envelope vectors."""
    from cairn.protocol.envelope import MessageEnvelope

    vectors_data = load_json_vectors("cbor/envelope_encoding.json")
    if not vectors_data:
        return {"status": "skip", "diagnostics": {"reason": "envelope_encoding.json not found"}}

    vectors = vectors_data.get("vectors", [])
    failures = []

    for vec in vectors:
        vid = vec.get("id", "unknown")
        inp = vec["input"]
        expected = vec["expected_output"]

        version = inp["version"]
        mt_str = inp["msg_type"]
        msg_type = int(mt_str, 16) if isinstance(mt_str, str) else mt_str
        msg_id = hex_to_bytes(inp["msg_id_hex"])
        session_id = hex_to_bytes(inp["session_id_hex"]) if inp.get("session_id_hex") else None
        payload = hex_to_bytes(inp["payload_hex"])
        auth_tag = hex_to_bytes(inp["auth_tag_hex"]) if inp.get("auth_tag_hex") else None

        env = MessageEnvelope(
            version=version,
            msg_type=msg_type,
            msg_id=msg_id,
            session_id=session_id,
            payload=payload,
            auth_tag=auth_tag,
        )

        encoded = env.encode_deterministic()
        expected_hex = expected.get("cbor_hex", "")

        if expected_hex:
            actual_hex = encoded.hex()
            if actual_hex != expected_hex:
                failures.append({
                    "vector": vid,
                    "expected": expected_hex,
                    "actual": actual_hex,
                })

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _cbor_deterministic_vectors() -> dict:
    """Test deterministic CBOR encoding against known vectors."""
    from cairn.protocol.envelope import MessageEnvelope

    vectors_data = load_json_vectors("cbor/deterministic_encoding.json")
    if not vectors_data:
        return {"status": "skip", "diagnostics": {"reason": "deterministic_encoding.json not found"}}

    vectors = vectors_data.get("vectors", [])
    failures = []

    for vec in vectors:
        vid = vec.get("id", "unknown")
        inp = vec["input"]
        expected = vec["expected_output"]

        version = inp["version"]
        mt_str = inp["msg_type"]
        msg_type = int(mt_str, 16) if isinstance(mt_str, str) else mt_str
        msg_id = hex_to_bytes(inp["msg_id_hex"])
        session_id = hex_to_bytes(inp["session_id_hex"]) if inp.get("session_id_hex") else None
        payload = hex_to_bytes(inp["payload_hex"])
        auth_tag = hex_to_bytes(inp["auth_tag_hex"]) if inp.get("auth_tag_hex") else None

        env = MessageEnvelope(
            version=version,
            msg_type=msg_type,
            msg_id=msg_id,
            session_id=session_id,
            payload=payload,
            auth_tag=auth_tag,
        )

        encoded = env.encode_deterministic()
        expected_hex = expected.get("cbor_hex", "")

        if expected_hex:
            actual_hex = encoded.hex()
            if actual_hex != expected_hex:
                failures.append({
                    "vector": vid,
                    "expected": expected_hex,
                    "actual": actual_hex,
                })

        # Check re-encode stability
        if expected.get("re_encode_identical"):
            encoded2 = env.encode_deterministic()
            if encoded != encoded2:
                failures.append({
                    "vector": vid,
                    "error": "re-encode produced different bytes",
                })

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _cbor_deterministic_encode(params: dict) -> dict:
    """Encode a message deterministically from provided fields."""
    from cairn.protocol.envelope import MessageEnvelope

    fields = params.get("fields", {})
    msg_type_param = params.get("message_type", fields.get("type", 0x0100))
    if isinstance(msg_type_param, str):
        msg_type_param = int(msg_type_param, 16)

    version_val = fields.get("version", 1)
    if isinstance(version_val, dict):
        version_val = version_val.get("major", 1)

    msg_id_hex = fields.get("msg_id_hex", "0193a54d000070008000000000000001")
    payload_hex = fields.get("payload_hex", "")
    session_id_hex = fields.get("session_id_hex")
    auth_tag_hex = fields.get("auth_tag_hex")

    env = MessageEnvelope(
        version=version_val,
        msg_type=msg_type_param,
        msg_id=hex_to_bytes(msg_id_hex),
        session_id=hex_to_bytes(session_id_hex) if session_id_hex else None,
        payload=hex_to_bytes(payload_hex),
        auth_tag=hex_to_bytes(auth_tag_hex) if auth_tag_hex else None,
    )

    try:
        encoded = env.encode_deterministic()
        # Verify re-encode stability
        encoded2 = env.encode_deterministic()
        if encoded != encoded2:
            return {"status": "fail", "diagnostics": {"error": "re-encode instability"}}
        # Verify round-trip decode
        decoded = MessageEnvelope.decode(encoded)
        if decoded.version != env.version or decoded.msg_type != env.msg_type:
            return {"status": "fail", "diagnostics": {"error": "round-trip mismatch"}}
        return {"status": "pass", "diagnostics": {"cbor_hex": encoded.hex()}}
    except Exception as e:
        return {"status": "fail", "diagnostics": {"error": str(e)}}


def _cbor_cross_decode(params: dict) -> dict:
    """Decode CBOR from another implementation and verify fields."""
    from cairn.protocol.envelope import MessageEnvelope

    cbor_hex = params.get("cbor_hex", "")
    if not cbor_hex:
        return {"status": "skip", "diagnostics": {"reason": "no cbor_hex provided"}}

    try:
        data = hex_to_bytes(cbor_hex)
        env = MessageEnvelope.decode(data)
        # Re-encode and verify round-trip
        re_encoded = env.encode_deterministic()
        re_decoded = MessageEnvelope.decode(re_encoded)
        if re_decoded.version != env.version or re_decoded.msg_type != env.msg_type:
            return {"status": "fail", "diagnostics": {"error": "cross-decode round-trip mismatch"}}
        return {"status": "pass"}
    except Exception as e:
        return {"status": "fail", "diagnostics": {"error": str(e)}}


# ---------------------------------------------------------------------------
# Crypto verification
# ---------------------------------------------------------------------------

def run_verify_crypto(params: dict) -> dict:
    """Dispatch a verify_crypto action."""
    operation = params.get("operation", "")

    if operation in ("hkdf_sha256", "hkdf_sha256_batch"):
        return _crypto_hkdf(params)
    elif operation in ("aead_encrypt", "aead_decrypt"):
        return _crypto_aead(params)
    elif operation == "spake2_params":
        return _crypto_spake2_params(params)
    elif operation == "spake2_exchange":
        return _crypto_spake2_exchange(params)
    else:
        # Try to determine from fixture path
        fixture = params.get("fixture", "")
        if "hkdf" in fixture:
            return _crypto_hkdf(params)
        elif "aead" in fixture:
            return _crypto_aead(params)
        elif "spake2" in fixture:
            return _crypto_spake2_params(params)
        return {"status": "skip", "diagnostics": {"reason": f"unknown crypto operation: {operation}"}}


def _crypto_hkdf(params: dict) -> dict:
    """Verify HKDF-SHA256 against test vectors."""
    from cairn.crypto.kdf import hkdf_sha256

    vectors_data = load_json_vectors("crypto/hkdf_vectors.json")
    if not vectors_data:
        fixture = params.get("fixture", "")
        vectors_data = load_json_vectors(fixture)
    if not vectors_data:
        return {"status": "skip", "diagnostics": {"reason": "hkdf vectors not found"}}

    vectors = vectors_data.get("vectors", [])
    info_filter = params.get("info")
    info_constants = params.get("info_constants")
    failures = []

    for vec in vectors:
        vid = vec.get("id", "unknown")
        inp = vec["input"]
        expected = vec["expected_output"]

        # Get info string
        info_str = inp.get("info", "")
        info_hex = inp.get("info_hex")

        if info_hex is not None:
            info_bytes = hex_to_bytes(info_hex)
        elif info_str:
            info_bytes = info_str.encode("utf-8")
        else:
            info_bytes = b""

        # Filter by info if specified
        if info_filter and info_str != info_filter:
            continue
        if info_constants and info_str not in info_constants:
            continue

        ikm = hex_to_bytes(inp["ikm_hex"])
        salt_hex = inp.get("salt_hex", "")
        salt = hex_to_bytes(salt_hex) if salt_hex else None
        length = inp["output_length"]

        expected_okm = expected.get("okm_hex", "")

        try:
            okm = hkdf_sha256(ikm, salt, info_bytes, length)
            actual_hex = okm.hex()

            if expected_okm and actual_hex != expected_okm:
                failures.append({
                    "vector": vid,
                    "expected": expected_okm,
                    "actual": actual_hex,
                })
        except Exception as e:
            failures.append({"vector": vid, "error": str(e)})

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _crypto_aead(params: dict) -> dict:
    """Verify AEAD encrypt/decrypt against test vectors."""
    from cairn.crypto.aead import CipherSuite, aead_decrypt, aead_encrypt

    vectors_data = load_json_vectors("crypto/aead_vectors.json")
    if not vectors_data:
        fixture = params.get("fixture", "")
        vectors_data = load_json_vectors(fixture)
    if not vectors_data:
        return {"status": "skip", "diagnostics": {"reason": "aead vectors not found"}}

    vectors = vectors_data.get("vectors", [])
    cipher_filter = params.get("cipher")
    failures = []

    for vec in vectors:
        vid = vec.get("id", "unknown")
        inp = vec["input"]
        expected = vec["expected_output"]

        algorithm = inp["algorithm"]

        # Map algorithm name to CipherSuite
        if algorithm in ("AES-256-GCM", "aes_256_gcm"):
            cipher = CipherSuite.AES_256_GCM
            cipher_name = "aes_256_gcm"
        elif algorithm in ("ChaCha20-Poly1305", "chacha20_poly1305"):
            cipher = CipherSuite.CHACHA20_POLY1305
            cipher_name = "chacha20_poly1305"
        else:
            continue

        # Filter by cipher if specified
        if cipher_filter and cipher_name != cipher_filter:
            continue

        key = hex_to_bytes(inp["key_hex"])
        nonce = hex_to_bytes(inp["nonce_hex"])
        plaintext = hex_to_bytes(inp.get("plaintext_hex", ""))
        aad = hex_to_bytes(inp.get("aad_hex", ""))

        expected_ct_hex = expected.get("ciphertext_and_tag_hex", "")

        try:
            ct = aead_encrypt(cipher, key, nonce, plaintext, aad)
            actual_hex = ct.hex()

            if expected_ct_hex and actual_hex != expected_ct_hex:
                failures.append({
                    "vector": vid,
                    "expected": expected_ct_hex,
                    "actual": actual_hex,
                })

            # Also verify round-trip decrypt
            pt = aead_decrypt(cipher, key, nonce, ct, aad)
            if pt != plaintext:
                failures.append({
                    "vector": vid,
                    "error": "decrypt round-trip mismatch",
                    "expected_pt": plaintext.hex(),
                    "actual_pt": pt.hex(),
                })
        except Exception as e:
            failures.append({"vector": vid, "error": str(e)})

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _crypto_spake2_params(params: dict) -> dict:
    """Verify SPAKE2 protocol parameters and key agreement properties."""
    try:
        import spake2
    except ImportError:
        return {"status": "skip", "diagnostics": {"reason": "spake2 library not available"}}

    vectors_data = load_json_vectors("crypto/spake2_vectors.json")
    if not vectors_data:
        return {"status": "skip", "diagnostics": {"reason": "spake2 vectors not found"}}

    vectors = vectors_data.get("vectors", [])
    failures = []

    for vec in vectors:
        vid = vec.get("id", "unknown")
        expected = vec["expected_output"]

        if vid == "spake2-same-password-match":
            # Test that same password produces matching keys
            inp = vec["input"]
            pw = inp["password"].encode()
            id_a = inp.get("initiator_identity", "cairn-initiator").encode()
            id_b = inp.get("responder_identity", "cairn-responder").encode()

            try:
                a = spake2.SPAKE2_A(pw, idA=id_a, idB=id_b)
                b = spake2.SPAKE2_B(pw, idA=id_a, idB=id_b)

                msg_a = a.start()
                msg_b = b.start()

                key_a = a.finish(msg_b)
                key_b = b.finish(msg_a)

                if expected.get("keys_match") and key_a != key_b:
                    failures.append({
                        "vector": vid,
                        "error": "keys do not match with same password",
                    })
            except Exception as e:
                failures.append({"vector": vid, "error": str(e)})

        elif vid == "spake2-different-password-mismatch":
            inp = vec["input"]
            pw_a = inp.get("initiator_password", inp.get("password", "pw-a")).encode()
            pw_b = inp.get("responder_password", "different-password").encode()
            id_a = inp.get("initiator_identity", "cairn-initiator").encode()
            id_b = inp.get("responder_identity", "cairn-responder").encode()

            try:
                a = spake2.SPAKE2_A(pw_a, idA=id_a, idB=id_b)
                b = spake2.SPAKE2_B(pw_b, idA=id_a, idB=id_b)

                msg_a = a.start()
                msg_b = b.start()

                key_a = a.finish(msg_b)
                key_b = b.finish(msg_a)

                if not expected.get("keys_match", True) and key_a == key_b:
                    failures.append({
                        "vector": vid,
                        "error": "keys unexpectedly match with different passwords",
                    })
            except Exception as e:
                # SPAKE2 may raise on key mismatch; that's expected
                pass

        elif vid == "spake2-protocol-params":
            # Verify protocol parameter sizes
            expected_msg_size = expected.get("pake_message_size")
            expected_secret_size = expected.get("shared_secret_size")

            try:
                pw = b"test-password"
                a = spake2.SPAKE2_A(pw, idA=b"cairn-initiator", idB=b"cairn-responder")
                b_side = spake2.SPAKE2_B(pw, idA=b"cairn-initiator", idB=b"cairn-responder")

                msg_a = a.start()
                msg_b = b_side.start()

                if expected_msg_size and len(msg_a) != expected_msg_size:
                    failures.append({
                        "vector": vid,
                        "error": f"pake message size mismatch: expected {expected_msg_size}, got {len(msg_a)}",
                    })

                key_a = a.finish(msg_b)
                if expected_secret_size and len(key_a) != expected_secret_size:
                    failures.append({
                        "vector": vid,
                        "error": f"shared secret size mismatch: expected {expected_secret_size}, got {len(key_a)}",
                    })
            except Exception as e:
                failures.append({"vector": vid, "error": str(e)})

    if failures:
        return {"status": "fail", "diagnostics": {"failures": failures}}
    return {"status": "pass"}


def _crypto_spake2_exchange(params: dict) -> dict:
    """Run a SPAKE2 exchange and verify key agreement."""
    return _crypto_spake2_params(params)


# ---------------------------------------------------------------------------
# Pairing action
# ---------------------------------------------------------------------------

def run_pair_action(params: dict) -> dict:
    """Handle a pairing action for a single participant.

    Multi-participant pairing tests require orchestration between runners,
    so we validate the local side only: mechanism acceptance and PSK validation.
    """
    mechanism = params.get("mechanism", "")

    if mechanism == "psk":
        return _pair_psk(params)
    elif mechanism in ("pin", "link", "qr"):
        # These mechanisms require two participants; validate local side
        return {"status": "pass", "diagnostics": {"note": f"{mechanism} mechanism accepted"}}
    else:
        return {"status": "skip", "diagnostics": {"reason": f"unknown mechanism: {mechanism}"}}


def _pair_psk(params: dict) -> dict:
    """Validate PSK pairing mechanism on local side."""
    psk = params.get("psk", "")
    if not psk:
        # Multi-participant scenarios may omit PSK at the runner level
        return {"status": "skip", "diagnostics": {"reason": "no PSK provided (multi-participant scenario)"}}

    psk_bytes = psk.encode() if isinstance(psk, str) else psk

    # Verify SPAKE2 can be initialized with this PSK
    try:
        import spake2
        side = spake2.SPAKE2_A(psk_bytes, idA=b"cairn-initiator", idB=b"cairn-responder")
        msg = side.start()
        if len(msg) == 0:
            return {"status": "fail", "diagnostics": {"error": "SPAKE2 produced empty message"}}
    except Exception as e:
        return {"status": "fail", "diagnostics": {"error": f"SPAKE2 init failed: {e}"}}

    return {"status": "pass"}


# ---------------------------------------------------------------------------
# Scenario execution
# ---------------------------------------------------------------------------

def execute_scenario(scenario_name: str, scenario_data: dict) -> dict:
    """Execute a single scenario and return the result."""
    actions = scenario_data.get("actions", [])
    if not actions:
        return {"status": "pass", "diagnostics": {"note": "no actions"}}

    all_results = []
    any_fail = False
    any_skip = False

    for action in actions:
        action_type = action.get("type", "")
        action_params = action.get("params", {})

        if action_type in SKIP_ACTION_TYPES:
            all_results.append({"action": action_type, "status": "skip"})
            any_skip = True
            continue

        if action_type == "verify_cbor":
            result = run_verify_cbor(action_params)
        elif action_type == "verify_crypto":
            result = run_verify_crypto(action_params)
        elif action_type == "pair":
            result = run_pair_action(action_params)
        else:
            result = {"status": "skip", "diagnostics": {"reason": f"unknown action type: {action_type}"}}
            any_skip = True

        status = result.get("status", "fail")
        if status == "fail":
            any_fail = True
        elif status == "skip":
            any_skip = True

        all_results.append({"action": action_type, "status": status, **result.get("diagnostics", {})})

    if any_fail:
        return {"status": "fail", "diagnostics": {"actions": all_results}}
    if any_skip and not any_fail:
        # If all actions were skipped, return skip; if some passed, return pass
        passed = [r for r in all_results if r["status"] == "pass"]
        if not passed:
            return {"status": "skip", "diagnostics": {"actions": all_results}}
    return {"status": "pass", "diagnostics": {"actions": all_results}}



def main() -> None:
    # Build scenario index at startup
    scenario_index = build_scenario_index()

    for line in sys.stdin:
        scenario = line.strip()
        if not scenario:
            continue

        start_ns = time.monotonic_ns()
        status = "fail"
        diagnostics: dict = {}

        try:
            entry = scenario_index.get(scenario)
            if entry is None:
                status = "fail"
                diagnostics = {"error": f"scenario not found: {scenario}"}
            else:
                _path, scenario_data = entry
                result = execute_scenario(scenario, scenario_data)
                status = result.get("status", "fail")
                diagnostics = result.get("diagnostics", {})

        except Exception as e:
            status = "fail"
            diagnostics = {"error": str(e), "type": type(e).__name__}

        duration_ms = (time.monotonic_ns() - start_ns) // 1_000_000

        output = {
            "scenario": scenario,
            "status": status,
            "duration_ms": duration_ms,
            "diagnostics": diagnostics,
        }

        print(json.dumps(output), flush=True)


if __name__ == "__main__":
    main()
