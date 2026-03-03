#!/usr/bin/env php
<?php
/**
 * PHP conformance runner — reads scenario names from stdin, outputs JSON-lines.
 *
 * Dispatches verify_cbor, verify_crypto, and pair actions to cairn-p2p
 * protocol objects and validates results against test vectors.
 */

declare(strict_types=1);

// Autoload cairn-p2p classes
$autoloadPaths = [
    '/app/vendor/autoload.php',                  // Docker
    __DIR__ . '/../../packages/php/cairn-p2p/vendor/autoload.php', // Local dev
];
$loaded = false;
foreach ($autoloadPaths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $loaded = true;
        break;
    }
}
if (!$loaded) {
    fwrite(STDERR, "ERROR: Could not find cairn-p2p autoloader\n");
    exit(1);
}

// Try to load symfony/yaml
$yamlAvailable = class_exists(\Symfony\Component\Yaml\Yaml::class);
if (!$yamlAvailable) {
    // Try alternate autoload paths for yaml
    $yamlPaths = [
        '/app/vendor/symfony/yaml/Yaml.php',
        __DIR__ . '/../../packages/php/cairn-p2p/vendor/symfony/yaml/Yaml.php',
    ];
    foreach ($yamlPaths as $yp) {
        if (file_exists($yp)) {
            require_once dirname($yp) . '/../../../autoload.php';
            $yamlAvailable = class_exists(\Symfony\Component\Yaml\Yaml::class);
            break;
        }
    }
}

use Cairn\Crypto\Aead;
use Cairn\Crypto\CipherSuite;
use Cairn\Crypto\Kdf;
use Cairn\Crypto\Spake2;
use Cairn\Crypto\SpakeRole;
use Cairn\Protocol\Cbor;
use Cairn\Protocol\Envelope;

// --- Configuration ---

$testsDir = '/conformance/tests';
$vectorsDir = '/conformance/vectors';

if (getenv('CAIRN_TESTS_DIR')) {
    $testsDir = getenv('CAIRN_TESTS_DIR');
}
if (getenv('CAIRN_VECTORS_DIR')) {
    $vectorsDir = getenv('CAIRN_VECTORS_DIR');
}

$categories = ['pairing', 'session', 'data', 'wire', 'crypto', 'transport', 'mesh', 'forward'];

// --- Vector caches ---

$hkdfVectors = null;
$aeadVectors = null;
$cborVectors = null;

function loadHkdfVectors(): ?array
{
    global $vectorsDir, $hkdfVectors;
    if ($hkdfVectors !== null) {
        return $hkdfVectors;
    }
    $path = $vectorsDir . '/crypto/hkdf_vectors.json';
    if (!file_exists($path)) {
        return null;
    }
    $data = json_decode(file_get_contents($path), true);
    $hkdfVectors = $data['vectors'] ?? [];
    return $hkdfVectors;
}

function loadAeadVectors(): ?array
{
    global $vectorsDir, $aeadVectors;
    if ($aeadVectors !== null) {
        return $aeadVectors;
    }
    $path = $vectorsDir . '/crypto/aead_vectors.json';
    if (!file_exists($path)) {
        return null;
    }
    $data = json_decode(file_get_contents($path), true);
    $aeadVectors = $data['vectors'] ?? [];
    return $aeadVectors;
}

function loadCborVectors(): ?array
{
    global $vectorsDir, $cborVectors;
    if ($cborVectors !== null) {
        return $cborVectors;
    }
    $path = $vectorsDir . '/cbor/envelope_encoding.json';
    if (!file_exists($path)) {
        return null;
    }
    $data = json_decode(file_get_contents($path), true);
    $cborVectors = $data['vectors'] ?? [];
    return $cborVectors;
}

// --- Scenario file resolution ---

function findScenarioFile(string $scenario): ?string
{
    global $categories, $testsDir;
    foreach ($categories as $cat) {
        foreach (['.yml', '.yaml'] as $ext) {
            $path = $testsDir . '/' . $cat . '/' . $scenario . $ext;
            if (file_exists($path)) {
                return $path;
            }
        }
    }
    return null;
}

function parseYaml(string $path): ?array
{
    if (class_exists(\Symfony\Component\Yaml\Yaml::class)) {
        return \Symfony\Component\Yaml\Yaml::parseFile($path);
    }
    // Fallback: try yaml extension
    if (function_exists('yaml_parse_file')) {
        $result = yaml_parse_file($path);
        return $result !== false ? $result : null;
    }
    return null;
}

function findScenarioInFile(array $data, string $scenarioName): ?array
{
    $scenarios = $data['scenarios'] ?? [];
    foreach ($scenarios as $s) {
        if (($s['scenario'] ?? '') === $scenarioName) {
            return $s;
        }
    }
    return null;
}

// --- Action Dispatchers ---

/**
 * Check if we are a relevant participant (lang: any, or lang: php).
 */
function isRelevantParticipant(array $participants): bool
{
    foreach ($participants as $p) {
        $lang = $p['lang'] ?? 'any';
        if ($lang === 'any' || $lang === 'php') {
            return true;
        }
    }
    return false;
}

/**
 * Dispatch verify_cbor action.
 */
function dispatchVerifyCbor(array $params, array &$diag): string
{
    $operation = $params['operation'] ?? '';

    switch ($operation) {
        case 'roundtrip':
            return verifyCborRoundtrip($params, $diag);
        case 'field_types':
            return verifyCborFieldTypes($params, $diag);
        case 'deterministic_encode':
        case 'encode_vectors':
        case 'deterministic_vectors':
            return verifyCborDeterministic($params, $diag);
        case 'cross_decode':
        case 'decode':
        case 'encode':
            return verifyCborVectors($params, $diag);
        default:
            $diag['skip'] = "unsupported cbor operation: $operation";
            return 'skip';
    }
}

/**
 * CBOR roundtrip: encode an envelope, decode it, verify field equality.
 */
function verifyCborRoundtrip(array $params, array &$diag): string
{
    $messageTypes = $params['message_types'] ?? [0x0100, 0x0300];
    $vectors = loadCborVectors();

    // If we have vectors, verify against them
    if ($vectors !== null && count($vectors) > 0) {
        foreach ($vectors as $vec) {
            $input = $vec['input'] ?? [];
            $expected = $vec['expected_output'] ?? [];

            $version = $input['version'] ?? 1;
            $msgTypeStr = $input['msg_type'] ?? '0x0100';
            $msgType = intval($msgTypeStr, 0);
            $msgIdHex = $input['msg_id_hex'] ?? '';
            $payloadHex = $input['payload_hex'] ?? '';
            $sessionIdHex = $input['session_id_hex'] ?? null;
            $authTagHex = $input['auth_tag_hex'] ?? null;

            $msgId = hex2bin($msgIdHex);
            $payload = $payloadHex !== '' ? hex2bin($payloadHex) : '';
            $sessionId = ($sessionIdHex !== null && $sessionIdHex !== '') ? hex2bin($sessionIdHex) : null;
            $authTag = ($authTagHex !== null && $authTagHex !== '') ? hex2bin($authTagHex) : null;

            $envelope = new Envelope($version, $msgType, $msgId, $sessionId, $payload, $authTag);

            try {
                $encoded = $envelope->encode();
            } catch (\Throwable $e) {
                $diag['error'] = 'encode failed: ' . $e->getMessage();
                $diag['vector_id'] = $vec['id'] ?? 'unknown';
                return 'fail';
            }

            $expectedHex = $expected['cbor_hex'] ?? null;
            if ($expectedHex !== null) {
                $actualHex = bin2hex($encoded);
                if ($actualHex !== $expectedHex) {
                    $diag['error'] = 'CBOR encoding mismatch';
                    $diag['vector_id'] = $vec['id'] ?? 'unknown';
                    $diag['expected_hex'] = $expectedHex;
                    $diag['actual_hex'] = $actualHex;
                    return 'fail';
                }
            }

            // Decode back and verify
            try {
                $decoded = Envelope::decode($encoded);
            } catch (\Throwable $e) {
                $diag['error'] = 'decode failed: ' . $e->getMessage();
                $diag['vector_id'] = $vec['id'] ?? 'unknown';
                return 'fail';
            }

            if ($decoded->version !== $version) {
                $diag['error'] = 'version mismatch after roundtrip';
                $diag['expected'] = $version;
                $diag['actual'] = $decoded->version;
                return 'fail';
            }
            if ($decoded->messageType !== $msgType) {
                $diag['error'] = 'message_type mismatch after roundtrip';
                return 'fail';
            }
        }
        return 'pass';
    }

    // Fallback: simple roundtrip without vectors
    foreach ($messageTypes as $mt) {
        $msgType = is_string($mt) ? intval($mt, 0) : $mt;
        $msgId = random_bytes(16);
        $payload = Cbor::encode(['test' => true]);
        $env = new Envelope(1, $msgType, $msgId, null, $payload, null);

        $encoded = $env->encode();
        $decoded = Envelope::decode($encoded);

        if ($decoded->version !== 1 || $decoded->messageType !== $msgType) {
            $diag['error'] = "roundtrip mismatch for msg_type 0x" . dechex($msgType);
            return 'fail';
        }
    }
    return 'pass';
}

/**
 * Verify CBOR field types (integer keys, major types).
 */
function verifyCborFieldTypes(array $params, array &$diag): string
{
    // Create an envelope with all fields
    $msgId = str_repeat("\x01", 16);
    $sessionId = str_repeat("\x02", 32);
    $payload = Cbor::encode('test');
    $authTag = str_repeat("\x03", 16);

    $env = new Envelope(1, 0x0100, $msgId, $sessionId, $payload, $authTag);
    $encoded = $env->encode();

    // Decode raw CBOR to check structure
    $raw = Cbor::decode($encoded);
    if (!is_array($raw)) {
        $diag['error'] = 'encoded envelope is not a CBOR map';
        return 'fail';
    }

    // Check required integer keys exist
    $requiredKeys = [0, 1, 2, 4]; // version, type, msg_id, payload
    foreach ($requiredKeys as $key) {
        if (!array_key_exists($key, $raw)) {
            $diag['error'] = "missing required key: $key";
            return 'fail';
        }
    }

    // version (key 0) should be int
    if (!is_int($raw[0])) {
        $diag['error'] = 'key 0 (version) is not an integer';
        return 'fail';
    }
    // type (key 1) should be int
    if (!is_int($raw[1])) {
        $diag['error'] = 'key 1 (type) is not an integer';
        return 'fail';
    }
    // msg_id (key 2) should be byte string (16 bytes)
    if (!is_string($raw[2]) || strlen($raw[2]) !== 16) {
        $diag['error'] = 'key 2 (msg_id) is not a 16-byte string';
        return 'fail';
    }
    // payload (key 4) should be byte string
    if (!is_string($raw[4])) {
        $diag['error'] = 'key 4 (payload) is not a byte string';
        return 'fail';
    }

    return 'pass';
}

/**
 * Verify deterministic CBOR encoding against test vectors.
 */
function verifyCborDeterministic(array $params, array &$diag): string
{
    $vectors = loadCborVectors();
    if ($vectors === null) {
        $diag['skip'] = 'no CBOR test vectors available';
        return 'skip';
    }

    foreach ($vectors as $vec) {
        $input = $vec['input'] ?? [];
        $expected = $vec['expected_output'] ?? [];

        $version = $input['version'] ?? 1;
        $msgTypeStr = $input['msg_type'] ?? '0x0100';
        $msgType = intval($msgTypeStr, 0);
        $msgIdHex = $input['msg_id_hex'] ?? '';
        $payloadHex = $input['payload_hex'] ?? '';
        $sessionIdHex = $input['session_id_hex'] ?? null;
        $authTagHex = $input['auth_tag_hex'] ?? null;

        $msgId = hex2bin($msgIdHex);
        $payload = $payloadHex !== '' ? hex2bin($payloadHex) : '';
        $sessionId = ($sessionIdHex !== null && $sessionIdHex !== '') ? hex2bin($sessionIdHex) : null;
        $authTag = ($authTagHex !== null && $authTagHex !== '') ? hex2bin($authTagHex) : null;

        $envelope = new Envelope($version, $msgType, $msgId, $sessionId, $payload, $authTag);
        $encoded = $envelope->encodeDeterministic();

        $expectedHex = $expected['cbor_hex'] ?? null;
        if ($expectedHex !== null) {
            $actualHex = bin2hex($encoded);
            if ($actualHex !== $expectedHex) {
                $diag['error'] = 'deterministic CBOR encoding mismatch';
                $diag['vector_id'] = $vec['id'] ?? 'unknown';
                $diag['expected_hex'] = $expectedHex;
                $diag['actual_hex'] = $actualHex;
                return 'fail';
            }
        }
    }

    return 'pass';
}

/**
 * Verify CBOR encode/decode against vectors.
 */
function verifyCborVectors(array $params, array &$diag): string
{
    $vectors = loadCborVectors();
    if ($vectors === null) {
        $diag['skip'] = 'no CBOR test vectors available';
        return 'skip';
    }

    foreach ($vectors as $vec) {
        $expected = $vec['expected_output'] ?? [];
        $expectedHex = $expected['cbor_hex'] ?? null;
        if ($expectedHex === null) {
            continue;
        }

        $cborBytes = hex2bin($expectedHex);

        try {
            $decoded = Envelope::decode($cborBytes);
        } catch (\Throwable $e) {
            $diag['error'] = 'decode failed for vector: ' . ($vec['id'] ?? 'unknown') . ': ' . $e->getMessage();
            return 'fail';
        }

        // Re-encode and verify deterministic output
        $reEncoded = $decoded->encode();
        $reHex = bin2hex($reEncoded);

        if ($reHex !== $expectedHex) {
            $diag['error'] = 'round-trip encoding mismatch';
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            $diag['expected_hex'] = $expectedHex;
            $diag['actual_hex'] = $reHex;
            return 'fail';
        }
    }

    return 'pass';
}

/**
 * Dispatch verify_crypto action.
 */
function dispatchVerifyCrypto(array $params, array &$diag): string
{
    $operation = $params['operation'] ?? '';

    switch ($operation) {
        case 'hkdf_sha256':
            return verifyHkdf($params, $diag);
        case 'hkdf_sha256_batch':
            return verifyHkdfBatch($params, $diag);
        case 'aead_encrypt':
            return verifyAeadEncrypt($params, $diag);
        case 'aead_decrypt':
            return verifyAeadDecrypt($params, $diag);
        case 'spake2_exchange':
            return verifySpake2($params, $diag);
        case 'double_ratchet_chain_kdf':
        case 'double_ratchet_message_keys':
            return verifyDoubleRatchet($params, $diag);
        default:
            $diag['skip'] = "unsupported crypto operation: $operation";
            return 'skip';
    }
}

/**
 * Verify HKDF-SHA256 against test vectors.
 */
function verifyHkdf(array $params, array &$diag): string
{
    $vectors = loadHkdfVectors();
    if ($vectors === null) {
        $diag['skip'] = 'no HKDF test vectors available';
        return 'skip';
    }

    $infoFilter = $params['info'] ?? null;

    foreach ($vectors as $vec) {
        $input = $vec['input'] ?? [];
        $expected = $vec['expected_output'] ?? [];

        $info = $input['info'] ?? '';
        if ($infoFilter !== null && $info !== $infoFilter) {
            continue;
        }

        $ikm = hex2bin($input['ikm_hex'] ?? '');
        $salt = hex2bin($input['salt_hex'] ?? '');
        $outputLen = $input['output_length'] ?? 32;
        $expectedOkm = $expected['okm_hex'] ?? '';

        try {
            $actualOkm = Kdf::hkdfSha256($ikm, $info, $outputLen, $salt);
        } catch (\Throwable $e) {
            $diag['error'] = 'HKDF computation failed: ' . $e->getMessage();
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            return 'fail';
        }

        $actualHex = bin2hex($actualOkm);
        if ($actualHex !== $expectedOkm) {
            $diag['error'] = 'HKDF output mismatch';
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            $diag['expected'] = $expectedOkm;
            $diag['actual'] = $actualHex;
            return 'fail';
        }
    }

    return 'pass';
}

/**
 * Verify HKDF-SHA256 batch (all domain separation constants).
 */
function verifyHkdfBatch(array $params, array &$diag): string
{
    $infoConstants = $params['info_constants'] ?? [];
    if (empty($infoConstants)) {
        $infoConstants = [
            Kdf::HKDF_INFO_SESSION_KEY,
            Kdf::HKDF_INFO_RENDEZVOUS,
            Kdf::HKDF_INFO_SAS,
            Kdf::HKDF_INFO_CHAIN_KEY,
            Kdf::HKDF_INFO_MESSAGE_KEY,
        ];
    }

    foreach ($infoConstants as $info) {
        $result = verifyHkdf(['info' => $info], $diag);
        if ($result !== 'pass') {
            return $result;
        }
    }

    return 'pass';
}

/**
 * Verify AEAD encryption against test vectors.
 */
function verifyAeadEncrypt(array $params, array &$diag): string
{
    $vectors = loadAeadVectors();
    if ($vectors === null) {
        $diag['skip'] = 'no AEAD test vectors available';
        return 'skip';
    }

    $cipherFilter = $params['cipher'] ?? null;

    foreach ($vectors as $vec) {
        $input = $vec['input'] ?? [];
        $expected = $vec['expected_output'] ?? [];

        $algorithm = $input['algorithm'] ?? '';
        $vecCipher = mapCipherName($algorithm);

        // Filter by cipher if specified
        if ($cipherFilter !== null) {
            $filterCipher = mapCipherFilter($cipherFilter);
            if ($vecCipher !== $filterCipher) {
                continue;
            }
        }

        // Only process encrypt vectors
        if (!isset($expected['ciphertext_and_tag_hex'])) {
            continue;
        }

        $key = hex2bin($input['key_hex'] ?? '');
        $nonce = hex2bin($input['nonce_hex'] ?? '');
        $plaintext = hex2bin($input['plaintext_hex'] ?? '');
        $aad = hex2bin($input['aad_hex'] ?? '');
        $expectedCt = $expected['ciphertext_and_tag_hex'] ?? '';

        $cipher = match ($vecCipher) {
            'aes256gcm' => CipherSuite::Aes256Gcm,
            'chacha20poly1305' => CipherSuite::ChaCha20Poly1305,
            default => null,
        };

        if ($cipher === null) {
            continue;
        }

        try {
            $ct = Aead::encrypt($cipher, $key, $nonce, $plaintext, $aad);
        } catch (\Throwable $e) {
            $diag['error'] = 'AEAD encrypt failed: ' . $e->getMessage();
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            return 'fail';
        }

        $actualHex = bin2hex($ct);
        if ($actualHex !== $expectedCt) {
            $diag['error'] = 'AEAD ciphertext mismatch';
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            $diag['expected_hex'] = $expectedCt;
            $diag['actual_hex'] = $actualHex;
            return 'fail';
        }
    }

    return 'pass';
}

/**
 * Verify AEAD decryption against test vectors.
 */
function verifyAeadDecrypt(array $params, array &$diag): string
{
    $vectors = loadAeadVectors();
    if ($vectors === null) {
        $diag['skip'] = 'no AEAD test vectors available';
        return 'skip';
    }

    $cipherFilter = $params['cipher'] ?? null;

    foreach ($vectors as $vec) {
        $input = $vec['input'] ?? [];
        $expected = $vec['expected_output'] ?? [];

        $algorithm = $input['algorithm'] ?? '';
        $vecCipher = mapCipherName($algorithm);

        if ($cipherFilter !== null) {
            $filterCipher = mapCipherFilter($cipherFilter);
            if ($vecCipher !== $filterCipher) {
                continue;
            }
        }

        if (!isset($expected['ciphertext_and_tag_hex'])) {
            continue;
        }

        $key = hex2bin($input['key_hex'] ?? '');
        $nonce = hex2bin($input['nonce_hex'] ?? '');
        $plaintext = hex2bin($input['plaintext_hex'] ?? '');
        $aad = hex2bin($input['aad_hex'] ?? '');
        $ctHex = $expected['ciphertext_and_tag_hex'];

        $cipher = match ($vecCipher) {
            'aes256gcm' => CipherSuite::Aes256Gcm,
            'chacha20poly1305' => CipherSuite::ChaCha20Poly1305,
            default => null,
        };

        if ($cipher === null) {
            continue;
        }

        try {
            $decrypted = Aead::decrypt($cipher, $key, $nonce, hex2bin($ctHex), $aad);
        } catch (\Throwable $e) {
            $diag['error'] = 'AEAD decrypt failed: ' . $e->getMessage();
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            return 'fail';
        }

        if ($decrypted !== $plaintext) {
            $diag['error'] = 'AEAD decryption mismatch';
            $diag['vector_id'] = $vec['id'] ?? 'unknown';
            $diag['expected_hex'] = bin2hex($plaintext);
            $diag['actual_hex'] = bin2hex($decrypted);
            return 'fail';
        }
    }

    return 'pass';
}

function mapCipherName(string $algorithm): string
{
    return match (strtolower($algorithm)) {
        'aes-256-gcm', 'aes256gcm' => 'aes256gcm',
        'chacha20-poly1305', 'chacha20poly1305' => 'chacha20poly1305',
        default => strtolower($algorithm),
    };
}

function mapCipherFilter(string $filter): string
{
    return match (strtolower($filter)) {
        'aes_256_gcm', 'aes-256-gcm', 'aes256gcm' => 'aes256gcm',
        'chacha20_poly1305', 'chacha20-poly1305', 'chacha20poly1305' => 'chacha20poly1305',
        default => strtolower($filter),
    };
}

/**
 * Verify SPAKE2 exchange (self-test: both sides run locally).
 */
function verifySpake2(array $params, array &$diag): string
{
    if (!function_exists('sodium_crypto_core_ristretto255_scalar_random')) {
        $diag['skip'] = 'ristretto255 not available (requires PHP 8.3+ / libsodium 1.0.18+)';
        return 'skip';
    }

    try {
        $password = 'test-conformance-spake2-password';
        $initiator = Spake2::startA($password);
        $responder = Spake2::startB($password);

        $secretA = $initiator->finish($responder->outboundMessage());
        $secretB = $responder->finish($initiator->outboundMessage());

        if ($secretA !== $secretB) {
            $diag['error'] = 'SPAKE2 shared secret mismatch';
            $diag['secret_a_hex'] = bin2hex($secretA);
            $diag['secret_b_hex'] = bin2hex($secretB);
            return 'fail';
        }

        // Verify key confirmation
        $confirmKey = Kdf::hkdfSha256($secretA, 'cairn-pairing-key-confirm-v1', 32);
        $initConfirm = hash_hmac('sha256', 'initiator', $confirmKey, true);
        $respConfirm = hash_hmac('sha256', 'responder', $confirmKey, true);

        if (strlen($initConfirm) !== 32 || strlen($respConfirm) !== 32) {
            $diag['error'] = 'Key confirmation HMAC length incorrect';
            return 'fail';
        }

        // Verify wrong password produces different secret
        $wrongInit = Spake2::startA('wrong-password');
        $wrongResp = Spake2::startB($password);
        $wrongSecretA = $wrongInit->finish($wrongResp->outboundMessage());
        $wrongSecretB = $wrongResp->finish($wrongInit->outboundMessage());

        if ($wrongSecretA === $wrongSecretB) {
            $diag['error'] = 'SPAKE2 should not produce matching secrets with different passwords';
            return 'fail';
        }

        return 'pass';
    } catch (\Throwable $e) {
        $diag['error'] = 'SPAKE2 verification failed: ' . $e->getMessage();
        return 'fail';
    }
}

/**
 * Verify Double Ratchet chain KDF against test vectors.
 */
function verifyDoubleRatchet(array $params, array &$diag): string
{
    global $vectorsDir;
    $path = $vectorsDir . '/crypto/double_ratchet_vectors.json';
    if (!file_exists($path)) {
        $diag['skip'] = 'double_ratchet_vectors.json not found';
        return 'skip';
    }

    $data = json_decode(file_get_contents($path), true);
    $vectors = $data['vectors'] ?? [];
    $failures = [];

    foreach ($vectors as $vec) {
        $id = $vec['id'] ?? 'unknown';
        $input = $vec['input'] ?? [];
        $expected = $vec['expected_output'] ?? [];

        try {
            if (str_starts_with($id, 'ratchet-kdf-rk')) {
                // Root chain KDF: HKDF(salt=root_key, ikm=dh_output, info)
                $rootKey = hex2bin($input['root_key_hex'] ?? '');
                $dhOutput = hex2bin($input['dh_output_hex'] ?? '');
                $info = $input['hkdf_info'] ?? Kdf::HKDF_INFO_ROOT_CHAIN;

                $output = Kdf::hkdfSha256($dhOutput, $info, 64, $rootKey);
                $newRootKey = substr($output, 0, 32);
                $chainKey = substr($output, 32, 32);

                $expRoot = $expected['new_root_key_hex'] ?? null;
                $expChain = $expected['new_chain_key_hex'] ?? null;

                if ($expRoot !== null && bin2hex($newRootKey) !== $expRoot) {
                    $failures[] = [
                        'vector' => "$id (new_root_key)",
                        'expected' => $expRoot,
                        'actual' => bin2hex($newRootKey),
                    ];
                }
                if ($expChain !== null && bin2hex($chainKey) !== $expChain) {
                    $failures[] = [
                        'vector' => "$id (chain_key)",
                        'expected' => $expChain,
                        'actual' => bin2hex($chainKey),
                    ];
                }
            } elseif ($id === 'ratchet-kdf-ck-step0') {
                // Chain KDF: HKDF(ikm=chain_key, salt='', info=chain_advance)
                $chainKey = hex2bin($input['chain_key_hex'] ?? '');
                $chainInfo = $input['chain_advance_info'] ?? Kdf::HKDF_INFO_CHAIN_ADVANCE;
                $msgInfo = $input['msg_encrypt_info'] ?? Kdf::HKDF_INFO_MSG_ENCRYPT;

                // Chain advance: derive new_chain_key and message_key from chain_key
                $output = Kdf::hkdfSha256($chainKey, $chainInfo, 64);
                $newChainKey = substr($output, 0, 32);
                $msgKey = substr($output, 32, 32);

                $expCk = $expected['new_chain_key_hex'] ?? null;
                $expMk = $expected['message_key_hex'] ?? null;

                if ($expCk !== null && bin2hex($newChainKey) !== $expCk) {
                    $failures[] = [
                        'vector' => "$id (new_chain_key)",
                        'expected' => $expCk,
                        'actual' => bin2hex($newChainKey),
                    ];
                }
                if ($expMk !== null && bin2hex($msgKey) !== $expMk) {
                    $failures[] = [
                        'vector' => "$id (message_key)",
                        'expected' => $expMk,
                        'actual' => bin2hex($msgKey),
                    ];
                }
            } elseif ($id === 'ratchet-send-chain-3-messages') {
                // Multi-step chain KDF
                $chainKey = hex2bin($input['initial_chain_key_hex'] ?? '');
                $numMessages = $input['num_messages'] ?? 3;
                $steps = $expected['steps'] ?? [];

                for ($i = 0; $i < $numMessages && $i < count($steps); $i++) {
                    $step = $steps[$i];
                    $output = Kdf::hkdfSha256($chainKey, Kdf::HKDF_INFO_CHAIN_ADVANCE, 64);
                    $newChainKey = substr($output, 0, 32);
                    $msgKey = substr($output, 32, 32);

                    $expCk = $step['output_chain_key_hex'] ?? null;
                    $expMk = $step['message_key_hex'] ?? null;

                    if ($expCk !== null && bin2hex($newChainKey) !== $expCk) {
                        $failures[] = [
                            'vector' => "$id step $i (chain_key)",
                            'expected' => $expCk,
                            'actual' => bin2hex($newChainKey),
                        ];
                    }
                    if ($expMk !== null && bin2hex($msgKey) !== $expMk) {
                        $failures[] = [
                            'vector' => "$id step $i (message_key)",
                            'expected' => $expMk,
                            'actual' => bin2hex($msgKey),
                        ];
                    }

                    $chainKey = $newChainKey;
                }
            } elseif (str_starts_with($id, 'ratchet-nonce-')) {
                // Nonce derivation: first 8 bytes from message key, last 4 from big-endian msg_num
                $msgKey = hex2bin($input['message_key_hex'] ?? '');
                $msgNum = $input['msg_num'] ?? 0;
                $expectedNonce = $expected['nonce_hex'] ?? null;

                $nonce = substr($msgKey, 0, 8) . pack('N', $msgNum);

                if ($expectedNonce !== null && bin2hex($nonce) !== $expectedNonce) {
                    $failures[] = [
                        'vector' => $id,
                        'expected' => $expectedNonce,
                        'actual' => bin2hex($nonce),
                    ];
                }
            }
            // Skip config/header/property vectors (not KDF operations)
        } catch (\Throwable $e) {
            $failures[] = ['vector' => $id, 'error' => $e->getMessage()];
        }
    }

    if (!empty($failures)) {
        $diag['failures'] = $failures;
        return 'fail';
    }
    return 'pass';
}

/**
 * Dispatch pair action.
 */
function dispatchPair(array $params, array &$diag): string
{
    $mechanism = $params['mechanism'] ?? '';

    if ($mechanism !== 'psk') {
        $diag['skip'] = "unsupported pairing mechanism: $mechanism";
        return 'skip';
    }

    $psk = $params['psk'] ?? '';
    if ($psk === '') {
        $diag['skip'] = 'no psk param (bulk/specialized pairing scenario)';
        return 'skip';
    }

    // Check if ristretto255 functions are available
    if (!function_exists('sodium_crypto_core_ristretto255_scalar_random')) {
        $diag['skip'] = 'ristretto255 not available in this PHP build';
        return 'skip';
    }

    try {
        return verifyPskPairing($psk, $diag);
    } catch (\Throwable $e) {
        $diag['error'] = 'PSK pairing failed: ' . $e->getMessage();
        return 'fail';
    }
}

/**
 * Run a standalone PSK pairing: initiator and responder complete SPAKE2 locally.
 */
function verifyPskPairing(string $psk, array &$diag): string
{
    // Start both sides of SPAKE2
    $initiator = Spake2::startA($psk);
    $responder = Spake2::startB($psk);

    // Exchange messages
    $initMsg = $initiator->outboundMessage();
    $respMsg = $responder->outboundMessage();

    // Finish with each other's messages
    $secretA = $initiator->finish($respMsg);
    $secretB = $responder->finish($initMsg);

    if ($secretA !== $secretB) {
        $diag['error'] = 'SPAKE2 shared secrets do not match';
        $diag['secret_a_hex'] = bin2hex($secretA);
        $diag['secret_b_hex'] = bin2hex($secretB);
        return 'fail';
    }

    // Derive session key via HKDF
    $hkdfInfo = 'cairn-pairing-session-key-v1';
    $sessionKeyA = Kdf::hkdfSha256($secretA, $hkdfInfo);
    $sessionKeyB = Kdf::hkdfSha256($secretB, $hkdfInfo);

    if ($sessionKeyA !== $sessionKeyB) {
        $diag['error'] = 'session keys do not match after HKDF';
        return 'fail';
    }

    // Verify key confirmation (HMAC-SHA256)
    $confirmInfo = 'cairn-pairing-key-confirm-v1';
    $confirmKeyA = Kdf::hkdfSha256($secretA, $confirmInfo);
    $confirmKeyB = Kdf::hkdfSha256($secretB, $confirmInfo);

    $confirmA = hash_hmac('sha256', 'initiator', $confirmKeyA, true);
    $confirmB = hash_hmac('sha256', 'responder', $confirmKeyB, true);

    // Verify cross-confirmation
    $expectedA = hash_hmac('sha256', 'initiator', $confirmKeyB, true);
    $expectedB = hash_hmac('sha256', 'responder', $confirmKeyA, true);

    if ($confirmA !== $expectedA) {
        $diag['error'] = 'initiator key confirmation mismatch';
        return 'fail';
    }

    if ($confirmB !== $expectedB) {
        $diag['error'] = 'responder key confirmation mismatch';
        return 'fail';
    }

    return 'pass';
}

// --- Infrastructure actions (skip) ---

$skipActions = [
    'establish_session', 'send_data', 'receive_data', 'open_channel',
    'close_channel', 'disconnect', 'reconnect', 'resume_session',
    'forward_message', 'mesh_route', 'heartbeat', 'queue_message',
    'verify_delivery', 'wait', 'kill_process',
];

// --- Main loop ---

function runScenario(string $scenarioName): array
{
    global $skipActions;

    $startMs = (int)(microtime(true) * 1000);
    $diag = new \stdClass();
    $diagArr = [];

    // Find scenario file
    $scenarioFile = findScenarioFile($scenarioName);
    if ($scenarioFile === null) {
        // Try finding via category prefix
        $parts = explode('-', $scenarioName, 2);
        if (count($parts) >= 2) {
            $scenarioFile = findScenarioFileByCategory($scenarioName, $parts[0]);
        }
    }

    if ($scenarioFile === null) {
        return buildResult($scenarioName, 'skip', $startMs, ['skip' => "scenario file not found: $scenarioName"]);
    }

    $data = parseYaml($scenarioFile);
    if ($data === null) {
        return buildResult($scenarioName, 'skip', $startMs, ['skip' => 'failed to parse YAML']);
    }

    $scenario = findScenarioInFile($data, $scenarioName);
    if ($scenario === null) {
        return buildResult($scenarioName, 'skip', $startMs, ['skip' => "scenario not found in file: $scenarioName"]);
    }

    // Check if we are a relevant participant
    $participants = $scenario['participants'] ?? [];
    if (!isRelevantParticipant($participants)) {
        return buildResult($scenarioName, 'skip', $startMs, ['skip' => 'not a PHP participant']);
    }

    // Execute actions
    $actions = $scenario['actions'] ?? [];
    if (empty($actions)) {
        return buildResult($scenarioName, 'pass', $startMs, []);
    }

    foreach ($actions as $action) {
        $type = $action['type'] ?? '';
        $params = $action['params'] ?? [];

        // Skip infrastructure actions
        if (in_array($type, $skipActions, true)) {
            return buildResult($scenarioName, 'skip', $startMs, ['skip' => "infrastructure action: $type"]);
        }

        switch ($type) {
            case 'verify_cbor':
                $result = dispatchVerifyCbor($params, $diagArr);
                break;
            case 'verify_crypto':
                $result = dispatchVerifyCrypto($params, $diagArr);
                break;
            case 'pair':
                $result = dispatchPair($params, $diagArr);
                break;
            default:
                $result = 'skip';
                $diagArr['skip'] = "unsupported action type: $type";
                break;
        }

        if ($result === 'fail') {
            return buildResult($scenarioName, 'fail', $startMs, $diagArr);
        }

        if ($result === 'skip') {
            return buildResult($scenarioName, 'skip', $startMs, $diagArr);
        }
    }

    return buildResult($scenarioName, 'pass', $startMs, $diagArr);
}

function findScenarioFileByCategory(string $scenarioName, string $prefix): ?string
{
    global $categories, $testsDir;
    // Map common prefixes to categories
    $prefixMap = [
        'wire' => 'wire',
        'crypto' => 'crypto',
        'pair' => 'pairing',
        'session' => 'session',
        'data' => 'data',
        'transport' => 'transport',
        'mesh' => 'mesh',
        'forward' => 'forward',
    ];
    $cat = $prefixMap[$prefix] ?? null;
    if ($cat === null) {
        return null;
    }
    // Search all yml files in this category
    $dir = $testsDir . '/' . $cat;
    if (!is_dir($dir)) {
        return null;
    }
    $files = glob($dir . '/*.yml');
    if ($files === false) {
        return null;
    }
    foreach ($files as $file) {
        $data = parseYaml($file);
        if ($data === null) {
            continue;
        }
        if (findScenarioInFile($data, $scenarioName) !== null) {
            return $file;
        }
    }
    return null;
}

function buildResult(string $scenario, string $status, int $startMs, array $diagnostics): array
{
    $endMs = (int)(microtime(true) * 1000);
    return [
        'scenario' => $scenario,
        'status' => $status,
        'duration_ms' => $endMs - $startMs,
        'diagnostics' => empty($diagnostics) ? new \stdClass() : $diagnostics,
    ];
}

// --- Entry point ---

$stdin = fopen('php://stdin', 'r');
if ($stdin === false) {
    fwrite(STDERR, "Failed to open stdin\n");
    exit(1);
}

while (($line = fgets($stdin)) !== false) {
    $scenario = trim($line);
    if ($scenario === '') {
        continue;
    }

    $result = runScenario($scenario);
    echo json_encode($result, JSON_UNESCAPED_SLASHES) . "\n";
}

fclose($stdin);
