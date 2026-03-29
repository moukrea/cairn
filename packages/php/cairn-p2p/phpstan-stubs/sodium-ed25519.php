<?php

/**
 * PHPStan stubs for libsodium Ed25519 functions added in PHP 8.1.
 *
 * These functions exist at runtime when ext-sodium is built against
 * libsodium >= 1.0.18, but PHPStan's bundled stubs don't declare them.
 */

/**
 * Generate a random Ed25519 scalar.
 *
 * @return string 32-byte scalar
 */
function sodium_crypto_core_ed25519_scalar_random(): string {}

/**
 * Compute scalar * basepoint (no clamping).
 *
 * @param string $scalar 32-byte scalar
 * @return string 32-byte compressed Edwards-Y point
 */
function sodium_crypto_scalarmult_ed25519_base_noclamp(string $scalar): string {}

/**
 * Compute scalar * point (no clamping).
 *
 * @param string $scalar 32-byte scalar
 * @param string $point 32-byte compressed Edwards-Y point
 * @return string 32-byte compressed Edwards-Y point
 */
function sodium_crypto_scalarmult_ed25519_noclamp(string $scalar, string $point): string {}

/**
 * Add two Ed25519 points.
 *
 * @param string $p 32-byte compressed Edwards-Y point
 * @param string $q 32-byte compressed Edwards-Y point
 * @return string 32-byte compressed Edwards-Y point
 */
function sodium_crypto_core_ed25519_add(string $p, string $q): string {}

/**
 * Subtract two Ed25519 points (p - q).
 *
 * @param string $p 32-byte compressed Edwards-Y point
 * @param string $q 32-byte compressed Edwards-Y point
 * @return string 32-byte compressed Edwards-Y point
 */
function sodium_crypto_core_ed25519_sub(string $p, string $q): string {}

/**
 * Reduce a 64-byte scalar mod L (Ed25519 group order).
 *
 * @param string $scalar 64-byte scalar
 * @return string 32-byte reduced scalar
 */
function sodium_crypto_core_ed25519_scalar_reduce(string $scalar): string {}
