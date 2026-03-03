<?php

declare(strict_types=1);

namespace Cairn\Pairing;

use Cairn\Crypto\Kdf;

/**
 * Short Authentication String (SAS) derivation for verification-only pairing.
 *
 * Numeric SAS: 6-digit code derived from handshake transcript.
 * Emoji SAS: 4 emoji derived from handshake transcript.
 *
 * Both parties compute the SAS independently from their local view of the
 * handshake transcript. If the handshake was not tampered with, the SAS
 * values match.
 *
 * Matches the Rust derive_numeric_sas/derive_emoji_sas in
 * packages/rs/cairn-p2p/src/pairing/mechanisms/mod.rs.
 */
final class Sas
{
    /** HKDF info string for numeric SAS derivation. */
    private const HKDF_INFO_SAS_NUMERIC = 'cairn-sas-numeric-v1';

    /** HKDF info string for emoji SAS derivation. */
    private const HKDF_INFO_SAS_EMOJI = 'cairn-sas-emoji-v1';

    /**
     * 64 visually distinct, cross-platform emoji for SAS derivation.
     * Matches the Rust SAS_EMOJI_LIST.
     *
     * @var list<string>
     */
    public const EMOJI_TABLE = [
        "\u{1F436}", // dog face
        "\u{1F431}", // cat face
        "\u{1F41F}", // fish
        "\u{1F426}", // bird
        "\u{1F43B}", // bear
        "\u{1F981}", // lion
        "\u{1F43A}", // wolf
        "\u{1F98A}", // fox
        "\u{1F98C}", // deer
        "\u{1F989}", // owl
        "\u{1F41D}", // honeybee
        "\u{1F41C}", // ant
        "\u{2B50}",  // star
        "\u{1F319}", // crescent moon
        "\u{2600}",  // sun
        "\u{1F525}", // fire
        "\u{1F333}", // deciduous tree
        "\u{1F343}", // leaf fluttering
        "\u{1F339}", // rose
        "\u{1F30A}", // wave
        "\u{1F327}", // cloud with rain
        "\u{2744}",  // snowflake
        "\u{26A1}",  // lightning bolt
        "\u{1F32C}", // wind face
        "\u{1FAA8}", // rock
        "\u{1F48E}", // gem stone
        "\u{1F514}", // bell
        "\u{1F511}", // key
        "\u{1F512}", // lock
        "\u{1F3F3}", // white flag
        "\u{1F4D6}", // open book
        "\u{1F58A}", // pen
        "\u{2615}",  // hot beverage
        "\u{1F3A9}", // top hat
        "\u{1F45F}", // running shoe
        "\u{1F48D}", // ring
        "\u{1F382}", // birthday cake
        "\u{1F381}", // wrapped gift
        "\u{1F4A1}", // light bulb
        "\u{2699}",  // gear
        "\u{1F6A2}", // ship
        "\u{1F697}", // automobile
        "\u{1F6B2}", // bicycle
        "\u{1F941}", // drum
        "\u{1F4EF}", // postal horn
        "\u{1F3B5}", // musical note
        "\u{1F3B2}", // game die
        "\u{1FA99}", // coin
        "\u{1F5FA}", // world map
        "\u{26FA}",  // tent
        "\u{1F451}", // crown
        "\u{2694}",  // crossed swords
        "\u{1F6E1}", // shield
        "\u{1F3F9}", // bow and arrow
        "\u{1FA93}", // axe
        "\u{1F528}", // hammer
        "\u{2693}",  // anchor
        "\u{2638}",  // wheel of dharma
        "\u{23F0}",  // alarm clock
        "\u{2764}",  // red heart
        "\u{1F480}", // skull
        "\u{1F47B}", // ghost
        "\u{1F916}", // robot
        "\u{1F47D}", // alien
    ];

    private function __construct()
    {
    }

    /**
     * Derive a 6-digit numeric SAS from a handshake transcript.
     *
     * Uses HKDF-SHA256 with info="cairn-sas-numeric-v1".
     * Takes the first 4 bytes, interprets as big-endian uint32,
     * then computes code = value % 1_000_000, zero-padded to 6 digits.
     */
    public static function deriveNumeric(string $transcript): string
    {
        $derived = Kdf::hkdfSha256($transcript, self::HKDF_INFO_SAS_NUMERIC, 4);
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', $derived);
        $value = $unpacked[1] % 1_000_000;
        return sprintf('%06d', $value);
    }

    /**
     * Derive an emoji SAS from a handshake transcript.
     *
     * Uses HKDF-SHA256 with info="cairn-sas-emoji-v1".
     * Takes 8 bytes, splits into 4 x 2-byte values, each mod 64 selects an emoji.
     *
     * @return list<string> Four emoji characters
     */
    public static function deriveEmoji(string $transcript): array
    {
        $derived = Kdf::hkdfSha256($transcript, self::HKDF_INFO_SAS_EMOJI, 8);
        $emojis = [];
        for ($i = 0; $i < 4; $i++) {
            /** @var array{1: int} $unpacked */
            $unpacked = unpack('n', substr($derived, $i * 2, 2));
            $index = $unpacked[1] % 64;
            $emojis[] = self::EMOJI_TABLE[$index];
        }
        return $emojis;
    }
}
