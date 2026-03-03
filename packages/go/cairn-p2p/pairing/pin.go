package pairing

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// Crockford Base32 alphabet (excludes I, L, O, U).
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const pinLength = 8

// GeneratePin generates a random 8-character Crockford Base32 PIN code.
// Returns the formatted "XXXX-XXXX" string and the raw 5 bytes of entropy.
func GeneratePin() (string, []byte, error) {
	var bytes [5]byte // 40 bits of entropy
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", nil, fmt.Errorf("pin entropy generation failed: %w", err)
	}
	raw := encodeCrockford(bytes)
	formatted := FormatPin(raw)
	return formatted, bytes[:], nil
}

// FormatPin formats an 8-character PIN as "XXXX-XXXX".
func FormatPin(pin string) string {
	if len(pin) == pinLength {
		return pin[:4] + "-" + pin[4:]
	}
	return pin
}

// NormalizePin normalizes a user-entered PIN:
//   - Uppercases
//   - Strips hyphens and spaces
//   - I/L -> 1, O -> 0
//   - Removes U (excluded from Crockford Base32)
func NormalizePin(input string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(input) {
		switch c {
		case '-', ' ':
			continue
		case 'U':
			continue
		case 'I', 'L':
			b.WriteByte('1')
		case 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ValidatePin validates that a normalized PIN is a valid 8-character Crockford Base32 string.
func ValidatePin(normalized string) error {
	if len(normalized) != pinLength {
		return fmt.Errorf("invalid pin length: expected %d, got %d", pinLength, len(normalized))
	}
	for _, c := range normalized {
		if !strings.ContainsRune(crockfordAlphabet, c) {
			return fmt.Errorf("invalid pin character: '%c'", c)
		}
	}
	return nil
}

// encodeCrockford encodes 5 bytes (40 bits) to 8 Crockford Base32 characters.
func encodeCrockford(bytes [5]byte) string {
	var bits uint64
	for _, b := range bytes {
		bits = (bits << 8) | uint64(b)
	}
	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		idx := (bits >> (uint(i) * 5)) & 0x1F
		result[7-i] = crockfordAlphabet[idx]
	}
	return string(result)
}

// DecodeCrockford decodes an 8-character Crockford Base32 string to 5 bytes.
func DecodeCrockford(input string) ([5]byte, error) {
	if len(input) != pinLength {
		return [5]byte{}, fmt.Errorf("expected %d characters, got %d", pinLength, len(input))
	}
	var bits uint64
	for _, ch := range input {
		idx := strings.IndexRune(crockfordAlphabet, ch)
		if idx < 0 {
			return [5]byte{}, fmt.Errorf("invalid crockford character: '%c'", ch)
		}
		bits = (bits << 5) | uint64(idx)
	}
	var result [5]byte
	for i := 4; i >= 0; i-- {
		result[4-i] = byte((bits >> (uint(i) * 8)) & 0xFF)
	}
	return result, nil
}
