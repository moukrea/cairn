package pairing

import (
	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
)

// SASFromTranscript derives both numeric and emoji SAS from a Noise XX transcript hash.
type SASResult struct {
	Numeric string
	Emoji   []string
}

// DeriveSAS derives SAS values from a Noise XX handshake transcript hash.
func DeriveSAS(transcriptHash [32]byte) (*SASResult, error) {
	numeric, err := crypto.NumericSAS(transcriptHash)
	if err != nil {
		return nil, err
	}
	emoji, err := crypto.EmojiSAS(transcriptHash)
	if err != nil {
		return nil, err
	}
	return &SASResult{
		Numeric: numeric,
		Emoji:   emoji,
	}, nil
}
