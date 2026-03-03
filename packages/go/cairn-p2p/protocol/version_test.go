package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentProtocolVersion(t *testing.T) {
	assert.Equal(t, uint8(1), CurrentProtocolVersion)
}

func TestSupportedVersionsContainsCurrent(t *testing.T) {
	found := false
	for _, v := range SupportedVersions {
		if v == CurrentProtocolVersion {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestSupportedVersionsHighestFirst(t *testing.T) {
	for i := 0; i < len(SupportedVersions)-1; i++ {
		assert.GreaterOrEqual(t, SupportedVersions[i], SupportedVersions[i+1])
	}
}

func TestSelectVersionCommon(t *testing.T) {
	v, err := SelectVersion([]uint8{3, 2, 1}, []uint8{2, 1})
	require.NoError(t, err)
	assert.Equal(t, uint8(2), v)
}

func TestSelectVersionExactMatch(t *testing.T) {
	v, err := SelectVersion([]uint8{1}, []uint8{1})
	require.NoError(t, err)
	assert.Equal(t, uint8(1), v)
}

func TestSelectVersionPicksHighestMutual(t *testing.T) {
	v, err := SelectVersion([]uint8{5, 3, 1}, []uint8{4, 3, 2, 1})
	require.NoError(t, err)
	assert.Equal(t, uint8(3), v)
}

func TestSelectVersionNoCommon(t *testing.T) {
	_, err := SelectVersion([]uint8{3, 2}, []uint8{5, 4})
	assert.Error(t, err)
}

func TestSelectVersionEmptyOurs(t *testing.T) {
	_, err := SelectVersion([]uint8{}, []uint8{1})
	assert.Error(t, err)
}

func TestSelectVersionEmptyPeer(t *testing.T) {
	_, err := SelectVersion([]uint8{1}, []uint8{})
	assert.Error(t, err)
}
