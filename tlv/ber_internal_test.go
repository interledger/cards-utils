package tlv

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Encode never writes more than MaxInputSize, so the three- and four-byte
// length forms are tested here directly.
func TestEncodeLength(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0x00}},
		{0x7F, []byte{0x7F}},
		{0x80, []byte{0x81, 0x80}},
		{0xFFFF, []byte{0x82, 0xFF, 0xFF}},
		{0x10000, []byte{0x83, 0x01, 0x00, 0x00}},
		{0x1000000, []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		got, err := encodeLength(tt.length)
		require.NoError(t, err)
		assert.Equal(t, tt.want, got, "length %d", tt.length)
	}

	if strconv.IntSize == 64 {
		var tooLong uint64 = 1 << 32
		_, err := encodeLength(int(tooLong))
		require.ErrorIs(t, err, ErrUnsupportedLength)
	}
}
