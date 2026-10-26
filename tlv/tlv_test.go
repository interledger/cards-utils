package tlv_test

import (
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/interledger/cards-utils/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAmount(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantAmount string
		wantErr    error
	}{
		{
			name:       "matching amount",
			data:       []byte{0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantAmount: "100",
		},
		{
			name:       "matching amount with leading zeroes",
			data:       []byte{0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantAmount: "000100",
		},
		{
			name:       "malformed TLV",
			data:       []byte{0x9F, 0x02, 0x06, 0x00},
			wantAmount: "100",
			wantErr:    tlv.ErrParsingTLV,
		},
		{
			name:       "missing amount tag",
			data:       []byte{0x5F, 0x2A, 0x01, 0x08},
			wantAmount: "100",
			wantErr:    tlv.ErrInvalidTLV,
		},
		{
			name:       "incorrect amount length",
			data:       []byte{0x9F, 0x02, 0x03, 0x00, 0x01, 0x00},
			wantAmount: "100",
			wantErr:    tlv.ErrInvalidTLV,
		},
		{
			name:       "invalid amount BCD",
			data:       []byte{0x9F, 0x02, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x00},
			wantAmount: "100",
			wantErr:    tlv.ErrInvalidTLV,
		},
		{
			name:       "invalid expected amount",
			data:       []byte{0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantAmount: "1.00",
			wantErr:    tlv.ErrInvalidAmount,
		},
		{
			name:       "amount mismatch",
			data:       []byte{0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			wantAmount: "200",
			wantErr:    tlv.ErrAmountMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tlv.ValidateAmount(tt.data, tt.wantAmount)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestValidateAmountFindsNestedTag(t *testing.T) {
	data := []byte{
		0xE1, 0x09,
		0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	}

	require.NoError(t, tlv.ValidateAmount(data, "100"))
}

func TestValidateAmountSupportsLongFormLength(t *testing.T) {
	data := append([]byte{0x9F, 0x03, 0x81, 0x80}, make([]byte, 128)...)
	data = append(data, 0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00)

	require.NoError(t, tlv.ValidateAmount(data, "100"))
}

func TestNumericBCDToUint(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		want    uint64
		wantErr bool
	}{
		{name: "leading zeroes", value: []byte{0x00, 0x00, 0x01, 0x23}, want: 123},
		{name: "all decimal digits", value: []byte{0x98, 0x76, 0x54}, want: 987654},
		{name: "invalid high nibble", value: []byte{0xA0}, wantErr: true},
		{name: "invalid low nibble", value: []byte{0x0F}, wantErr: true},
		{name: "empty", value: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlv.NumericBCDToUint(tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateAmountErrorsRemainComparable(t *testing.T) {
	err := tlv.ValidateAmount([]byte{0x9F, 0x02, 0x06, 0x00}, "100")

	assert.True(t, errors.Is(err, tlv.ErrParsingTLV))
}

// A malformed payload must be an error, never a panic. SRED decrypted under
// the wrong key is random bytes, and github.com/moov-io/bertlv v0.1.0 panicked
// on about one in three of those, on a long-form length that overflows.
func TestValidateAmountDoesNotPanicOnMalformedLength(t *testing.T) {
	for name, data := range map[string][]byte{
		"8-byte length overflows int":     {0x5A, 0x88, 0xFA, 0xBA, 0xDA, 0xBA, 0xDA, 0xBA, 0xDA, 0xBA},
		"8-byte length of the amount tag": {0x9F, 0x02, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"length bytes missing":            {0x9F, 0x02, 0x84, 0xFF},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() { err = tlv.ValidateAmount(data, "100") })
			require.ErrorIs(t, err, tlv.ErrParsingTLV)
		})
	}
}

func TestValidateAmountDoesNotPanicOnRandomPayloads(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	payload := make([]byte, 160)
	for i := 0; i < 10000; i++ {
		for j := range payload {
			payload[j] = byte(rng.Uint32())
		}
		require.NotPanics(t, func() { _ = tlv.ValidateAmount(payload, "100") }, "payload %X", payload)
	}
}

func FuzzValidateAmount(f *testing.F) {
	f.Add([]byte{0x9F, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte{0x5A, 0x88, 0xFA, 0xBA, 0xDA, 0xBA, 0xDA, 0xBA, 0xDA, 0xBA})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = tlv.ValidateAmount(data, "100")
	})
}
