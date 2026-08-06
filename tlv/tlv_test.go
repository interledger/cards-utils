package tlv_test

import (
	"errors"
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
