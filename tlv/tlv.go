// Package tlv provides helpers for validating EMV BER-TLV payloads.
package tlv

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/moov-io/bertlv"
)

const (
	// AmountTag is the EMV tag for the authorized amount (numeric).
	AmountTag = "9F02"

	amountLength = 6
)

var (
	// ErrParsingTLV indicates that a payload is not valid BER-TLV data.
	ErrParsingTLV = errors.New("TLV parsing failed")
	// ErrInvalidTLV indicates that the payload does not contain a valid amount tag.
	ErrInvalidTLV = errors.New("invalid TLV payload")
	// ErrInvalidAmount indicates that the expected amount is not an unsigned decimal integer.
	ErrInvalidAmount = errors.New("invalid amount")
	// ErrAmountMismatch indicates that the payload and expected amounts differ.
	ErrAmountMismatch = errors.New("amount mismatch in TLV and request")
)

// ValidateAmount verifies that data contains a six-byte EMV numeric amount
// matching wantAmount. The amount is compared as an unsigned decimal integer,
// so leading zeroes in either representation do not affect the result.
func ValidateAmount(data []byte, wantAmount string) error {
	decoded, err := bertlv.Decode(data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParsingTLV, err)
	}

	amountTLV, ok := bertlv.FindFirstTag(decoded, AmountTag)
	if !ok || len(amountTLV.Value) != amountLength {
		return ErrInvalidTLV
	}

	amount, err := NumericBCDToUint(amountTLV.Value)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTLV, err)
	}

	expected, err := strconv.ParseUint(wantAmount, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAmount, err)
	}

	if amount != expected {
		return ErrAmountMismatch
	}

	return nil
}

// NumericBCDToUint converts an EMV numeric binary-coded decimal value to an
// unsigned integer. Each nibble must contain a decimal digit.
func NumericBCDToUint(value []byte) (uint64, error) {
	encoded := hex.EncodeToString(value)

	result, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode numeric BCD: %w", err)
	}

	return result, nil
}
