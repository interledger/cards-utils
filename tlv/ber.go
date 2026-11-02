package tlv

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// MaxDepth is the deepest nesting of constructed tags that Decode and
	// Encode accept. Real EMV data nests three or four levels at most.
	MaxDepth = 16

	// maxTagBytes and maxLengthBytes bound the tag and the long-form length
	// field. Four bytes covers every EMV tag (the longest are three bytes) and
	// lengths up to 4 GiB.
	maxTagBytes    = 4
	maxLengthBytes = 4

	constructedBit = 0b0010_0000
	multiByteTag   = 0b0001_1111
	moreTagBytes   = 0b1000_0000
	longFormLength = 0b1000_0000
)

var (
	// ErrTruncated indicates that the input ends inside a tag or length field.
	ErrTruncated = errors.New("truncated input")
	// ErrLengthOutOfRange indicates a declared length longer than the data
	// that remains.
	ErrLengthOutOfRange = errors.New("length exceeds remaining data")
	// ErrUnsupportedLength indicates the indefinite form (0x80), the reserved
	// form (0xFF) or a long-form length of more than four bytes.
	ErrUnsupportedLength = errors.New("unsupported length form")
	// ErrTagTooLong indicates a tag of more than four bytes.
	ErrTagTooLong = errors.New("tag too long")
	// ErrMaxDepth indicates constructed tags nested deeper than MaxDepth.
	ErrMaxDepth = errors.New("maximum nesting depth exceeded")
	// ErrInvalidTag indicates a tag that Encode cannot write.
	ErrInvalidTag = errors.New("invalid tag")
)

// DecodeError reports where in the input decoding failed. It never includes
// value bytes, which may hold cardholder data.
type DecodeError struct {
	// Offset is the position in the input passed to Decode.
	Offset int
	// Tag is the tag being decoded, in upper-case hex, if it was read.
	Tag string
	Err error
}

func (e *DecodeError) Error() string {
	if e.Tag == "" {
		return fmt.Sprintf("decode BER-TLV at offset %d: %v", e.Offset, e.Err)
	}

	return fmt.Sprintf("decode BER-TLV tag %s at offset %d: %v", e.Tag, e.Offset, e.Err)
}

func (e *DecodeError) Unwrap() error {
	return e.Err
}

// TLV is a decoded BER-TLV data object. A constructed tag holds its children
// in TLVs; a primitive tag holds its content in Value.
type TLV struct {
	// Tag is the tag in upper-case hex, such as "9F02".
	Tag   string
	Value []byte
	TLVs  []TLV
}

// NewTag returns a primitive TLV.
func NewTag(tag string, value []byte) TLV {
	return TLV{Tag: tag, Value: value}
}

// NewComposite returns a constructed TLV holding tlvs.
func NewComposite(tag string, tlvs ...TLV) TLV {
	return TLV{Tag: tag, TLVs: tlvs}
}

// Decode parses BER-TLV data as used by EMV. It is safe for untrusted input:
// it never panics, and every error wraps one of the sentinel errors above in
// a *DecodeError.
//
// Single '00' bytes between data objects are padding and are skipped. Values
// share memory with data, capped so that appending to a Value cannot
// overwrite the bytes that follow it.
func Decode(data []byte) ([]TLV, error) {
	return decode(data, 0, 0)
}

func decode(data []byte, base, depth int) ([]TLV, error) {
	var tlvs []TLV

	for off := 0; off < len(data); {
		start := off

		// EMV Book 3 Annex B allows '00' bytes before, between and after
		// data objects.
		if data[off] == 0x00 {
			off++
			continue
		}

		tagLen, err := decodeTag(data[off:])
		if err != nil {
			return nil, &DecodeError{Offset: base + start, Err: err}
		}
		tagBytes := data[off : off+tagLen]
		tag := strings.ToUpper(hex.EncodeToString(tagBytes))
		off += tagLen

		length, lenLen, err := decodeLength(data[off:])
		if err != nil {
			return nil, &DecodeError{Offset: base + start, Tag: tag, Err: err}
		}
		off += lenLen

		// Compare as uint64 so a four-byte length cannot overflow int on
		// 32-bit platforms.
		if length > uint64(len(data)-off) {
			return nil, &DecodeError{Offset: base + start, Tag: tag, Err: ErrLengthOutOfRange}
		}
		end := off + int(length)
		value := data[off:end:end]

		if isConstructed(tagBytes) {
			if depth >= MaxDepth {
				return nil, &DecodeError{Offset: base + start, Tag: tag, Err: ErrMaxDepth}
			}

			children, err := decode(value, base+off, depth+1)
			if err != nil {
				return nil, err
			}
			tlvs = append(tlvs, TLV{Tag: tag, TLVs: children})
		} else {
			tlvs = append(tlvs, TLV{Tag: tag, Value: value})
		}

		off = end
	}

	return tlvs, nil
}

// decodeTag returns the length of the tag at the start of data, which must
// not be empty.
func decodeTag(data []byte) (int, error) {
	if data[0]&multiByteTag != multiByteTag {
		return 1, nil
	}

	// Subsequent bytes have bit 8 set, except the last.
	for i := 1; i < len(data); i++ {
		if i >= maxTagBytes {
			return 0, ErrTagTooLong
		}

		if data[i]&moreTagBytes == 0 {
			return i + 1, nil
		}
	}

	return 0, ErrTruncated
}

// decodeLength returns the length value and the size of the length field.
func decodeLength(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrTruncated
	}

	first := data[0]
	if first&longFormLength == 0 {
		return uint64(first), 1, nil
	}

	n := int(first &^ longFormLength)
	if n == 0 || n > maxLengthBytes {
		// 0x80 is the indefinite form; 0x85 to 0xFF (including the reserved
		// 0xFF) are longer than we accept.
		return 0, 0, ErrUnsupportedLength
	}

	if len(data) < 1+n {
		return 0, 0, ErrTruncated
	}

	var length uint64
	for _, b := range data[1 : 1+n] {
		length = length<<8 | uint64(b)
	}

	return length, 1 + n, nil
}

// Encode writes tlvs as BER-TLV with minimal-length encoding. A TLV with
// children is written from TLVs; otherwise Value is written as is, so a
// constructed tag may carry pre-encoded content in Value.
func Encode(tlvs []TLV) ([]byte, error) {
	return encode(nil, tlvs, 0)
}

func encode(out []byte, tlvs []TLV, depth int) ([]byte, error) {
	for _, t := range tlvs {
		tag, err := hex.DecodeString(t.Tag)
		if err != nil {
			return nil, fmt.Errorf("%w %q: not hex", ErrInvalidTag, t.Tag)
		}

		if err := validateTag(tag); err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidTag, t.Tag, err)
		}

		value := t.Value
		if len(t.TLVs) > 0 {
			if !isConstructed(tag) {
				return nil, fmt.Errorf("%w %q: primitive tag has children", ErrInvalidTag, t.Tag)
			}

			if depth >= MaxDepth {
				return nil, fmt.Errorf("encode tag %s: %w", t.Tag, ErrMaxDepth)
			}

			value, err = encode(nil, t.TLVs, depth+1)
			if err != nil {
				return nil, err
			}
		}

		length, err := encodeLength(len(value))
		if err != nil {
			return nil, fmt.Errorf("encode tag %s: %w", t.Tag, err)
		}

		out = append(out, tag...)
		out = append(out, length...)
		out = append(out, value...)
	}

	return out, nil
}

func validateTag(tag []byte) error {
	switch {
	case len(tag) == 0:
		return errors.New("empty")
	case len(tag) > maxTagBytes:
		return ErrTagTooLong
	case len(tag) == 1 && tag[0] == 0x00:
		return errors.New("00 is padding")
	}

	if tag[0]&multiByteTag != multiByteTag {
		if len(tag) != 1 {
			return errors.New("single-byte tag has extra bytes")
		}

		return nil
	}

	if len(tag) < 2 {
		return errors.New("multi-byte tag is incomplete")
	}

	for i := 1; i < len(tag)-1; i++ {
		if tag[i]&moreTagBytes == 0 {
			return fmt.Errorf("byte %d must have bit 8 set", i+1)
		}
	}

	if tag[len(tag)-1]&moreTagBytes != 0 {
		return errors.New("last byte must have bit 8 clear")
	}

	return nil
}

func encodeLength(length int) ([]byte, error) {
	if length < 0x80 {
		return []byte{byte(length)}, nil
	}

	var field []byte
	for l := uint64(length); l > 0; l >>= 8 {
		field = append([]byte{byte(l)}, field...)
	}

	if len(field) > maxLengthBytes {
		return nil, ErrUnsupportedLength
	}

	return append([]byte{longFormLength | byte(len(field))}, field...), nil
}

func isConstructed(tag []byte) bool {
	return tag[0]&constructedBit != 0
}

// FindFirstTag returns the first TLV with the given tag, searching depth-first
// in encoding order. The tag is compared without regard to case.
func FindFirstTag(tlvs []TLV, tag string) (TLV, bool) {
	for _, t := range tlvs {
		if strings.EqualFold(t.Tag, tag) {
			return t, true
		}

		if found, ok := FindFirstTag(t.TLVs, tag); ok {
			return found, true
		}
	}

	return TLV{}, false
}
