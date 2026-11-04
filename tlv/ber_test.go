package tlv_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/interledger/cards-utils/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err)

	return b
}

// sentinels lists every error Decode may wrap.
var sentinels = []error{
	tlv.ErrTruncated,
	tlv.ErrLengthOutOfRange,
	tlv.ErrUnsupportedLength,
	tlv.ErrTagTooLong,
	tlv.ErrMaxDepth,
	tlv.ErrInputTooLarge,
}

func TestDecodeTags(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantTag string
	}{
		{name: "single byte primitive", data: "5A 01 AA", wantTag: "5A"},
		{name: "single byte context specific", data: "8A 02 3030", wantTag: "8A"},
		{name: "two bytes", data: "9F02 06 000000000100", wantTag: "9F02"},
		{name: "two bytes private class", data: "DF31 01 01", wantTag: "DF31"},
		{name: "three bytes", data: "DF8101 01 01", wantTag: "DF8101"},
		{name: "three bytes proprietary", data: "DFF101 01 01", wantTag: "DFF101"},
		{name: "four bytes", data: "DF818101 01 01", wantTag: "DF818101"},
		{name: "subsequent byte 80 is accepted", data: "1F8001 01 01", wantTag: "1F8001"},
		{name: "subsequent byte 00 is accepted", data: "9F00 01 01", wantTag: "9F00"},
		{name: "first byte FF starts a multi-byte tag", data: "FF01 00", wantTag: "FF01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlv.Decode(mustHex(t, tt.data))
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, tt.wantTag, got[0].Tag)
		})
	}
}

func TestDecodeLengths(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		valLen  int
		trailer string
	}{
		{name: "short form zero", header: "5A 00", valLen: 0},
		{name: "short form one", header: "5A 01", valLen: 1},
		{name: "short form max", header: "5A 7F", valLen: 127},
		{name: "one byte long form min", header: "5A 81 80", valLen: 128},
		{name: "one byte long form max", header: "5A 81 FF", valLen: 255},
		{name: "two byte long form", header: "5A 82 0100", valLen: 256},
		{name: "two byte long form at the input limit", header: "5A 82 FFFC", valLen: tlv.MaxInputSize - 4},
		{name: "three byte long form", header: "5A 83 000101", valLen: 257},
		{name: "four byte long form", header: "5A 84 00000102", valLen: 258},
		{name: "non-minimal long form for short value", header: "5A 81 05", valLen: 5},
		{name: "non-minimal long form with leading zeroes", header: "5A 84 00000003", valLen: 3},
		{name: "non-minimal long form zero", header: "5A 82 0000", valLen: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := bytes.Repeat([]byte{0xAB}, tt.valLen)
			data := append(mustHex(t, tt.header), value...)

			got, err := tlv.Decode(data)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, value, got[0].Value)
			assert.Len(t, got[0].Value, tt.valLen)
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantErr    error
		wantOffset int
	}{
		// Tag
		{name: "multi-byte tag missing second byte", data: "9F", wantErr: tlv.ErrTruncated},
		{name: "multi-byte tag missing last byte", data: "DF81", wantErr: tlv.ErrTruncated},
		{name: "multi-byte tag missing fourth byte", data: "DF8181", wantErr: tlv.ErrTruncated},
		{name: "five byte tag", data: "DF81818101 01 01", wantErr: tlv.ErrTagTooLong},
		{name: "endless tag", data: "1F" + strings.Repeat("FF", 64), wantErr: tlv.ErrTagTooLong},
		{name: "truncated tag after valid TLV", data: "5A0101 9F", wantErr: tlv.ErrTruncated, wantOffset: 3},

		// Length
		{name: "length missing", data: "5A", wantErr: tlv.ErrTruncated},
		{name: "length missing after multi-byte tag", data: "9F02", wantErr: tlv.ErrTruncated},
		{name: "long-form length bytes missing", data: "5A 81", wantErr: tlv.ErrTruncated},
		{name: "long-form length bytes short", data: "9F02 84 FFFF", wantErr: tlv.ErrTruncated},
		{name: "indefinite length", data: "E1 80 5A0101 0000", wantErr: tlv.ErrUnsupportedLength},
		{name: "indefinite length on primitive", data: "5A 80", wantErr: tlv.ErrUnsupportedLength},
		{name: "five length bytes", data: "5A 85 0000000001 AA", wantErr: tlv.ErrUnsupportedLength},
		{name: "eight length bytes", data: "5A 88 0000000000000001 AA", wantErr: tlv.ErrUnsupportedLength},
		{name: "reserved length FF", data: "5A FF", wantErr: tlv.ErrUnsupportedLength},

		// Value
		{name: "short-form value truncated", data: "5A 05 AABBCC", wantErr: tlv.ErrLengthOutOfRange},
		{name: "long-form value truncated", data: "5A 81 80 AA", wantErr: tlv.ErrLengthOutOfRange},
		{name: "max four byte length", data: "5A 84 FFFFFFFF AA", wantErr: tlv.ErrLengthOutOfRange},
		{name: "length one past end", data: "9F02 07 000000000100", wantErr: tlv.ErrLengthOutOfRange},

		// Constructed
		{name: "child overruns parent", data: "E1 03 5A 05 AA", wantErr: tlv.ErrLengthOutOfRange, wantOffset: 2},
		{name: "parent overruns input", data: "E1 09 5A01AA", wantErr: tlv.ErrLengthOutOfRange},
		{name: "truncated child tag", data: "70 03 5A01AA 77 01 9F", wantErr: tlv.ErrTruncated, wantOffset: 7},
		{name: "error in second sibling", data: "70 03 5A01AA 77 02 9F02", wantErr: tlv.ErrTruncated, wantOffset: 7},
		{name: "template length too short", data: "770A9F2701809F360200019F2608AABBCCDDEEFF0011", wantErr: tlv.ErrTruncated, wantOffset: 11},
		{name: "error after padding inside constructed", data: "70 06 0000 5A 05 AABB", wantErr: tlv.ErrLengthOutOfRange, wantOffset: 4},
		{name: "FF is not padding", data: "5A01AA FFFF", wantErr: tlv.ErrTruncated, wantOffset: 3},
		{name: "error deep inside", data: "70 08 77 06 A5 04 5A 05 AA BB", wantErr: tlv.ErrLengthOutOfRange, wantOffset: 6},

		// HSM-53
		{name: "HSM-53 8-byte length overflows int", data: "5A 88 FABADABADABADA BA", wantErr: tlv.ErrUnsupportedLength},
		{name: "HSM-53 8-byte length of amount tag", data: "9F02 88 8000000000000000", wantErr: tlv.ErrUnsupportedLength},
		{name: "HSM-53 length bytes missing", data: "9F02 84 FF", wantErr: tlv.ErrTruncated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				got []tlv.TLV
				err error
			)
			require.NotPanics(t, func() { got, err = tlv.Decode(mustHex(t, tt.data)) })
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, got)

			var decodeErr *tlv.DecodeError
			require.ErrorAs(t, err, &decodeErr)
			assert.Equal(t, tt.wantOffset, decodeErr.Offset, "offset")
		})
	}
}

func TestDecodeEmptyInput(t *testing.T) {
	for name, data := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			got, err := tlv.Decode(data)
			require.NoError(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestDecodeSkipsZeroPadding(t *testing.T) {
	want := []tlv.TLV{
		{Tag: "5A", Value: []byte{0xAA}},
		{Tag: "70", TLVs: []tlv.TLV{{Tag: "9F02", Value: []byte{0x01}}}},
	}

	tests := map[string]string{
		"none":               "5A01AA 70 04 9F020101",
		"leading":            "0000 5A01AA 70 04 9F020101",
		"between":            "5A01AA 000000 70 04 9F020101",
		"trailing":           "5A01AA 70 04 9F020101 00",
		"inside constructed": "5A01AA 70 07 00 9F020101 0000",
		"everywhere":         "00 5A01AA 00 70 06 00 9F020101 00 00",
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tlv.Decode(mustHex(t, data))
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}

	t.Run("only padding", func(t *testing.T) {
		got, err := tlv.Decode(make([]byte, 32))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("00 inside a value is data", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "5A 03 000000"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{Tag: "5A", Value: []byte{0, 0, 0}}}, got)
	})
}

func TestDecodeConstructed(t *testing.T) {
	t.Run("nested", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "6F 0B 84 01 AA A5 06 BF0C 03 5A 01 BB"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{
			Tag: "6F",
			TLVs: []tlv.TLV{
				{Tag: "84", Value: []byte{0xAA}},
				{Tag: "A5", TLVs: []tlv.TLV{
					{Tag: "BF0C", TLVs: []tlv.TLV{{Tag: "5A", Value: []byte{0xBB}}}},
				}},
			},
		}}, got)
	})

	t.Run("empty constructed", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "70 00 5A 01 AA"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{Tag: "70"}, {Tag: "5A", Value: []byte{0xAA}}}, got)
	})

	t.Run("siblings after constructed", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "70 03 5A01AA 77 03 8A01BB 9F02 01 CC"))
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, []string{"70", "77", "9F02"}, []string{got[0].Tag, got[1].Tag, got[2].Tag})
	})

	t.Run("constructed bit in multi-byte tag", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "FF8101 03 5A01AA"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{Tag: "FF8101", TLVs: []tlv.TLV{{Tag: "5A", Value: []byte{0xAA}}}}}, got)
	})

	t.Run("primitive holding TLV bytes is not parsed", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "9F10 03 5A01AA"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{Tag: "9F10", Value: mustHex(t, "5A01AA")}}, got)
	})

	t.Run("primitive holding malformed TLV bytes is not an error", func(t *testing.T) {
		got, err := tlv.Decode(mustHex(t, "9F10 02 5A05"))
		require.NoError(t, err)
		assert.Equal(t, []tlv.TLV{{Tag: "9F10", Value: mustHex(t, "5A05")}}, got)
	})
}

// nested wraps inner in levels constructed E1 tags. It writes the bytes
// itself, because Encode refuses to nest deeper than MaxDepth.
func nested(levels int, inner []byte) []byte {
	data := inner
	for range levels {
		var header []byte
		switch n := len(data); {
		case n < 0x80:
			header = []byte{0xE1, byte(n)}
		case n <= 0xFF:
			header = []byte{0xE1, 0x81, byte(n)}
		default:
			header = []byte{0xE1, 0x82, byte(n >> 8), byte(n)}
		}
		data = append(header, data...)
	}

	return data
}

func TestDecodeMaxDepth(t *testing.T) {
	leaf := []byte{0x5A, 0x01, 0xAA}

	t.Run("at the limit", func(t *testing.T) {
		got, err := tlv.Decode(nested(tlv.MaxDepth, leaf))
		require.NoError(t, err)

		found, ok := tlv.FindFirstTag(got, "5A")
		require.True(t, ok)
		assert.Equal(t, []byte{0xAA}, found.Value)
	})

	t.Run("empty constructed at the limit", func(t *testing.T) {
		_, err := tlv.Decode(nested(tlv.MaxDepth, nil))
		require.NoError(t, err)
	})

	t.Run("one past the limit", func(t *testing.T) {
		_, err := tlv.Decode(nested(tlv.MaxDepth+1, leaf))
		require.ErrorIs(t, err, tlv.ErrMaxDepth)

		// The innermost E1 starts two bytes in per level.
		var decodeErr *tlv.DecodeError
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, 2*tlv.MaxDepth, decodeErr.Offset)
	})

	t.Run("empty constructed one past the limit", func(t *testing.T) {
		_, err := tlv.Decode(nested(tlv.MaxDepth+1, nil))
		require.ErrorIs(t, err, tlv.ErrMaxDepth)
	})

	t.Run("very deep input stops at the limit", func(t *testing.T) {
		data := nested(10_000, leaf)
		require.LessOrEqual(t, len(data), tlv.MaxInputSize)

		var err error
		require.NotPanics(t, func() { _, err = tlv.Decode(data) })
		require.ErrorIs(t, err, tlv.ErrMaxDepth)
	})

	t.Run("wide input at depth 1 is fine", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x5A, 0x01, 0xAA}, 10_000)
		got, err := tlv.Decode(data)
		require.NoError(t, err)
		assert.Len(t, got, 10_000)
	})
}

// When a length is wrong, the decoder reads part of a value as the next tag.
// Nothing it read may reach the error, because the value may be a PAN.
func TestDecodeErrorDoesNotLeakValues(t *testing.T) {
	const pan = "4761739001010119"

	tests := map[string]string{
		"well framed, then malformed": "5A08" + pan + "9F02 05 0000",
		"PAN length one short":        "5A07" + pan,
		"PAN length far too short":    "5A03" + pan,
		"PAN length one long":         "5A09" + pan,
		"PAN inside template":         "70 0A 5A07" + pan,
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tlv.Decode(mustHex(t, data))
			require.Error(t, err)
			assertTypedError(t, err)

			// The offset is the only number in the message, so no PAN
			// digits can appear in it, in hex or as a tag.
			assert.Regexp(t, `^decode BER-TLV at offset \d+: [a-z ]+$`, err.Error())
		})
	}
}

func TestDecodeErrorMessage(t *testing.T) {
	_, err := tlv.Decode(mustHex(t, "5A01AA 9F"))
	require.EqualError(t, err, "decode BER-TLV at offset 3: truncated input")
}

func TestDecodeInputSize(t *testing.T) {
	t.Run("at the limit", func(t *testing.T) {
		data := append(mustHex(t, "5A 82 FFFC"), make([]byte, tlv.MaxInputSize-4)...)
		require.Len(t, data, tlv.MaxInputSize)

		got, err := tlv.Decode(data)
		require.NoError(t, err)
		assert.Len(t, got[0].Value, tlv.MaxInputSize-4)
	})

	t.Run("one past the limit", func(t *testing.T) {
		got, err := tlv.Decode(make([]byte, tlv.MaxInputSize+1))
		require.ErrorIs(t, err, tlv.ErrInputTooLarge)
		assert.Nil(t, got)

		var decodeErr *tlv.DecodeError
		require.ErrorAs(t, err, &decodeErr)
		assert.Equal(t, 0, decodeErr.Offset)
	})
}

func TestDecodeEmptyValues(t *testing.T) {
	got, err := tlv.Decode(mustHex(t, "5A00 7000"))
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.NotNil(t, got[0].Value, "a primitive with no content has an empty, non-nil value")
	assert.Empty(t, got[0].Value)
	assert.Nil(t, got[0].TLVs)

	assert.Nil(t, got[1].Value, "a constructed tag keeps its content in TLVs")
	assert.Nil(t, got[1].TLVs)
}

func TestDecodeValueCannotOverwriteInput(t *testing.T) {
	data := mustHex(t, "5A 02 AABB 9F02 01 CC")
	original := bytes.Clone(data)

	got, err := tlv.Decode(data)
	require.NoError(t, err)

	pan := got[0].Value
	assert.Equal(t, 2, cap(pan))
	_ = append(pan, 0xFF, 0xFF, 0xFF)
	assert.Equal(t, original, data)
}

func TestFindFirstTag(t *testing.T) {
	decoded, err := tlv.Decode(mustHex(t,
		"70 0B 77 05 8A 01 01 5A 00 9F02 01 02"+ // 70{77{8A,5A},9F02}
			"A5 03 8A 01 03"+ // A5{8A}
			"9F27 01 04"+
			"5A 01 05"))
	require.NoError(t, err)

	tests := []struct {
		name      string
		tag       string
		wantValue []byte
		wantFound bool
	}{
		{name: "nested two deep", tag: "8A", wantValue: []byte{0x01}, wantFound: true},
		{name: "depth-first beats a later top-level match", tag: "5A", wantValue: []byte{}, wantFound: true},
		{name: "after a nested constructed sibling", tag: "9F02", wantValue: []byte{0x02}, wantFound: true},
		{name: "after two constructed tags", tag: "9F27", wantValue: []byte{0x04}, wantFound: true},
		{name: "lower case", tag: "9f27", wantValue: []byte{0x04}, wantFound: true},
		{name: "constructed tag itself", tag: "A5", wantFound: true},
		{name: "missing", tag: "9F26"},
		{name: "empty tag", tag: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tlv.FindFirstTag(decoded, tt.tag)
			require.Equal(t, tt.wantFound, ok)
			if tt.wantValue != nil {
				assert.Equal(t, tt.wantValue, got.Value)
			}
			if !ok {
				assert.Equal(t, tlv.TLV{}, got)
			}
		})
	}

	t.Run("nil list", func(t *testing.T) {
		_, ok := tlv.FindFirstTag(nil, "5A")
		assert.False(t, ok)
	})

	t.Run("constructed tag returns its children", func(t *testing.T) {
		got, ok := tlv.FindFirstTag(decoded, "77")
		require.True(t, ok)
		assert.Len(t, got.TLVs, 2)
	})
}

func TestFindFirstTagStopsAtMaxDepth(t *testing.T) {
	cycle := []tlv.TLV{{Tag: "70"}}
	cycle[0].TLVs = cycle

	var ok bool
	require.NotPanics(t, func() { _, ok = tlv.FindFirstTag(cycle, "5A") })
	assert.False(t, ok)

	// A tag at the deepest level Decode allows is still found.
	decoded, err := tlv.Decode(nested(tlv.MaxDepth, mustHex(t, "5A01AA")))
	require.NoError(t, err)
	_, ok = tlv.FindFirstTag(decoded, "5A")
	assert.True(t, ok)
}

// moov-io/bertlv returned from the first constructed tag's subtree even when
// the tag was not in it, so tags after a template were never found.
func TestFindFirstTagSearchesPastConstructedSiblings(t *testing.T) {
	decoded, err := tlv.Decode(mustHex(t, "E1 04 5F2A0108 9F02 06 000000000100"))
	require.NoError(t, err)

	got, ok := tlv.FindFirstTag(decoded, "9F02")
	require.True(t, ok)
	assert.Equal(t, mustHex(t, "000000000100"), got.Value)

	require.NoError(t, tlv.ValidateAmount(mustHex(t, "E1 04 5F2A0108 9F02 06 000000000100"), "100"))
}

func TestEncode(t *testing.T) {
	tests := []struct {
		name string
		tlvs []tlv.TLV
		want string
	}{
		{name: "nothing", tlvs: nil, want: ""},
		{name: "primitive", tlvs: []tlv.TLV{tlv.NewTag("5A", []byte{0xAA})}, want: "5A01AA"},
		{name: "empty value", tlvs: []tlv.TLV{tlv.NewTag("5A", nil)}, want: "5A00"},
		{name: "lower-case tag", tlvs: []tlv.TLV{tlv.NewTag("9f02", []byte{0x01})}, want: "9F020101"},
		{name: "three-byte tag", tlvs: []tlv.TLV{tlv.NewTag("DFF101", []byte{0x01})}, want: "DFF1010101"},
		{name: "four-byte tag", tlvs: []tlv.TLV{tlv.NewTag("DF818101", []byte{0x01})}, want: "DF8181010101"},
		{
			name: "composite",
			tlvs: []tlv.TLV{tlv.NewComposite("70",
				tlv.NewTag("5A", []byte{0xAA}),
				tlv.NewComposite("A5", tlv.NewTag("8A", []byte{0xBB})),
			)},
			want: "7008 5A01AA A503 8A01BB",
		},
		{name: "empty composite", tlvs: []tlv.TLV{tlv.NewComposite("70")}, want: "7000"},
		{name: "constructed tag with raw value", tlvs: []tlv.TLV{tlv.NewTag("70", mustHex(t, "5A01AA"))}, want: "7003 5A01AA"},
		{name: "children win over value", tlvs: []tlv.TLV{{Tag: "70", Value: []byte{0xFF}, TLVs: []tlv.TLV{tlv.NewTag("5A", nil)}}}, want: "7002 5A00"},
		{name: "several", tlvs: []tlv.TLV{tlv.NewTag("5A", []byte{1}), tlv.NewTag("8A", []byte{2})}, want: "5A0101 8A0102"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlv.Encode(tt.tlvs)
			require.NoError(t, err)
			assert.Equal(t, strings.ReplaceAll(tt.want, " ", ""), strings.ToUpper(hex.EncodeToString(got)))
		})
	}
}

func TestEncodeLengthIsMinimal(t *testing.T) {
	tests := []struct {
		valLen     int
		wantHeader string
	}{
		{0, "5A00"},
		{127, "5A7F"},
		{128, "5A8180"},
		{255, "5A81FF"},
		{256, "5A820100"},
		{tlv.MaxInputSize - 4, "5A82FFFC"},
	}

	for _, tt := range tests {
		t.Run(tt.wantHeader, func(t *testing.T) {
			got, err := tlv.Encode([]tlv.TLV{tlv.NewTag("5A", make([]byte, tt.valLen))})
			require.NoError(t, err)

			header := mustHex(t, tt.wantHeader)
			require.Len(t, got, len(header)+tt.valLen)
			assert.Equal(t, header, got[:len(header)])
		})
	}
}

func TestEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		tlvs    []tlv.TLV
		wantErr error
	}{
		{name: "empty tag", tlvs: []tlv.TLV{tlv.NewTag("", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "not hex", tlvs: []tlv.TLV{tlv.NewTag("ZZ", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "odd hex", tlvs: []tlv.TLV{tlv.NewTag("9F0", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "padding tag", tlvs: []tlv.TLV{tlv.NewTag("00", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "single-byte tag with extra byte", tlvs: []tlv.TLV{tlv.NewTag("5A01", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "multi-byte tag incomplete", tlvs: []tlv.TLV{tlv.NewTag("9F", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "last byte has bit 8 set", tlvs: []tlv.TLV{tlv.NewTag("9F81", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "middle byte lacks bit 8", tlvs: []tlv.TLV{tlv.NewTag("DF0101", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "five-byte tag", tlvs: []tlv.TLV{tlv.NewTag("DF81818101", nil)}, wantErr: tlv.ErrTagTooLong},
		{name: "primitive with children", tlvs: []tlv.TLV{tlv.NewComposite("5A", tlv.NewTag("8A", nil))}, wantErr: tlv.ErrInvalidTag},
		{name: "invalid nested tag", tlvs: []tlv.TLV{tlv.NewComposite("70", tlv.NewTag("9F", nil))}, wantErr: tlv.ErrInvalidTag},
		{name: "invalid later tag", tlvs: []tlv.TLV{tlv.NewTag("5A", nil), tlv.NewTag("XX", nil)}, wantErr: tlv.ErrInvalidTag},
		{name: "raw constructed value truncated", tlvs: []tlv.TLV{tlv.NewTag("70", []byte{0xFF})}, wantErr: tlv.ErrTruncated},
		{name: "raw constructed value overruns", tlvs: []tlv.TLV{tlv.NewTag("70", mustHex(t, "5A05AA"))}, wantErr: tlv.ErrLengthOutOfRange},
		{name: "raw constructed value indefinite", tlvs: []tlv.TLV{tlv.NewTag("70", mustHex(t, "E180"))}, wantErr: tlv.ErrUnsupportedLength},
		{name: "raw constructed value too deep", tlvs: []tlv.TLV{tlv.NewTag("70", nested(tlv.MaxDepth, nil))}, wantErr: tlv.ErrMaxDepth},
		{name: "raw value inside composite", tlvs: []tlv.TLV{tlv.NewComposite("70", tlv.NewTag("77", []byte{0x9F}))}, wantErr: tlv.ErrTruncated},
		{name: "output over the limit", tlvs: []tlv.TLV{tlv.NewTag("5A", make([]byte, tlv.MaxInputSize-3))}, wantErr: tlv.ErrInputTooLarge},
		{name: "outputs over the limit together", tlvs: []tlv.TLV{tlv.NewTag("5A", make([]byte, tlv.MaxInputSize/2)), tlv.NewTag("5A", make([]byte, tlv.MaxInputSize/2))}, wantErr: tlv.ErrInputTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlv.Encode(tt.tlvs)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, got)
		})
	}
}

func TestEncodeMaxDepth(t *testing.T) {
	build := func(levels int) []tlv.TLV {
		inner := []tlv.TLV{tlv.NewTag("5A", []byte{0xAA})}
		for range levels {
			inner = []tlv.TLV{tlv.NewComposite("E1", inner...)}
		}
		return inner
	}

	encoded, err := tlv.Encode(build(tlv.MaxDepth))
	require.NoError(t, err)
	_, err = tlv.Decode(encoded)
	require.NoError(t, err)

	_, err = tlv.Encode(build(tlv.MaxDepth + 1))
	require.ErrorIs(t, err, tlv.ErrMaxDepth)

	// Raw content counts towards the depth too: MaxDepth-1 nested levels
	// inside a raw E1 value make MaxDepth in all.
	_, err = tlv.Encode([]tlv.TLV{tlv.NewTag("E1", nested(tlv.MaxDepth-1, nil))})
	require.NoError(t, err)
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tlvs := []tlv.TLV{
		tlv.NewTag("5A", mustHex(t, "4111111111111111")),
		tlv.NewTag("5F34", []byte{0x01}),
		tlv.NewComposite("77",
			tlv.NewTag("9F27", []byte{0x80}),
			tlv.NewTag("9F10", bytes.Repeat([]byte{0x11}, 200)),
			tlv.NewComposite("BF0C", tlv.NewTag("DFF101", []byte("https://example.test"))),
		),
		tlv.NewTag("9F02", mustHex(t, "000000000100")),
	}

	encoded, err := tlv.Encode(tlvs)
	require.NoError(t, err)

	decoded, err := tlv.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, tlvs, decoded)
}

// Payloads in the shapes merchant-api and issuer-api receive, with test card
// data. Each must decode to the listed tags and values.
func TestDecodeRealPayloads(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		want   map[string]string // tag -> value hex, found via FindFirstTag
		padded bool              // re-encoding drops the padding
	}{
		{
			name: "SRED PAN and cryptogram",
			data: "5A0841111111111111119F2608A4EECDFD19B3A9F1",
			want: map[string]string{"5A": "4111111111111111", "9F26": "A4EECDFD19B3A9F1"},
		},
		{
			name: "SRED PAN, PSN and cryptogram",
			data: "5A0841111111111111115F3401019F2608A4EECDFD19B3A9F1",
			want: map[string]string{"5A": "4111111111111111", "5F34": "01", "9F26": "A4EECDFD19B3A9F1"},
		},
		{
			name: "SRED with CDOL1 data and proprietary URLs",
			data: "5A084111111111111111" +
				"DF3109000000000100084002" +
				"DFF1011E" + hex.EncodeToString([]byte("https://cardholder.example/pay")) +
				"DFF1021C" + hex.EncodeToString([]byte("https://merchant.example/pay")),
			want: map[string]string{
				"5A":     "4111111111111111",
				"DF31":   "000000000100084002",
				"DFF101": hex.EncodeToString([]byte("https://cardholder.example/pay")),
				"DFF102": hex.EncodeToString([]byte("https://merchant.example/pay")),
			},
		},
		{
			name: "GENERATE AC response format 2",
			data: "77149F2701809F360200019F2608AABBCCDDEEFF0011",
			want: map[string]string{"9F27": "80", "9F36": "0001", "9F26": "AABBCCDDEEFF0011"},
		},
		{
			name: "GENERATE AC response format 2 with IAD",
			data: "772C" +
				"9F2701 80" +
				"9F3602 0001" +
				"9F2608 AABBCCDDEEFF0011" +
				"9F1012 0110A00003220000000000000000000000FF" +
				"9F4B00",
			want: map[string]string{"9F27": "80", "9F10": "0110A00003220000000000000000000000FF", "9F4B": ""},
		},
		{
			name: "SELECT response FCI",
			data: "6F1B 8407A0000000031010 A510 500B5649534120435245444954 8701 01",
			want: map[string]string{"84": "A0000000031010", "50": hex.EncodeToString([]byte("VISA CREDIT")), "87": "01"},
		},
		{
			name: "READ RECORD with track 2 and long cardholder name",
			data: "70819D" +
				"5713 4111111111111111D29122011234567890123F" +
				"5F2081 80" + strings.Repeat("41", 128) +
				"5F3401 01",
			want: map[string]string{
				"57":   "4111111111111111D29122011234567890123F",
				"5F20": strings.Repeat("41", 128),
				"5F34": "01",
			},
		},
		{
			name: "issuer result with ARC, auth code, IAD and script",
			data: "8A023030" +
				"8906313233343536" +
				"910A1122334455667788 3030" +
				"7115 9F1804 00000001 860C 04DA9F5807 00 112233445566",
			want: map[string]string{
				"8A":   "3030",
				"89":   hex.EncodeToString([]byte("123456")),
				"91":   "11223344556677883030",
				"9F18": "00000001",
				"86":   "04DA9F580700112233445566",
			},
		},
		{
			name:   "amount with padding",
			data:   "00 9F0206000000000100 5F2A020840 00",
			want:   map[string]string{"9F02": "000000000100", "5F2A": "0840"},
			padded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := mustHex(t, tt.data)

			decoded, err := tlv.Decode(data)
			require.NoError(t, err)

			for tag, wantHex := range tt.want {
				got, ok := tlv.FindFirstTag(decoded, tag)
				require.True(t, ok, "tag %s", tag)
				assert.Equal(t, strings.ToUpper(wantHex), strings.ToUpper(hex.EncodeToString(got.Value)), "tag %s", tag)
			}

			reencoded, err := tlv.Encode(decoded)
			require.NoError(t, err)
			if !tt.padded {
				assert.Equal(t, data, reencoded, "canonical input re-encodes to the same bytes")
			}
			redecoded, err := tlv.Decode(reencoded)
			require.NoError(t, err)
			assert.Equal(t, decoded, redecoded)
		})
	}
}

// Every prefix of a valid payload either decodes or fails with a typed
// error; none panics.
func TestDecodeEveryTruncation(t *testing.T) {
	data := mustHex(t, "70819D"+
		"5713 4111111111111111D29122011234567890123F"+
		"5F2081 80"+strings.Repeat("41", 128)+
		"5F3401 01")

	for n := 1; n < len(data); n++ {
		var err error
		require.NotPanics(t, func() { _, err = tlv.Decode(data[:n]) }, "prefix %d", n)
		require.Error(t, err, "prefix %d", n)
		assertTypedError(t, err)
	}
}

// Flipping any single bit of a valid payload never panics, and any error is
// typed.
func TestDecodeEveryBitFlip(t *testing.T) {
	data := mustHex(t, "6F1B 8407A0000000031010 A510 500B5649534120435245444954 8701 01 9F0206000000000100")

	for i := range len(data) {
		for bit := range 8 {
			mutated := bytes.Clone(data)
			mutated[i] ^= 1 << bit

			var err error
			require.NotPanics(t, func() { _, err = tlv.Decode(mutated) }, "byte %d bit %d", i, bit)
			if err != nil {
				assertTypedError(t, err)
			}
		}
	}
}

func TestDecodeRandomPayloads(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 50_000 {
		payload := make([]byte, rng.IntN(256))
		for j := range payload {
			payload[j] = byte(rng.Uint32())
		}

		var err error
		require.NotPanics(t, func() { _, err = tlv.Decode(payload) }, "payload %X", payload)
		if err != nil {
			assertTypedError(t, err)
		}
	}
}

func assertTypedError(t *testing.T, err error) {
	t.Helper()

	var decodeErr *tlv.DecodeError
	require.ErrorAs(t, err, &decodeErr)

	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return
		}
	}
	t.Fatalf("error %v wraps no sentinel", err)
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"",
		"00",
		"5A0841111111111111119F2608A4EECDFD19B3A9F1",
		"77149F2701809F360200019F2608AABBCCDDEEFF0011",
		"6F1B8407A0000000031010A510500B56495341204352454449548701019F0206000000000100",
		"8A0230308906313233343536",
		"5A88FABADABADABADABA",
		"9F02888000000000000000",
		"9F0284FF",
		"E180",
		"5A84FFFFFFFF",
		"DF8181818101",
	} {
		f.Add(mustHex(f, seed))
	}
	f.Add(nested(tlv.MaxDepth, []byte{0x5A, 0x01, 0xAA}))

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := tlv.Decode(data)
		if err != nil {
			assertTypedError(t, err)
			return
		}

		// Whatever decodes must encode, and decode back to the same thing.
		encoded, err := tlv.Encode(decoded)
		require.NoError(t, err)
		require.LessOrEqual(t, len(encoded), len(data))

		again, err := tlv.Decode(encoded)
		require.NoError(t, err)
		require.Equal(t, decoded, again)
	})
}

// Whatever Encode writes, Decode must read back.
func FuzzEncode(f *testing.F) {
	f.Add("5A", mustHex(f, "4111111111111111"))
	f.Add("9f02", mustHex(f, "000000000100"))
	f.Add("70", mustHex(f, "5A01AA 77039F2700"))
	f.Add("70", mustHex(f, "00 5A8101AA 00"))
	f.Add("E1", mustHex(f, "E180"))
	f.Add("70", []byte{0xFF})
	f.Add("DFF101", []byte("https://cardholder.example/pay"))

	f.Fuzz(func(t *testing.T, tag string, value []byte) {
		encoded, err := tlv.Encode([]tlv.TLV{tlv.NewTag(tag, value)})
		if err != nil {
			require.Nil(t, encoded)
			return
		}

		decoded, err := tlv.Decode(encoded)
		require.NoError(t, err, "Decode rejected what Encode wrote: %X", encoded)
		require.Len(t, decoded, 1)
		require.True(t, strings.EqualFold(tag, decoded[0].Tag))

		again, err := tlv.Encode(decoded)
		require.NoError(t, err)
		redecoded, err := tlv.Decode(again)
		require.NoError(t, err)
		require.Equal(t, decoded, redecoded)
	})
}
