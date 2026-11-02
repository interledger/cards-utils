package redact_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/interledger/cards-utils/redact"
)

func TestError(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   `failed to create incoming payment: failed to resolve wallet address: Get "merchant@ilf.org": unsupported protocol scheme ""`,
			want: `failed to create incoming payment: failed to resolve wallet address: Get "[REDACTED]": unsupported protocol scheme ""`,
		},
		{
			in:   `Post "https://cards-playground-ilp.interledger.tech/alice/incoming-payments": dial tcp: i/o timeout`,
			want: `Post "[REDACTED]": dial tcp: i/o timeout`,
		},
		{
			in:   `wallet https://cards-playground-ilp.interledger.tech/alice not found`,
			want: `wallet [REDACTED] not found`,
		},
		{
			in:   `SRED_DECRYPT: rpc error: code = InvalidArgument desc = HSM returned error 08 in field 04`,
			want: `SRED_DECRYPT: rpc error: code = InvalidArgument desc = HSM returned error 08 in field 04`,
		},
	}

	for _, tc := range cases {
		require.Equal(t, tc.want, redact.Error(errors.New(tc.in)))
	}
	require.Empty(t, redact.Error(nil))
}
