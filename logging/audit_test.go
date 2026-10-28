package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/interledger/cards-utils/logging"
	"github.com/interledger/cards-utils/redact"
)

type auditedThing struct {
	ID         string
	Status     string
	City       string         `sensitive:"pii"`
	VatNumber  *string        `sensitive:"confidential"`
	BDK        []byte         `sensitive:"crypto_key"`
	PINBlock   []byte         `sensitive:"credential"`
	TLVData    []byte         `sensitive:"crypto_data"`
	Attributes map[string]any `sensitive:"dynamic"`
}

func TestAudit_CarriesRequestFieldsAndNoClassifiedValues(t *testing.T) {
	var logs bytes.Buffer
	base := zerolog.New(&logs).With().Str("request_id", "req-1").Logger()
	ctx := logging.WithLogger(context.Background(), base)

	vat := "SI12345678"
	thing := auditedThing{
		ID:         "thing-1",
		Status:     "ACTIVE",
		City:       "Ljubljana",
		VatNumber:  &vat,
		BDK:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
		PINBlock:   []byte{0x04, 0x12},
		TLVData:    []byte{0x9F, 0x26},
		Attributes: map[string]any{"email": "alice@example.com", "colour": "blue"},
	}

	logging.Audit(ctx).
		Str("thing_id", thing.ID).
		Object("thing", redact.AuditObject(thing)).
		Msg("thing_created")

	out := logs.String()
	for _, v := range []string{"Ljubljana", "SI1", "678", "alice", "blue"} {
		require.NotContains(t, out, v)
	}

	var event map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &event))
	require.Equal(t, "info", event["level"])
	require.Equal(t, true, event["audit"])
	require.Equal(t, "req-1", event["request_id"])
	require.Equal(t, "thing_created", event["message"])

	logged := event["thing"].(map[string]any)
	require.Equal(t, "thing-1", logged["ID"])
	require.Equal(t, "ACTIVE", logged["Status"])
	require.Equal(t, "[REDACTED]", logged["City"])
	require.Equal(t, "[REDACTED]", logged["VatNumber"])
	require.Equal(t, "[REDACTED 4B]", logged["BDK"])
	// Audit hides unknown dynamic keys too, not only the ones the key rules
	// match.
	require.Equal(t, map[string]any{"email": "[REDACTED]", "colour": "[REDACTED]"}, logged["Attributes"])
}
