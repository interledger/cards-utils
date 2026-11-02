package redact_test

import (
	"io"
	"testing"

	"github.com/rs/zerolog"

	"github.com/interledger/cards-utils/redact"
)

// authorizeResult mirrors issuer-api's authorization.AuthorizeResult, which
// is logged twice, redacted, on every card authorization.
type authorizeResult struct {
	RequestID       string
	AuthorizationId string
	Status          string
	ARC             string
	AuthCode        string
	ARPC            []byte `sensitive:"crypto_data"`
	ARQCValid       bool
	PINValid        *bool
}

func BenchmarkRedactStruct(b *testing.B) {
	r := authorizeResult{"req-123", "auth-456", "APPROVED", "00", "123456", []byte{1, 2, 3, 4, 5, 6, 7, 8}, true, ptr(true)}
	b.ReportAllocs()
	for b.Loop() {
		redact.Redact(&r)
	}
}

func BenchmarkObjectInfoAndAudit(b *testing.B) {
	log := zerolog.New(io.Discard)
	r := authorizeResult{"req-123", "auth-456", "APPROVED", "00", "123456", []byte{1, 2, 3, 4, 5, 6, 7, 8}, true, ptr(true)}
	b.ReportAllocs()
	for b.Loop() {
		log.Info().Object("result", redact.Object(&r)).Msg("card_auth_verified")
		log.Info().Bool("audit", true).Object("result", redact.AuditObject(&r)).Msg("card_auth_verified")
	}
}

func BenchmarkJSONBody(b *testing.B) {
	body := []byte(`{"legalName":"Test Merchant","countryCode":"SI","vatNumber":"SI12345678",` +
		`"registrationNumber":"REG-998877-X","address":{"street":"Main 1","city":"Ljubljana","postalCode":"1000"},` +
		`"locations":[{"id":"loc-1","name":"Shop","terminals":[{"serialNumber":"SN-1","model":"X1"}]}]}`)
	b.ReportAllocs()
	for b.Loop() {
		redact.JSON(body)
	}
}
