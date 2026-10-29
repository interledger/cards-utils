package redact

import (
	"testing"
)

// keyCorpus covers every key word in each position and case, near misses,
// and keys keyAction hands to the regexes.
var keyCorpus = []string{
	"", "id", "status", "amount", "createdAt",
	"pin", "PIN", "pinBlock", "newPin", "spinner", "token", "accessToken", "secret", "clientSecret",
	"password", "passphrase", "credential", "csr", "payload", "privateKey", "private_key", "apiKey", "API_KEY",
	"cvv", "cvc", "CVC2", "track", "track2Data",
	"pan", "PAN", "panSequence", "maskedPan", "company", "panel", "expand", "span", "japan",
	"taxId", "tax_id", "vat", "vatNumber", "registrationNumber", "email", "phone", "address",
	"city", "postalCode", "walletAddress", "name", "legalName", "serialNumber", "iban", "accountId",
	"descriptionText", "x-request-id",
	// Non-ASCII: the Kelvin sign folds to k and the long s to s under (?i).
	"ﬁle", "toKen", "ſecret", "naïve", "名前", "émail",
	// Longer than keyAction's stack buffer.
	"aVeryLongFieldNameThatGoesOnAndOnWellPastSixtyFourBytesAndEndsWithPan",
	"aVeryLongFieldNameThatGoesOnAndOnWellPastSixtyFourBytesWithNothingInIt",
}

func TestKeyWordsMatchKeyRules(t *testing.T) {
	for _, key := range keyCorpus {
		gotAct, gotOK := keyAction(key)
		wantAct, wantOK := regexKeyAction(key)
		if gotAct != wantAct || gotOK != wantOK {
			t.Errorf("keyAction(%q) = %v, %v; keyRules give %v, %v", key, gotAct, gotOK, wantAct, wantOK)
		}
	}
}

func FuzzKeyWordsMatchKeyRules(f *testing.F) {
	for _, key := range keyCorpus {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		gotAct, gotOK := keyAction(key)
		wantAct, wantOK := regexKeyAction(key)
		if gotAct != wantAct || gotOK != wantOK {
			t.Errorf("keyAction(%q) = %v, %v; keyRules give %v, %v", key, gotAct, gotOK, wantAct, wantOK)
		}
	})
}

func BenchmarkKeyAction(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		for _, key := range keyCorpus {
			keyAction(key)
		}
	}
}

func BenchmarkRegexKeyAction(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		for _, key := range keyCorpus {
			regexKeyAction(key)
		}
	}
}
