package redact_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/interledger/cards-utils/redact"
)

func ptr[T any](v T) *T { return &v }

// merchant is a stand-in for a hand-written domain struct: no json tags, so
// fields key by their Go names.
type merchant struct {
	ID                 string
	LegalName          string
	VatNumber          *string `sensitive:"confidential"`
	RegistrationNumber *string `sensitive:"confidential"`
	City               string  `sensitive:"pii"`
	CreatedAt          time.Time
}

// wrappedKeys stands in for a generated OpenAPI type: json tags drive the
// output key names and byte slices carry key material.
type wrappedKeys struct {
	Scheme  *string `json:"scheme"`
	Payload []byte  `json:"payload" sensitive:"crypto_key"`
	Token   string  `json:"token" sensitive:"credential"`
}

// submission carries a free-form dynamic map plus a declared field.
type submission struct {
	DefinitionToken string         `json:"definitionToken" sensitive:"credential"`
	Data            map[string]any `json:"data" sensitive:"dynamic"`
}

func TestRedactMasksConfidentialAndPII(t *testing.T) {
	m := &merchant{
		ID:                 "7c1f4f9a",
		LegalName:          "Acme Payments d.o.o.",
		VatNumber:          ptr("SI12345678"),
		RegistrationNumber: ptr("1234567000"),
		City:               "Ljubljana",
		CreatedAt:          time.Date(2026, 1, 31, 12, 34, 56, 0, time.UTC),
	}

	out, ok := redact.Redact(m).(map[string]any)
	require.True(t, ok, "struct should redact to a map")

	assert.Equal(t, "Acme Payments d.o.o.", out["LegalName"], "untagged fields pass through")
	assert.Equal(t, "SI1****678", out["VatNumber"])
	assert.Equal(t, "123****000", out["RegistrationNumber"])
	assert.Equal(t, "Lju****ana", out["City"])
	assert.Equal(t, m.CreatedAt, out["CreatedAt"], "time.Time passes through")
}

func TestRedactHidesKeyMaterial(t *testing.T) {
	wk := &wrappedKeys{
		Scheme:  ptr("TR-34"),
		Payload: []byte("super-secret-tr34-key-block"),
		Token:   "eyJhbGciOiJIUzI1NiJ9",
	}

	out := redact.Redact(wk).(map[string]any)
	assert.Equal(t, "TR-34", out["scheme"], "generated structs key by JSON name")
	assert.Equal(t, "[REDACTED 27B]", out["payload"], "key bytes reduce to length only")
	assert.Equal(t, redact.Redacted, out["token"], "credential strings hide")

	serialized, err := json.Marshal(out)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), "super-secret-tr34-key-block")
}

func TestRedactSlicesOfStructs(t *testing.T) {
	list := []merchant{
		{LegalName: "One", VatNumber: ptr("SI11111111")},
		{LegalName: "Two", VatNumber: ptr("SI22222222")},
	}

	out, ok := redact.Redact(list).([]any)
	require.True(t, ok)
	require.Len(t, out, 2)
	first := out[0].(map[string]any)
	assert.Equal(t, "SI1****111", first["VatNumber"])
}

func TestRedactDynamicMapAppliesKeyRules(t *testing.T) {
	sub := submission{
		DefinitionToken: "eyJhbGciOiJIUzI1NiJ9.secret-token-body",
		Data: map[string]any{
			"taxId":        "TAX123456789",
			"contactEmail": "me@interledger.org",
			"pinCode":      "1234",
			"country":      "US",
		},
	}

	out := redact.Redact(sub).(map[string]any)
	assert.Equal(t, redact.Redacted, out["definitionToken"], "credential class hides")

	data, ok := out["data"].(map[string]any)
	require.True(t, ok, "dynamic field should resolve through its JSON form")
	assert.Equal(t, "TAX****789", data["taxId"])
	assert.Equal(t, "me@****org", data["contactEmail"])
	assert.Equal(t, redact.Redacted, data["pinCode"])
	assert.Equal(t, "US", data["country"], "unmatched keys pass through in app profile")
}

func TestAuditProfileFailsClosed(t *testing.T) {
	m := &merchant{LegalName: "Acme", VatNumber: ptr("SI12345678")}
	out := redact.WithProfile(redact.ProfileAudit).Redact(m).(map[string]any)
	assert.Equal(t, redact.Redacted, out["VatNumber"], "audit hides instead of masking")

	sub := submission{Data: map[string]any{"country": "US"}}
	audit := redact.WithProfile(redact.ProfileAudit).Redact(sub).(map[string]any)
	data := audit["data"].(map[string]any)
	assert.Equal(t, redact.Redacted, data["country"], "audit hides unmatched dynamic keys")
}

func TestJSONRedactsRawBodies(t *testing.T) {
	raw := []byte(`{
		"legalName": "Acme Payments d.o.o.",
		"vatNumber": "SI12345678",
		"wrapped": {"payload": "AAECAwQF", "scheme": "TR-34"},
		"items": [{"walletAddress": "https://merchant.example/.well-known/pay"}]
	}`)

	out := redact.JSON(raw)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(out, &parsed))
	assert.Equal(t, "SI1****678", parsed["vatNumber"])
	assert.Equal(t, "Acm****.o.", parsed["legalName"], "name keys mask")
	wrapped := parsed["wrapped"].(map[string]any)
	assert.Equal(t, redact.Redacted, wrapped["payload"])
	item := parsed["items"].([]any)[0].(map[string]any)
	assert.NotContains(t, item["walletAddress"], "merchant.example")

	assert.Equal(t, `"[REDACTED unparseable]"`, string(redact.JSON([]byte("not json"))),
		"uninspectable bodies are dropped wholesale")
}

func TestZerologObjectGolden(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	m := &merchant{
		LegalName:          "Acme Payments d.o.o.",
		VatNumber:          ptr("SI12345678"),
		RegistrationNumber: ptr("1234567000"),
	}
	wk := &wrappedKeys{
		Scheme:  ptr("TR-34"),
		Payload: []byte("super-secret-tr34-key-block"),
	}

	logger.Info().
		Object("merchant", redact.Object(m)).
		Object("keys", redact.Object(wk)).
		Msg("golden")

	line := buf.String()
	assert.Contains(t, line, `"VatNumber":"SI1****678"`)
	assert.Contains(t, line, `"payload":"[REDACTED 27B]"`)
	assert.Contains(t, line, `"scheme":"TR-34"`)
	assert.NotContains(t, line, "SI12345678")
	assert.NotContains(t, line, "1234567000")
	assert.NotContains(t, line, "super-secret-tr34-key-block")
}

type selfRef struct {
	Name string
	Next *selfRef
}

func TestDepthCapOnCyclicValues(t *testing.T) {
	a := &selfRef{Name: "a"}
	a.Next = a // cycle

	done := make(chan any, 1)
	go func() { done <- redact.Redact(a) }()
	select {
	case v := <-done:
		assert.NotNil(t, v)
	case <-time.After(5 * time.Second):
		t.Fatal("redaction of cyclic value did not terminate")
	}
}

func TestMaskString(t *testing.T) {
	assert.Equal(t, "", redact.MaskString(""))
	assert.Equal(t, "****", redact.MaskString("short"))
	assert.Equal(t, "****", redact.MaskString("12345678"))
	assert.Equal(t, "SI1****678", redact.MaskString("SI12345678"))
}

func TestConcurrentRedactSharesPlanCache(t *testing.T) {
	m := &merchant{VatNumber: ptr("SI12345678")}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := redact.Redact(m).(map[string]any)
			if out["VatNumber"] != "SI1****678" {
				t.Error("unexpected redaction result under concurrency")
			}
		}()
	}
	wg.Wait()
}

func TestUnknownClassFailsClosed(t *testing.T) {
	type miscTagged struct {
		Field string `sensitive:"not-a-real-class"`
	}
	out := redact.Redact(miscTagged{Field: "value"}).(map[string]any)
	assert.Equal(t, redact.Redacted, out["Field"])
}

func TestRedactableEscapeHatch(t *testing.T) {
	out := redact.Redact(customType{secret: "raw"}).(map[string]any)
	assert.Equal(t, map[string]any{"custom": "form"}, out)
	assert.NotContains(t, strings.Join(keys(out), ","), "secret")
}

type customType struct{ secret string }

func (customType) RedactedFields() map[string]any { return map[string]any{"custom": "form"} }

type pointerCustomType struct{ secret string }

func (*pointerCustomType) RedactedFields() map[string]any { return map[string]any{"pointer": "form"} }

// The escape hatch applies wherever the value sits: behind a pointer, in an
// interface field, or in a slice, and for a pointer-receiver implementation.
func TestRedactableEscapeHatchThroughIndirection(t *testing.T) {
	type holder struct {
		Value     customType
		Ptr       *customType
		Any       any
		AnyPtr    any
		PtrRecv   *pointerCustomType
		AnyRecv   any
		Slice     []customType
		NotCustom any
	}
	out := redact.Redact(holder{
		Value:     customType{secret: "raw"},
		Ptr:       &customType{secret: "raw"},
		Any:       customType{secret: "raw"},
		AnyPtr:    &customType{secret: "raw"},
		PtrRecv:   &pointerCustomType{secret: "raw"},
		AnyRecv:   &pointerCustomType{secret: "raw"},
		Slice:     []customType{{secret: "raw"}},
		NotCustom: "plain",
	}).(map[string]any)

	custom := map[string]any{"custom": "form"}
	pointer := map[string]any{"pointer": "form"}
	assert.Equal(t, custom, out["Value"])
	assert.Equal(t, custom, out["Ptr"])
	assert.Equal(t, custom, out["Any"])
	assert.Equal(t, custom, out["AnyPtr"])
	assert.Equal(t, pointer, out["PtrRecv"])
	assert.Equal(t, pointer, out["AnyRecv"])
	assert.Equal(t, []any{custom}, out["Slice"])
	assert.Equal(t, "plain", out["NotCustom"])
}

// The escape hatch is not consulted for a field whose tag already redacts
// it.
func TestRedactableIgnoredOnTaggedField(t *testing.T) {
	type holder struct {
		Hidden customType `sensitive:"credential"`
	}
	out := redact.Redact(holder{Hidden: customType{secret: "raw"}}).(map[string]any)
	assert.Equal(t, redact.Redacted, out["Hidden"])
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestValidClassesRejectsTypos(t *testing.T) {
	assert.True(t, redact.ValidClasses[redact.ClassPII])
	assert.True(t, redact.ValidClasses[redact.ClassDynamic])
	assert.False(t, redact.ValidClasses["not-a-real-class"])
}
