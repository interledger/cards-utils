package redact

import (
	"encoding/json"
	"regexp"
)

// keyRules classify free-form keys - dynamic-map entries and raw JSON bodies -
// where struct tags cannot reach. First match wins; matching is deliberately
// substring-based so over-redaction is the failure mode, never leakage.
var keyRules = []struct {
	regex *regexp.Regexp
	act   action
}{
	{regexp.MustCompile(`(?i)(pin|token|secret|password|passphrase|credential|csr|payload|privatekey|apikey|cvv|cvc|pan$|^pan|track)`), actHide},
	{regexp.MustCompile(`(?i)(taxid|vat|registration|email|phone|address|city|postal|wallet|name|serial|iban|account)`), actMask},
}

func keyAction(key string) (action, bool) {
	for _, rule := range keyRules {
		if rule.regex.MatchString(key) {
			return rule.act, true
		}
	}
	return actClear, false
}

// JSON redacts a raw JSON document by key rules using the default (app)
// profile - for request/response body logging and audit writers that see
// bytes rather than typed structs. Unparseable input is replaced wholesale:
// a body that cannot be inspected must not be logged.
func JSON(raw []byte) []byte { return appRedactor.JSON(raw) }

// JSON redacts a raw JSON document under the redactor's profile.
func (r *Redactor) JSON(raw []byte) []byte {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return []byte(`"[REDACTED unparseable]"`)
	}
	out, err := json.Marshal(r.redactParsed(parsed, 0))
	if err != nil {
		return []byte(`"` + Redacted + `"`)
	}
	return out
}

// redactParsed walks a json.Unmarshal-shaped value (map[string]any, []any,
// scalars) applying key rules. Under ProfileAudit unmatched keys with scalar
// values are hidden rather than passed through.
func (r *Redactor) redactParsed(value any, depth int) any {
	if depth > maxDepth {
		return Redacted
	}
	switch val := value.(type) {
	case map[string]any:
		return r.redactParsedMap(val, depth)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = r.redactParsed(item, depth+1)
		}
		return out
	default:
		if r.profile == ProfileAudit {
			return Redacted
		}
		return value
	}
}

func (r *Redactor) redactParsedMap(val map[string]any, depth int) map[string]any {
	out := make(map[string]any, len(val))
	for k, item := range val {
		out[k] = r.redactParsedMapItem(k, item, depth)
	}
	return out
}

func (r *Redactor) redactParsedMapItem(key string, item any, depth int) any {
	act, matched := keyAction(key)
	if matched {
		if r.profile == ProfileAudit {
			act = actHide
		}
		return applyToParsed(act, item)
	}

	return r.redactParsed(item, depth+1)
}

func applyToParsed(act action, value any) any {
	if act == actHide {
		return Redacted
	}
	// actMask
	if s, ok := value.(string); ok {
		return MaskString(s)
	}
	return "****"
}
