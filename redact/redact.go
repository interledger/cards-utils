// Package redact produces loggable copies of API and domain values with
// sensitive fields masked or hidden, driven by `sensitive:"<class>"` struct
// tags. Classification lives in the OpenAPI spec (x-oapi-codegen-extra-tags)
// for generated types and directly on hand-written domain structs; see each
// service's docs/sensitive-data.md for the taxonomy and conventions.
//
// Never log a request/response/domain struct directly - always go through
// Redact or Object:
//
//	log.Info().Object("merchant", redact.Object(m)).Msg("merchant created")
package redact

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

// Classes accepted in `sensitive:"..."` struct tags. The taxonomy follows
// the ILF EMV Field Data v1.0 sensitivity classification key.
const (
	ClassPII          = "pii"          // identifies a person/account - masked
	ClassCryptoKey    = "crypto_key"   // key material - hidden
	ClassCryptoData   = "crypto_data"  // cryptograms, CSRs, TLV payloads - hidden
	ClassCredential   = "credential"   // tokens, passwords, PIN blocks - hidden
	ClassConfidential = "confidential" // tax/registration identifiers - masked
	ClassPCI          = "pci"          // reserved for PAN/track data - hidden
	ClassDynamic      = "dynamic"      // free-form map, redacted per key rules
)

// ValidClasses is consulted by the coverage lint to reject tag typos.
var ValidClasses = map[string]bool{
	ClassPII:          true,
	ClassCryptoKey:    true,
	ClassCryptoData:   true,
	ClassCredential:   true,
	ClassConfidential: true,
	ClassPCI:          true,
	ClassDynamic:      true,
}

// Redacted is the placeholder emitted for hidden values.
const Redacted = "[REDACTED]"

type action uint8

const (
	actClear action = iota
	actMask
	actHide
	actDynamic
)

// Profile selects how classes translate to redaction actions.
type Profile uint8

const (
	// ProfileApp is the default for application logs: identifiers are
	// masked, secrets are hidden, unclassified dynamic-map keys pass through.
	ProfileApp Profile = iota
	// ProfileAudit fails closed for long-lived audit records: every
	// classified field is hidden and unmatched dynamic-map keys are hidden.
	ProfileAudit
)

func (p Profile) actionFor(class string) action {
	switch class {
	case ClassPII, ClassConfidential:
		if p == ProfileAudit {
			return actHide
		}
		return actMask
	case ClassCryptoKey, ClassCryptoData, ClassCredential, ClassPCI:
		return actHide
	case ClassDynamic:
		return actDynamic
	default:
		// Unknown class: fail closed. The coverage lint rejects the typo,
		// but a stale binary must still not leak.
		return actHide
	}
}

// Redactable lets exotic types supply their own loggable form; the walker
// checks it before reflecting. Prefer struct tags - this is an escape hatch,
// not the pattern.
type Redactable interface {
	RedactedFields() map[string]any
}

// Redactor applies a Profile. The zero value is not usable; use Default or
// WithProfile.
type Redactor struct {
	profile Profile
	plans   *sync.Map // reflect.Type -> *typePlan
}

var (
	appRedactor   = &Redactor{profile: ProfileApp, plans: &sync.Map{}}
	auditRedactor = &Redactor{profile: ProfileAudit, plans: &sync.Map{}}
)

// Default returns the ProfileApp redactor used by the package-level helpers.
func Default() *Redactor { return appRedactor }

// WithProfile returns the shared redactor for the given profile.
func WithProfile(p Profile) *Redactor {
	if p == ProfileAudit {
		return auditRedactor
	}
	return appRedactor
}

// Redact returns a loggable deep copy of v using the default (app) profile:
// structs become map[string]any keyed by JSON field name, with tagged fields
// masked or hidden. v is never mutated.
func Redact(v any) any { return appRedactor.Redact(v) }

// Redact returns a loggable deep copy of v under the redactor's profile.
func (r *Redactor) Redact(v any) any {
	if v == nil {
		return nil
	}
	return r.walk(reflect.ValueOf(v), actClear, 0)
}

// maxDepth bounds recursion so cyclic values (e.g. accidental self-references)
// cannot hang the logger.
const maxDepth = 32

var timeType = reflect.TypeOf(time.Time{})

type fieldPlan struct {
	index []int
	name  string // JSON field name if present, else the Go field name
	act   action
}

type typePlan struct {
	fields []fieldPlan
}

func (r *Redactor) planFor(t reflect.Type) *typePlan {
	if p, ok := r.plans.Load(t); ok {
		return p.(*typePlan)
	}
	p := buildPlan(t, r.profile)
	actual, _ := r.plans.LoadOrStore(t, p)
	return actual.(*typePlan)
}

func buildPlan(t reflect.Type, profile Profile) *typePlan {
	p := &typePlan{fields: make([]fieldPlan, 0, t.NumField())}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, included := jsonFieldName(f)
		if !included {
			continue
		}
		act := actClear
		if class, ok := f.Tag.Lookup("sensitive"); ok {
			act = profile.actionFor(class)
		}
		p.fields = append(p.fields, fieldPlan{
			index: f.Index,
			name:  name,
			act:   act,
		})
	}
	return p
}

func jsonFieldName(f reflect.StructField) (string, bool) {
	jsonTag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name, true
	}

	jsonName, _, _ := strings.Cut(jsonTag, ",")
	if jsonName == "-" {
		return "", false
	}
	if jsonName == "" {
		return f.Name, true
	}
	return jsonName, true
}

func (r *Redactor) walk(v reflect.Value, act action, depth int) any {
	if depth > maxDepth {
		return Redacted
	}
	if !v.IsValid() {
		return nil
	}

	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil
	}

	if act == actClear && v.CanInterface() {
		if red, ok := v.Interface().(Redactable); ok {
			return red.RedactedFields()
		}
	}

	if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		return r.walk(v.Elem(), act, depth+1)
	}

	switch act {
	case actHide:
		return hidden(v)
	case actMask:
		return masked(v)
	case actDynamic:
		return r.redactDynamic(v)
	}

	// actClear: recurse structurally so nested tagged fields are still caught.
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		if t == timeType {
			return v.Interface()
		}
		plan := r.planFor(t)
		out := make(map[string]any, len(plan.fields))
		for _, f := range plan.fields {
			out[f.name] = r.walk(v.FieldByIndex(f.index), f.act, depth+1)
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Interface() // clear []byte passes through untouched
		}
		out := make([]any, v.Len())
		for i := range out {
			out[i] = r.walk(v.Index(i), actClear, depth+1)
		}
		return out
	case reflect.Array:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = r.walk(v.Index(i), actClear, depth+1)
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = r.walk(iter.Value(), actClear, depth+1)
		}
		return out
	default:
		return v.Interface()
	}
}

func hidden(v reflect.Value) any {
	if isBytes(v) {
		return fmt.Sprintf("[REDACTED %dB]", v.Len())
	}
	return Redacted
}

func masked(v reflect.Value) any {
	if isBytes(v) {
		return fmt.Sprintf("[REDACTED %dB]", v.Len())
	}
	if v.Kind() == reflect.String {
		return MaskString(v.String())
	}
	// Non-string maskable values (numbers, bools) carry no partial-reveal
	// value - blank them entirely.
	return "****"
}

func isBytes(v reflect.Value) bool {
	return v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8
}

// MaskString keeps the first and last three characters of values longer than
// eight characters ("SI12345678" -> "SI1****678") and blanks shorter ones.
func MaskString(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) > 8 {
		return string(runes[:3]) + "****" + string(runes[len(runes)-3:])
	}
	return "****"
}

// redactDynamic handles `sensitive:"dynamic"` fields: free-form maps (and
// generated types carrying additionalProperties) whose keys are only known at
// runtime. The value is serialized through its JSON form - which for
// oapi-codegen types includes AdditionalProperties - and every key is matched
// against the shared key-rule table.
func (r *Redactor) redactDynamic(v reflect.Value) any {
	raw, err := json.Marshal(v.Interface())
	if err != nil {
		return Redacted
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Redacted
	}
	return r.redactParsed(parsed, 0)
}
