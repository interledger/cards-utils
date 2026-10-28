package redact

import "github.com/rs/zerolog"

// Object wraps v for structured zerolog logging with redaction applied:
//
//	log.Info().Object("merchant", redact.Object(m)).Msg("merchant created")
func Object(v any) zerolog.LogObjectMarshaler { return objectMarshaler{v: v, r: appRedactor} }

// AuditObject wraps v for an audit event, under ProfileAudit, which hides
// every classified field:
//
//	logging.Audit(ctx).Object("merchant", redact.AuditObject(m)).Msg("merchant_created")
func AuditObject(v any) zerolog.LogObjectMarshaler { return objectMarshaler{v: v, r: auditRedactor} }

// Object wraps v using the redactor's profile.
func (r *Redactor) Object(v any) zerolog.LogObjectMarshaler { return objectMarshaler{v: v, r: r} }

type objectMarshaler struct {
	v any
	r *Redactor
}

func (o objectMarshaler) MarshalZerologObject(e *zerolog.Event) {
	switch red := o.r.Redact(o.v).(type) {
	case map[string]any:
		e.Fields(red)
	default:
		// Scalars, slices and hidden values land under a stable key so the
		// call site stays uniform.
		e.Interface("value", red)
	}
}
