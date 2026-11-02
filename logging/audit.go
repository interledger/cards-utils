package logging

import (
	"context"

	"github.com/rs/zerolog"
)

// Audit starts an audit event: an info event marked audit=true, carrying the
// request-scoped fields of the logger in ctx. Emit one for each business
// state change and each authorization outcome, and log any object on it
// through redact.AuditObject, which hides every classified field:
//
//	logging.Audit(ctx).
//		Str("merchant_id", m.ID).
//		Object("merchant", redact.AuditObject(m)).
//		Msg("merchant_created")
func Audit(ctx context.Context) *zerolog.Event {
	log := FromContext(ctx)
	return log.Info().Bool("audit", true)
}
