// Package logging sets up a service's zerolog logger and carries a
// request-scoped logger in the context. Use FromContext to log from code
// that handles a request.
//
// Every service must use this package, not a copy: the request logger is
// stored under this package's context key, and FromContext on a copy finds
// nothing and returns a Nop logger.
//
// # Levels
//
//   - Error: a request failed with a 5xx status, or a startup or shutdown
//     step failed. Someone needs to look.
//   - Warn: a request failed with a 4xx status, or the service runs in a
//     setup that works but is risky, such as plaintext to the HSM adapter
//     outside dev.
//   - Info: one line per completed request, and each business state change,
//     such as an entity written, a key generated or imported, or a card
//     authorization completed. Startup and shutdown.
//   - Debug: the steps inside a request, such as each HSM adapter call and
//     each Open Payments call.
//
// # Middleware
//
// Register the middleware in this order, after echo's RequestID and the
// otelecho middleware:
//
//	e.Use(logging.ZerologMiddleware(logger))
//	e.Use(logging.BodyMiddleware(cfg.Log.Bodies))
//	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
//		DisableStackAll:     true,
//		DisableErrorHandler: true,
//		LogErrorFunc:        logging.LogPanic,
//	}))
//
// ZerologMiddleware logs each successful request once, as request_completed.
//
// # Failures are logged once
//
// A failed request is logged by the service's HTTP error handler, with the
// wrapped error that names the failed step. Code that returns an error does
// not log it as well. The handler logs the error the response was mapped
// from, after redact.Error has redacted its URLs, and a failed_step field
// when the error carries one. LatencyMS gives it the request's latency.
//
// A panic in a handler is logged once, at error, as panic_recovered with
// the stack of the panicking goroutine and no request data (see LogPanic).
// The error handler then answers 500.
//
// # Structs go through redact
//
// Never log a struct, map or slice with .Interface, .Any, .Fields or a bare
// .Object. Log it through redact.Object, which masks or hides each field by
// its `sensitive:"<class>"` tag:
//
//	log.Info().Str("merchant_id", m.ID).Object("merchant", redact.Object(m)).Msg("merchant_created")
//
// Keep logging IDs and KCVs as their own fields next to the object, so a
// line can be searched without parsing the object. When a struct gains a
// field that holds sensitive data, tag it.
//
// Each service enforces this with redactcheck.LogCalls, which parses its
// non-test, non-generated Go files and fails on a value-logging zerolog call
// whose value is not a redact.* call, and redactcheck.TagCoverage, which
// fails on a suspicious field name with no tag. Justified exceptions go in
// the service's allowlists, with the reason.
//
// # Audit events
//
// Each business state change and each authorization outcome also emits an
// audit event: Audit(ctx) starts an info event with audit=true and the
// request-scoped fields. Objects on an audit event go through
// redact.AuditObject, which hides every classified field, and every key of
// a dynamic map, rather than masking them:
//
//	logging.Audit(ctx).
//		Str("merchant_id", m.ID).
//		Object("merchant", redact.AuditObject(m)).
//		Msg("merchant_created")
//
// The audit event uses the same message as the info line it follows.
//
// # Request and response bodies
//
// With the service's log.bodies set (default false) and the logger at
// debug, BodyMiddleware logs the application/json request and response
// bodies of each request as one debug event, http_bodies, with request_body
// and response_body fields. Each body goes through redact.JSON, which masks
// or hides values by key name. A body over MaxLoggedBodyBytes (16 KB) is not
// logged, and /health and /metrics are skipped. Keep log.bodies off in
// production.
//
// # Never log
//
// PANs, PIN blocks, key material (BDK, PWK, ZMK, IPEK), SRED or EMV TLV data,
// wallet addresses, webhook secrets, or any other secret. IDs and Key Check
// Values (KCVs) are safe: a KCV identifies a key without revealing it.
package logging
