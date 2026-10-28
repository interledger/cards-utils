package logging

import (
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

// RequestStartKey holds the request's start time in the echo context, so the
// error handler can report the latency of a failed request.
const RequestStartKey = "request_start"

// ZerologMiddleware attaches a request-scoped logger to the request context
// and logs each successful request once, at info. A failed request is logged
// by the HTTP error handler instead, so each request produces one line.
func ZerologMiddleware(base zerolog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			c.Set(RequestStartKey, start)
			req := c.Request()

			ctx := base.With().
				Str("request_id", c.Response().Header().Get(echo.HeaderXRequestID)).
				Str("method", req.Method).
				Str("path", c.Path()).
				Str("remote_ip", c.RealIP())

			// Present only when telemetry is on and the request was sampled.
			// Without a recording span the IDs are zero, so leave them off
			// rather than write a row of zeros.
			if sc := trace.SpanContextFromContext(req.Context()); sc.IsValid() {
				ctx = ctx.
					Str("trace_id", sc.TraceID().String()).
					Str("span_id", sc.SpanID().String())
			}

			log := ctx.Logger()

			c.SetRequest(req.WithContext(WithLogger(req.Context(), log)))

			err := next(c)
			if err == nil {
				log.Info().
					Int("status", c.Response().Status).
					Int64("bytes", c.Response().Size).
					Int64("latency_ms", time.Since(start).Milliseconds()).
					Msg("request_completed")
			}

			return err
		}
	}
}

// LatencyMS returns the milliseconds since the request started, or -1 when
// the start time is not in the echo context.
func LatencyMS(c echo.Context) int64 {
	start, ok := c.Get(RequestStartKey).(time.Time)
	if !ok {
		return -1
	}
	return time.Since(start).Milliseconds()
}
