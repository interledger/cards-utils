package logging

import (
	"github.com/labstack/echo/v4"

	"github.com/interledger/cards-utils/redact"
)

// LogPanic is the LogErrorFunc for echo's Recover middleware. It logs the
// panic once, at error, with the stack of the panicking goroutine, and
// returns the error so the HTTP error handler answers 500.
//
// It adds no request data. The panic value goes through redact.Error, since
// it may quote a URL.
func LogPanic(c echo.Context, err error, stack []byte) error {
	log := FromContext(c.Request().Context())
	log.Error().
		Str("error", redact.Error(err)).
		Str("stack", string(stack)).
		Msg("panic_recovered")
	return err
}
