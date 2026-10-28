package logging_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/interledger/cards-utils/logging"
)

func TestLogPanic_LogsOnceAtErrorAndReturnsTheError(t *testing.T) {
	var logs bytes.Buffer
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/v1/things?pan=4111111111111111", strings.NewReader(`{"pin":"1234"}`))
	req = req.WithContext(logging.WithLogger(req.Context(), zerolog.New(&logs)))
	c := e.NewContext(req, httptest.NewRecorder())

	panicErr := errors.New(`boom calling Get "https://ilp.example/alice"`)
	err := logging.LogPanic(c, panicErr, []byte("goroutine 1 [running]:\nmain.handler()"))

	require.Same(t, panicErr, err)
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], `"level":"error"`)
	require.Contains(t, lines[0], `"message":"panic_recovered"`)
	require.Contains(t, lines[0], `"stack":"goroutine 1 [running]:\nmain.handler()"`)
	require.Contains(t, lines[0], `[REDACTED]`)
	for _, v := range []string{"ilp.example", "4111111111111111", "1234"} {
		require.NotContains(t, lines[0], v)
	}
}
