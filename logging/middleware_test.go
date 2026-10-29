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

func serve(t *testing.T, handler echo.HandlerFunc) (string, int64) {
	t.Helper()

	var logs bytes.Buffer
	e := echo.New()
	var latency int64
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		latency = logging.LatencyMS(c)
		_ = c.NoContent(http.StatusInternalServerError)
	}
	e.Use(logging.ZerologMiddleware(zerolog.New(&logs)))
	e.GET("/things/:id", handler)

	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things/1", nil))
	return logs.String(), latency
}

func TestZerologMiddleware_LogsACompletedRequestOnceAtInfo(t *testing.T) {
	out, _ := serve(t, func(c echo.Context) error {
		log := logging.FromContext(c.Request().Context())
		log.Debug().Msg("inside_handler")
		return c.String(http.StatusCreated, "ok")
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)
	// The handler's logger carries the request fields.
	require.Contains(t, lines[0], `"path":"/things/:id"`)
	require.Contains(t, lines[0], `"message":"inside_handler"`)
	require.Contains(t, lines[1], `"level":"info"`)
	require.Contains(t, lines[1], `"status":201`)
	require.Contains(t, lines[1], `"latency_ms":`)
	require.Contains(t, lines[1], `"message":"request_completed"`)
}

func TestZerologMiddleware_LeavesFailedRequestsToTheErrorHandler(t *testing.T) {
	out, latency := serve(t, func(echo.Context) error {
		return errors.New("boom")
	})

	require.NotContains(t, out, "request_completed")
	require.GreaterOrEqual(t, latency, int64(0))
}

func TestLatencyMS_WithoutStartTime(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())

	require.Equal(t, int64(-1), logging.LatencyMS(c))
}
