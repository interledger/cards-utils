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

func TestZerologMiddlewareLogsACompletedRequestOnceAtInfo(t *testing.T) {
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

// A handler that answers with an error status itself and returns nil is
// logged at the level its status calls for.
func TestZerologMiddlewareLevelFollowsTheStatus(t *testing.T) {
	for _, tc := range []struct {
		status int
		level  string
	}{
		{http.StatusOK, "info"},
		{http.StatusFound, "info"},
		{http.StatusNotFound, "warn"},
		{http.StatusUnprocessableEntity, "warn"},
		{http.StatusInternalServerError, "error"},
		{http.StatusServiceUnavailable, "error"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			out, _ := serve(t, func(c echo.Context) error {
				return c.NoContent(tc.status)
			})

			require.Contains(t, out, `"level":"`+tc.level+`"`)
			require.Contains(t, out, `"message":"request_completed"`)
		})
	}
}

func TestZerologMiddlewareLeavesFailedRequestsToTheErrorHandler(t *testing.T) {
	out, latency := serve(t, func(echo.Context) error {
		return errors.New("boom")
	})

	require.NotContains(t, out, "request_completed")
	require.GreaterOrEqual(t, latency, int64(0))
}

func TestLatencyMSWithoutStartTime(t *testing.T) {
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())

	require.Equal(t, int64(-1), logging.LatencyMS(c))
}
