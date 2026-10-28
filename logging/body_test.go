package logging_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/interledger/cards-utils/logging"
)

const sensitiveRequest = `{"terminalId":"t-1","pinBlock":"0412AC89FFFFFFFF","walletAddress":"https://ilp.example/alice","vatNumber":"SI12345678","amount":100}`

const sensitiveResponse = `{"id":"m-1","accessToken":"tok-secret-value","email":"alice@example.com","status":"ACTIVE"}`

var sensitiveValues = []string{"0412AC89FFFFFFFF", "https://ilp.example/alice", "SI12345678", "tok-secret-value", "alice@example.com"}

// serveBodies runs one request through ZerologMiddleware and BodyMiddleware
// and returns the logs and what the handler read from the request body.
func serveBodies(t *testing.T, enabled bool, level zerolog.Level, path, body string, handler echo.HandlerFunc) (string, string) {
	t.Helper()

	var logs bytes.Buffer
	var seen string
	e := echo.New()
	e.Use(logging.ZerologMiddleware(zerolog.New(&logs).Level(level)))
	e.Use(logging.BodyMiddleware(enabled))
	e.Any(path, func(c echo.Context) error {
		read, err := io.ReadAll(c.Request().Body)
		require.NoError(t, err)
		seen = string(read)
		return handler(c)
	})

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, "application/json; charset=utf-8")
	e.ServeHTTP(httptest.NewRecorder(), req)
	return logs.String(), seen
}

func respondSensitive(c echo.Context) error {
	return c.JSONBlob(http.StatusOK, []byte(sensitiveResponse))
}

func bodiesEvent(t *testing.T, logs string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		if event["message"] == "http_bodies" {
			return event
		}
	}
	t.Fatalf("no http_bodies event in:\n%s", logs)
	return nil
}

func TestBodyMiddleware_LogsRedactedBodies(t *testing.T) {
	logs, seen := serveBodies(t, true, zerolog.DebugLevel, "/v1/things", sensitiveRequest, respondSensitive)

	require.Equal(t, sensitiveRequest, seen, "the handler must still read the whole body")
	for _, v := range sensitiveValues {
		require.NotContains(t, logs, v)
	}

	event := bodiesEvent(t, logs)
	require.Equal(t, "debug", event["level"])
	require.Equal(t, "/v1/things", event["path"])

	reqBody := event["request_body"].(map[string]any)
	require.Equal(t, "[REDACTED]", reqBody["pinBlock"])
	require.Equal(t, "SI1****678", reqBody["vatNumber"])
	require.Equal(t, "t-1", reqBody["terminalId"])
	require.EqualValues(t, 100, reqBody["amount"])

	resBody := event["response_body"].(map[string]any)
	require.Equal(t, "[REDACTED]", resBody["accessToken"])
	require.Equal(t, "ACTIVE", resBody["status"])
}

func TestBodyMiddleware_LogsTheErrorResponse(t *testing.T) {
	var logs bytes.Buffer
	e := echo.New()
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		_ = c.JSON(http.StatusBadRequest, map[string]string{"detail": "bad pin", "pin": "1234"})
	}
	e.Use(logging.ZerologMiddleware(zerolog.New(&logs).Level(zerolog.DebugLevel)))
	e.Use(logging.BodyMiddleware(true))
	e.POST("/v1/things", func(echo.Context) error { return echo.ErrBadRequest })

	req := httptest.NewRequest(http.MethodPost, "/v1/things", strings.NewReader(sensitiveRequest))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	resBody := bodiesEvent(t, logs.String())["response_body"].(map[string]any)
	require.Equal(t, "[REDACTED]", resBody["pin"])
	require.Equal(t, "bad pin", resBody["detail"])
	require.NotContains(t, logs.String(), "1234")
}

func TestBodyMiddleware_IsANoOpWhenDisabled(t *testing.T) {
	logs, seen := serveBodies(t, false, zerolog.DebugLevel, "/v1/things", sensitiveRequest, respondSensitive)

	require.Equal(t, sensitiveRequest, seen)
	require.NotContains(t, logs, "http_bodies")
	require.NotContains(t, logs, "request_body")
}

func TestBodyMiddleware_IsANoOpAboveDebug(t *testing.T) {
	logs, _ := serveBodies(t, true, zerolog.InfoLevel, "/v1/things", sensitiveRequest, respondSensitive)

	require.NotContains(t, logs, "http_bodies")
}

func TestBodyMiddleware_SkipsHealthAndMetrics(t *testing.T) {
	for _, path := range []string{"/health", "/metrics"} {
		logs, _ := serveBodies(t, true, zerolog.DebugLevel, path, sensitiveRequest, respondSensitive)
		require.NotContains(t, logs, "http_bodies", path)
	}
}

func TestBodyMiddleware_OmitsABodyOverTheCap(t *testing.T) {
	big := `{"note":"` + strings.Repeat("a", logging.MaxLoggedBodyBytes) + `","pin":"1234"}`

	logs, seen := serveBodies(t, true, zerolog.DebugLevel, "/v1/things", big, respondSensitive)

	require.Equal(t, big, seen, "the handler must still read the whole body")
	require.NotContains(t, logs, "1234")
	require.Contains(t, bodiesEvent(t, logs)["request_body"], "OMITTED")
}

func TestBodyMiddleware_IgnoresNonJSON(t *testing.T) {
	var logs bytes.Buffer
	e := echo.New()
	e.Use(logging.ZerologMiddleware(zerolog.New(&logs).Level(zerolog.DebugLevel)))
	e.Use(logging.BodyMiddleware(true))
	e.POST("/upload", func(c echo.Context) error { return c.String(http.StatusOK, "pin=1234") })

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("pin=1234"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e.ServeHTTP(httptest.NewRecorder(), req)

	require.NotContains(t, logs.String(), "http_bodies")
	require.NotContains(t, logs.String(), "1234")
}
