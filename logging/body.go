package logging

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/interledger/cards-utils/redact"
)

// MaxLoggedBodyBytes caps the request and response bodies BodyMiddleware
// logs. A larger body is not logged; the request still gets all of it.
const MaxLoggedBodyBytes = 16 << 10

// bodyOmitted stands in for a body over MaxLoggedBodyBytes. A truncated JSON
// document cannot be parsed, so it cannot be redacted either.
const bodyOmitted = `"[OMITTED: body over 16 KB]"`

// BodyMiddleware logs the JSON request and response bodies of each request
// as one debug event, http_bodies, after redact.JSON has masked or hidden
// their sensitive keys. It does nothing unless enabled (log.bodies) and the
// request logger is at debug. /health and /metrics are skipped.
//
// Register it after ZerologMiddleware, which puts the request logger in the
// context. A failed request is answered here, through c.Error, so its
// response body is logged too; the error handler then sees the response
// committed and does nothing on later calls.
func BodyMiddleware(enabled bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		if !enabled {
			return next
		}
		return func(c echo.Context) error {
			req := c.Request()
			log := FromContext(req.Context())
			if !debugEnabled(log) || skipBodyLogging(req.URL.Path) {
				return next(c)
			}

			var reqBody []byte
			reqOver := false
			if isJSON(req.Header.Get(echo.HeaderContentType)) && req.Body != nil && req.Body != http.NoBody {
				read, err := io.ReadAll(io.LimitReader(req.Body, MaxLoggedBodyBytes+1))
				// Hand downstream handlers the bytes read plus whatever is
				// left, so a body over the cap still arrives whole.
				req.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(read), req.Body), closer: req.Body}
				if err == nil {
					reqBody, reqOver = read, len(read) > MaxLoggedBodyBytes
				}
			}

			res := c.Response()
			capture := &captureWriter{ResponseWriter: res.Writer}
			res.Writer = capture

			err := next(c)
			if err != nil {
				c.Error(err)
			}
			res.Writer = capture.ResponseWriter

			event := log.Debug()
			logged := false
			if len(reqBody) > 0 {
				event = event.RawJSON("request_body", loggableBody(reqBody, reqOver))
				logged = true
			}
			if capture.buf.Len() > 0 && isJSON(res.Header().Get(echo.HeaderContentType)) {
				event = event.RawJSON("response_body", loggableBody(capture.buf.Bytes(), capture.over))
				logged = true
			}
			if logged {
				event.Msg("http_bodies")
			} else {
				event.Discard()
			}

			return err
		}
	}
}

func debugEnabled(log zerolog.Logger) bool {
	return log.GetLevel() <= zerolog.DebugLevel && zerolog.GlobalLevel() <= zerolog.DebugLevel
}

func skipBodyLogging(path string) bool {
	for _, p := range []string{"/health", "/metrics"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// isJSON reports whether a Content-Type is application/json or a +json type
// such as application/problem+json.
func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == echo.MIMEApplicationJSON || strings.HasSuffix(mediaType, "+json")
}

func loggableBody(body []byte, over bool) []byte {
	if over {
		return []byte(bodyOmitted)
	}
	return redact.JSON(body)
}

// replayBody serves the bytes BodyMiddleware read, then the rest of the
// original body, and closes the original.
type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b *replayBody) Close() error { return b.closer.Close() }

// captureWriter keeps a copy of up to MaxLoggedBodyBytes of the response.
type captureWriter struct {
	http.ResponseWriter
	buf  bytes.Buffer
	over bool
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if room := MaxLoggedBodyBytes - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.over = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.over = true
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the original writer.
func (w *captureWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
