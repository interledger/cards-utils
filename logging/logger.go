package logging

import (
	"context"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

func Init(level string, env string) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	logger := zerolog.New(os.Stdout).
		Level(lvl).
		With().
		Timestamp().
		Str("env", env).
		Logger()

	return logger
}

func WithLogger(ctx context.Context, log zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, log)
}

func FromContext(ctx context.Context) zerolog.Logger {
	if log, ok := ctx.Value(loggerKey).(zerolog.Logger); ok {
		return log
	}

	// No logger in ctx: the request did not pass through ZerologMiddleware,
	// or the service imports a copy of this package (see the package doc).
	return zerolog.Nop()
}
