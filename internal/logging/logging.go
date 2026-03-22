// Package logging initialises the shared slog logger for pve-imds.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New creates and sets a global slog logger at the given level string.
// Level must be one of: debug, info, warn, error (case-insensitive).
// Defaults to info if the string is unrecognised.
func New(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}

	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
