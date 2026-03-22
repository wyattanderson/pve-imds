// Package logging initialises the shared slog logger for pve-imds.
package logging

import (
	"log/slog"
	"os"
	"strings"

	"github.com/coreos/go-systemd/v22/journal"
	slogjournal "github.com/systemd/slog-journal"
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

	var h slog.Handler
	if isJournal, _ := journal.StderrIsJournalStream(); isJournal {
		jh, err := slogjournal.NewHandler(&slogjournal.Options{
			Level: l,
			ReplaceGroup: func(k string) string {
				return strings.ReplaceAll(strings.ToUpper(k), "-", "_")
			},
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				a.Key = strings.ReplaceAll(strings.ToUpper(a.Key), "-", "_")
				return a
			},
		})
		if err == nil {
			h = jh
		}
	}
	if h == nil {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	}

	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}
