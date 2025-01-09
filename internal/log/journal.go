package log

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/coreos/go-systemd/v22/journal"
)

// JournalHandler is a custom slog.Handler for systemd journal.
type JournalHandler struct{}

// Handle handles a log record.
func (h *JournalHandler) Handle(ctx context.Context, record slog.Record) error {
	priority := mapPriority(record.Level)

	// Build message and fields
	message := record.Message
	fields := make(map[string]string)
	record.Attrs(func(a slog.Attr) bool {
		fields[a.Key] = fmt.Sprintf("%v", a.Value.Any())
		return true
	})

	// Send log entry to the journal
	return journal.Send(message, priority, fields)
}

// Enabled implements slog.Handler.
func (h *JournalHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= globalLevel.Level()
}

// WithAttrs implements slog.Handler.
func (h *JournalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

// WithGroup implements slog.Handler.
func (h *JournalHandler) WithGroup(name string) slog.Handler {
	return h
}

func mapPriority(level slog.Level) journal.Priority {
	if level <= slog.LevelDebug {
		return journal.PriDebug
	}
	if level <= slog.LevelInfo {
		return journal.PriInfo
	}
	if level <= slog.LevelWarn {
		return journal.PriWarning
	}
	if level <= slog.LevelError {
		return journal.PriErr
	}
	return journal.PriCrit
}
