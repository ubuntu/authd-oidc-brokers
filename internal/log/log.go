// Package log configures the logging utilities for the project.
package log

import (
	"fmt"
	"log/slog"

	"github.com/coreos/go-systemd/v22/journal"
)

var globalLevel = &slog.LevelVar{}

// InitHandler initializes the log handler.
func InitHandler() {
	// Use the journal handler if stderr is connected to the journal
	isJournalStream, err := journal.StderrIsJournalStream()
	if err != nil {
		slog.Warn(fmt.Sprintf("Error checking if stderr is connected to the journal: %v", err))
	}

	if isJournalStream {
		slog.SetDefault(slog.New(&JournalHandler{}))
	} else {
		slog.SetLogLoggerLevel(globalLevel.Level())
	}
}

// SetLevel change global handler log level.
func SetLevel(l slog.Level) {
	globalLevel.Set(l)
	slog.SetLogLoggerLevel(l)
}
