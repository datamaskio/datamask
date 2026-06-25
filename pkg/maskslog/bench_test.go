package maskslog

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func BenchmarkHandler(b *testing.B) {
	base := slog.NewJSONHandler(io.Discard, nil)
	h := NewHandler(base)
	logger := slog.New(h)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		logger.InfoContext(ctx, "test",
			"name", "Alice",
			"token", "ghp_"+strings.Repeat("a", 36),
		)
	}
}

func BenchmarkHandlerClean(b *testing.B) {
	base := slog.NewJSONHandler(io.Discard, nil)
	h := NewHandler(base)
	logger := slog.New(h)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		logger.InfoContext(ctx, "test", "user", "Alice", "action", "login")
	}
}

func BenchmarkHandlerBaseline(b *testing.B) {
	base := slog.NewJSONHandler(io.Discard, nil)
	logger := slog.New(base)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		logger.InfoContext(ctx, "test", "user", "Alice", "action", "login")
	}
}
