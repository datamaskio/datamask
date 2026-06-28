// Package maskslog provides a slog.Handler wrapper that automatically
// redacts sensitive data before it reaches the underlying handler.
//
// One-line adoption:
//
//	logger := slog.New(maskslog.NewHandler(slog.NewJSONHandler(os.Stdout, nil)))
package maskslog

import (
	"context"
	"log/slog"

	"github.com/datamaskio/datamask"
	"github.com/datamaskio/datamask/secret"
)

// Handler wraps a slog.Handler and redacts sensitive values in log
// attributes before passing them to the underlying handler.
type Handler struct {
	base         slog.Handler
	masker       *datamask.Masker
	redactStruct bool
	logger       *slog.Logger
}

// Option configures a Handler.
type Option func(*Handler)

// WithMasker sets the Masker instance used for struct redaction.
// When not set, a default Masker is created.
func WithMasker(m *datamask.Masker) Option {
	return func(h *Handler) {
		h.masker = m
	}
}

// WithRedactStructs enables full struct redaction for slog.Any values.
// When enabled, struct values passed via slog.Any are redacted using
// the Masker before being written.
func WithRedactStructs() Option {
	return func(h *Handler) {
		h.redactStruct = true
	}
}

// NewHandler creates a Handler that wraps base.
func NewHandler(base slog.Handler, opts ...Option) *Handler {
	h := &Handler{
		base:   base,
		masker: datamask.New(),
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Enabled reports whether the underlying handler is enabled for level.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle redacts sensitive attributes in r and passes the cleaned record
// to the underlying handler. The original record is not mutated.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	msg := r.Message
	if findings := secret.Detect(msg); len(findings) > 0 {
		msg = "[" + findings[0].Type + "]"
	}

	clean := slog.NewRecord(r.Time, r.Level, msg, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.base.Handle(ctx, clean)
}

// WithAttrs returns a new Handler with the given attrs pre-redacted.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		cleaned = append(cleaned, h.redactAttr(a))
	}
	return &Handler{
		base:         h.base.WithAttrs(cleaned),
		masker:       h.masker,
		redactStruct: h.redactStruct,
		logger:       h.logger,
	}
}

// WithGroup returns a new Handler with the given group.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		base:         h.base.WithGroup(name),
		masker:       h.masker,
		redactStruct: h.redactStruct,
		logger:       h.logger,
	}
}

// redactAttr returns a copy of a with sensitive values replaced.
func (h *Handler) redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		s := a.Value.String()
		findings := secret.Detect(s)
		if len(findings) > 0 {
			return slog.String(a.Key, "["+findings[0].Type+"]")
		}

	case slog.KindAny:
		v := a.Value.Any()

		// Scan struct/pointer values for secrets in their fields.
		findings := secret.DetectAll(v)
		for _, f := range findings {
			h.logger.Warn("datamask: secret detected in struct field",
				"field", f.Field,
				"secret_type", f.Type,
			)
		}
		if len(findings) > 0 {
			return slog.String(a.Key, "[SECRETS_DETECTED]")
		}

		if h.redactStruct {
			if redacted, err := h.masker.RedactAny(v); err == nil {
				return slog.Any(a.Key, redacted)
			}
		}

	case slog.KindGroup:
		// Recursively process each child attribute.
		attrs := a.Value.Group()
		kvs := make([]any, 0, len(attrs)*2)
		for _, child := range attrs {
			clean := h.redactAttr(child)
			kvs = append(kvs, clean.Key, clean.Value.Any())
		}
		return slog.Group(a.Key, kvs...)
	}

	return a
}
