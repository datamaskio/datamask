package maskslog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/datamaskio/datamask/pkg/datamask"
)

func TestHandlerPassesThroughCleanLogs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	logger.Info("hello", "user", "Alice")

	if !strings.Contains(buf.String(), "Alice") {
		t.Errorf("clean log should pass through unchanged, got: %s", buf.String())
	}
}

func TestHandlerRedactsSecretInAttr(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	token := "ghp_" + strings.Repeat("a", 36)
	logger.Info("auth", "token", token)

	output := buf.String()
	if strings.Contains(output, token) {
		t.Errorf("secret should be redacted, got: %s", output)
	}
	if !strings.Contains(output, "[GitHubPAT]") {
		t.Errorf("expected [GITHUBPAT] placeholder, got: %s", output)
	}
}

func TestHandlerRedactsAWSKey(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	logger.Info("config", "aws_key", "AKIAIOSFODNN7EXAMPLE")

	output := buf.String()
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key should be redacted")
	}
	if !strings.Contains(output, "[AWSKey]") {
		t.Errorf("expected [AWSKEY] placeholder, got: %s", output)
	}
}

func TestHandlerRedactsOpenAIKey(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	key := "sk-" + strings.Repeat("b", 48)
	logger.Info("llm", "api_key", key)

	output := buf.String()
	if strings.Contains(output, key) {
		t.Error("OpenAI key should be redacted")
	}
	if !strings.Contains(output, "[OpenAIKey]") {
		t.Errorf("expected [OPENAI_API_KEY] placeholder, got: %s", output)
	}
}

func TestHandlerPreservesRecordFields(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	logger.Info("test", "key", "value")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["msg"] != "test" {
		t.Errorf("msg = %v, want test", m["msg"])
	}
	if m["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", m["level"])
	}
	if m["key"] != "value" {
		t.Errorf("key = %v, want value", m["key"])
	}
	if m["time"] == nil {
		t.Error("time field missing")
	}
}

func TestHandlerMultipleAttrs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	logger.Info("multi",
		"name", "Alice",
		"token", "ghp_"+strings.Repeat("a", 36),
		"clean", "value",
	)

	output := buf.String()
	if !strings.Contains(output, "Alice") {
		t.Error("clean attr should pass through")
	}
	if !strings.Contains(output, "value") {
		t.Error("clean attr should pass through")
	}
	if strings.Contains(output, "ghp_") {
		t.Error("secret should be redacted")
	}
}

func TestHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)

	// Pre-set a secret attr via WithAttrs.
	logger := slog.New(h.WithAttrs([]slog.Attr{
		slog.String("token", "ghp_"+strings.Repeat("a", 36)),
	}))

	logger.Info("test", "extra", "data")

	output := buf.String()
	if strings.Contains(output, "ghp_") {
		t.Error("WithAttrs secret should be redacted")
	}
}

func TestHandlerWithGroup(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h.WithGroup("db"))

	logger.Info("query", "sql", "SELECT * FROM users")

	output := buf.String()
	if !strings.Contains(output, "db") {
		t.Errorf("group name should appear in output: %s", output)
	}
}

func TestHandlerEnabled(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	h := NewHandler(base)

	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error level should be enabled")
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info level should be disabled when base is Error+")
	}
}

func TestHandlerNoFalsePositive(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(base)
	logger := slog.New(h)

	// Normal-looking values should not be flagged.
	logger.Info("user",
		"email", "alice@example.com",
		"name", "Alice Johnson",
		"id", "user-12345",
	)

	output := buf.String()
	if strings.Contains(output, "[") && strings.Contains(output, "]") {
		t.Errorf("normal values should not be redacted: %s", output)
	}
}

func TestHandlerWithRedactStructs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	m := datamask.New()
	h := NewHandler(base, WithMasker(m), WithRedactStructs())
	logger := slog.New(h)

	type User struct {
		Name  string
		Email string `mask:"email"`
	}
	user := User{Name: "Alice", Email: "alice@example.com"}

	logger.Info("user", slog.Any("user", user))

	output := buf.String()
	if strings.Contains(output, "alice@example.com") {
		t.Error("struct Email should be redacted")
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output: %s", output)
	}
}

func TestHandlerWithSharedMasker(t *testing.T) {
	// Sharing a Masker between the slog handler and direct Redact calls
	// should use the same cache.
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	m := datamask.New()
	h := NewHandler(base, WithMasker(m))
	logger := slog.New(h)

	logger.Info("test", "token", "ghp_"+strings.Repeat("a", 36))

	// Direct call with the same masker.
	type Data struct {
		Secret string `mask:"secret"`
	}
	d := Data{Secret: "sensitive"}
	redacted, err := datamask.Redact(m, d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if redacted.Secret != "[REDACTED]" {
		t.Errorf("shared masker: Secret = %q, want [REDACTED]", redacted.Secret)
	}
}
