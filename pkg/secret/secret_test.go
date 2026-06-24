package secret

import (
	"strings"
	"testing"
)

func TestDetectGitHubPAT(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	findings := Detect(token)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "GitHubPAT" {
		t.Errorf("Type = %q, want GitHubPAT", f.Type)
	}
	if f.Field != "" {
		t.Errorf("Field = %q, want empty for Detect", f.Field)
	}
	if f.Position != 0 {
		t.Errorf("Position = %d, want 0", f.Position)
	}
	if f.Value != "ghp_..." {
		t.Errorf("Value = %q, want ghp_...", f.Value)
	}
}

func TestDetectNoSecret(t *testing.T) {
	findings := Detect("hello world, nothing here")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestDetectEmpty(t *testing.T) {
	findings := Detect("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty string, got %d", len(findings))
	}
}

func TestDetectOpenAIKey(t *testing.T) {
	key := "sk-" + strings.Repeat("b", 48)
	findings := Detect(key)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "OpenAIKey" {
		t.Errorf("Type = %q, want OpenAIKey", findings[0].Type)
	}
	if findings[0].Value != "sk-b..." {
		t.Errorf("Value = %q, want sk-b... (first 4 chars)", findings[0].Value)
	}
}

func TestDetectAWSKey(t *testing.T) {
	findings := Detect("AKIAIOSFODNN7EXAMPLE")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "AWSKey" {
		t.Errorf("Type = %q, want AWSKey", findings[0].Type)
	}
}

func TestDetectJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlGMvF0K0mR0"
	findings := Detect(jwt)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "JWT" {
		t.Errorf("Type = %q, want JWT", findings[0].Type)
	}
}

func TestDetectMultipleInOneString(t *testing.T) {
	// A string containing both a GitHub PAT and an AWS key.
	text := "key1: ghp_" + strings.Repeat("a", 36) + " and key2: AKIAIOSFODNN7EXAMPLE"
	findings := Detect(text)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}
}

// -- DetectAll tests --

type ApiConfig struct {
	Token  string
	Key    string
	secret string // unexported — should be skipped
}

type nestedConfig struct {
	Name string
	Auth ApiConfig
}

type embeddedConfig struct {
	Name string
	ApiConfig
}

type pointerConfig struct {
	Name  string
	Token *string
}

func TestDetectAllFindsSecret(t *testing.T) {
	cfg := &ApiConfig{
		Token: "ghp_" + strings.Repeat("a", 36),
		Key:   "sk-" + strings.Repeat("b", 48),
	}

	findings := DetectAll(cfg)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}

	types := map[string]bool{}
	for _, f := range findings {
		types[f.Type] = true
		if f.Field == "" {
			t.Error("Field should be set for DetectAll")
		}
	}
	if !types["GitHubPAT"] || !types["OpenAIKey"] {
		t.Errorf("expected both GitHubPAT and OpenAIKey, got %v", types)
	}
}

func TestDetectAllCleanStruct(t *testing.T) {
	cfg := &ApiConfig{
		Token: "normal value",
		Key:   "another normal value",
	}

	findings := DetectAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean struct, got %d", len(findings))
	}
}

func TestDetectAllSkipsUnexported(t *testing.T) {
	cfg := &ApiConfig{
		Token:  "clean",
		Key:    "clean",
		secret: "ghp_" + strings.Repeat("a", 36), // unexported — skipped
	}

	findings := DetectAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (unexported skipped), got %d", len(findings))
	}
}

func TestDetectAllNestedStruct(t *testing.T) {
	cfg := &nestedConfig{
		Name: "test",
		Auth: ApiConfig{
			Token: "ghp_" + strings.Repeat("a", 36),
			Key:   "clean",
		},
	}

	findings := DetectAll(cfg)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in nested struct, got %d", len(findings))
	}
	if findings[0].Field != "Auth.Token" {
		t.Errorf("Field = %q, want Auth.Token", findings[0].Field)
	}
}

func TestDetectAllEmbeddedStruct(t *testing.T) {
	cfg := &embeddedConfig{
		Name: "test",
		ApiConfig: ApiConfig{
			Token: "ghp_" + strings.Repeat("a", 36),
		},
	}

	findings := DetectAll(cfg)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in embedded struct, got %d", len(findings))
	}
	if findings[0].Field != "Token" {
		t.Errorf("Field = %q, want Token (promoted)", findings[0].Field)
	}
}

func TestDetectAllPointerField(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	cfg := &pointerConfig{
		Name:  "test",
		Token: &token,
	}

	findings := DetectAll(cfg)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for pointer field, got %d", len(findings))
	}
	if findings[0].Field != "Token" {
		t.Errorf("Field = %q, want Token", findings[0].Field)
	}
}

func TestDetectAllNilPointerField(t *testing.T) {
	cfg := &pointerConfig{
		Name:  "test",
		Token: nil,
	}

	findings := DetectAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil pointer, got %d", len(findings))
	}
}

func TestDetectAllNonStruct(t *testing.T) {
	findings := DetectAll(42)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-struct, got %d", len(findings))
	}

	findings = DetectAll("hello")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for string, got %d", len(findings))
	}
}

func TestDetectAllNilPointer(t *testing.T) {
	var cfg *ApiConfig
	findings := DetectAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil pointer, got %d", len(findings))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"a", "a"},
		{"abcd", "abcd"},
		{"abcde", "abcd..."},
		{"abcdefgh", "abcd..."},
	}

	for _, tt := range tests {
		got := truncate(tt.in)
		if got != tt.want {
			t.Errorf("truncate(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func FuzzDetect(f *testing.F) {
	f.Add("hello")
	f.Add("")
	f.Add("ghp_" + strings.Repeat("a", 36))
	f.Add("sk-" + strings.Repeat("b", 48))
	f.Add("AKIAIOSFODNN7EXAMPLE")

	f.Fuzz(func(t *testing.T, s string) {
		// Detect must never panic.
		findings := Detect(s)
		for _, f := range findings {
			if f.Type == "" {
				t.Error("Finding.Type must not be empty")
			}
			if f.Value == "" {
				t.Error("Finding.Value must not be empty")
			}
		}
	})
}
