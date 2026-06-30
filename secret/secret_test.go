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

func TestDetectAllEmbeddedPointer(t *testing.T) {
	type outer struct {
		Name string
		*ApiConfig
	}
	cfg := &outer{
		Name:      "test",
		ApiConfig: &ApiConfig{Token: "ghp_" + strings.Repeat("a", 36)},
	}
	findings := DetectAll(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for embedded pointer, got %d", len(findings))
	}
}

func TestDetectAllNilEmbeddedPointer(t *testing.T) {
	type outer struct {
		Name string
		*ApiConfig
	}
	cfg := &outer{
		Name:      "test",
		ApiConfig: nil,
	}
	findings := DetectAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil embedded pointer, got %d", len(findings))
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

func TestDetectAllPointerToStruct(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	cfg := &ApiConfig{
		Token: token,
	}
	findings := DetectAll(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for pointer-to-struct, got %d", len(findings))
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

func TestDetectPANWithSeparators(t *testing.T) {
	// Card with spaces: 16 digits, should match.
	card := "4111 1111 1111 1111"
	f := Detect(card)
	if len(f) != 1 || f[0].Type != "PAN" {
		t.Fatalf("expected 1 PAN finding, got %d: %v", len(f), f)
	}
}

func TestDetectPANDigitsReset(t *testing.T) {
	// 12 digits, then a letter (resets), then more digits.
	// Should NOT match because no 13-consecutive-digit run.
	s := "123456789012a1234567890123"
	f := Detect(s)
	for _, ff := range f {
		if ff.Type == "PAN" {
			t.Error("PAN should not match when digits are interrupted by letter")
		}
	}
}

func TestDetectNoPanInShortDigitRun(t *testing.T) {
	// Only 12 consecutive digits — below the minimum.
	s := "123456789012"
	f := Detect(s)
	if len(f) != 0 {
		t.Errorf("expected 0 findings for 12-digit string, got %d", len(f))
	}
}

func TestDetectAllCyclicStruct(t *testing.T) {
	type Node struct {
		Name string
		Next *Node
	}
	node := &Node{Name: "first"}
	node.Next = node

	findings := DetectAll(node)
	if len(findings) != 0 {
		t.Logf("findings: %v", findings)
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

// -- ScanBytes tests --

func TestScanBytesGitHubPAT(t *testing.T) {
	data := []byte("ghp_" + strings.Repeat("a", 36))
	findings := ScanBytes(data)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "GitHubPAT" {
		t.Errorf("Type = %q, want GitHubPAT", f.Type)
	}
	if f.Field != "" {
		t.Errorf("Field = %q, want empty", f.Field)
	}
	if f.Position != 0 {
		t.Errorf("Position = %d, want 0", f.Position)
	}
	if f.Value != "ghp_..." {
		t.Errorf("Value = %q, want ghp_...", f.Value)
	}
}

func TestScanBytesNoSecret(t *testing.T) {
	data := []byte("hello world")
	findings := ScanBytes(data)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanBytesShortInput(t *testing.T) {
	data := []byte("short")
	findings := ScanBytes(data)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for short input, got %d", len(findings))
	}
}

func TestScanBytesMultiplePatterns(t *testing.T) {
	data := []byte("ghp_" + strings.Repeat("a", 36) + " sk-" + strings.Repeat("b", 48))
	findings := ScanBytes(data)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Type != "GitHubPAT" {
		t.Errorf("first Type = %q, want GitHubPAT", findings[0].Type)
	}
	if findings[1].Type != "OpenAIKey" {
		t.Errorf("second Type = %q, want OpenAIKey", findings[1].Type)
	}
}

func TestScanBytesEmpty(t *testing.T) {
	findings := ScanBytes(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil, got %d", len(findings))
	}
	findings = ScanBytes([]byte{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty, got %d", len(findings))
	}
}

func TestScanBytesPAN(t *testing.T) {
	data := []byte("4111111111111111")
	findings := ScanBytes(data)

	if len(findings) < 1 {
		t.Fatal("expected at least 1 finding for PAN")
	}
	if findings[0].Type != "PAN" {
		t.Errorf("Type = %q, want PAN", findings[0].Type)
	}
}

func TestScanBytesMatchDetect(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	bFindings := ScanBytes([]byte(token))
	sFindings := Detect(token)

	if len(bFindings) != len(sFindings) {
		t.Fatalf("ScanBytes returned %d findings, Detect returned %d", len(bFindings), len(sFindings))
	}
	for i := range bFindings {
		if bFindings[i].Type != sFindings[i].Type {
			t.Errorf("finding[%d].Type: ScanBytes=%q Detect=%q", i, bFindings[i].Type, sFindings[i].Type)
		}
		if bFindings[i].Position != sFindings[i].Position {
			t.Errorf("finding[%d].Position: ScanBytes=%d Detect=%d", i, bFindings[i].Position, sFindings[i].Position)
		}
	}
}
func TestScanBytesFalsePositive(t *testing.T) {
	// Prefix check passes but regex doesn't match — exercises the
	// no-match path through the pattern loop.
	data := []byte("sk-incomplete")
	findings := ScanBytes(data)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestTruncateBytes(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ab", "ab"},
		{"abcd", "abcd"},
		{"abcde", "abcd..."},
		{"hello world", "hell..."},
	}
	for _, tt := range tests {
		got := truncateBytes([]byte(tt.in))
		if got != tt.want {
			t.Errorf("truncateBytes(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLikelyPANBytes(t *testing.T) {
	if likelyPANBytes([]byte("abc")) {
		t.Error("abc should not be PAN")
	}
	if !likelyPANBytes([]byte("4111111111111")) {
		t.Error("13 digits should be PAN")
	}
	if likelyPANBytes([]byte("1234abcd567890")) {
		t.Error("digits interrupted by letters should not be PAN")
	}
	if !likelyPANBytes([]byte("4111-1111-1111-1111")) {
		t.Error("16 digits with dashes should be PAN")
	}
}
