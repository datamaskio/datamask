package secret

import (
	"strings"
	"testing"
)

func BenchmarkDetect(b *testing.B) {
	s := "ghp_" + strings.Repeat("a", 36)
	b.ResetTimer()
	for b.Loop() {
		Detect(s)
	}
}

func BenchmarkDetectKB(b *testing.B) {
	// Build a 1 KB string containing a secret.
	s := strings.Repeat("x", 1024-40) + "ghp_" + strings.Repeat("a", 36)
	b.ResetTimer()
	for b.Loop() {
		Detect(s)
	}
}

func BenchmarkDetectClean(b *testing.B) {
	s := "hello world, nothing to see here, just normal text"
	b.ResetTimer()
	for b.Loop() {
		Detect(s)
	}
}

func BenchmarkDetectAll(b *testing.B) {
	v := &ApiConfig{
		Token: "ghp_" + strings.Repeat("a", 36),
		Key:   "sk-" + strings.Repeat("b", 48),
	}
	b.ResetTimer()
	for b.Loop() {
		DetectAll(v)
	}
}
