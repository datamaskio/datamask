package datamask

import "testing"

func BenchmarkRedact(b *testing.B) {
	for b.Loop() {
		Redact("john@example.com")
	}
}

func BenchmarkRedactEmail(b *testing.B) {
	for b.Loop() {
		RedactEmail("john@example.com")
	}
}

func BenchmarkHash(b *testing.B) {
	for b.Loop() {
		Hash("john@example.com")
	}
}

func BenchmarkTokenize(b *testing.B) {
	for b.Loop() {
		Tokenize("john@example.com", "secret-key")
	}
}

func BenchmarkPartialEmail(b *testing.B) {
	for b.Loop() {
		Partial("john@example.com")
	}
}

func BenchmarkPartialPhone(b *testing.B) {
	for b.Loop() {
		Partial("123-45-6789")
	}
}

func BenchmarkPartialGeneric(b *testing.B) {
	for b.Loop() {
		Partial("sensitive_value_here")
	}
}
