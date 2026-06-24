package datamask

import "testing"

type benchUser struct {
	Name  string
	Email string `mask:"email"`
	Phone string `mask:"phone"`
	SSN   string `mask:"secret"`
}

func BenchmarkRedact(b *testing.B) {
	m := New()
	user := benchUser{
		Name:  "John Doe",
		Email: "john@example.com",
		Phone: "+1-555-1234",
		SSN:   "123-45-6789",
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = Redact(m, user)
	}
}

func BenchmarkRedactInPlace(b *testing.B) {
	m := New()
	b.ResetTimer()
	for b.Loop() {
		user := &benchUser{
			Name:  "John Doe",
			Email: "john@example.com",
			Phone: "+1-555-1234",
			SSN:   "123-45-6789",
		}
		_ = m.RedactInPlace(user)
	}
}

func BenchmarkRedactValue(b *testing.B) {
	for b.Loop() {
		RedactValue("john@example.com")
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
