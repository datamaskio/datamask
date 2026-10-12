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

// -- Selective-copy benchmarks (Checkpoint 4) --

type benchProfile struct {
	Avatar string
	Email  string `mask:"email"`
}

type benchPlain struct {
	Label string
	Tags  []string
}

type benchNested struct {
	Name    string
	Profile *benchProfile
	Plain   *benchPlain
	Orders  []benchProfile
}

func benchNestedValue() benchNested {
	return benchNested{
		Name:    "Ann",
		Profile: &benchProfile{Avatar: "a.png", Email: "ann@example.com"},
		Plain:   &benchPlain{Label: "x", Tags: []string{"a", "b"}},
		Orders:  []benchProfile{{Email: "a@x.y"}, {Email: "b@x.y"}, {Email: "c@x.y"}},
	}
}

func BenchmarkRedactNested(b *testing.B) {
	m := New()
	v := benchNestedValue()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Redact(m, v)
	}
}

func BenchmarkRedactInPlaceNested(b *testing.B) {
	m := New()
	b.ReportAllocs()
	for b.Loop() {
		v := benchNestedValue()
		_ = m.RedactInPlace(&v)
	}
}

// Nothing to mask below the top struct: should be close to a plain copy.
func BenchmarkRedactNothingToMask(b *testing.B) {
	m := New()
	v := struct {
		Plain *benchPlain
		List  []benchPlain
		Tags  map[string]int
	}{Plain: &benchPlain{Label: "x"}, List: make([]benchPlain, 50), Tags: map[string]int{"a": 1}}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Redact(m, v)
	}
}

func BenchmarkRedactSlice100(b *testing.B) {
	m := New()
	v := make([]benchProfile, 100)
	for i := range v {
		v[i] = benchProfile{Avatar: "a", Email: "u@example.com"}
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Redact(m, v)
	}
}

func BenchmarkRedactMap10(b *testing.B) {
	m := New()
	v := make(map[string]benchProfile, 10)
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		v[k] = benchProfile{Email: "u@example.com"}
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Redact(m, v)
	}
}

func BenchmarkRedactInterface(b *testing.B) {
	m := New()
	v := struct{ Payload any }{Payload: benchProfile{Email: "u@example.com"}}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Redact(m, v)
	}
}

func BenchmarkSchemaRedact(b *testing.B) {
	s := MustCompile[benchUser](New())
	user := benchUser{Name: "John Doe", Email: "john@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = s.Redact(user)
	}
}

func BenchmarkSchemaRedactNested(b *testing.B) {
	s := MustCompile[benchNested](New())
	v := benchNestedValue()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = s.Redact(v)
	}
}

func BenchmarkCompileCacheHit(b *testing.B) {
	m := New()
	_ = MustCompile[benchNested](m)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Compile[benchNested](m)
	}
}

func BenchmarkCompileCold(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Compile[benchNested](New())
	}
}

func BenchmarkRedactParallel(b *testing.B) {
	m := New()
	v := benchNestedValue()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = Redact(m, v)
		}
	})
}

// -- Policy and generated-style Mask() --

func BenchmarkApplyPolicy(b *testing.B) {
	m := New(WithHashKey("k"))
	user := benchUser{Name: "John Doe", Email: "john@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}
	p := m.RedactPII()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = Apply(m, user, p)
	}
}

func BenchmarkSchemaApplyPolicy(b *testing.B) {
	m := New(WithHashKey("k"))
	s := MustCompile[benchUser](m)
	user := benchUser{Name: "John Doe", Email: "john@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}
	p := m.RedactPII()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = s.Apply(user, p)
	}
}

func BenchmarkCompose(b *testing.B) {
	m := New()
	b.ReportAllocs()
	for b.Loop() {
		_ = Compose(m.RedactPII(), m.HashEmails())
	}
}

// benchGenerated mirrors what `datamask generate` emits for benchUser.
type benchGenerated struct {
	Name  string
	Email string
	Phone string
	SSN   string
}

func (g benchGenerated) Mask() (any, error) {
	g.Email = "[REDACTED]"
	g.Phone = "[REDACTED]"
	g.SSN = "[REDACTED]"
	return g, nil
}

var benchSink any

// The generated method called directly: the floor for generated code.
func BenchmarkGeneratedMaskDirect(b *testing.B) {
	g := benchGenerated{Name: "John Doe", Email: "john@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}
	b.ReportAllocs()
	for b.Loop() {
		benchSink, _ = g.Mask()
	}
}

// The same type reached through Redact: Maskable wins, so this is the
// "transparent upgrade" path and avoids the reflection walk entirely.
func BenchmarkGeneratedMaskViaRedact(b *testing.B) {
	m := New()
	g := benchGenerated{Name: "John Doe", Email: "john@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}
	s := MustCompile[benchGenerated](m)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = s.Redact(g)
	}
}
