package datamask

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type polUser struct {
	Name  string
	Email string  `mask:"email"`
	Hash  string  `mask:"email,hash"`
	Part  string  `mask:"email,partial"`
	Tok   string  `mask:"email,tokenize"`
	Phone string  `mask:"phone,partial"`
	SSN   string  `mask:"ssn"`
	Card  string  `mask:"credit-card,partial"`
	Key   string  `mask:"secret,hash"`
	PTR   *string `mask:"email,partial"`
}

func polMasker() *Masker { return New(WithHashKey("hk"), WithTokenizeKey("tk")) }

func polUserValue() polUser {
	p := "ptr@example.com"
	return polUser{
		Name: "Ann", Email: "a@example.com", Hash: "b@example.com", Part: "c@example.com",
		Tok: "d@example.com", Phone: "+1-555-1234", SSN: "123-45-6789",
		Card: "4111111111111111", Key: "k", PTR: &p,
	}
}

// -- the rule-set type --

func TestZeroPolicyHasNoRules(t *testing.T) {
	var p Policy
	if p.String() != "(no rules)" {
		t.Errorf("String() = %q", p.String())
	}
	m := polMasker()
	want, err := Redact(m, polUserValue())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(m, polUserValue(), p)
	if err != nil {
		t.Fatal(err)
	}
	// Compare values; the PTR field is a fresh pointer in each result.
	if *got.PTR != *want.PTR {
		t.Errorf("PTR = %q, want %q", *got.PTR, *want.PTR)
	}
	got.PTR, want.PTR = nil, nil
	if got != want {
		t.Errorf("zero Policy changed the result:\n got %+v\nwant %+v", got, want)
	}
}

func TestPolicyString(t *testing.T) {
	p := Compose(ForDataType(DataTypePhone, TransformRedact), ForDataType(DataTypeEmail, TransformHash))
	if got := p.String(); got != "email=hash, phone=redact" {
		t.Errorf("String() = %q", got)
	}
}

func TestForDataTypeRejectsUnknowns(t *testing.T) {
	m := polMasker()
	in := polUserValue()
	if _, err := Apply(m, in, ForDataType(DataType(99), TransformRedact)); !errors.Is(err, ErrInvalidInput) || !errors.Is(err, ErrUnknownDataType) {
		t.Errorf("unknown data type err = %v", err)
	}
	if _, err := Apply(m, in, ForDataType(DataTypeEmail, Transform(99))); !errors.Is(err, ErrInvalidInput) || !errors.Is(err, ErrUnknownTransform) {
		t.Errorf("unknown transform err = %v", err)
	}
	// The error survives Compose, so a typo can never be dropped.
	bad := Compose(ForDataType(DataTypeEmail, TransformRedact), ForDataType(DataType(0), TransformRedact))
	if _, err := Apply(m, in, bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("composed err = %v", err)
	}
}

func TestComposeDoesNotAliasOrMutate(t *testing.T) {
	a := ForDataType(DataTypeEmail, TransformPartial)
	b := ForDataType(DataTypeEmail, TransformRedact)
	c := Compose(a, b)
	if a.String() != "email=partial" || b.String() != "email=redact" || c.String() != "email=redact" {
		t.Errorf("a=%s b=%s c=%s", a, b, c)
	}
	_ = Compose(c, ForDataType(DataTypePhone, TransformHash))
	if c.String() != "email=redact" {
		t.Errorf("Compose mutated its argument: %s", c)
	}
}

// -- restrictiveness: Redact > Tokenize > Hash > Partial --

func TestRestrictivenessOrder(t *testing.T) {
	// Least to most restrictive.
	order := []Transform{TransformPartial, TransformHash, TransformTokenize, TransformRedact}
	for i, lo := range order {
		for j, hi := range order {
			want := order[max(i, j)]
			if got := moreRestrictive(lo, hi); got != want {
				t.Errorf("moreRestrictive(%v,%v) = %v, want %v", lo, hi, got, want)
			}
		}
	}
}

// -- resolution: tag floor × policy rule --

func TestResolveTransformMatrix(t *testing.T) {
	transforms := []Transform{TransformRedact, TransformHash, TransformTokenize, TransformPartial}
	for _, tag := range transforms {
		for _, rule := range transforms {
			t.Run(fmt.Sprintf("tag=%v/rule=%v", tag, rule), func(t *testing.T) {
				p := ForDataType(DataTypeEmail, rule)
				got := resolveTransform(tag, p, DataTypeEmail)
				if restrictiveness(got) < restrictiveness(tag) {
					t.Errorf("policy lowered protection: tag %v -> %v", tag, got)
				}
				if restrictiveness(got) < restrictiveness(rule) {
					t.Errorf("rule %v not honored: got %v", rule, got)
				}
				if got != tag && got != rule {
					t.Errorf("result %v is neither tag %v nor rule %v", got, tag, rule)
				}
				// A rule for a different data type changes nothing.
				if other := resolveTransform(tag, p, DataTypePhone); other != tag {
					t.Errorf("rule for email changed a phone field: %v", other)
				}
			})
		}
	}
}

// -- end to end through Apply --

func TestApplyPolicyOnlyRaisesProtection(t *testing.T) {
	m := polMasker()
	base, err := Redact(m, polUserValue())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(m, polUserValue(), m.RedactPII())
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Ann" {
		t.Error("untagged field changed")
	}
	// RedactPII raises every email, phone, ssn and credit-card field to redact.
	for name, v := range map[string]string{"Email": got.Email, "Hash": got.Hash, "Part": got.Part, "Tok": got.Tok, "Phone": got.Phone, "SSN": got.SSN, "Card": got.Card, "PTR": *got.PTR} {
		if v != "[REDACTED]" {
			t.Errorf("%s = %q, want [REDACTED]", name, v)
		}
	}
	// Key is a secret, not covered by RedactPII: it keeps its tag transform.
	if got.Key != base.Key {
		t.Errorf("Key = %q, want %q (tag floor)", got.Key, base.Key)
	}
}

func TestApplyHashEmailsKeepsStrongerTags(t *testing.T) {
	m := polMasker()
	in := polUserValue()
	got, err := Apply(m, in, m.HashEmails())
	if err != nil {
		t.Fatal(err)
	}
	// Tag redact is stronger than the policy's hash: stays redact.
	if got.Email != "[REDACTED]" {
		t.Errorf("Email = %q, want [REDACTED] (tag floor)", got.Email)
	}
	// Tag tokenize is stronger than hash: stays tokenize.
	if !strings.HasPrefix(got.Tok, "tok:") {
		t.Errorf("Tok = %q, want a tokenize pseudonym", got.Tok)
	}
	// Tag partial is weaker than hash: raised to hash (keyed here: tok: prefix).
	if got.Part == in.Part || strings.Contains(got.Part, "***") {
		t.Errorf("Part = %q, want it raised from partial to hash", got.Part)
	}
	if !strings.HasPrefix(got.Part, "tok:") {
		t.Errorf("Part = %q, want a keyed hash", got.Part)
	}
	// Other data types are untouched by an email rule.
	base, _ := Redact(m, in)
	if got.Phone != base.Phone || got.SSN != base.SSN {
		t.Error("an email rule changed other data types")
	}
}

func TestApplyDoesNotDiscoverUntaggedFields(t *testing.T) {
	type rec struct {
		Plain string // looks like an email, but has no tag
		Mail  string `mask:"email"`
	}
	got, err := Apply(polMasker(), rec{Plain: "x@y.z", Mail: "a@b.c"}, New().RedactPII())
	if err != nil || got.Plain != "x@y.z" || got.Mail != "[REDACTED]" {
		t.Errorf("(%+v, %v)", got, err)
	}
}

func TestApplyNeverMutatesInput(t *testing.T) {
	m := polMasker()
	in := polUserValue()
	p := *in.PTR
	if _, err := Apply(m, in, m.RedactPII()); err != nil {
		t.Fatal(err)
	}
	if in.Email != "a@example.com" || *in.PTR != p {
		t.Errorf("input mutated: %+v", in)
	}
}

func TestApplyPolicyReachesNestedValues(t *testing.T) {
	m := polMasker()
	type holder struct {
		In    polUser
		List  []polUser
		ByKey map[string]*polUser
		Any   any
	}
	u := polUserValue()
	in := holder{In: u, List: []polUser{u}, ByKey: map[string]*polUser{"k": &u}, Any: u}
	got, err := Apply(m, in, m.RedactPII())
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"In": got.In.Part, "List": got.List[0].Part, "ByKey": got.ByKey["k"].Part, "Any": got.Any.(polUser).Part,
	} {
		if v != "[REDACTED]" {
			t.Errorf("%s.Part = %q, want policy applied", name, v)
		}
	}
}

// -- Maskable stays absolute --

func TestPolicyDoesNotOverrideMaskable(t *testing.T) {
	type holder struct {
		V    okVal  `mask:"email"`
		Mail string `mask:"email"`
	}
	got, err := Apply(polMasker(), holder{V: okVal{S: "x"}, Mail: "a@b.c"}, New().RedactPII())
	if err != nil {
		t.Fatal(err)
	}
	if got.V.S != "***" {
		t.Errorf("Maskable field = %q, want its own Mask() output", got.V.S)
	}
	if got.Mail != "[REDACTED]" {
		t.Errorf("Mail = %q", got.Mail)
	}
	_, err = Apply(polMasker(), holder{V: okVal{S: "x"}}, ForDataType(DataTypeEmail, TransformRedact))
	if err != nil {
		t.Fatal(err)
	}
	type bad struct {
		V failVal `mask:"email"`
	}
	if _, err := Apply(polMasker(), bad{V: failVal{S: "x"}}, New().RedactPII()); !errors.Is(err, ErrMaskFailed) {
		t.Errorf("failing Maskable under policy err = %v", err)
	}
}

// -- order invariance --

func TestComposeOrderNeverChangesResults(t *testing.T) {
	m := polMasker()
	rules := []Policy{
		ForDataType(DataTypeEmail, TransformHash),
		ForDataType(DataTypeEmail, TransformRedact),
		ForDataType(DataTypeEmail, TransformPartial),
		ForDataType(DataTypePhone, TransformHash),
		ForDataType(DataTypeSSN, TransformTokenize),
		m.RedactPII(),
		m.HashEmails(),
		{},
	}
	permutations := func(n int) [][]int {
		var out [][]int
		var rec func(cur []int, used []bool)
		rec = func(cur []int, used []bool) {
			if len(cur) == n {
				out = append(out, append([]int(nil), cur...))
				return
			}
			for i := range n {
				if !used[i] {
					used[i] = true
					rec(append(cur, i), used)
					used[i] = false
				}
			}
		}
		rec(nil, make([]bool, n))
		return out
	}
	// Every ordering of a 5-policy subset, over several subsets.
	subsets := [][]int{{0, 1, 2, 3, 4}, {0, 3, 4, 5, 6}, {2, 3, 5, 6, 7}, {1, 2, 4, 6, 7}}
	for _, sub := range subsets {
		var want string
		for i, perm := range permutations(len(sub)) {
			ps := make([]Policy, len(perm))
			for k, idx := range perm {
				ps[k] = rules[sub[idx]]
			}
			c := Compose(ps...)
			got, err := Apply(m, polUserValue(), c)
			if err != nil {
				t.Fatal(err)
			}
			got.PTR = nil // pointer identity differs between runs; value checked via Part etc.
			key := fmt.Sprintf("%+v|%s", got, c)
			if i == 0 {
				want = key
			} else if key != want {
				t.Fatalf("subset %v: order %v changed the result\n got %s\nwant %s", sub, perm, key, want)
			}
		}
	}
}

func TestComposeIsAssociativeAndIdempotent(t *testing.T) {
	a := ForDataType(DataTypeEmail, TransformHash)
	b := ForDataType(DataTypeEmail, TransformTokenize)
	c := ForDataType(DataTypePhone, TransformRedact)
	if x, y := Compose(Compose(a, b), c).String(), Compose(a, Compose(b, c)).String(); x != y {
		t.Errorf("not associative: %s vs %s", x, y)
	}
	if x, y := Compose(a, a).String(), a.String(); x != y {
		t.Errorf("not idempotent: %s vs %s", x, y)
	}
	if Compose().String() != "(no rules)" {
		t.Error("empty Compose should have no rules")
	}
}

// -- keys --

func TestPolicyNeedingMissingKeyFails(t *testing.T) {
	m := New() // no keys
	type rec struct {
		Mail string `mask:"email,partial"`
	}
	_, err := Apply(m, rec{Mail: "a@b.c"}, m.HashEmails())
	if !errors.Is(err, ErrInvalidSchema) || !strings.Contains(err.Error(), "WithHashKey") {
		t.Errorf("HashEmails without key err = %v", err)
	}
	_, err = Apply(m, rec{Mail: "a@b.c"}, ForDataType(DataTypeEmail, TransformTokenize))
	if !errors.Is(err, ErrInvalidSchema) || !strings.Contains(err.Error(), "WithTokenizeKey") {
		t.Errorf("tokenize rule without key err = %v", err)
	}
	// Redact and partial rules need no key.
	if _, err := Apply(m, rec{Mail: "a@b.c"}, Compose(m.RedactPII(), ForDataType(DataTypeEmail, TransformPartial))); err != nil {
		t.Errorf("keyless rules: %v", err)
	}
	// With a key it works.
	km := New(WithHashKey("k"))
	got, err := Apply(km, rec{Mail: "a@b.c"}, km.HashEmails())
	if err != nil || !strings.HasPrefix(got.Mail, "tok:") {
		t.Errorf("(%+v, %v)", got, err)
	}
}

// -- Apply entry points --

func TestApplyGuardsAndTypes(t *testing.T) {
	type rec struct {
		Mail string `mask:"email,partial"`
	}
	if _, err := Apply(nil, rec{}, Policy{}); !errors.Is(err, ErrNilReceiver) {
		t.Errorf("nil masker err = %v", err)
	}
	if _, err := Apply(&Masker{}, rec{}, Policy{}); !errors.Is(err, ErrUninitialized) {
		t.Errorf("zero masker err = %v", err)
	}
	var s Schema[rec]
	if _, err := s.Apply(rec{}, Policy{}); !errors.Is(err, ErrUninitialized) {
		t.Errorf("zero Schema err = %v", err)
	}
	if _, err := Apply(New(), 42, Policy{}); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("unsupported type err = %v", err)
	}

	m := New()
	// Schema.Apply returns the concrete type and reuses the compiled plan.
	sch := MustCompile[rec](m)
	got, err := sch.Apply(rec{Mail: "a@b.c"}, m.RedactPII())
	if err != nil || got.Mail != "[REDACTED]" {
		t.Errorf("Schema.Apply = (%+v, %v)", got, err)
	}
	// Containers and pointers too.
	list, err := Apply(m, []rec{{Mail: "a@b.c"}}, m.RedactPII())
	if err != nil || list[0].Mail != "[REDACTED]" {
		t.Errorf("slice Apply = (%+v, %v)", list, err)
	}
	// Apply on a nil value of an interface type is an input error.
	if _, err := Apply[any](m, nil, Policy{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil any err = %v", err)
	}
}

func TestPresetsAreUsableFromNilMasker(t *testing.T) {
	// Presets are plain rule sets and need no receiver state.
	var m *Masker
	if got := m.RedactPII().String(); got != "email=redact, phone=redact, ssn=redact, credit-card=redact" {
		t.Errorf("RedactPII = %q", got)
	}
	if got := m.HashEmails().String(); got != "email=hash" {
		t.Errorf("HashEmails = %q", got)
	}
}

func TestApplyPointerFieldsAndTokenize(t *testing.T) {
	m := polMasker()
	tok := "t@example.com"
	type rec struct {
		P *string `mask:"email,partial"`
	}
	got, err := Apply(m, rec{P: &tok}, ForDataType(DataTypeEmail, TransformTokenize))
	if err != nil || got.P == nil || !strings.HasPrefix(*got.P, "tok:") {
		t.Fatalf("(%+v, %v)", got, err)
	}
	if tok != "t@example.com" {
		t.Error("pointer target mutated")
	}
}
