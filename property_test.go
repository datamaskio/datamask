package datamask

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// propShape is a recursive type that exercises every container the walker
// supports. Mail is the only tagged field; every raw value contains "@" so a
// leak is easy to spot, and every other string is "plain".
type propShape struct {
	Name  string
	Mail  string `mask:"email"`
	Ptr   *propShape
	Slice []propShape
	PSl   []*propShape
	Map   map[string]*propShape
	VMap  map[string]propShape
	Any   any
	Arr   [2]*propShape
	Inner propInner
	Tok   *string `mask:"secret"`
}

type propInner struct {
	Label string
	Mail  string `mask:"email"`
}

// propGen builds a random acyclic graph. With the same seed it builds an
// identical, fully independent graph, which gives us a pristine copy to
// compare the input against after Redact. Shared pointers (diamonds) are
// produced by reusing earlier nodes.
type propGen struct {
	r     *rand.Rand
	n     int
	nodes []*propShape
}

func (g *propGen) mail() string {
	g.n++
	return fmt.Sprintf("user%d@example.com", g.n)
}

func (g *propGen) shape(depth int) *propShape {
	s := &propShape{Name: "plain", Mail: g.mail(), Inner: propInner{Label: "plain", Mail: g.mail()}}
	// Register s only once it is complete (see the defer): sharing is limited
	// to finished nodes, so a node can never be reused as its own descendant.
	defer func() { g.nodes = append(g.nodes, s) }()
	if g.r.Intn(3) == 0 {
		tok := g.mail()
		s.Tok = &tok
	}
	if depth <= 0 {
		return s
	}
	child := func() *propShape {
		// Reuse a finished node about a quarter of the time: a diamond.
		if len(g.nodes) > 0 && g.r.Intn(4) == 0 {
			return g.nodes[g.r.Intn(len(g.nodes))]
		}
		return g.shape(depth - 1)
	}
	if g.r.Intn(2) == 0 {
		s.Ptr = child()
	}
	for range g.r.Intn(3) {
		s.Slice = append(s.Slice, *g.shape(depth - 1))
	}
	for range g.r.Intn(3) {
		s.PSl = append(s.PSl, child())
	}
	if g.r.Intn(2) == 0 {
		s.Map = map[string]*propShape{"a": child(), "nil": nil}
	}
	if g.r.Intn(2) == 0 {
		s.VMap = map[string]propShape{"v": *g.shape(depth - 1)}
	}
	switch g.r.Intn(4) {
	case 0:
		s.Any = *g.shape(depth - 1)
	case 1:
		s.Any = child()
	case 2:
		s.Any = "plain"
	}
	if g.r.Intn(2) == 0 {
		s.Arr[g.r.Intn(2)] = child()
	}
	return s
}

// leaks reports the path of any string containing "@" reachable from v.
// Outputs are acyclic, so no visited set is needed.
func leaks(v reflect.Value, path string) string {
	switch v.Kind() {
	case reflect.String:
		if strings.Contains(v.String(), "@") {
			return path + "=" + v.String()
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return leaks(v.Elem(), path)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if p := leaks(v.Field(i), path+"."+v.Type().Field(i).Name); p != "" {
				return p
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if p := leaks(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if p := leaks(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k)); p != "" {
				return p
			}
		}
	}
	return ""
}

func TestPropertyRedactNeverMutatesAndNeverLeaks(t *testing.T) {
	m := New()
	for seed := int64(0); seed < 200; seed++ {
		in := (&propGen{r: rand.New(rand.NewSource(seed))}).shape(3)
		pristine := (&propGen{r: rand.New(rand.NewSource(seed))}).shape(3)

		if leaks(reflect.ValueOf(in), "in") == "" {
			t.Fatalf("seed %d: generator produced no raw values; the leak check would be vacuous", seed)
		}
		out, err := Redact(m, in)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if !reflect.DeepEqual(in, pristine) {
			t.Fatalf("seed %d: Redact mutated its input", seed)
		}
		if p := leaks(reflect.ValueOf(out), "out"); p != "" {
			t.Fatalf("seed %d: unmasked value in output at %s", seed, p)
		}
		if out.Name != "plain" || out.Inner.Label != "plain" {
			t.Fatalf("seed %d: untagged fields changed", seed)
		}
		// A value-typed root works the same way.
		outV, err := Redact(m, *in)
		if err != nil || leaks(reflect.ValueOf(outV), "outV") != "" {
			t.Fatalf("seed %d: value root: err=%v", seed, err)
		}
		if !reflect.DeepEqual(in, pristine) {
			t.Fatalf("seed %d: Redact(value) mutated its input", seed)
		}
	}
}

func TestPropertyInPlaceMatchesRedact(t *testing.T) {
	m := New()
	for seed := int64(0); seed < 200; seed++ {
		want, err := Redact(m, (&propGen{r: rand.New(rand.NewSource(seed))}).shape(3))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		got := (&propGen{r: rand.New(rand.NewSource(seed))}).shape(3)
		if err := m.RedactInPlace(got); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if p := leaks(reflect.ValueOf(got), "got"); p != "" {
			t.Fatalf("seed %d: RedactInPlace left %s", seed, p)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: RedactInPlace result differs from Redact", seed)
		}
	}
}

func TestPropertyRedactIsIdempotent(t *testing.T) {
	m := New()
	for seed := int64(0); seed < 100; seed++ {
		once, err := Redact(m, (&propGen{r: rand.New(rand.NewSource(seed))}).shape(3))
		if err != nil {
			t.Fatal(err)
		}
		twice, err := Redact(m, once)
		if err != nil || !reflect.DeepEqual(once, twice) {
			t.Fatalf("seed %d: not idempotent (err=%v)", seed, err)
		}
	}
}

// Concurrent readers of one shared input: with -race this fails if Redact
// ever writes to the input or the Masker's caches are unsafe.
func TestPropertyConcurrentRedactOnSharedInput(t *testing.T) {
	m := New()
	in := (&propGen{r: rand.New(rand.NewSource(7))}).shape(4)
	pristine := (&propGen{r: rand.New(rand.NewSource(7))}).shape(4)
	s := MustCompile[*propShape](m)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				out, err := s.Redact(in)
				if err != nil || leaks(reflect.ValueOf(out), "out") != "" {
					t.Errorf("concurrent Redact: err=%v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(in, pristine) {
		t.Error("shared input was mutated")
	}
}
