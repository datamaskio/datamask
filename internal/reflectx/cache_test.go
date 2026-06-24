package reflectx

import (
	"reflect"
	"sync"
	"testing"
)

func TestCacheLoadMiss(t *testing.T) {
	c := &Cache{}
	meta, ok := c.Load(reflect.TypeFor[int]())
	if ok {
		t.Error("expected miss on empty cache")
	}
	if meta != nil {
		t.Error("expected nil meta on miss")
	}
}

func TestCacheStoreAndLoad(t *testing.T) {
	c := &Cache{}
	typ := reflect.TypeOf(struct{}{})
	want := &TypeMeta{
		Fields: []FieldMeta{{Index: []int{0}, Tag: "email"}},
	}

	c.Store(typ, want)
	got, ok := c.Load(typ)

	if !ok {
		t.Fatal("expected hit after Store")
	}
	if got != want {
		t.Fatalf("got %p, want %p", got, want)
	}
}

func TestCacheDifferentTypes(t *testing.T) {
	c := &Cache{}
	typeA := reflect.TypeOf(struct{ A string }{})
	typeB := reflect.TypeOf(struct{ B int }{})
	metaA := &TypeMeta{Fields: []FieldMeta{{Index: []int{0}, Tag: "email"}}}
	metaB := &TypeMeta{Fields: []FieldMeta{{Index: []int{0}, Tag: "secret"}}}

	c.Store(typeA, metaA)
	c.Store(typeB, metaB)

	gotA, _ := c.Load(typeA)
	gotB, _ := c.Load(typeB)

	if gotA != metaA {
		t.Error("wrong meta for typeA")
	}
	if gotB != metaB {
		t.Error("wrong meta for typeB")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := &Cache{}
	typ := reflect.TypeOf(struct{}{})
	meta := &TypeMeta{}

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			c.Store(typ, meta)
			got, ok := c.Load(typ)
			if !ok || got != meta {
				t.Errorf("concurrent access failed: ok=%v got=%p", ok, got)
			}
		})
	}
	wg.Wait()
}

func BenchmarkCacheLoad(b *testing.B) {
	c := &Cache{}
	typ := reflect.TypeOf(struct{}{})
	c.Store(typ, &TypeMeta{Fields: []FieldMeta{{Index: []int{0}, Tag: "email"}}})

	b.ResetTimer()
	for b.Loop() {
		c.Load(typ)
	}
}

func BenchmarkCacheStore(b *testing.B) {
	c := &Cache{}
	typ := reflect.TypeOf(struct{}{})
	meta := &TypeMeta{}

	b.ResetTimer()
	for b.Loop() {
		c.Store(typ, meta)
	}
}
