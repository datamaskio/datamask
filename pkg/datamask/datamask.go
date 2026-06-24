package datamask

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// ErrNoMaskableFields is returned when a struct has no mask-tagged fields.
var ErrNoMaskableFields = errors.New("datamask: no mask-tagged fields")

// Masker is the core redaction engine. Create one with New and reuse it
// across goroutines. A zero-value Masker is not usable; always use New.
type Masker struct {
	cfg   Config
	cache *Cache
}

// New creates a Masker with the given options. A Masker is safe for
// concurrent use.
func New(opts ...Option) *Masker {
	m := &Masker{
		cfg: Config{
			DetectSecrets: true,
		},
		cache: NewCache(),
	}
	for _, o := range opts {
		o(&m.cfg)
	}
	return m
}

// Redact is the generic entry point for struct redaction. It returns a
// shallow copy of v with all mask-tagged fields replaced by their
// redaction placeholder.
//
// Redact uses Go generics so the caller gets back T, not any:
//
//	masked, err := datamask.Redact(masker, user)  // masked is User
//
// If v's type has no mask-tagged fields, the copy is returned unchanged
// along with ErrNoMaskableFields.
func Redact[T any](m *Masker, v T) (T, error) {
	result, err := m.redact(v)
	if err != nil {
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// redact is the type-erased implementation. See Redact for the public API.
func (m *Masker) redact(v any) (any, error) {
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("datamask: Redact requires a struct, got %v", t.Kind())
	}

	meta := m.getOrParseMeta(t)
	if len(meta.Fields) == 0 {
		return v, ErrNoMaskableFields
	}

	// Allocate a pointer to a new struct, copy v into it, walk the
	// copy via its pointer (so fields are settable), then return the
	// struct value (not the pointer) so the generic Redact wrapper
	// can cast back to T.
	cpPtr := reflect.New(t)
	cpPtr.Elem().Set(reflect.ValueOf(v))
	reflectx.Walk(cpPtr.Interface(), meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
		if fv.Kind() == reflect.String {
			fv.SetString(m.transform(fv.String(), fm.Strategy))
		}
	})

	return cpPtr.Elem().Interface(), nil
}

// RedactInPlace mutates the struct pointed to by v in-place. Every
// mask-tagged field is replaced with its redaction placeholder.
//
// RedactInPlace panics if v is not a non-nil pointer to a struct.
// Use this for high-throughput code paths where allocations must be
// minimized.
func (m *Masker) RedactInPlace(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		panic("datamask: RedactInPlace requires a non-nil pointer to a struct")
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		panic("datamask: RedactInPlace requires a pointer to a struct")
	}

	meta := m.getOrParseMeta(rv.Type())
	if len(meta.Fields) == 0 {
		return ErrNoMaskableFields
	}

	reflectx.Walk(v, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
		if fv.Kind() == reflect.String {
			fv.SetString(m.transform(fv.String(), fm.Strategy))
		}
	})

	return nil
}

// Apply applies a custom policy to v and returns the result.
// Apply uses Go generics so the caller gets back T:
//
//	masked, err := datamask.Apply(masker, user, datamask.Compose(
//	    masker.RedactPII(),
//	    masker.HashEmails(),
//	))
func Apply[T any](m *Masker, v T, policy Policy) (T, error) {
	result, err := policy(v)
	if err != nil {
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// RedactPII returns a Policy that redacts all mask-tagged fields using the
// Masker's configuration.
func (m *Masker) RedactPII() Policy {
	return func(v any) (any, error) {
		t := reflect.TypeOf(v)
		if t.Kind() != reflect.Struct {
			return v, nil
		}
		meta := m.getOrParseMeta(t)
		if len(meta.Fields) == 0 {
			return v, nil
		}
		cpPtr := shallowCopy(v)
		reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
			if fv.Kind() == reflect.String {
				fv.SetString(m.transform(fv.String(), fm.Strategy))
			}
		})
		return reflect.ValueOf(cpPtr).Elem().Interface(), nil
	}
}

// HashEmails returns a Policy that hashes fields tagged mask:"hash"
// using SHA-256. Other mask-tagged fields are left unchanged.
func (m *Masker) HashEmails() Policy {
	return func(v any) (any, error) {
		t := reflect.TypeOf(v)
		if t.Kind() != reflect.Struct {
			return v, nil
		}
		meta := m.getOrParseMeta(t)
		if len(meta.Fields) == 0 {
			return v, nil
		}
		cpPtr := shallowCopy(v)
		reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
			if fv.Kind() != reflect.String {
				return
			}
			if fm.Strategy == HashStrategy {
				fv.SetString(Hash(fv.String()))
			}
		})
		return reflect.ValueOf(cpPtr).Elem().Interface(), nil
	}
}

// getOrParseMeta returns the cached TypeMeta for t, parsing and caching
// it if this is the first lookup.
func (m *Masker) getOrParseMeta(t reflect.Type) *TypeMeta {
	if meta, ok := m.cache.Load(t); ok {
		return meta
	}
	meta := parseTags(t)
	m.cache.Store(t, meta)
	return meta
}

// transform applies the strategy to s using the Masker's configuration.
func (m *Masker) transform(s string, st Strategy) string {
	switch st {
	case HashStrategy:
		if m.cfg.HashKey != "" {
			return Tokenize(s, m.cfg.HashKey)
		}
		return Hash(s)
	case TokenizeStrategy:
		return Tokenize(s, m.cfg.TokenizeKey)
	case PartialStrategy:
		return Partial(s)
	default:
		return RedactValue(s)
	}
}

// shallowCopy returns a pointer to a shallow copy of v (v must be a struct
// value, not a pointer). The copy's fields share backing memory for pointer,
// map, and slice types — only the top-level struct is copied.
//
// The returned pointer is suitable for passing to reflectx.Walk, which can
// then set fields on the copy.
func shallowCopy(v any) any {
	rv := reflect.ValueOf(v)
	cpPtr := reflect.New(rv.Type())
	cpPtr.Elem().Set(rv)
	return cpPtr.Interface()
}
