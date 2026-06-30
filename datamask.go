package datamask

import (
	"fmt"
	"reflect"

	"github.com/datamaskio/datamask/internal/reflectx"
)

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
	m.cfg.initTokenizeMAC()
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
// If v's type has no mask-tagged fields, the copy is returned unchanged.
func Redact[T any](m *Masker, v T) (T, error) {
	result, err := m.redact(v)
	if err != nil {
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// redact is the type-erased implementation. It handles structs, slices,
// arrays, and pointers to structs. Maps and other types return an error.
func (m *Masker) redact(v any) (any, error) {
	return m.redactVisited(v, map[uintptr]bool{})
}

func (m *Masker) redactVisited(v any, visited map[uintptr]bool) (any, error) {
	// Maskable check: if the value implements Maskable, use Mask()
	// instead of reflection-based walking.
	if maskable, ok := v.(Maskable); ok {
		return maskable.Mask(), nil
	}

	rv := reflect.ValueOf(v)

	// Pointer-receiver Maskable: non-pointer T where *T implements Maskable.
	if rv.Kind() != reflect.Pointer && reflect.PointerTo(rv.Type()).Implements(typeOfMaskable) {
		newPtr := reflect.New(rv.Type())
		newPtr.Elem().Set(rv)
		result := newPtr.Interface().(Maskable).Mask()
		if rResult := reflect.ValueOf(result); rResult.Kind() == reflect.Pointer {
			return rResult.Elem().Interface(), nil
		}
		return result, nil
	}

	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			return v, nil
		}
		ptr := rv.Pointer()
		if visited[ptr] {
			return v, nil // cycle detected — return original pointer
		}
		visited[ptr] = true
		result, err := m.redactVisited(rv.Elem().Interface(), visited)
		if err != nil {
			return nil, err
		}
		cpPtr := reflect.New(rv.Type().Elem())
		cpPtr.Elem().Set(reflect.ValueOf(result))
		return cpPtr.Interface(), nil

	case reflect.Struct:
		return m.redactStructVisited(v, visited)

	case reflect.Slice:
		if rv.IsNil() {
			return v, nil
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			elem := rv.Index(i).Interface()
			redacted, err := m.redactVisited(elem, visited)
			if err != nil {
				out.Index(i).Set(rv.Index(i))
				continue
			}
			out.Index(i).Set(reflect.ValueOf(redacted))
		}
		return out.Interface(), nil

	case reflect.Array:
		out := reflect.New(rv.Type()).Elem()
		for i := range rv.Len() {
			elem := rv.Index(i).Interface()
			redacted, err := m.redactVisited(elem, visited)
			if err != nil {
				out.Index(i).Set(rv.Index(i))
				continue
			}
			out.Index(i).Set(reflect.ValueOf(redacted))
		}
		return out.Interface(), nil

	default:
		return nil, fmt.Errorf("datamask: Redact requires a struct, slice, or array, got %v", rv.Kind())
	}
}

func (m *Masker) redactStructVisited(v any, visited map[uintptr]bool) (any, error) {
	t := reflect.TypeOf(v)
	meta := m.getOrParseMeta(t)

	cpPtr := reflect.New(t)
	cpPtr.Elem().Set(reflect.ValueOf(v))

	// Pass 0: tag-optional Maskable fields — fields whose type implements
	// Maskable are redacted even without a mask tag.
	applyMaskableFields(cpPtr.Elem())

	// Pass 1: apply mask-tag transforms to tagged fields.
	// Maskable takes precedence over tag strategy.
	if len(meta.Fields) > 0 {
		reflectx.Walk(cpPtr.Interface(), meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
			// Maskable takes precedence over tag-based strategy.
			if result, ok := callMaskOnField(fv); ok {
				fv.Set(reflect.ValueOf(result))
				return
			}
			if fv.Kind() == reflect.String {
				fv.SetString(m.transform(fv.String(), fm.Strategy))
			}
			if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
				newVal := m.transform(fv.Elem().String(), fm.Strategy)
				newPtr := reflect.New(fv.Type().Elem())
				newPtr.Elem().SetString(newVal)
				fv.Set(newPtr)
			}
		})
	}

	// Pass 2: recursively redact container fields.
	rv := cpPtr.Elem()
	for i := range rv.NumField() {
		fv := rv.Field(i)
		if !fv.CanSet() {
			continue
		}
		if !needsRecurse(fv) {
			continue
		}
		redacted, err := m.redactVisited(fv.Interface(), visited)
		if err == nil {
			fv.Set(reflect.ValueOf(redacted))
		}
	}

	return cpPtr.Elem().Interface(), nil
}

// needsRecurse reports whether the value contains a struct that should
// be recursively redacted.
func needsRecurse(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return v.Len() > 0
	case reflect.Pointer:
		return !v.IsNil() && needsRecurse(v.Elem())
	case reflect.Struct:
		return true
	}
	return false
}

// RedactAny is the type-erased version of Redact. It accepts any value
// and returns any. Prefer the generic Redact[T] when the concrete type
// is known at compile time.
func (m *Masker) RedactAny(v any) (any, error) {
	return m.redact(v)
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

	// Tag-optional: apply Maskable to all fields.
	applyMaskableFields(rv)

	meta := m.getOrParseMeta(rv.Type())
	if len(meta.Fields) == 0 {
		return nil
	}

	reflectx.Walk(v, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
		// Maskable takes precedence over tag-based strategy.
		if result, ok := callMaskOnField(fv); ok {
			fv.Set(reflect.ValueOf(result))
			return
		}
		if fv.Kind() == reflect.String {
			fv.SetString(m.transform(fv.String(), fm.Strategy))
		}
		if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
			newVal := m.transform(fv.Elem().String(), fm.Strategy)
			newPtr := reflect.New(fv.Type().Elem())
			newPtr.Elem().SetString(newVal)
			fv.Set(newPtr)
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
		cpPtr := shallowCopy(v)
		rv := reflect.ValueOf(cpPtr).Elem()

		// Tag-optional: apply Maskable to all fields.
		applyMaskableFields(rv)

		meta := m.getOrParseMeta(t)
		if len(meta.Fields) > 0 {
			reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
				// Maskable takes precedence over tag-based strategy.
				if result, ok := callMaskOnField(fv); ok {
					fv.Set(reflect.ValueOf(result))
					return
				}
				if fv.Kind() == reflect.String {
					fv.SetString(m.transform(fv.String(), fm.Strategy))
				}
				if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
					newVal := m.transform(fv.Elem().String(), fm.Strategy)
					newPtr := reflect.New(fv.Type().Elem())
					newPtr.Elem().SetString(newVal)
					fv.Set(newPtr)
				}
			})
		}
		return rv.Interface(), nil
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
		cpPtr := shallowCopy(v)
		rv := reflect.ValueOf(cpPtr).Elem()

		// Tag-optional: apply Maskable to all fields.
		applyMaskableFields(rv)

		meta := m.getOrParseMeta(t)
		if len(meta.Fields) > 0 {
			reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
				// Maskable takes precedence over hash strategy.
				if result, ok := callMaskOnField(fv); ok {
					fv.Set(reflect.ValueOf(result))
					return
				}
				if fm.Strategy != HashStrategy {
					return
				}
				if fv.Kind() == reflect.String {
					fv.SetString(Hash(fv.String()))
				}
				if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
					newVal := Hash(fv.Elem().String())
					newPtr := reflect.New(fv.Type().Elem())
					newPtr.Elem().SetString(newVal)
					fv.Set(newPtr)
				}
			})
		}
		return rv.Interface(), nil
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
		if m.cfg.tokenizeMAC != nil {
			return TokenizeWithMAC(s, m.cfg.tokenizeMAC)
		}
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
