package datamask

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// Masker is the core redaction engine. Create one with New and reuse it
// across goroutines. A zero-value Masker is not usable; always use New.
type Masker struct {
	cfg     Config
	schemas *sync.Map // map[reflect.Type]*compiledSchema; nil means not created by New
}

// New creates a Masker with the given options. A Masker is safe for
// concurrent use.
func New(opts ...Option) *Masker {
	m := &Masker{
		cfg: Config{
			DetectSecrets: true,
		},
		schemas: &sync.Map{},
	}
	for _, o := range opts {
		o(&m.cfg)
	}
	m.cfg.initTokenizeMAC()
	return m
}

// check validates the receiver: nil → ErrNilReceiver, zero-value Masker
// (not created by New) → ErrUninitialized.
func (m *Masker) check() error {
	if m == nil {
		return ErrNilReceiver
	}
	if m.schemas == nil {
		return ErrUninitialized
	}
	return nil
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
	// Same path as Compile[T](m).Redact(v), but the Schema stays on the
	// stack so the convenience wrapper allocates nothing extra.
	if err := m.check(); err != nil {
		var zero T
		return zero, err
	}
	plan, err := m.compile(reflect.TypeFor[T]())
	if err != nil {
		var zero T
		return zero, err
	}
	s := Schema[T]{masker: m, plan: plan}
	return s.Redact(v)
}

// redact is the type-erased implementation. It handles structs, slices,
// arrays, and pointers to structs. Maps and other types return an error.
func (m *Masker) redact(v any) (any, error) {
	return m.redactVisited(v, map[uintptr]bool{})
}

func (m *Masker) redactVisited(v any, visited map[uintptr]bool) (any, error) {
	// Maskable check: if the value implements Maskable, use Mask()
	// instead of reflection-based walking.
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, fmt.Errorf("%w: nil value", ErrInvalidInput)
	}
	if maskable, ok := v.(Maskable); ok {
		return checkMaskResult(rv.Type(), maskable)
	}

	// Pointer-receiver Maskable: non-pointer T where *T implements Maskable.
	if rv.Kind() != reflect.Pointer && reflect.PointerTo(rv.Type()).Implements(typeOfMaskable) {
		newPtr := reflect.New(rv.Type())
		newPtr.Elem().Set(rv)
		return checkMaskResult(rv.Type(), newPtr.Interface().(Maskable))
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
				return nil, err
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
				return nil, err
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
	meta, err := m.getOrParseMeta(t)
	if err != nil {
		return nil, err
	}

	cpPtr := reflect.New(t)
	cpPtr.Elem().Set(reflect.ValueOf(v))

	// Pass 0: tag-optional Maskable fields — fields whose type implements
	// Maskable are redacted even without a mask tag.
	if err := applyMaskableFields(cpPtr.Elem()); err != nil {
		return nil, err
	}

	// Pass 1: apply mask-tag transforms to tagged fields.
	// Maskable takes precedence over tag transform.
	var maskErr error
	if len(meta.Fields) > 0 {
		walkErr := reflectx.Walk(cpPtr.Interface(), meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
			// Maskable takes precedence over tag-based transform.
			if ok, err := maskField(fv); ok {
				if err != nil && maskErr == nil {
					maskErr = err
				}
				return
			}
			if fv.Kind() == reflect.String {
				fv.SetString(m.transform(fv.String(), fm.Transform))
			}
			if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
				newVal := m.transform(fv.Elem().String(), fm.Transform)
				newPtr := reflect.New(fv.Type().Elem())
				newPtr.Elem().SetString(newVal)
				fv.Set(newPtr)
			}
		})
		if walkErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedType, walkErr)
		}
	}

	if maskErr != nil {
		return nil, maskErr
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
		if err != nil {
			return nil, err
		}
		fv.Set(reflect.ValueOf(redacted))
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
	if err := m.check(); err != nil {
		return nil, err
	}
	return m.redact(v)
}

// RedactInPlace mutates the struct pointed to by v in-place. Every
// mask-tagged field is replaced with its redaction placeholder.
//
// RedactInPlace returns ErrInvalidInput if v is not a non-nil pointer to
// a struct, or ErrUnsupportedType if it's a pointer to a non-struct type.
// Use this for high-throughput code paths where allocations must be
// minimized.
func (m *Masker) RedactInPlace(v any) error {
	if err := m.check(); err != nil {
		return err
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		return fmt.Errorf("%w: expected pointer, got %v", ErrInvalidInput, rv.Kind())
	}
	if rv.IsNil() {
		return fmt.Errorf("%w: nil pointer", ErrInvalidInput)
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("%w: expected pointer to struct, got pointer to %v", ErrUnsupportedType, rv.Kind())
	}

	// Tag-optional: apply Maskable to all fields. Failing fields are zeroed;
	// masking continues so no other field is left unmasked.
	maskErr := applyMaskableFields(rv)

	meta, err := m.getOrParseMeta(rv.Type())
	if err != nil {
		return err
	}
	if len(meta.Fields) == 0 {
		return maskErr
	}

	walkErr := reflectx.Walk(v, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
		// Maskable takes precedence over tag-based transform.
		if ok, err := maskField(fv); ok {
			if err != nil && maskErr == nil {
				maskErr = err
			}
			return
		}
		if fv.Kind() == reflect.String {
			fv.SetString(m.transform(fv.String(), fm.Transform))
		}
		if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
			newVal := m.transform(fv.Elem().String(), fm.Transform)
			newPtr := reflect.New(fv.Type().Elem())
			newPtr.Elem().SetString(newVal)
			fv.Set(newPtr)
		}
	})
	if walkErr != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedType, walkErr)
	}

	return maskErr
}

// Apply applies a custom policy to v and returns the result.
// Apply uses Go generics so the caller gets back T:
//
//	masked, err := datamask.Apply(masker, user, datamask.Compose(
//	    masker.RedactPII(),
//	    masker.HashEmails(),
//	))
func Apply[T any](m *Masker, v T, policy Policy) (T, error) {
	var zero T
	if err := m.check(); err != nil {
		return zero, err
	}
	if policy == nil {
		return zero, fmt.Errorf("%w: nil policy", ErrInvalidInput)
	}
	result, err := policy(v)
	if err != nil {
		return zero, err
	}
	out, ok := result.(T)
	if !ok {
		return zero, fmt.Errorf("%w: policy returned %T, want %T", ErrInvalidInput, result, zero)
	}
	return out, nil
}

// RedactPII returns a Policy that redacts all mask-tagged fields using the
// Masker's configuration.
func (m *Masker) RedactPII() Policy {
	return func(v any) (any, error) {
		if err := m.check(); err != nil {
			return nil, err
		}
		t := reflect.TypeOf(v)
		if t.Kind() != reflect.Struct {
			return v, nil
		}
		cpPtr := shallowCopy(v)
		rv := reflect.ValueOf(cpPtr).Elem()

		// Tag-optional: apply Maskable to all fields.
		if err := applyMaskableFields(rv); err != nil {
			return nil, err
		}

		meta, err := m.getOrParseMeta(t)
		if err != nil {
			return nil, err
		}
		var maskErr error
		if len(meta.Fields) > 0 {
			walkErr := reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
				// Maskable takes precedence over tag-based transform.
				if ok, err := maskField(fv); ok {
					if err != nil && maskErr == nil {
						maskErr = err
					}
					return
				}
				if fv.Kind() == reflect.String {
					fv.SetString(m.transform(fv.String(), fm.Transform))
				}
				if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
					newVal := m.transform(fv.Elem().String(), fm.Transform)
					newPtr := reflect.New(fv.Type().Elem())
					newPtr.Elem().SetString(newVal)
					fv.Set(newPtr)
				}
			})
			if walkErr != nil {
				return nil, fmt.Errorf("%w: %v", ErrUnsupportedType, walkErr)
			}
		}
		if maskErr != nil {
			return nil, maskErr
		}
		return rv.Interface(), nil
	}
}

// HashEmails returns a Policy that hashes fields whose tag transform is hash (e.g. mask:"email,hash")
// using SHA-256. Other mask-tagged fields are left unchanged.
func (m *Masker) HashEmails() Policy {
	return func(v any) (any, error) {
		if err := m.check(); err != nil {
			return nil, err
		}
		t := reflect.TypeOf(v)
		if t.Kind() != reflect.Struct {
			return v, nil
		}
		cpPtr := shallowCopy(v)
		rv := reflect.ValueOf(cpPtr).Elem()

		// Tag-optional: apply Maskable to all fields.
		if err := applyMaskableFields(rv); err != nil {
			return nil, err
		}

		meta, err := m.getOrParseMeta(t)
		if err != nil {
			return nil, err
		}
		var maskErr error
		if len(meta.Fields) > 0 {
			walkErr := reflectx.Walk(cpPtr, meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
				// Maskable takes precedence over hash transform.
				if ok, err := maskField(fv); ok {
					if err != nil && maskErr == nil {
						maskErr = err
					}
					return
				}
				if fm.Transform != TransformHash {
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
			if walkErr != nil {
				return nil, fmt.Errorf("%w: %v", ErrUnsupportedType, walkErr)
			}
		}
		if maskErr != nil {
			return nil, maskErr
		}
		return rv.Interface(), nil
	}
}

// getOrParseMeta returns the field metadata for struct type t from the
// Masker's compiled-schema cache, compiling it on first use.
func (m *Masker) getOrParseMeta(t reflect.Type) (*reflectx.TypeMeta, error) {
	plan, err := m.compile(t)
	if err != nil {
		return nil, err
	}
	return plan.meta, nil
}

// transform applies the transform to s using the Masker's configuration.
func (m *Masker) transform(s string, tr Transform) string {
	switch tr {
	case TransformHash:
		if m.cfg.HashKey != "" {
			return Tokenize(s, m.cfg.HashKey)
		}
		return Hash(s)
	case TransformTokenize:
		if m.cfg.tokenizeMAC != nil {
			return TokenizeWithMAC(s, m.cfg.tokenizeMAC)
		}
		return Tokenize(s, m.cfg.TokenizeKey)
	case TransformPartial:
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

// checkMaskResult calls Mask() and verifies the result has type want
// (dereferencing a returned pointer for pointer-receiver types). Any
// failure wraps ErrMaskFailed so callers never see an unmasked value.
func checkMaskResult(want reflect.Type, mk Maskable) (any, error) {
	result, err := mk.Mask()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMaskFailed, err)
	}
	rv := reflect.ValueOf(result)
	if rv.IsValid() && rv.Kind() == reflect.Pointer && want.Kind() != reflect.Pointer && !rv.IsNil() {
		rv = rv.Elem()
		result = rv.Interface()
	}
	if !rv.IsValid() || rv.Type() != want {
		return nil, fmt.Errorf("%w: Mask() returned %T, want %v", ErrMaskFailed, result, want)
	}
	return result, nil
}
