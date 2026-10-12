package datamask

import (
	"fmt"
	"reflect"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// compiledSchema is the type-erased plan stored in a Masker's cache
// (ADR-0024). It is immutable once published.
type compiledSchema struct {
	typ reflect.Type
	// meta holds the parsed field plan for struct types; nil otherwise.
	meta *reflectx.TypeMeta
	// maskable is true when the type (or a pointer to it) implements
	// Maskable. Maskable always takes precedence over the field plan.
	maskable bool
}

// Schema is a reusable, concurrency-safe compiled masking plan for type T.
// Create one with Compile or MustCompile. The zero value is not usable and
// every method returns ErrUninitialized.
type Schema[T any] struct {
	masker *Masker
	plan   *compiledSchema
}

// Compile parses T's mask tags once and returns a reusable Schema bound to m.
// Tag errors (ErrUnknownDataType, ErrUnknownTransform) surface here rather
// than on the first Redact call.
//
// T may be a struct, a pointer, slice or array of structs, a Maskable type,
// or an interface type (resolved from the dynamic value at Redact time).
// Other kinds return ErrUnsupportedType. A nil m returns ErrNilReceiver and a
// Masker not created by New returns ErrUninitialized.
//
// Compile is a package function because Go has no generic methods.
func Compile[T any](m *Masker) (*Schema[T], error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	plan, err := m.compile(reflect.TypeFor[T]())
	if err != nil {
		return nil, err
	}
	return &Schema[T]{masker: m, plan: plan}, nil
}

// MustCompile is like Compile but panics on error. It is the only
// intentional panic in the package; use it for package-level
// initialization where a bad tag is a programming error.
func MustCompile[T any](m *Masker) *Schema[T] {
	s, err := Compile[T](m)
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Schema[T]) check() error {
	if s == nil || s.masker == nil || s.plan == nil {
		return ErrUninitialized
	}
	return nil
}

// Redact returns a masked copy of v. It never modifies v. On any error the
// zero value of T is returned.
func (s *Schema[T]) Redact(v T) (T, error) {
	var zero T
	if err := s.check(); err != nil {
		return zero, err
	}
	result, err := s.masker.redact(v)
	if err != nil {
		return zero, err
	}
	out, ok := result.(T)
	if !ok {
		return zero, fmt.Errorf("%w: result is %T, want %T", ErrMaskFailed, result, zero)
	}
	return out, nil
}

// RedactInPlace masks the struct v points to. It returns ErrInvalidInput if
// v is nil and ErrUnsupportedType if T is not a struct.
func (s *Schema[T]) RedactInPlace(v *T) error {
	if err := s.check(); err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("%w: nil pointer", ErrInvalidInput)
	}
	return s.masker.RedactInPlace(v)
}

// compile returns the cached plan for t, building it on first use. The
// first plan stored for a type wins, so concurrent callers share one plan.
func (m *Masker) compile(t reflect.Type) (*compiledSchema, error) {
	if v, ok := m.schemas.Load(t); ok {
		return v.(*compiledSchema), nil
	}
	plan := &compiledSchema{
		typ:      t,
		maskable: t.Implements(typeOfMaskable) || reflect.PointerTo(t).Implements(typeOfMaskable),
	}
	switch t.Kind() {
	case reflect.Struct:
		// Always parse tags, even for Maskable structs, so tag errors
		// surface at Compile and RedactInPlace has a field plan.
		meta, err := parseTags(t)
		if err != nil {
			return nil, err
		}
		plan.meta = meta
	case reflect.Pointer, reflect.Slice, reflect.Array:
		// Validate the element eagerly; the container carries no plan.
		if _, err := m.compile(t.Elem()); err != nil && !plan.maskable {
			return nil, err
		}
	case reflect.Interface:
		// Dynamic: the concrete type is compiled when a value is seen.
	default:
		if !plan.maskable {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedType, t)
		}
	}
	actual, _ := m.schemas.LoadOrStore(t, plan)
	return actual.(*compiledSchema), nil
}
