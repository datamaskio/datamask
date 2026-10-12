package datamask

import (
	"fmt"
	"reflect"
)

// Maskable is implemented by types that control their own masking logic.
// When Redact encounters a Maskable value, it calls Mask() instead of
// using the tag-based reflection strategy.
//
// Maskable types do not need a mask tag — the interface contract is
// sufficient for automatic redaction. When both a mask tag and the
// Maskable interface are present, Maskable takes precedence.
//
// The error return allows implementations to signal failure:
// encryption key unavailable, tokenization service unreachable, input
// validation failure. If Mask() returns an error, Redact propagates it
// to the caller wrapped in ErrMaskFailed (the failing field is zeroed, never
// left holding its unmasked value).
type Maskable interface {
	Mask() (any, error)
}

var typeOfMaskable = reflect.TypeFor[Maskable]()

// callMaskOnField checks whether the field value fv implements Maskable
// and, if so, calls Mask() and returns the result. It handles both value
// and pointer receivers:
//
//   - If T implements Maskable, calls fv.Interface().(Maskable).Mask().
//   - If *T implements Maskable (but T doesn't), creates an addressable
//     copy of fv and calls Mask() on the pointer.
//
// Returns (nil, false, nil) when fv does not implement Maskable or when
// fv is a nil pointer — the caller should fall through to other strategies.
// Otherwise ok is true and the result or Mask()'s error is returned.
func callMaskOnField(fv reflect.Value) (result any, ok bool, err error) {
	t := fv.Type()

	// Direct: T implements Maskable (includes pointers to Maskable value types).
	if t.Implements(typeOfMaskable) {
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			return nil, false, nil
		}
		result, err = fv.Interface().(Maskable).Mask()
		return result, true, err
	}

	// Pointer-receiver: non-pointer T where *T implements Maskable.
	if t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(typeOfMaskable) {
		newPtr := reflect.New(t)
		newPtr.Elem().Set(fv)
		result, err = newPtr.Interface().(Maskable).Mask()
		if err != nil {
			return nil, true, err
		}
		// If Mask() returns a pointer, dereference to match the input type.
		if rv := reflect.ValueOf(result); rv.Kind() == reflect.Pointer && !rv.IsNil() {
			return rv.Elem().Interface(), true, nil
		}
		return result, true, nil
	}

	return nil, false, nil
}

// maskField applies Maskable to the settable field fv. It reports whether
// fv was Maskable. It fails closed: on a Mask() error, a nil result or a
// result whose type cannot be assigned to fv, the field is zeroed and an
// error wrapping ErrMaskFailed is returned.
func maskField(fv reflect.Value) (bool, error) {
	result, ok, err := callMaskOnField(fv)
	if !ok {
		return false, nil
	}
	if err != nil {
		fv.SetZero()
		return true, fmt.Errorf("%w: %w", ErrMaskFailed, err)
	}
	rv := reflect.ValueOf(result)
	if !rv.IsValid() || !rv.Type().AssignableTo(fv.Type()) {
		fv.SetZero()
		return true, fmt.Errorf("%w: Mask() returned %T, want %v", ErrMaskFailed, result, fv.Type())
	}
	fv.Set(rv)
	return true, nil
}

// applyMaskableFields walks all exported fields of a struct value and
// calls Mask() on any field whose type implements Maskable. Embedded
// structs are promoted. Pointer fields are dereferenced.
//
// This implements tag-optional masking: a field does not need a mask
// tag when its type carries the Maskable contract. Every Maskable field
// is attempted; the first error is returned.
func applyMaskableFields(rv reflect.Value) error {
	var firstErr error
	t := rv.Type()
	for i := range t.NumField() {
		sf := t.Field(i)

		// Embedded structs are promoted even when the embedded type's own
		// name is unexported: their exported fields are still reachable
		// and settable, and skipping them would leave Maskable fields
		// unmasked.
		if sf.Anonymous {
			fv := rv.Field(i)
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct {
				if err := applyMaskableFields(fv); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			continue
		}

		if !sf.IsExported() {
			continue
		}
		fv := rv.Field(i)
		if !fv.CanSet() {
			continue
		}

		if _, err := maskField(fv); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
