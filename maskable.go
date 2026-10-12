package datamask

import "reflect"

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
// to the caller and the field is left unchanged.
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
// Returns (nil, nil, false) when fv does not implement Maskable or when
// fv is a nil pointer — the caller should fall through to other strategies.
// Returns (result, nil, true) on success, or (nil, err, true) on Mask() error.
func callMaskOnField(fv reflect.Value) (any, error, bool) {
	t := fv.Type()

	// Direct: T implements Maskable (includes pointers to Maskable value types).
	if t.Implements(typeOfMaskable) {
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			return nil, nil, false
		}
		result, err := fv.Interface().(Maskable).Mask()
		return result, err, true
	}

	// Pointer-receiver: non-pointer T where *T implements Maskable.
	if t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(typeOfMaskable) {
		newPtr := reflect.New(t)
		newPtr.Elem().Set(fv)
		result, err := newPtr.Interface().(Maskable).Mask()
		if err != nil {
			return nil, err, true
		}
		// If Mask() returns a pointer, dereference to match the input type.
		if rv := reflect.ValueOf(result); rv.Kind() == reflect.Pointer {
			return rv.Elem().Interface(), nil, true
		}
		return result, nil, true
	}

	return nil, nil, false
}

// applyMaskableFields walks all exported fields of a struct value and
// calls Mask() on any field whose type implements Maskable. Embedded
// structs are promoted. Pointer fields are dereferenced.
//
// This implements tag-optional masking: a field does not need a mask
// tag when its type carries the Maskable contract.
func applyMaskableFields(rv reflect.Value) {
	t := rv.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		fv := rv.Field(i)
		if !fv.CanSet() {
			continue
		}

		if sf.Anonymous {
			// Promote embedded struct fields.
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct {
				applyMaskableFields(fv)
			}
			continue
		}

		if result, _, ok := callMaskOnField(fv); ok && result != nil {
			fv.Set(reflect.ValueOf(result))
		}
	}
}
