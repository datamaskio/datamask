package datamask

import "reflect"

// Maskable is implemented by types that control their own masking logic.
// When Redact encounters a Maskable value, it calls Mask() instead of
// using the tag-based reflection strategy.
//
// Maskable types do not need a mask tag — the interface contract is
// sufficient for automatic redaction. When both a mask tag and the
// Maskable interface are present, Maskable takes precedence.
type Maskable interface {
	Mask() any
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
// The bool is false when fv does not implement Maskable, or when fv is
// a nil pointer — the caller should fall through to other strategies.
func callMaskOnField(fv reflect.Value) (any, bool) {
	t := fv.Type()

	// Direct: T implements Maskable (includes pointers to Maskable value types).
	if t.Implements(typeOfMaskable) {
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			return nil, false
		}
		return fv.Interface().(Maskable).Mask(), true
	}

	// Pointer-receiver: non-pointer T where *T implements Maskable.
	if t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(typeOfMaskable) {
		newPtr := reflect.New(t)
		newPtr.Elem().Set(fv)
		result := newPtr.Interface().(Maskable).Mask()
		// If Mask() returns a pointer, dereference to match the input type.
		if rv := reflect.ValueOf(result); rv.Kind() == reflect.Pointer {
			return rv.Elem().Interface(), true
		}
		return result, true
	}

	return nil, false
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

		if result, ok := callMaskOnField(fv); ok {
			fv.Set(reflect.ValueOf(result))
		}
	}
}