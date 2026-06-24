package reflectx

import "reflect"

// Walk traverses the struct fields described by fields on the value v and
// calls visitor for each field that is valid and exported.
//
// v may be a struct or a pointer to a struct. If v is a nil pointer, Walk
// is a no-op.
//
// fields is typically obtained from a cached *TypeMeta. Each FieldMeta.Index
// is passed to reflect.Value.FieldByIndex to reach nested and embedded fields.
//
// visitor receives the reflect.Value of the field and the corresponding
// FieldMeta. The field value is settable only if v was an addressable
// pointer to a struct; otherwise the visitor can read but not mutate.
func Walk(v any, fields []FieldMeta, visitor func(field reflect.Value, fm FieldMeta)) {
	rv := reflect.ValueOf(v)

	// Dereference pointer.
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}

	if rv.Kind() != reflect.Struct {
		panic("reflectx: Walk called with non-struct value")
	}

	for _, fm := range fields {
		fv, ok := fieldByIndex(rv, fm.Index)
		if !ok {
			continue
		}
		visitor(fv, fm)
	}
}

// fieldByIndex walks the value tree step by step following the index path.
// It returns (Value, false) if any step encounters a nil pointer or an
// out-of-range index — the caller should skip the field. Unlike
// reflect.Value.FieldByIndex, this does not panic on nil pointers.
func fieldByIndex(v reflect.Value, index []int) (reflect.Value, bool) {
	for idx, i := range index {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return reflect.Value{}, false
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		if i < 0 || i >= v.NumField() {
			return reflect.Value{}, false
		}
		// Only check the leaf field for export status. Intermediate
		// embedded struct fields may be unexported but their promoted
		// fields are still reachable through the value tree.
		isLeaf := idx == len(index)-1
		if isLeaf && v.Type().Field(i).PkgPath != "" {
			return reflect.Value{}, false
		}
		v = v.Field(i)
	}
	return v, true
}
