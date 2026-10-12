package datamask

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// maskerSeq issues Masker IDs.
var maskerSeq atomic.Uint64

// Masker is the core redaction engine. Create one with New and reuse it
// across goroutines. A zero-value Masker is not usable; always use New.
type Masker struct {
	cfg     Config
	id      uint64    // unique per New call; audit metadata only
	schemas *sync.Map // map[reflect.Type]*compiledSchema; nil means not created by New
	touched *sync.Map // map[reflect.Type]bool: type reaches something to mask
}

// New creates a Masker with the given options. A Masker is safe for
// concurrent use.
func New(opts ...Option) *Masker {
	m := &Masker{
		cfg: Config{
			DetectSecrets: true,
		},
		id:      maskerSeq.Add(1),
		schemas: &sync.Map{},
		touched: &sync.Map{},
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

// walkState tracks the traversal path for cycle detection (ADR-0032).
// A pointer is "on the path" while its target is being redacted, so a
// pointer reached again from inside itself is a cycle, while the same
// pointer reached from two sibling branches (a diamond) is not.
type walkState struct {
	path map[uintptr]struct{}
	// maskErr is the first Maskable failure seen by RedactInPlace, which
	// keeps masking the remaining fields before reporting it.
	maskErr error
}

// redact is the type-erased implementation. It handles structs, slices,
// arrays, and pointers to them. Maps and other types return an error.
func (m *Masker) redact(v any) (any, error) {
	return m.redactVisited(v, &walkState{}, 0)
}

// exceedsDepth reports whether depth is past the configured limit.
func (m *Masker) exceedsDepth(depth int) bool {
	return depth > m.cfg.MaxTraversalDepth
}

// redactVisited returns a masked copy of v and never modifies v. Only the
// paths that lead to a maskable field are cloned; subtrees with nothing to
// mask are shared with the input (ADR-0026). depth counts nested struct,
// slice and array levels entered.
func (m *Masker) redactVisited(v any, st *walkState, depth int) (any, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil, fmt.Errorf("%w: nil value", ErrInvalidInput)
	}
	// Maskable check: if the value implements Maskable, use Mask()
	// instead of reflection-based walking.
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
		need, err := m.touches(rv.Type().Elem())
		if err != nil {
			return nil, err
		}
		if !need {
			return v, nil // nothing to mask below: share the target
		}
		ptr := rv.Pointer()
		if _, onPath := st.path[ptr]; onPath {
			return nil, fmt.Errorf("%w: %v", ErrCyclicReference, rv.Type())
		}
		if st.path == nil {
			st.path = map[uintptr]struct{}{}
		}
		st.path[ptr] = struct{}{}
		defer delete(st.path, ptr)

		result, err := m.redactVisited(rv.Elem().Interface(), st, depth)
		if err != nil {
			return nil, err
		}
		cpPtr := reflect.New(rv.Type().Elem())
		cpPtr.Elem().Set(reflect.ValueOf(result))
		return cpPtr.Interface(), nil

	case reflect.Struct:
		return m.redactStructVisited(v, st, depth)

	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return v, nil
		}
		need, err := m.touches(rv.Type().Elem())
		if err != nil {
			return nil, err
		}
		if !need {
			return v, nil // no element needs masking: share the backing array
		}
		if m.exceedsDepth(depth + 1) {
			return nil, fmt.Errorf("%w: limit %d", ErrMaxDepthExceeded, m.cfg.MaxTraversalDepth)
		}
		var out reflect.Value
		if rv.Kind() == reflect.Slice {
			out = reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		} else {
			out = reflect.New(rv.Type()).Elem()
		}
		for i := range rv.Len() {
			redacted, err := m.redactVisited(rv.Index(i).Interface(), st, depth+1)
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

func (m *Masker) redactStructVisited(v any, st *walkState, depth int) (any, error) {
	if m.exceedsDepth(depth + 1) {
		return nil, fmt.Errorf("%w: limit %d", ErrMaxDepthExceeded, m.cfg.MaxTraversalDepth)
	}
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

	// Pass 2: recursively redact fields whose subtree contains something
	// to mask. All other fields keep the value (or pointer) copied from the
	// input, which is the "shared subtree" half of ADR-0026.
	rv := cpPtr.Elem()
	for i := range rv.NumField() {
		fv := rv.Field(i)
		if !fv.CanSet() {
			continue
		}
		switch fv.Kind() {
		case reflect.Struct, reflect.Pointer, reflect.Slice, reflect.Array:
		default:
			continue
		}
		if isMaskableType(fv.Type()) {
			continue // already masked by pass 0 / pass 1
		}
		if (fv.Kind() == reflect.Pointer || fv.Kind() == reflect.Slice) && fv.IsNil() {
			continue
		}
		need, err := m.touches(fv.Type())
		if err != nil {
			return nil, err
		}
		if !need {
			continue
		}
		redacted, err := m.redactVisited(fv.Interface(), st, depth+1)
		if err != nil {
			return nil, err
		}
		fv.Set(reflect.ValueOf(redacted))
	}

	return cpPtr.Elem().Interface(), nil
}

// touches reports whether redacting a value of type t can change or clone
// anything: t (or something reachable from it) has a mask tag, is Maskable,
// or is interface-typed (dynamic contents). Results are cached per Masker.
func (m *Masker) touches(t reflect.Type) (bool, error) {
	switch t.Kind() {
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32,
		reflect.Float64, reflect.Complex64, reflect.Complex128:
		return false, nil
	}
	if v, ok := m.touched.Load(t); ok {
		return v.(bool), nil
	}
	res, err := m.reachesMasking(t, map[reflect.Type]bool{})
	if err != nil {
		return false, err
	}
	// Only the outermost result is cached: intermediate results computed
	// while a type was still "in progress" can be incomplete.
	m.touched.Store(t, res)
	return res, nil
}

func (m *Masker) reachesMasking(t reflect.Type, seen map[reflect.Type]bool) (bool, error) {
	if seen[t] {
		return false, nil
	}
	seen[t] = true
	if t.Implements(typeOfMaskable) || reflect.PointerTo(t).Implements(typeOfMaskable) {
		return true, nil
	}
	switch t.Kind() {
	case reflect.Interface:
		return true, nil
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return m.reachesMasking(t.Elem(), seen)
	case reflect.Struct:
		plan, err := m.compile(t)
		if err != nil {
			return false, err
		}
		if len(plan.meta.Fields) > 0 {
			return true, nil
		}
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			ok, err := m.reachesMasking(f.Type, seen)
			if err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
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
// mask-tagged field, including those in nested structs, pointer targets,
// slice elements and arrays, is replaced with its redaction placeholder.
//
// RedactInPlace returns ErrInvalidInput if v is not a non-nil pointer to
// a struct, or ErrUnsupportedType if it's a pointer to a non-struct type.
// Use this for high-throughput code paths where allocations must be
// minimized.
//
// It mutates by contract, including data shared through pointers and slices.
// Cycles return ErrCyclicReference and over-deep graphs ErrMaxDepthExceeded;
// after any error v may be partially masked and must not be used. A pointer
// reachable through two fields is masked once per path.
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
	st := &walkState{}
	if err := m.inPlaceStruct(rv, st, 0); err != nil {
		return err
	}
	return st.maskErr
}

// isMaskableType reports whether values of type t are masked by their own
// Mask() method (value or pointer receiver).
func isMaskableType(t reflect.Type) bool {
	return t.Implements(typeOfMaskable) || reflect.PointerTo(t).Implements(typeOfMaskable)
}

// inPlaceStruct masks the addressable struct rv. Maskable failures are
// recorded in st.maskErr and masking continues, so no other field is left
// unmasked; structural errors (cycle, depth) are returned immediately.
func (m *Masker) inPlaceStruct(rv reflect.Value, st *walkState, depth int) error {
	if m.exceedsDepth(depth + 1) {
		return fmt.Errorf("%w: limit %d", ErrMaxDepthExceeded, m.cfg.MaxTraversalDepth)
	}
	t := rv.Type()
	meta, err := m.getOrParseMeta(t)
	if err != nil {
		return err
	}

	// Tag-optional: apply Maskable to all fields.
	if err := applyMaskableFields(rv); err != nil && st.maskErr == nil {
		st.maskErr = err
	}

	if len(meta.Fields) > 0 {
		walkErr := reflectx.Walk(rv.Addr().Interface(), meta.Fields, func(fv reflect.Value, fm reflectx.FieldMeta) {
			// Maskable takes precedence over tag-based transform.
			if ok, err := maskField(fv); ok {
				if err != nil && st.maskErr == nil {
					st.maskErr = err
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
	}

	// Recurse into fields that hold more to mask. Maskable-typed fields were
	// already handled above and must not have Mask() applied twice.
	for i := range rv.NumField() {
		fv := rv.Field(i)
		switch fv.Kind() {
		case reflect.Struct, reflect.Pointer, reflect.Slice, reflect.Array:
		default:
			continue
		}
		if !fv.CanSet() || isMaskableType(fv.Type()) {
			continue
		}
		if err := m.inPlaceValue(fv, st, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// inPlaceValue masks the addressable value fv in place.
func (m *Masker) inPlaceValue(fv reflect.Value, st *walkState, depth int) error {
	switch fv.Kind() {
	case reflect.Struct, reflect.Pointer, reflect.Slice, reflect.Array:
	default:
		return nil
	}
	need, err := m.touches(fv.Type())
	if err != nil || !need {
		return err
	}
	switch fv.Kind() {
	case reflect.Pointer:
		if fv.IsNil() {
			return nil
		}
		ptr := fv.Pointer()
		if _, onPath := st.path[ptr]; onPath {
			return fmt.Errorf("%w: %v", ErrCyclicReference, fv.Type())
		}
		if st.path == nil {
			st.path = map[uintptr]struct{}{}
		}
		st.path[ptr] = struct{}{}
		defer delete(st.path, ptr)
		return m.inPlaceElem(fv.Elem(), st, depth)
	case reflect.Slice, reflect.Array:
		if m.exceedsDepth(depth + 1) {
			return fmt.Errorf("%w: limit %d", ErrMaxDepthExceeded, m.cfg.MaxTraversalDepth)
		}
		for i := range fv.Len() {
			if err := m.inPlaceElem(fv.Index(i), st, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return m.inPlaceStruct(fv, st, depth)
	}
}

// inPlaceElem masks one element or pointer target: a Maskable value is
// replaced by its Mask() result, anything else is walked.
func (m *Masker) inPlaceElem(ev reflect.Value, st *walkState, depth int) error {
	if isMaskableType(ev.Type()) {
		if _, err := maskField(ev); err != nil && st.maskErr == nil {
			st.maskErr = err
		}
		return nil
	}
	return m.inPlaceValue(ev, st, depth)
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
