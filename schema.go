package datamask

import (
	"fmt"
	"reflect"
	"strings"
	"time"

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
	// elem is the plan for the element type of a pointer, slice or array.
	elem *compiledSchema
	// warnings lists fields whose masking cannot be verified (ADR-0024).
	warnings  []CompileWarning
	createdAt time.Time
}

// Version is the library version recorded in SchemaMetadata.
const Version = "v0.2.0-dev"

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
		typ:       t,
		createdAt: time.Now(),
		maskable:  t.Implements(typeOfMaskable) || reflect.PointerTo(t).Implements(typeOfMaskable),
	}
	switch t.Kind() {
	case reflect.Struct:
		// Always parse tags, even for Maskable structs, so tag errors
		// surface at Compile and RedactInPlace has a field plan.
		meta, err := parseTags(t)
		if err != nil {
			return nil, err
		}
		for _, f := range meta.Fields {
			if f.Unexported {
				return nil, fmt.Errorf("%w: %v.%s: mask tag on unexported field cannot be applied", ErrInvalidSchema, t.Name(), f.Path)
			}
		}
		if err := m.checkKeys(t, meta); err != nil {
			return nil, err
		}
		plan.meta = meta
		plan.warnings = unverifiableFields(t)
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		// Validate the element eagerly; the container carries no plan.
		elem, err := m.compile(t.Elem())
		if err != nil && !plan.maskable {
			return nil, err
		}
		plan.elem = elem
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

// structPlan returns the plan for the struct that p ultimately describes
// (through pointers, slices and arrays), or nil if there is none.
func (p *compiledSchema) structPlan() *compiledSchema {
	for p != nil && p.meta == nil {
		p = p.elem
	}
	return p
}

// typeName is the display name of the compiled type.
func (p *compiledSchema) typeName() string {
	if n := p.typ.Name(); n != "" {
		return n
	}
	return p.typ.String()
}

// Validate checks that the compiled schema is internally consistent: every
// field has a valid data type and transform and is settable, and the struct
// types reachable from T also compile. It returns nil when valid, or an
// error wrapping ErrInvalidSchema (or the tag error) for the first problem.
// Call it at startup to fail before serving traffic.
func (s *Schema[T]) Validate() error {
	if err := s.check(); err != nil {
		return err
	}
	return s.masker.validate(s.plan, map[reflect.Type]bool{})
}

func (m *Masker) validate(p *compiledSchema, seen map[reflect.Type]bool) error {
	if p == nil || seen[p.typ] {
		return nil
	}
	seen[p.typ] = true
	if p.elem != nil {
		if err := m.validate(p.elem, seen); err != nil {
			return err
		}
	}
	if p.meta == nil {
		return nil
	}
	for _, f := range p.meta.Fields {
		switch {
		case f.Unexported:
			return fmt.Errorf("%w: %s.%s: mask tag on unexported field", ErrInvalidSchema, p.typeName(), f.Path)
		case f.DataType < DataTypeEmail || f.DataType > DataTypeJWT:
			return fmt.Errorf("%w: %s.%s: %w", ErrInvalidSchema, p.typeName(), f.Path, ErrUnknownDataType)
		case f.Transform > TransformPartial:
			return fmt.Errorf("%w: %s.%s: %w", ErrInvalidSchema, p.typeName(), f.Path, ErrUnknownTransform)
		}
	}
	// Struct types nested in fields are compiled lazily during Redact;
	// compile them now so their tag errors surface at startup.
	return m.validateFieldTypes(p.typ, seen)
}

func (m *Masker) validateFieldTypes(t reflect.Type, seen map[reflect.Type]bool) error {
	for i := range t.NumField() {
		ft := t.Field(i).Type
		for {
			switch ft.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
				ft = ft.Elem()
				continue
			}
			break
		}
		if ft.Kind() != reflect.Struct || ft.PkgPath() == "" {
			continue
		}
		nested, err := m.compile(ft)
		if err != nil {
			return fmt.Errorf("%w: field %s.%s: %w", ErrInvalidSchema, t.Name(), t.Field(i).Name, err)
		}
		if err := m.validate(nested, seen); err != nil {
			return err
		}
	}
	return nil
}

// Metadata returns lifecycle information about the Schema. A zero-value
// Schema returns the zero SchemaMetadata.
func (s *Schema[T]) Metadata() SchemaMetadata {
	if s.check() != nil {
		return SchemaMetadata{}
	}
	return SchemaMetadata{
		TypeName:  s.plan.typeName(),
		MaskerID:  s.masker.id,
		Version:   Version,
		CreatedAt: s.plan.createdAt,
	}
}

// Warnings returns the non-fatal findings from compilation: fields whose
// masking cannot be verified at compile time (chan, func, unsafe.Pointer,
// and interface-typed fields that are not Maskable). The slice is a copy.
func (s *Schema[T]) Warnings() []CompileWarning {
	if s.check() != nil {
		return nil
	}
	sp := s.plan.structPlan()
	if sp == nil || len(sp.warnings) == 0 {
		return nil
	}
	return append([]CompileWarning(nil), sp.warnings...)
}

// Explain returns a human-readable report of what the Schema will do: each
// field it touches, its data type and its transform. The format is
// line-oriented and stable; field paths are dot-separated.
func (s *Schema[T]) Explain() string {
	if s.check() != nil {
		return "Schema: (uninitialized)\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Schema: %s\n", s.plan.typeName())
	if s.plan.maskable {
		b.WriteString("\n  Maskable: Mask() takes precedence over the field plan\n")
	}
	if sp := s.plan.structPlan(); sp != nil {
		for _, f := range sp.meta.Fields {
			fmt.Fprintf(&b, "\n  %s (%s)\n    data type: %s\n    transform: %s\n", f.Path, f.GoType, f.DataType, f.Transform)
		}
	}
	for _, w := range s.Warnings() {
		fmt.Fprintf(&b, "\n  warning: %s: %s\n", w.FieldPath, w.Reason)
	}
	return b.String()
}

// unverifiableFields reports exported fields of struct type t (recursing
// into nested structs) whose masking cannot be verified at compile time.
func unverifiableFields(t reflect.Type) []CompileWarning {
	var out []CompileWarning
	walkUnverifiable(t, t.Name(), map[reflect.Type]bool{t: true}, &out)
	return out
}

func walkUnverifiable(t reflect.Type, prefix string, seen map[reflect.Type]bool, out *[]CompileWarning) {
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		path := prefix + "." + f.Name
		ft := f.Type
		for {
			switch ft.Kind() {
			case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
				ft = ft.Elem()
				continue
			}
			break
		}
		switch {
		case ft.Kind() == reflect.Chan, ft.Kind() == reflect.Func, ft.Kind() == reflect.UnsafePointer:
			*out = append(*out, CompileWarning{path, fmt.Sprintf("%s-typed field is not masked", ft.Kind())})
		case ft.Kind() == reflect.Interface && !ft.Implements(typeOfMaskable):
			*out = append(*out, CompileWarning{path, "interface-typed field; dynamic contents are not verified"})
		case ft.Kind() == reflect.Struct && !seen[ft] && ft.PkgPath() != "":
			seen[ft] = true
			walkUnverifiable(ft, path, seen, out)
		}
	}
}

// checkKeys rejects hash and tokenize fields when the Masker has no key for
// them. A missing key must fail at Compile, never produce a weak,
// unkeyed pseudonym at runtime (ADR-0024).
func (m *Masker) checkKeys(t reflect.Type, meta *reflectx.TypeMeta) error {
	for _, f := range meta.Fields {
		switch {
		case f.Transform == TransformHash && m.cfg.HashKey == "":
			return fmt.Errorf("%w: %s.%s: transform hash requires a key; configure WithHashKey", ErrInvalidSchema, t.Name(), f.Path)
		case f.Transform == TransformTokenize && m.cfg.TokenizeKey == "":
			return fmt.Errorf("%w: %s.%s: transform tokenize requires a key; configure WithTokenizeKey", ErrInvalidSchema, t.Name(), f.Path)
		}
	}
	return nil
}
