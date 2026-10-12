package codegen

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// A generated Mask() replaces the runtime's whole reflection walk for its
// type, because Maskable always wins. So the generator must never emit code
// that masks *less* than the Schema path would. It therefore generates a type
// only when it can prove every field is either handled by the generated code
// or has nothing to mask; any other type is skipped with a warning and keeps
// using the Schema path (ADR-0019).

// Warning describes a type the generator skipped, and why.
type Warning struct {
	Type   string // struct name, e.g. "User"
	Reason string
}

func (w Warning) String() string {
	return fmt.Sprintf("datamask: skipping %s: %s", w.Type, w.Reason)
}

// kind classifies a field type for the generator.
type kind int

const (
	kindInert     kind = iota // nothing to mask (ints, bools, time.Time, func, ...)
	kindString                // string or a named string type: a tagged one is redacted
	kindMaskable              // the type has a Mask() method (value or pointer receiver)
	kindUnhandled             // cannot be proven safe: interfaces, unknown imports, ...
)

// verdict is a memoized classification, kept with its reason so a cache hit
// explains itself exactly like the first lookup did.
type verdict struct {
	k   kind
	why string
}

// pkgIndex holds what the generator can learn from the parsed package
// without type-checking: its type declarations and which types declare Mask.
type pkgIndex struct {
	types    map[string]*ast.TypeSpec
	hasMask  map[string]bool    // types declaring a Mask method, any receiver
	inert    map[string]verdict // memoized results for local named types
	visiting map[string]bool
}

func newIndex(pkg *ast.Package) *pkgIndex {
	idx := &pkgIndex{
		types:    map[string]*ast.TypeSpec{},
		hasMask:  map[string]bool{},
		inert:    map[string]verdict{},
		visiting: map[string]bool{},
	}
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						idx.types[ts.Name.Name] = ts
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && d.Name.Name == "Mask" && len(d.Recv.List) == 1 {
					if name := receiverName(d.Recv.List[0].Type); name != "" {
						idx.hasMask[name] = true
					}
				}
			}
		}
	}
	return idx
}

// receiverName returns the type name of a method receiver, looking through
// pointers, parentheses and generic instantiations.
func receiverName(expr ast.Expr) string {
	for {
		switch t := expr.(type) {
		case *ast.StarExpr:
			expr = t.X
		case *ast.ParenExpr:
			expr = t.X
		case *ast.IndexExpr:
			expr = t.X
		case *ast.IndexListExpr:
			expr = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// builtinInert are predeclared types with nothing to mask.
var builtinInert = map[string]bool{
	"bool": true, "byte": true, "rune": true, "uintptr": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
}

// classify returns the kind of a type expression and, for kindUnhandled,
// the reason.
func (idx *pkgIndex) classify(expr ast.Expr) (kind, string) {
	switch t := expr.(type) {
	case *ast.Ident:
		return idx.classifyIdent(t.Name)
	case *ast.StarExpr:
		if _, nested := t.X.(*ast.StarExpr); nested {
			return kindUnhandled, "pointer to pointer"
		}
		return idx.classify(t.X)
	case *ast.ParenExpr:
		return idx.classify(t.X)
	case *ast.ArrayType:
		return idx.classifyContainer(t.Elt, "slice or array")
	case *ast.MapType:
		if k, why := idx.classifyContainer(t.Key, "map key"); k == kindUnhandled {
			return k, why
		}
		return idx.classifyContainer(t.Value, "map value")
	case *ast.SelectorExpr:
		if pkg, ok := t.X.(*ast.Ident); ok && pkg.Name == "time" && (t.Sel.Name == "Time" || t.Sel.Name == "Duration") {
			return kindInert, ""
		}
		return kindUnhandled, fmt.Sprintf("imported type %s may need masking and cannot be inspected", typeExprString(t))
	case *ast.FuncType, *ast.ChanType:
		return kindInert, "" // passed through by the runtime too (ADR-0032)
	case *ast.InterfaceType:
		return kindUnhandled, "interface-typed field: dynamic contents cannot be verified"
	case *ast.StructType:
		return idx.classifyStruct(t, "anonymous struct")
	default:
		return kindUnhandled, fmt.Sprintf("unsupported type expression %s", typeExprString(expr))
	}
}

func (idx *pkgIndex) classifyIdent(name string) (kind, string) {
	if name == "string" {
		return kindString, ""
	}
	if builtinInert[name] {
		return kindInert, ""
	}
	if name == "any" || name == "error" {
		return kindUnhandled, fmt.Sprintf("%s-typed field: dynamic contents cannot be verified", name)
	}
	if idx.hasMask[name] {
		return kindMaskable, ""
	}
	spec, ok := idx.types[name]
	if !ok {
		return kindUnhandled, fmt.Sprintf("unknown type %s", name)
	}
	if spec.TypeParams != nil {
		return kindUnhandled, fmt.Sprintf("generic type %s", name)
	}
	if v, ok := idx.inert[name]; ok {
		return v.k, v.why
	}
	if idx.visiting[name] {
		return kindInert, "" // a recursive type adds no new masking by itself
	}
	idx.visiting[name] = true
	defer delete(idx.visiting, name)

	var (
		k   kind
		why string
	)
	if st, ok := spec.Type.(*ast.StructType); ok {
		k, why = idx.classifyStruct(st, name)
	} else {
		k, why = idx.classify(spec.Type)
	}
	if k == kindUnhandled {
		why = fmt.Sprintf("%s: %s", name, why)
	}
	idx.inert[name] = verdict{k, why}
	return k, why
}

// classifyContainer classifies an element or key type. Elements must have
// nothing to mask: the generated code does not walk containers.
func (idx *pkgIndex) classifyContainer(elem ast.Expr, what string) (kind, string) {
	k, why := idx.classify(elem)
	switch k {
	case kindInert, kindString:
		return kindInert, ""
	case kindMaskable:
		return kindUnhandled, fmt.Sprintf("%s of Maskable values is not generated", what)
	default:
		return kindUnhandled, why
	}
}

// classifyStruct reports whether a struct type has nothing to mask: no
// tagged fields, no Maskable fields, and nothing unhandled.
func (idx *pkgIndex) classifyStruct(st *ast.StructType, name string) (kind, string) {
	if st.Fields == nil {
		return kindInert, ""
	}
	for _, f := range st.Fields.List {
		if tagOf(f) != "" {
			return kindUnhandled, fmt.Sprintf("%s has a mask-tagged field and is used as a nested value", name)
		}
		if !fieldRelevant(f) {
			continue
		}
		switch k, why := idx.classify(f.Type); k {
		case kindMaskable:
			return kindUnhandled, fmt.Sprintf("%s has a Maskable field and is used as a nested value", name)
		case kindUnhandled:
			return kindUnhandled, why
		}
	}
	return kindInert, ""
}

// fieldRelevant reports whether the runtime looks at a field: exported
// fields and embedded fields (whose promoted fields it walks).
func fieldRelevant(f *ast.Field) bool {
	if len(f.Names) == 0 {
		return true
	}
	return ast.IsExported(f.Names[0].Name)
}

// tagOf returns the mask tag of a field, or "" if absent or mask:"-".
func tagOf(f *ast.Field) string {
	if f.Tag == nil {
		return ""
	}
	v, ok := reflectTag(strings.Trim(f.Tag.Value, "`")).Lookup("mask")
	if !ok || v == "-" {
		return ""
	}
	return v
}

// analyzeStruct decides whether a struct can be generated and, if so,
// returns the fields that need generated code.
func (idx *pkgIndex) analyzeStruct(ts *ast.TypeSpec, st *ast.StructType) (structInfo, *Warning) {
	si := structInfo{Name: ts.Name.Name}
	skip := func(format string, args ...any) (structInfo, *Warning) {
		return si, &Warning{Type: si.Name, Reason: fmt.Sprintf(format, args...)}
	}

	if ts.TypeParams != nil {
		return skip("generic type; the concrete type is unknown at generation time, so it keeps using the Schema path")
	}
	if idx.hasMask[si.Name] {
		return si, nil // hand-written Mask(): leave it alone, generate nothing
	}
	if st.Fields == nil {
		return si, nil
	}

	for _, f := range st.Fields.List {
		tag := tagOf(f)
		embedded := len(f.Names) == 0
		name := ""
		if embedded {
			name = typeExprString(f.Type)
		} else {
			name = f.Names[0].Name
		}

		if !fieldRelevant(f) {
			if tag != "" {
				return skip("mask tag on unexported field %s cannot be applied", name)
			}
			continue
		}

		k, why := idx.classify(f.Type)
		if tag != "" {
			if _, tr, err := reflectx.ParseTag(tag); err != nil {
				return skip("field %s has an invalid mask tag %q: %s", name, tag, tagErrorText(err))
			} else if tr != reflectx.TransformRedact && k != kindMaskable {
				return skip("field %s uses transform %s; generated code is redact-only because %s needs Masker keys and policy that generated code cannot see", name, tr, tr)
			}
		}

		switch {
		case embedded:
			if k != kindInert && k != kindString {
				return skip("embedded field %s %s", name, orReason(why, "has masking of its own and its fields are promoted"))
			}
		case k == kindUnhandled:
			return skip("field %s: %s", name, why)
		case k == kindMaskable:
			si.Fields = append(si.Fields, fieldInfo{
				Name:       name,
				IsPointer:  strings.HasPrefix(typeExprString(f.Type), "*"),
				IsMaskable: true,
				FieldType:  typeExprString(f.Type),
			})
		case tag != "":
			if k != kindString {
				return skip("field %s is tagged but has type %s; only string-based fields are redacted", name, typeExprString(f.Type))
			}
			si.Fields = append(si.Fields, fieldInfo{
				Name:      name,
				IsPointer: strings.HasPrefix(typeExprString(f.Type), "*"),
				Tag:       tag,
				FieldType: typeExprString(f.Type),
			})
		}
	}
	return si, nil
}

// tagErrorText renders a tag parse error without the internal package prefix.
func tagErrorText(err error) string {
	switch {
	case errors.Is(err, reflectx.ErrUnknownDataType):
		return "unknown data type (every tag must name a data type, e.g. \"secret,hash\")"
	case errors.Is(err, reflectx.ErrUnknownTransform):
		return "unknown transform"
	}
	return err.Error()
}

func orReason(why, fallback string) string {
	if why != "" {
		return why
	}
	return fallback
}

// sortWarnings orders warnings for deterministic output.
func sortWarnings(ws []Warning) {
	sort.Slice(ws, func(i, j int) bool {
		if ws[i].Type != ws[j].Type {
			return ws[i].Type < ws[j].Type
		}
		return ws[i].Reason < ws[j].Reason
	})
}
