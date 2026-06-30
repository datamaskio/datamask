// Package codegen generates zero-reflection Redact methods for Go structs.
//
// It walks Go source files via go/ast and go/parser, finds structs with
// mask tags or Maskable fields, and produces *_datamask.go files containing
// generated Mask() methods that satisfy the datamask.Maskable interface.
//
// Usage:
//
//	codegen.Generate("./mypkg")          // generate in package
//	codegen.Generate("./...")            // generate in all packages (CLI)
package codegen

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Generate walks the Go package at pkgPath and generates *_datamask.go
// files for all structs with mask tags or Maskable fields.
//
// Existing *_datamask.go files are overwritten. Non-Go files and test
// files are skipped.
func Generate(pkgPath string) error {
	files, err := GeneratedFiles(pkgPath)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(f.Path, f.Content, 0644); err != nil {
			return fmt.Errorf("codegen: write %s: %w", f.Path, err)
		}
	}
	return nil
}

// GeneratedFile holds the path and content of a generated file.
type GeneratedFile struct {
	Path    string
	Content []byte
}

// GeneratedFiles returns the files that would be generated for pkgPath
// without writing them. Used by --dry-run.
func GeneratedFiles(pkgPath string) ([]GeneratedFile, error) {
	pkgPath, err := filepath.Abs(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("codegen: %w", err)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgPath, goFileFilter, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("codegen: parse %s: %w", pkgPath, err)
	}

	var results []GeneratedFile
	for pkgName, pkg := range pkgs {
		structs := findStructs(pkg)
		if len(structs) == 0 {
			continue
		}

		outPath := filepath.Join(pkgPath, pkgName+"_datamask.go")
		// Sort for deterministic output.
		sort.Slice(structs, func(i, j int) bool {
			return structs[i].Name < structs[j].Name
		})

		buf := renderFile(pkgName, structs)
		results = append(results, GeneratedFile{Path: outPath, Content: buf})
	}
	return results, nil
}

// goFileFilter excludes generated files, test files, and non-Go files.
func goFileFilter(fi os.FileInfo) bool {
	name := fi.Name()
	if !strings.HasSuffix(name, ".go") {
		return false
	}
	if strings.HasSuffix(name, "_test.go") {
		return false
	}
	if strings.HasSuffix(name, "_datamask.go") {
		return false
	}
	return true
}

// structInfo holds the information needed to generate a Mask() method.
type structInfo struct {
	Name       string        // Struct name
	TypeParams []string      // Generic type parameter names (empty if not generic)
	Fields     []fieldInfo   // Fields to mask
	IsGeneric  bool
}

type fieldInfo struct {
	Name       string // Field name
	IsPointer  bool   // True if field is *T
	IsMaskable bool   // True if field type implements Maskable
	Tag        string // mask tag value, or empty
	FieldType  string // Go type expression (e.g., "string", "EmailMask", "*creditCard")
}

// findStructs walks the AST of a parsed package and returns information
// about structs that need code generation.
func findStructs(pkg *ast.Package) []structInfo {
	var structs []structInfo
	for _, file := range pkg.Files {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				si := extractStructInfo(typeSpec, structType)
				if len(si.Fields) > 0 {
					structs = append(structs, si)
				}
			}
		}
	}
	return structs
}

// extractStructInfo extracts masking information from a type spec and its struct type.
func extractStructInfo(typeSpec *ast.TypeSpec, st *ast.StructType) structInfo {
	si := structInfo{Name: typeSpec.Name.Name}

	// Extract type params for generic types.
	if typeSpec.TypeParams != nil {
		si.IsGeneric = true
		for _, field := range typeSpec.TypeParams.List {
			for _, name := range field.Names {
				si.TypeParams = append(si.TypeParams, name.Name)
			}
		}
	}

	if st.Fields == nil {
		return si
	}

	for _, field := range st.Fields.List {
		fi := extractFieldInfo(field)
		// Only include fields that need masking.
		if fi.Tag == "" && !fi.IsMaskable {
			continue
		}
		si.Fields = append(si.Fields, fi)
	}

	return si
}

// extractFieldInfo extracts a fieldInfo from an AST field.
func extractFieldInfo(field *ast.Field) fieldInfo {
	fi := fieldInfo{}

	// Field name (only one for non-embedded fields).
	if len(field.Names) > 0 {
		fi.Name = field.Names[0].Name
	} else {
		// Embedded field — use type name.
		fi.Name = typeExprString(field.Type)
	}

	// Extract mask tag.
	if field.Tag != nil {
		tag := field.Tag.Value
		// Remove surrounding backticks.
		tag = strings.Trim(tag, "`")
		stag := reflectTag(tag)
		if v, ok := stag.Lookup("mask"); ok && v != "-" {
			fi.Tag = v
		}
	}

	// Determine field type.
	fi.FieldType = typeExprString(field.Type)
	fi.IsPointer = strings.HasPrefix(fi.FieldType, "*")

	// Check if the type implements Maskable (heuristic: type name
	// ends with "Mask" or has a known custom mask method).
	fi.IsMaskable = looksMaskable(field.Type)

	return fi
}

// looksMaskable returns true if the type appears to implement Maskable.
// This is a heuristic — the definitive check is at compile time.
func looksMaskable(expr ast.Expr) bool {
	// Check for *T — dereference.
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		// Heuristic: type name contains "Mask" or known mask types.
		name := ident.Name
		return strings.Contains(name, "Mask") || strings.Contains(name, "mask")
	}
	return false
}

// reflectTag is a minimal struct tag parser mirroring reflect.StructTag.
type reflectTag string

func (t reflectTag) Lookup(key string) (string, bool) {
	v, _ := t.LookupWithDefault(key, "")
	return v, v != ""
}

func (t reflectTag) LookupWithDefault(key, def string) (string, bool) {
	for s := string(t); s != ""; {
		// Skip leading space.
		for len(s) > 0 && s[0] == ' ' {
			s = s[1:]
		}
		if s == "" {
			break
		}
		// Find key.
		i := 0
		for i < len(s) && s[i] > ' ' && s[i] != ':' && s[i] != '"' && s[i] != 0x7f {
			i++
		}
		if i == 0 || i >= len(s) || s[i] != ':' {
			break
		}
		k := s[:i]
		s = s[i+1:]
		if len(s) > 0 && s[0] == '"' {
			j := 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++ // skip escaped char
				}
				j++
			}
			if j < len(s) {
				v := s[1:j]
				s = s[j+1:]
				if k == key {
					return v, true
				}
				continue
			}
		}
		// Non-quoted value.
		j := 0
		for j < len(s) && s[j] > ' ' && s[j] != '"' && s[j] != 0x7f {
			j++
		}
		if k == key {
			return s[:j], true
		}
		s = s[j:]
	}
	return def, false
}

// typeExprString converts an AST type expression to a Go type string.
func typeExprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeExprString(t.X)
	case *ast.SelectorExpr:
		return typeExprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeExprString(t.Elt)
		}
		return "[" + typeExprString(t.Len) + "]" + typeExprString(t.Elt)
	case *ast.MapType:
		return "map[" + typeExprString(t.Key) + "]" + typeExprString(t.Value)
	case *ast.BasicLit:
		return t.Value
	case *ast.IndexExpr:
		return typeExprString(t.X) + "[" + typeExprString(t.Index) + "]"
	default:
		return fmt.Sprintf("%T", t)
	}
}
