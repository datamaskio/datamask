package codegen

import (
	"bytes"
	"fmt"
	"strings"
)

// renderFile generates the content of a *_datamask.go file.
//
// The generated code is redact-only and self-contained: it holds no package
// state (no Masker) and never calls datamask.Redact, so there is no global
// configuration and no Mask() -> Redact() -> Mask() recursion (ADR-0019).
func renderFile(pkgName string, structs []structInfo) []byte {
	var buf bytes.Buffer

	// Header.
	buf.WriteString(generatedHeader + "\n\n")
	buf.WriteString("package " + pkgName + "\n\n")

	// datamask is always needed (the compile-time Maskable check); fmt only
	// when a Maskable field's error is wrapped.
	needsFmt := false
	for _, s := range structs {
		for _, f := range s.Fields {
			if f.IsMaskable {
				needsFmt = true
			}
		}
	}
	if needsFmt {
		buf.WriteString("import (\n\t\"fmt\"\n\n\t\"github.com/datamaskio/datamask\"\n)\n\n")
	} else {
		buf.WriteString("import \"github.com/datamaskio/datamask\"\n\n")
	}

	for _, s := range structs {
		renderStruct(&buf, s)
	}

	// gofmt-clean: exactly one trailing newline.
	return append(bytes.TrimRight(buf.Bytes(), "\n"), '\n')
}

// renderStruct generates the Mask() method and compile-time check for one struct.
func renderStruct(buf *bytes.Buffer, s structInfo) {
	recv := strings.ToLower(s.Name[:1])

	buf.WriteString(fmt.Sprintf("func (%s %s) Mask() (any, error) {\n", recv, s.Name))
	for _, f := range s.Fields {
		if f.IsMaskable {
			renderMaskableField(buf, recv, s.Name, f)
			continue
		}
		renderTaggedField(buf, recv, f)
	}
	buf.WriteString(fmt.Sprintf("\treturn %s, nil\n}\n\n", recv))

	// Compile-time Maskable check.
	buf.WriteString(fmt.Sprintf("var _ datamask.Maskable = %s{}\n\n", s.Name))
}

// renderTaggedField emits code for a redact-tagged string field. The value
// is converted to the field's own type so named string types work, and a
// *string gets a fresh pointer: the caller's pointee is never modified.
func renderTaggedField(buf *bytes.Buffer, recv string, f fieldInfo) {
	fieldExpr := recv + "." + f.Name

	if f.IsPointer {
		value := `"[REDACTED]"`
		if elem := stripPointer(f.FieldType); elem != "string" {
			value = elem + "(" + value + ")"
		}
		buf.WriteString(fmt.Sprintf(
			"\tif %s != nil {\n"+
				"\t\tredacted := %s\n"+
				"\t\t%s = &redacted\n"+
				"\t}\n",
			fieldExpr, value, fieldExpr,
		))
		return
	}
	buf.WriteString(fmt.Sprintf("\t%s = \"[REDACTED]\"\n", fieldExpr))
}

// renderMaskableField emits fail-closed code for a field whose type
// implements Maskable: a Mask() error or a result of the wrong type returns
// the zero struct wrapped in datamask.ErrMaskFailed, never the unmasked value.
func renderMaskableField(buf *bytes.Buffer, recv, structName string, f fieldInfo) {
	fieldExpr := recv + "." + f.Name
	want := stripPointer(f.FieldType)
	assign := fieldExpr + " = v"
	indent := "\t"
	if f.IsPointer {
		assign = fieldExpr + " = &v"
		indent = "\t\t"
		buf.WriteString(fmt.Sprintf("\tif %s != nil {\n", fieldExpr))
	}
	buf.WriteString(fmt.Sprintf(
		"%[1]sif masked, err := %[2]s.Mask(); err != nil {\n"+
			"%[1]s\treturn %[3]s{}, fmt.Errorf(\"%%w: %[4]s: %%w\", datamask.ErrMaskFailed, err)\n"+
			"%[1]s} else if v, ok := masked.(%[5]s); ok {\n"+
			"%[1]s\t%[6]s\n"+
			"%[1]s} else {\n"+
			"%[1]s\treturn %[3]s{}, fmt.Errorf(\"%%w: %[4]s: Mask() returned %%T, want %[5]s\", datamask.ErrMaskFailed, masked)\n"+
			"%[1]s}\n",
		indent, fieldExpr, structName, f.Name, want, assign,
	))
	if f.IsPointer {
		buf.WriteString("\t}\n")
	}
}

// stripPointer removes the leading "*" from a type expression.
func stripPointer(t string) string {
	return strings.TrimPrefix(t, "*")
}
