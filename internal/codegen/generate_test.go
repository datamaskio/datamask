package codegen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateGolden(t *testing.T) {
	inputDir := "testdata/input"
	outputDir := "testdata/output"

	files, err := GeneratedFiles(inputDir)
	if err != nil {
		t.Fatalf("GeneratedFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one generated file")
	}

	for _, gen := range files {
		base := filepath.Base(gen.Path)
		goldenPath := filepath.Join(outputDir, base)

		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden %s: %v", goldenPath, err)
		}

		if string(gen.Content) != string(want) {
			t.Errorf("generated output differs from golden file %s", goldenPath)

			gotLines := strings.Split(string(gen.Content), "\n")
			wantLines := strings.Split(string(want), "\n")
			for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
				if gotLines[i] != wantLines[i] {
					t.Errorf("  line %d:\n    got:  %q\n    want: %q", i+1, gotLines[i], wantLines[i])
					break
				}
			}
		}
	}
}

func TestGeneratedCompiles(t *testing.T) {
	inputDir, err := filepath.Abs("testdata/input")
	if err != nil {
		t.Fatal(err)
	}
	files, err := GeneratedFiles(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one generated file")
	}

	// Create temp dir at module root level (not inside internal/) so
	// go build can resolve the package.
	modRoot, _ := filepath.Abs("../..")
	tmpDir, err := os.MkdirTemp(modRoot, "codegen-compile-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Copy input files, rewrite package name.
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(inputDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		content := strings.Replace(string(src), "package testdata", "package tmp", 1)
		if err := os.WriteFile(filepath.Join(tmpDir, e.Name()), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Write generated file with package renamed.
	for _, gen := range files {
		content := strings.Replace(string(gen.Content), "package testdata", "package tmp", 1)
		outName := filepath.Base(gen.Path)
		if err := os.WriteFile(filepath.Join(tmpDir, outName), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("go", "build", "-C", modRoot, "."+string(filepath.Separator)+filepath.Base(tmpDir))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated code does not compile:\n%s", out)
	}
}

func TestNoGeneratedForEmptyPackage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "codegen-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package empty
type Plain struct {
	Name string
	Age  int
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "plain.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := GeneratedFiles(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestGoFileFilter(t *testing.T) {
	tests := []struct {
		name   string
		accept bool
	}{
		{"foo.go", true},
		{"foo_test.go", false},
		{"foo_datamask.go", false},
		{"foo.txt", false},
	}
	for _, tt := range tests {
		mock := mockFileInfo{name: tt.name}
		got := goFileFilter(mock)
		if got != tt.accept {
			t.Errorf("goFileFilter(%q) = %v, want %v", tt.name, got, tt.accept)
		}
	}
}

type mockFileInfo struct {
	os.FileInfo
	name string
}

func (m mockFileInfo) Name() string { return m.name }

func TestGenerateWritesFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp(".", "codegen-write-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write an input file with a mask-tagged struct.
	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Generate(tmpDir); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Verify the generated file exists and contains expected content.
	genPath := filepath.Join(tmpDir, "tmp_datamask.go")
	content, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	if !strings.Contains(string(content), "func (s Secret) Mask() (any, error) {") {
		t.Error("generated file missing Mask method")
	}
	if !strings.Contains(string(content), "var _ datamask.Maskable = Secret{}") {
		t.Error("generated file missing compile-time check")
	}
}

func TestLookupWithDefault(t *testing.T) {
	tag := reflectTag(`mask:"secret" other:"value"`)
	if v, ok := tag.Lookup("mask"); !ok || v != "secret" {
		t.Errorf("mask = %q, %v, want secret, true", v, ok)
	}
	if v, ok := tag.Lookup("other"); !ok || v != "value" {
		t.Errorf("other = %q, %v, want value, true", v, ok)
	}
	if _, ok := tag.Lookup("missing"); ok {
		t.Error("missing key should not be found")
	}
}

func TestLookupWithDefaultNonQuoted(t *testing.T) {
	tag := reflectTag(`mask:secret`)
	v, ok := tag.LookupWithDefault("mask", "")
	if !ok || v != "secret" {
		t.Errorf("mask = %q, %v, want secret, true", v, ok)
	}
}

func TestTypeExprString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`type T struct{ F string }`, "string"},
		{`type T struct{ F *string }`, "*string"},
		{`type T struct{ F []string }`, "[]string"},
		{`type T struct{ F [4]string }`, "[4]string"},
		{`type T struct{ F map[string]int }`, "map[string]int"},
	}
	for _, tt := range tests {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "test.go", "package p\n"+tt.input, 0)
		if err != nil {
			t.Fatal(err)
		}
		typeSpec := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
		st := typeSpec.Type.(*ast.StructType)
		fieldType := st.Fields.List[0].Type
		got := typeExprString(fieldType)
		if got != tt.want {
			t.Errorf("typeExprString(%s) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTypeExprStringIndexExpr(t *testing.T) {
	// Generic instantiation like Foo[string].
	idx := &ast.IndexExpr{
		X:     &ast.Ident{Name: "Wrapper"},
		Index: &ast.Ident{Name: "string"},
	}
	got := typeExprString(idx)
	if got != "Wrapper[string]" {
		t.Errorf("typeExprString(Wrapper[string]) = %q, want Wrapper[string]", got)
	}
}

func TestTypeExprStringSelectorExpr(t *testing.T) {
	// Qualified type like pkg.Type.
	sel := &ast.SelectorExpr{
		X:   &ast.Ident{Name: "datamask"},
		Sel: &ast.Ident{Name: "Maskable"},
	}
	got := typeExprString(sel)
	if got != "datamask.Maskable" {
		t.Errorf("typeExprString(datamask.Maskable) = %q, want datamask.Maskable", got)
	}
}

func TestLooksMaskable(t *testing.T) {
	tests := []struct {
		typeName string
		want     bool
	}{
		{"EmailMask", true},
		{"maskedEmail", true},
		{"CreditCard", false},
		{"string", false},
		{"Token", false},
	}
	for _, tt := range tests {
		ident := &ast.Ident{Name: tt.typeName}
		got := looksMaskable(ident)
		if got != tt.want {
			t.Errorf("looksMaskable(%q) = %v, want %v", tt.typeName, got, tt.want)
		}
	}
	// *EmailMask should be Maskable.
	star := &ast.StarExpr{X: &ast.Ident{Name: "EmailMask"}}
	if !looksMaskable(star) {
		t.Error("*EmailMask should be Maskable")
	}
	// *string should NOT be Maskable.
	star2 := &ast.StarExpr{X: &ast.Ident{Name: "string"}}
	if looksMaskable(star2) {
		t.Error("*string should NOT be Maskable")
	}
}

func TestLookupWithDefaultEdgeCases(t *testing.T) {
	// Empty tag.
	tag := reflectTag(``)
	if _, ok := tag.LookupWithDefault("mask", "fallback"); ok {
		t.Error("empty tag should not match")
	}

	// Key without colon.
	tag2 := reflectTag(`keyonly`)
	if v, ok := tag2.LookupWithDefault("keyonly", ""); ok || v != "" {
		t.Errorf("key-only tag should not match: v=%q ok=%v", v, ok)
	}

	// Escaped quote in value.
	tag3 := reflectTag(`mask:"val\"ue"`)
	if v, ok := tag3.Lookup("mask"); ok {
		t.Logf("escaped quote value: %q", v)
	}
}

func TestParseDirError(t *testing.T) {
	_, err := GeneratedFiles("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestLooksMaskableDefault(t *testing.T) {
	// Non-Ident, non-StarExpr type — should not panic, return false.
	sel := &ast.SelectorExpr{X: &ast.Ident{Name: "p"}, Sel: &ast.Ident{Name: "T"}}
	if looksMaskable(sel) {
		t.Error("SelectorExpr should not be Maskable")
	}
}

// TestGeneratedFailsClosedAtRuntime builds a package whose Maskable field
// errors or returns the wrong type, generates Mask() for its parent, and
// runs it: the generated method must return the zero struct wrapped in
// datamask.ErrMaskFailed and never the unmasked value.
func TestGeneratedFailsClosedAtRuntime(t *testing.T) {
	modRoot, _ := filepath.Abs("../..")
	tmpDir, err := os.MkdirTemp(modRoot, "codegen-runtime-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp

import "errors"

var errBoom = errors.New("boom")

type BadMask string

func (BadMask) Mask() (any, error) { return nil, errBoom }

type WrongMask string

func (WrongMask) Mask() (any, error) { return 42, nil }

type GoodMask string

func (GoodMask) Mask() (any, error) { return GoodMask("***"), nil }

type Fails struct {
	Name  string
	Field BadMask
}

type FailsPtr struct {
	Field *BadMask
}

type Wrong struct {
	Field WrongMask
}

type Good struct {
	Name  string
	Field GoodMask
	Ptr   *GoodMask
}
`
	test := `package tmp

import (
	"errors"
	"testing"

	"github.com/datamaskio/datamask"
)

func TestFailClosed(t *testing.T) {
	bad := BadMask("secret")
	for name, fn := range map[string]func() (any, error){
		"error":   Fails{Name: "n", Field: "secret"}.Mask,
		"pointer": FailsPtr{Field: &bad}.Mask,
		"wrong":   Wrong{Field: "secret"}.Mask,
	} {
		got, err := fn()
		if !errors.Is(err, datamask.ErrMaskFailed) {
			t.Errorf("%s: err = %v, want ErrMaskFailed", name, err)
		}
		switch g := got.(type) {
		case Fails:
			if g != (Fails{}) || !errors.Is(err, errBoom) {
				t.Errorf("%s: got %+v, want zero wrapping errBoom", name, g)
			}
		case FailsPtr:
			if g.Field != nil {
				t.Errorf("%s: got %+v, want zero", name, g)
			}
		case Wrong:
			if g != (Wrong{}) {
				t.Errorf("%s: got %+v, want zero", name, g)
			}
		default:
			t.Errorf("%s: unexpected result %T", name, got)
		}
	}
}

func TestGoodMasks(t *testing.T) {
	p := GoodMask("secret")
	orig := Good{Name: "n", Field: "secret", Ptr: &p}
	got, err := orig.Mask()
	if err != nil {
		t.Fatal(err)
	}
	g := got.(Good)
	if g.Field != "***" || *g.Ptr != "***" {
		t.Errorf("got %+v", g)
	}
	if p != "secret" {
		t.Error("original pointee mutated")
	}
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "models.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := GeneratedFiles(tmpDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("GeneratedFiles = %d files, err %v", len(files), err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, filepath.Base(files[0].Path)), files[0].Content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "runtime_test.go"), []byte(test), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("go", "test", "-C", modRoot, "."+string(filepath.Separator)+filepath.Base(tmpDir)).CombinedOutput()
	if err != nil {
		t.Fatalf("generated code failed at runtime:\n%s", out)
	}
}
