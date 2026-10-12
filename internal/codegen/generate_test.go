package codegen

import (
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// -- P6.1: redact-only generation with skip warnings --

// analyzeSrc writes src into a temp package and runs Analyze on it.
func analyzeSrc(t *testing.T, src string) Result {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\n\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAnalyzeWarnings(t *testing.T) {
	const m = "`mask:\"%s\"`"
	tag := func(v string) string { return strings.Replace(m, "%s", v, 1) }

	tests := []struct {
		name string
		src  string
		want string // substring of the warning; "" means generated, no warning
		skip string // "silent" means skipped without a warning
	}{
		{"redact string", "type T struct{ A string " + tag("secret") + " }", "", ""},
		{"explicit redact", "type T struct{ A string " + tag("secret,redact") + " }", "", ""},
		{"tag options ignored", "type T struct{ A string " + tag("secret,redact,k=v") + " }", "", ""},
		{"pointer to string", "type T struct{ A *string " + tag("email") + " }", "", ""},
		{"named string", "type ID string\ntype T struct{ A ID " + tag("secret") + " }", "", ""},
		{"hash", "type T struct{ A string " + tag("secret,hash") + " }", "transform hash", ""},
		{"tokenize", "type T struct{ A string " + tag("secret,tokenize") + " }", "transform tokenize", ""},
		{"partial", "type T struct{ A string " + tag("phone,partial") + " }", "transform partial", ""},
		{"transform-only tag", "type T struct{ A string " + tag("hash") + " }", "unknown data type", ""},
		{"unknown transform", "type T struct{ A string " + tag("email,hsah") + " }", "unknown transform", ""},
		{"unknown data type", "type T struct{ A string " + tag("bogus") + " }", "unknown data type", ""},
		{"generic", "type T[X any] struct{ A string " + tag("secret") + " }", "generic type", ""},
		{"tagged int", "type T struct{ A int " + tag("secret") + " }", "tagged but has type int", ""},
		{"tagged struct", "type S struct{ X string }\ntype T struct{ A S " + tag("secret") + " }", "tagged but has type S", ""},
		{"unexported tag", "type T struct{ a string " + tag("secret") + " }", "unexported field a", ""},
		{"interface field", "type T struct{ A string " + tag("secret") + "\nB any }", "any-typed field", ""},
		{"error field", "type T struct{ A string " + tag("secret") + "\nB error }", "error-typed field", ""},
		{"empty interface", "type T struct{ A string " + tag("secret") + "\nB interface{ M() } }", "interface-typed field", ""},
		{"unknown import", "type T struct{ A string " + tag("secret") + "\nB sync.Mutex }", "imported type sync.Mutex", ""},
		{"nested tagged struct", "type S struct{ X string " + tag("secret") + " }\ntype T struct{ S S }", "nested value", ""},
		{"nested via slice", "type S struct{ X string " + tag("secret") + " }\ntype T struct{ A string " + tag("secret") + "\nL []S }", "nested value", ""},
		{"nested via map", "type S struct{ X string " + tag("secret") + " }\ntype T struct{ A string " + tag("secret") + "\nL map[string]S }", "nested value", ""},
		{"nested via pointer", "type S struct{ X string " + tag("secret") + " }\ntype T struct{ A string " + tag("secret") + "\nP *S }", "nested value", ""},
		{"nested Maskable struct", "type S struct{ X string }\nfunc (S) Mask() (any, error) { return nil, nil }\ntype T struct{ A string " + tag("secret") + "\nP []S }", "of Maskable values", ""},
		{"embedded tagged", "type B struct{ X string " + tag("secret") + " }\ntype T struct{ B\nA string " + tag("secret") + " }", "nested value", ""},
		{"inert nested", "type S struct{ X string }\ntype T struct{ A string " + tag("secret") + "\nV S\nP *S\nL []S\nM map[string]S }", "", ""},
		{"time and scalars", "type T struct{ A string " + tag("secret") + "\nN int\nF float64\nT time.Time\nD time.Duration\nB []byte\nFn func() }", "", ""},
		{"opt-out tag", "type T struct{ A string " + tag("secret") + "\nB string " + tag("-") + " }", "", ""},
		{"hand-written Mask", "type T struct{ A string " + tag("secret") + " }\nfunc (T) Mask() (any, error) { return nil, nil }", "", "silent"},
		{"nothing to mask", "type T struct{ A string\nB any }", "", "silent"},
		{"maskable field", "type M string\nfunc (M) Mask() (any, error) { return M(\"x\"), nil }\ntype T struct{ A M }", "", ""},
		{"maskable pointer field", "type M string\nfunc (*M) Mask() (any, error) { return M(\"x\"), nil }\ntype T struct{ A *M }", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := analyzeSrc(t, tc.src)
			var tw []Warning
			for _, w := range res.Warnings {
				if w.Type == "T" {
					tw = append(tw, w)
				}
			}
			generated := len(res.Files) == 1 && strings.Contains(string(res.Files[0].Content), "func (t T) Mask()")
			switch {
			case tc.skip == "silent":
				if generated || len(tw) != 0 {
					t.Errorf("want skipped silently; generated=%v warnings=%v", generated, tw)
				}
			case tc.want == "":
				if !generated || len(tw) != 0 {
					t.Errorf("want generated with no warning; generated=%v warnings=%v", generated, tw)
				}
			default:
				if generated {
					t.Error("type must be skipped, but Mask() was generated")
				}
				if len(tw) != 1 || !strings.Contains(tw[0].Reason, tc.want) {
					t.Errorf("warnings = %v, want one containing %q", tw, tc.want)
				}
			}
		})
	}
}

func TestSkippedTypesProduceNoFile(t *testing.T) {
	res := analyzeSrc(t, "type T struct{ A string `mask:\"secret,hash\"` }")
	if len(res.Files) != 0 {
		t.Errorf("expected no file, got %d", len(res.Files))
	}
	if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0].String(), "datamask: skipping T: ") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestSkippedTypeDoesNotBlockOthers(t *testing.T) {
	res := analyzeSrc(t, "type Good struct{ A string `mask:\"secret\"` }\ntype Bad struct{ A string `mask:\"secret,hash\"` }")
	if len(res.Files) != 1 || len(res.Warnings) != 1 {
		t.Fatalf("files=%d warnings=%v", len(res.Files), res.Warnings)
	}
	out := string(res.Files[0].Content)
	if !strings.Contains(out, "func (g Good) Mask()") || strings.Contains(out, "Bad") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestGenerateWarnsOnStderr(t *testing.T) {
	dir := t.TempDir()
	src := "package p\ntype G struct{ A string `mask:\"secret\"` }\ntype B struct{ A string `mask:\"secret,hash\"` }\n"
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	err := Generate(dir)
	w.Close()
	os.Stderr = old
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, rerr := r.Read(b)
		buf.Write(b[:n])
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(buf.String(), "datamask: skipping B: ") {
		t.Errorf("stderr = %q, want a skip warning for B", buf.String())
	}
}

func TestGeneratedOutputShape(t *testing.T) {
	res, err := Analyze("testdata/input")
	if err != nil || len(res.Files) != 1 {
		t.Fatalf("Analyze: %v, %d files", err, len(res.Files))
	}
	out := string(res.Files[0].Content)
	for _, bad := range []string{"_masker", "datamask.New", "datamask.Redact", "datamask.Compile", "Redact("} {
		if strings.Contains(out, bad) {
			t.Errorf("generated code must not contain %q", bad)
		}
	}
	// Valid, gofmt-clean Go.
	formatted, err := format.Source(res.Files[0].Content)
	if err != nil {
		t.Fatalf("generated code does not parse: %v", err)
	}
	if string(formatted) != out {
		t.Error("generated code is not gofmt-clean")
	}
	// Only generated types appear; skipped ones never do.
	for _, skipped := range []string{"Wrapper", "HashTagged", "PartialTagged", "IntTagged", "NestedTagged", "HasInterface", "BadTag", "UnexportedTag", "MaskableInMap", "HandWritten"} {
		if regexp.MustCompile(`func \(\w+ `+skipped+`[\[\)]`).MatchString(out) || strings.Contains(out, "= "+skipped+"{}") {
			t.Errorf("skipped type %s appears in generated output", skipped)
		}
	}
	// Testdata warnings are the documented ones.
	got := map[string]bool{}
	for _, w := range res.Warnings {
		got[w.Type] = true
	}
	for _, want := range []string{"Wrapper", "HashTagged", "PartialTagged", "IntTagged", "NestedTagged", "HasInterface", "HasUnknownImport", "BadTag", "UnexportedTag", "MaskableInMap"} {
		if !got[want] {
			t.Errorf("missing skip warning for %s; got %v", want, res.Warnings)
		}
	}
	if got["HandWritten"] || got["NoTags"] {
		t.Error("HandWritten and NoTags must be skipped silently")
	}
}

func TestGeneratedRedactOnlyIsEquivalentToRuntime(t *testing.T) {
	modRoot, _ := filepath.Abs("../..")
	tmpDir, err := os.MkdirTemp(modRoot, "codegen-equiv-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp

type ID string

type Addr struct{ Street string }

type Rec struct {
	Name   string
	Email  string ` + "`mask:\"email\"`" + `
	ID     ID     ` + "`mask:\"secret\"`" + `
	Backup *ID    ` + "`mask:\"secret\"`" + `
	Token  *string ` + "`mask:\"secret\"`" + `
	Home   Addr
	Tags   []string
	N      int
}
`
	test := `package tmp

import (
	"reflect"
	"testing"

	"github.com/datamaskio/datamask"
)

func TestGeneratedMatchesRuntime(t *testing.T) {
	b, tok := ID("b"), "t"
	in := Rec{Name: "n", Email: "a@b.c", ID: "i", Backup: &b, Token: &tok, Home: Addr{"s"}, Tags: []string{"x"}, N: 7}
	orig := in
	got, err := in.Mask()
	if err != nil {
		t.Fatal(err)
	}

	// The runtime walk, reached through a type that does not have the
	// generated method (Maskable would otherwise win).
	type plain Rec
	rt, err := datamask.Redact(datamask.New(), plain(in))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Rec(rt), got.(Rec)) {
		t.Errorf("generated:\n %+v\nruntime:\n %+v", got, rt)
	}
	if b != "b" || tok != "t" || !reflect.DeepEqual(in, orig) {
		t.Error("input mutated")
	}
}
`
	for name, body := range map[string]string{"models.go": src, "equiv_test.go": test} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := GeneratedFiles(tmpDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("GeneratedFiles: %d files, %v", len(files), err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, filepath.Base(files[0].Path)), files[0].Content, 0o644); err != nil {
		t.Fatal(err)
	}
	rel := "." + string(filepath.Separator) + filepath.Base(tmpDir)
	if out, err := exec.Command("go", "vet", "-C", modRoot, rel).CombinedOutput(); err != nil {
		t.Fatalf("go vet failed on generated output:\n%s", out)
	}
	if out, err := exec.Command("go", "test", "-C", modRoot, rel).CombinedOutput(); err != nil {
		t.Fatalf("generated code differs from the runtime:\n%s", out)
	}
}

// -- stale generated files --

func writePkg(t *testing.T, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStaleGeneratedFileIsRemoved(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, "type T struct{ A string `mask:\"secret\"` }\n")
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	gen := filepath.Join(dir, "p_datamask.go")
	if _, err := os.Stat(gen); err != nil {
		t.Fatalf("expected %s: %v", gen, err)
	}

	// The tag becomes hash: nothing can be generated, and the old redact-only
	// Mask() must not linger, because it would keep winning over the Schema.
	writePkg(t, dir, "type T struct{ A string `mask:\"secret,hash\"` }\n")
	res, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 || len(res.Stale) != 1 || res.Stale[0] != gen {
		t.Fatalf("Files=%d Stale=%v, want 0 files and %s stale", len(res.Files), res.Stale, gen)
	}
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gen); !os.IsNotExist(err) {
		t.Errorf("stale generated file still exists (stat err: %v)", err)
	}
}

func TestHandWrittenFileWithGeneratedNameIsNeverRemoved(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, "type T struct{ A string }\n")
	hand := filepath.Join(dir, "p_datamask.go")
	if err := os.WriteFile(hand, []byte("package p\n\n// written by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(dir)
	if err != nil || len(res.Stale) != 0 {
		t.Fatalf("Stale=%v err=%v", res.Stale, err)
	}
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hand); err != nil {
		t.Errorf("hand-written file was removed: %v", err)
	}
}

// -- analyzer edge cases --

func TestAnalyzeTypeExpressions(t *testing.T) {
	const sec = "`mask:\"secret\"`"
	tests := []struct {
		name string
		src  string
		want string // warning substring; "" means T is generated
	}{
		// Anonymous struct fields: inert unless they hide something.
		{"anonymous inert struct", "type T struct{ A string " + sec + "\nS struct{ X, Y int } }", ""},
		{"anonymous struct with tag", "type T struct{ A string " + sec + "\nS struct{ X string " + sec + " } }", "nested value"},
		{"anonymous struct with any", "type T struct{ A string " + sec + "\nS struct{ X any } }", "any-typed field"},
		{"anonymous struct with Maskable", "type M string\nfunc (M) Mask() (any, error) { return M(\"\"), nil }\ntype T struct{ A string " + sec + "\nS struct{ X M } }", "Maskable field"},
		{"empty struct field", "type T struct{ A string " + sec + "\nS struct{} }", ""},
		{"empty named struct", "type E struct{}\ntype T struct{ A string " + sec + "\nS E }", ""},
		// Parenthesized and nested pointer types.
		{"parenthesized type", "type T struct{ A string " + sec + "\nB (int) }", ""},
		{"pointer to pointer", "type T struct{ A string " + sec + "\nB **int }", "pointer to pointer"},
		// Generic instantiations and generic field types.
		{"generic instantiation", "type G[X any] struct{ V X }\ntype T struct{ A string " + sec + "\nB G[int] }", "unsupported type expression"},
		{"multi-arg instantiation", "type G[X, Y any] struct{ V X }\ntype T struct{ A string " + sec + "\nB G[int, string] }", "unsupported type expression"},
		{"named generic type", "type G[X any] struct{ V X }\ntype T struct{ A string " + sec + "\nB G }", "generic type G"},
		// Named non-struct types resolve through their underlying type.
		{"named slice of ints", "type L []int\ntype T struct{ A string " + sec + "\nB L }", ""},
		{"named slice of any", "type L []any\ntype T struct{ A string " + sec + "\nB L }", "any-typed field"},
		{"named map of interface", "type M map[string]interface{ X() }\ntype T struct{ A string " + sec + "\nB M }", "interface-typed field"},
		{"map key unhandled", "type T struct{ A string " + sec + "\nB map[any]int }", "any-typed field"},
		{"array of structs", "type S struct{ X int }\ntype T struct{ A string " + sec + "\nB [3]S }", ""},
		// Recursive types add nothing by themselves.
		{"self-referential inert", "type N struct{ Next *N\nV int }\ntype T struct{ A string " + sec + "\nHead *N }", ""},
		{"mutually recursive inert", "type A1 struct{ B *B1 }\ntype B1 struct{ A *A1 }\ntype T struct{ X string " + sec + "\nH *A1 }", ""},
		{"recursive with a tag inside", "type N struct{ Next *N\nS string " + sec + " }\ntype T struct{ A string " + sec + "\nHead *N }", "nested value"},
		// Embedded fields.
		{"embedded pointer inert", "type B struct{ ID int }\ntype T struct{ *B\nA string " + sec + " }", ""},
		{"embedded Maskable promotes Mask", "type B string\nfunc (B) Mask() (any, error) { return B(\"\"), nil }\ntype T struct{ B\nA string " + sec + " }", "embedded field B"},
		{"embedded unknown import", "type T struct{ sync.Mutex\nA string " + sec + " }", "embedded field sync.Mutex"},
		{"embedded any", "type T struct{ fmt.Stringer\nA string " + sec + " }", "embedded field fmt.Stringer"},
		// Tags interacting with kinds.
		{"tagged Maskable keeps Maskable", "type M string\nfunc (M) Mask() (any, error) { return M(\"\"), nil }\ntype T struct{ A M `mask:\"secret,hash\"` }", ""},
		{"tagged Maskable still needs a valid tag", "type M string\nfunc (M) Mask() (any, error) { return M(\"\"), nil }\ntype T struct{ A M `mask:\"hash\"` }", "invalid mask tag"},
		{"tagged named int", "type N int\ntype T struct{ A N " + sec + " }", "tagged but has type N"},
		{"tagged slice of strings", "type T struct{ A []string " + sec + " }", "tagged but has type []string"},
		{"tag with other keys", "type T struct{ A string `json:\"a\" mask:\"secret\" xml:\"a\"` }", ""},
		{"empty mask tag", "type T struct{ A string `mask:\"\"` ; B string " + sec + " }", ""},
		{"unexported untagged field of any", "type T struct{ A string " + sec + "\nhidden any }", ""},
		// Method receivers.
		{"generic receiver Mask", "type G[X any] struct{ A string " + sec + " }\nfunc (g *G[X]) Mask() (any, error) { return nil, nil }\ntype T struct{ A string " + sec + "\nB int }", ""},
		{"parenthesized receiver", "type M string\nfunc (*(M)) Mask() (any, error) { return nil, nil }\ntype T struct{ A M }", ""},
		{"function receiver is not a method", "func Mask() {}\ntype T struct{ A string " + sec + " }", ""},
		{"non-Mask method ignored", "type M string\nfunc (M) Other() {}\ntype T struct{ A M }", "SKIP"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src
			if !strings.Contains(src, "import") {
				src = "import (\n\t\"fmt\"\n\t\"sync\"\n\t\"time\"\n)\n\nvar _ = fmt.Sprint\nvar _ sync.Mutex\nvar _ time.Time\n\n" + src
			}
			res := analyzeSrc(t, src)
			var tw []Warning
			for _, w := range res.Warnings {
				if w.Type == "T" {
					tw = append(tw, w)
				}
			}
			generated := len(res.Files) == 1 && strings.Contains(string(res.Files[0].Content), "func (t T) Mask()")
			switch tc.want {
			case "":
				if !generated || len(tw) != 0 {
					t.Errorf("want generated; generated=%v warnings=%v", generated, tw)
				}
			case "SKIP": // nothing to generate and nothing to warn about
				if generated || len(tw) != 0 {
					t.Errorf("want silently skipped; generated=%v warnings=%v", generated, tw)
				}
			default:
				if generated {
					t.Error("type must be skipped, but Mask() was generated")
				}
				if len(tw) != 1 || !strings.Contains(tw[0].Reason, tc.want) {
					t.Errorf("warnings = %v, want one containing %q", tw, tc.want)
				}
			}
		})
	}
}

func TestTagErrorText(t *testing.T) {
	for tag, want := range map[string]string{
		"hash":        "unknown data type",
		"email,hsah":  "unknown transform",
		"bogus":       "unknown data type",
		"email,":      "unknown transform",
		"email,a,b,c": "unknown transform",
	} {
		res := analyzeSrc(t, "type T struct{ A string `mask:\""+tag+"\"` }")
		if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Reason, want) {
			t.Errorf("tag %q: warnings = %v, want %q", tag, res.Warnings, want)
		}
	}
	if got := tagErrorText(errors.New("other")); got != "other" {
		t.Errorf("tagErrorText(other) = %q", got)
	}
}

func TestWarningsAreSortedAndStable(t *testing.T) {
	src := "type Zed struct{ A string `mask:\"secret,hash\"` }\n" +
		"type Alpha struct{ A string `mask:\"secret,hash\"` }\n" +
		"type Mid struct{ A string `mask:\"secret,tokenize\"` }\n"
	for range 5 {
		res := analyzeSrc(t, src)
		var names []string
		for _, w := range res.Warnings {
			names = append(names, w.Type)
		}
		if strings.Join(names, ",") != "Alpha,Mid,Zed" {
			t.Fatalf("warning order = %v, want sorted by type", names)
		}
	}

	ws := []Warning{{"B", "z"}, {"A", "y"}, {"A", "x"}}
	sortWarnings(ws)
	if ws[0] != (Warning{"A", "x"}) || ws[1] != (Warning{"A", "y"}) || ws[2] != (Warning{"B", "z"}) {
		t.Errorf("sortWarnings = %v (reasons break ties)", ws)
	}
}

func TestHasMaskingIntent(t *testing.T) {
	// A skipped type warns only if the user would expect a Mask() for it.
	tests := []struct {
		name string
		src  string
		warn bool
	}{
		{"no fields", "type T struct{}", false},
		{"plain fields only", "type T struct{ A string\nB any }", false},
		{"opt-out tag only", "type T struct{ A string `mask:\"-\"`\nB any }", false},
		{"tag", "type T struct{ A string `mask:\"secret\"`\nB any }", true},
		{"Maskable field", "type M string\nfunc (M) Mask() (any, error) { return M(\"\"), nil }\ntype T struct{ A M\nB any }", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := analyzeSrc(t, tc.src)
			var n int
			for _, w := range res.Warnings {
				if w.Type == "T" {
					n++
				}
			}
			if (n > 0) != tc.warn {
				t.Errorf("warnings for T = %d, want warn=%v", n, tc.warn)
			}
		})
	}
}

// -- Generate error paths --

func TestGenerateErrors(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		if err := Generate(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("expected an error for a missing directory")
		}
	})
	t.Run("syntax error", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\nfunc ("), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Generate(dir); err == nil {
			t.Error("expected a parse error")
		}
		if _, err := Analyze(dir); err == nil {
			t.Error("Analyze should report the parse error too")
		}
	})
	t.Run("read-only directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		dir := t.TempDir()
		writePkg(t, dir, "type T struct{ A string `mask:\"secret\"` }\n")
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o755)
		err := Generate(dir)
		if err == nil || !strings.Contains(err.Error(), "write") {
			t.Errorf("err = %v, want a write error", err)
		}
	})
	t.Run("stale file cannot be removed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		dir := t.TempDir()
		writePkg(t, dir, "type T struct{ A string `mask:\"secret\"` }\n")
		if err := Generate(dir); err != nil {
			t.Fatal(err)
		}
		writePkg(t, dir, "type T struct{ A string `mask:\"secret,hash\"` }\n")
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o755)
		err := Generate(dir)
		if err == nil || !strings.Contains(err.Error(), "remove stale") {
			t.Errorf("err = %v, want a remove-stale error", err)
		}
	})
	t.Run("empty package", func(t *testing.T) {
		dir := t.TempDir()
		writePkg(t, dir, "")
		res, err := Analyze(dir)
		if err != nil || len(res.Files) != 0 || len(res.Warnings) != 0 || len(res.Stale) != 0 {
			t.Errorf("res=%+v err=%v", res, err)
		}
		if err := Generate(dir); err != nil {
			t.Errorf("Generate on an empty package: %v", err)
		}
	})
}

func TestStaleDetectionPerPackage(t *testing.T) {
	// One package keeps its output, another goes stale; each is judged alone.
	good, stale := t.TempDir(), t.TempDir()
	writePkg(t, good, "type T struct{ A string `mask:\"secret\"` }\n")
	writePkg(t, stale, "type T struct{ A string `mask:\"secret\"` }\n")
	for _, d := range []string{good, stale} {
		if err := Generate(d); err != nil {
			t.Fatal(err)
		}
	}
	writePkg(t, stale, "type T struct{ A string }\n")
	if res, _ := Analyze(good); len(res.Stale) != 0 || len(res.Files) != 1 {
		t.Errorf("good package: %+v", res)
	}
	if res, _ := Analyze(stale); len(res.Stale) != 1 || len(res.Files) != 0 {
		t.Errorf("stale package: %+v", res)
	}
}
