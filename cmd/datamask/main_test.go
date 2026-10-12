package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/datamaskio/datamask/internal/codegen"
)

func TestGoPackagesDot(t *testing.T) {
	abs, _ := filepath.Abs(".")
	pkgs, err := goPackages(".")
	if err != nil {
		t.Fatalf("goPackages(.): %v", err)
	}
	if len(pkgs) != 1 || pkgs[0] != abs {
		t.Errorf("goPackages(.) = %v, want [%s]", pkgs, abs)
	}
}

func TestWalkPackages(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "walk-pkgs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "mypkg")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file.go"), []byte("package mypkg\n"), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := walkPackages(tmpDir)
	if err != nil {
		t.Fatalf("walkPackages: %v", err)
	}

	found := false
	for _, p := range pkgs {
		if filepath.Base(p) == "mypkg" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("walkPackages did not find mypkg: %v", pkgs)
	}
}

func TestWalkPackagesSkipsTestAndGenerated(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "walk-skip-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "test_test.go"), []byte("package p"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "gen_datamask.go"), []byte("package p"), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := walkPackages(tmpDir)
	if err != nil {
		t.Fatalf("walkPackages: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestWalkPackagesSkipsVendor(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "walk-vendor-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.Mkdir(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := walkPackages(tmpDir)
	if err != nil {
		t.Fatalf("walkPackages: %v", err)
	}
	for _, p := range pkgs {
		if filepath.Base(p) == "vendor" {
			t.Error("walkPackages should skip vendor directories")
		}
	}
}

func TestCheckGeneratedMissing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "check-missing-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	err = checkGenerated(tmpDir)
	if err == nil {
		t.Error("expected error for missing generated file")
	}
}

func TestCheckGeneratedOK(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "check-ok-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	if err := codegen.Generate(tmpDir); err != nil {
		t.Fatal(err)
	}

	if err := checkGenerated(tmpDir); err != nil {
		t.Errorf("checkGenerated should pass: %v", err)
	}
}

func TestCheckGeneratedStale(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "check-stale-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a stale generated file.
	genPath := filepath.Join(tmpDir, "tmp_datamask.go")
	if err := os.WriteFile(genPath, []byte("// stale content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err = checkGenerated(tmpDir)
	if err == nil {
		t.Error("expected error for stale generated file")
	}
}

func TestRunGenerate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "run-gen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	code := run([]string{tmpDir})
	if code != 0 {
		t.Errorf("run: exit code = %d, want 0", code)
	}

	// Verify file was generated.
	genPath := filepath.Join(tmpDir, "tmp_datamask.go")
	if _, err := os.Stat(genPath); os.IsNotExist(err) {
		t.Error("generated file should exist")
	}
}

func TestRunDryRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "run-dry-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	code := run([]string{"--dry-run", tmpDir})
	if code != 0 {
		t.Errorf("run --dry-run: exit code = %d, want 0", code)
	}
}

func TestRunCheckStale(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "run-check-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// --check on missing file should fail.
	code := run([]string{"--check", tmpDir})
	if code != 1 {
		t.Errorf("run --check (missing): exit code = %d, want 1", code)
	}
}

func TestRunCheckOK(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "run-check-ok-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	src := `package tmp
type Secret struct {
	Name  string
	Token string ` + "`mask:\"secret\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "input.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate first.
	if err := codegen.Generate(tmpDir); err != nil {
		t.Fatal(err)
	}

	// --check should pass.
	code := run([]string{"--check", tmpDir})
	if code != 0 {
		t.Errorf("run --check (ok): exit code = %d, want 0", code)
	}
}

func TestRunDefaultToDot(t *testing.T) {
	// When no args given, defaults to ".".
	code := run([]string{"--dry-run"})
	// May succeed (if current dir has mask structs) or fail gracefully.
	_ = code
}

func TestRunBadFlag(t *testing.T) {
	code := run([]string{"--nonexistent"})
	if code != 1 {
		t.Errorf("run with bad flag: exit code = %d, want 1", code)
	}
}

func TestRunCheckFailsOnStaleGeneratedFile(t *testing.T) {
	dir := t.TempDir()
	write := func(src string) {
		if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\n"+src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("type T struct{ A string `mask:\"secret\"` }\n")
	if code := run([]string{dir}); code != 0 {
		t.Fatalf("generate exit code = %d", code)
	}
	if code := run([]string{"--check", dir}); code != 0 {
		t.Fatalf("check on fresh output exit code = %d", code)
	}

	write("type T struct{ A string `mask:\"secret,hash\"` }\n")
	if code := run([]string{"--check", dir}); code != 1 {
		t.Errorf("check with a stale generated file: exit code = %d, want 1", code)
	}
	if code := run([]string{"--dry-run", dir}); code != 0 {
		t.Errorf("dry-run exit code = %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "p_datamask.go")); err != nil {
		t.Errorf("--check and --dry-run must not touch files: %v", err)
	}
	if code := run([]string{dir}); code != 0 {
		t.Errorf("regenerate exit code = %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "p_datamask.go")); !os.IsNotExist(err) {
		t.Errorf("generate should remove the stale file (stat err: %v)", err)
	}
	if code := run([]string{"--check", dir}); code != 0 {
		t.Errorf("check after cleanup exit code = %d", code)
	}
}
