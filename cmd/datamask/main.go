package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/datamaskio/datamask/internal/codegen"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes the generate command with the given arguments and returns
// an exit code. Extracted for testability.
func run(args []string) int {
	flags := flag.NewFlagSet("datamask generate", flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "preview generated files without writing")
	check := flags.Bool("check", false, "exit non-zero if generated files are stale")

	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "datamask: %v\n", err)
		return 1
	}

	patterns := flags.Args()
	if len(patterns) == 0 {
		patterns = []string{"."}
	}

	var exitCode int
	for _, pattern := range patterns {
		pkgs, err := goPackages(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "datamask: %v\n", err)
			return 1
		}

		for _, pkg := range pkgs {
			switch {
			case *check:
				if err := checkGenerated(pkg); err != nil {
					fmt.Fprintf(os.Stderr, "datamask: %s: %v\n", pkg, err)
					exitCode = 1
				}
			case *dryRun:
				files, err := codegen.GeneratedFiles(pkg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "datamask: %s: %v\n", pkg, err)
					exitCode = 1
					continue
				}
				for _, f := range files {
					fmt.Printf("--- %s ---\n%s\n", f.Path, string(f.Content))
				}
			default:
				if err := codegen.Generate(pkg); err != nil {
					fmt.Fprintf(os.Stderr, "datamask: %s: %v\n", pkg, err)
					exitCode = 1
				}
			}
		}
	}
	return exitCode
}

// goPackages returns Go package directories matching pattern.
// For "./..." it walks the directory tree looking for .go files.
func goPackages(pattern string) ([]string, error) {
	if pattern == "./..." || pattern == "..." {
		return walkPackages(".")
	}
	// Single directory — verify it contains Go files.
	abs, err := filepath.Abs(pattern)
	if err != nil {
		return nil, err
	}
	return []string{abs}, nil
}

// walkPackages walks the directory tree from root and returns directories
// containing .go files (excluding test and generated files).
func walkPackages(root string) ([]string, error) {
	var pkgs []string
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		// Skip hidden and vendor directories.
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") || base == "vendor" {
			return filepath.SkipDir
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil // skip unreadable
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasSuffix(name, ".go") &&
				!strings.HasSuffix(name, "_test.go") &&
				!strings.HasSuffix(name, "_datamask.go") {
				abs, _ := filepath.Abs(path)
				if !seen[abs] {
					seen[abs] = true
					pkgs = append(pkgs, abs)
				}
				break
			}
		}
		return nil
	})
	return pkgs, err
}

// checkGenerated verifies that generated files in pkgPath are up to date.
// Returns nil if they match, or an error describing the difference.
func checkGenerated(pkgPath string) error {
	files, err := codegen.GeneratedFiles(pkgPath)
	if err != nil {
		return fmt.Errorf("generation failed: %w", err)
	}
	for _, gen := range files {
		existing, err := os.ReadFile(gen.Path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s is missing — run 'datamask generate %s'", gen.Path, pkgPath)
			}
			return err
		}
		if string(existing) != string(gen.Content) {
			return fmt.Errorf("%s is stale — run 'datamask generate %s'", gen.Path, pkgPath)
		}
	}
	return nil
}
