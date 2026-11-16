// Package archtest enforces architecture rules across the whole module.
package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImports must never appear in shellshawk code (docs/DESIGN.md §2.1).
var forbiddenImports = map[string]string{
	"os/exec": "shellshawk must never start OS processes",
	"plugin":  "plugins are compiled in; runtime .so loading is not allowed",
}

// moduleRoot walks up from the test's working directory to the go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// forbiddenCalls are package functions that must never be called. The
// pkg/sftp OS-backed server would expose the host file system.
var forbiddenCalls = map[string]map[string]string{
	"github.com/pkg/sftp": {"NewServer": "use sftp.NewRequestServer with the virtual file system"},
}

func TestForbiddenImports(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "bin" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		checked++
		rel, _ := filepath.Rel(root, path)
		names := map[string]string{} // local package name → import path
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if why, bad := forbiddenImports[p]; bad {
				t.Errorf("%s imports %q: %s", rel, p, why)
			}
			local := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			names[local] = p
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if why, bad := forbiddenCalls[names[pkg.Name]][sel.Sel.Name]; bad {
				t.Errorf("%s uses %s.%s: %s", rel, names[pkg.Name], sel.Sel.Name, why)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no Go files checked; walk is broken")
	}
}
