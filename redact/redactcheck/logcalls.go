package redactcheck

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// valueLoggers are the zerolog Event and Context methods that serialize an
// arbitrary value, with the number of arguments each takes. The value is the
// last argument.
var valueLoggers = map[string]int{
	"Interface": 2,
	"Any":       2,
	"Object":    2,
	"Fields":    1,
}

type logCall struct {
	position string
	expr     string
}

func checkLogCalls(root string, allowlist map[string]string) ([]string, error) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	scanned := 0
	var problems []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			// A nested module is not this module's code.
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".gen.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		if ast.IsGenerated(file) {
			return nil
		}
		scanned++

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, call := range unredactedLogCalls(fset, file) {
			key := filepath.ToSlash(rel) + ": " + call.expr
			if _, ok := allowlist[key]; ok {
				seen[key] = true
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"%s logs a value without redaction: %s. Wrap it in redact.Object (structs, maps) or redact.JSON (raw JSON), or allowlist %q with a justification",
				call.position, call.expr, key))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scanned == 0 {
		return nil, errors.New("no Go files scanned — the module root is wrong")
	}

	for key := range allowlist {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf("logging allowlist entry %q matches no call — remove it", key))
		}
	}
	return problems, nil
}

// unredactedLogCalls returns the value-logging calls in file whose value is
// not a redact.* call. Without type information it matches by method name
// and argument count, and skips package-qualified calls such as
// strings.Fields.
func unredactedLogCalls(fset *token.FileSet, file *ast.File) []logCall {
	imports := map[string]bool{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = true
	}

	var calls []logCall
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		arity, ok := valueLoggers[sel.Sel.Name]
		if !ok || len(call.Args) != arity {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && imports[pkg.Name] {
			return true
		}
		if isRedactCall(call.Args[len(call.Args)-1]) {
			return true
		}

		var buf bytes.Buffer
		_ = printer.Fprint(&buf, fset, &ast.CallExpr{Fun: sel.Sel, Args: call.Args})
		calls = append(calls, logCall{position: fset.Position(call.Pos()).String(), expr: buf.String()})
		return true
	})
	return calls
}

// isRedactCall reports whether expr is a call rooted at the redact package:
// redact.Object(v), redact.JSON(raw), redact.WithProfile(p).Object(v).
func isRedactCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	x := call.Fun
	for {
		switch e := x.(type) {
		case *ast.SelectorExpr:
			x = e.X
		case *ast.CallExpr:
			x = e.Fun
		case *ast.Ident:
			return e.Name == "redact"
		default:
			return false
		}
	}
}
