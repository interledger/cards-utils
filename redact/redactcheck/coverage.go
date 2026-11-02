package redactcheck

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/interledger/cards-utils/redact"
)

// SuspiciousField flags field names that typically carry sensitive data. A
// field matching it must either carry a `sensitive` tag or be allowlisted
// with a justification. Matching is substring-based on purpose: false
// positives cost one allowlist line, false negatives cost a data leak.
var SuspiciousField = regexp.MustCompile(
	`(?i)(vat|tax|registration|key|secret|token|password|email|phone|address|pan$|^pan|track|csr|wallet|payload|pin|tlv|bdk|kcv|cvv|cvc)`)

type fieldDecl struct {
	pkg      string
	strct    string
	field    string
	tag      reflect.StructTag
	position string
}

func checkTagCoverage(dirs []string, allowlist map[string]string) ([]string, error) {
	decls, err := scanStructFields(dirs)
	if err != nil {
		return nil, err
	}
	if len(decls) == 0 {
		return nil, errors.New("no struct fields scanned — scan roots are wrong")
	}

	var problems []string
	classByField := map[string]map[string]bool{}

	for _, d := range decls {
		key := d.pkg + "." + d.strct + "." + d.field
		class, tagged := d.tag.Lookup("sensitive")

		if tagged {
			if !redact.ValidClasses[class] {
				problems = append(problems, fmt.Sprintf(
					"%s: invalid sensitive class %q at %s (valid: pii, crypto_key, crypto_data, credential, confidential, pci, dynamic)",
					key, class, d.position))
			}
			if classByField[d.field] == nil {
				classByField[d.field] = map[string]bool{}
			}
			classByField[d.field][class] = true
			continue
		}

		if !SuspiciousField.MatchString(d.field) {
			continue
		}
		if _, exempt := allowlist[key]; exempt {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"%s at %s looks sensitive but has no `sensitive:\"<class>\"` tag; classify it (OpenAPI: x-oapi-codegen-extra-tags) or allowlist it with a justification",
			key, d.position))
	}

	// Consistency: one field name, one classification — a field tagged
	// confidential in the spec and pii in the domain is a drift bug.
	for field, classes := range classByField {
		if len(classes) > 1 {
			problems = append(problems, fmt.Sprintf(
				"field name %q carries conflicting sensitive classes %v across structs — align spec and domain tags", field, keySet(classes)))
		}
	}

	// Unused allowlist entries rot silently; fail so they get pruned.
	seen := map[string]bool{}
	for _, d := range decls {
		seen[d.pkg+"."+d.strct+"."+d.field] = true
	}
	for key := range allowlist {
		if !seen[key] {
			problems = append(problems, fmt.Sprintf("allowlist entry %q matches no scanned field — remove it", key))
		}
	}
	return problems, nil
}

func scanStructFields(dirs []string) ([]fieldDecl, error) {
	var out []fieldDecl
	fset := token.NewFileSet()

	for _, root := range dirs {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && (d.Name() == "mock" || d.Name() == "testdata") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			pkg := file.Name.Name

			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, f := range st.Fields.List {
					var tag reflect.StructTag
					if f.Tag != nil {
						tag = reflect.StructTag(strings.Trim(f.Tag.Value, "`"))
					}
					for _, name := range f.Names {
						if !name.IsExported() {
							continue
						}
						out = append(out, fieldDecl{
							pkg:      pkg,
							strct:    ts.Name.Name,
							field:    name.Name,
							tag:      tag,
							position: fset.Position(name.Pos()).String(),
						})
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", root, err)
		}
	}
	return out, nil
}

func keySet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
