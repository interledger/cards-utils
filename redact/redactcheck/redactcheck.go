// Package redactcheck holds the static checks a service runs in its tests to
// keep sensitive data out of its logs:
//
//   - LogCalls fails on a zerolog call that logs a value without redaction.
//   - TagCoverage fails on a struct field that looks sensitive but carries no
//     `sensitive:"<class>"` tag.
//
// Each takes an allowlist of justified exceptions, which stays in the
// service. A service calls them from one test:
//
//	func TestZerologCallsAreRedacted(t *testing.T) {
//		redactcheck.LogCalls(t, "../..", loggingAllowlist)
//	}
//
//	func TestSensitiveTagCoverage(t *testing.T) {
//		redactcheck.TagCoverage(t, []string{"../api/openapi", "../domain", "../config"}, allowlist)
//	}
//
// Both parse source with go/ast and need no type information.
package redactcheck

import "testing"

// LogCalls fails t for each zerolog call in the module at root that logs a
// value without redaction: .Interface, .Any, .Fields or .Object whose value
// is not a redact.* call. Test files, generated files, vendor, testdata,
// hidden directories and nested modules are skipped.
//
// allowlist maps "<path from root>: <call>" to a justification, where <call>
// is the call as gofmt prints it, e.g. `internal/foo/bar.go: Interface("tags", tags)`.
// An entry that matches no call fails too, so stale entries get pruned.
func LogCalls(t testing.TB, root string, allowlist map[string]string) {
	t.Helper()
	problems, err := checkLogCalls(root, allowlist)
	report(t, problems, err)
}

// TagCoverage fails t for each exported struct field under dirs that matches
// SuspiciousField but has no `sensitive` tag and is not in allowlist, for
// each tag whose class redact does not know, and for a field name that
// carries different classes in different structs. Test files and mock and
// testdata directories are skipped.
//
// allowlist maps "package.Struct.Field" to a justification. An entry that
// matches no scanned field fails too.
func TagCoverage(t testing.TB, dirs []string, allowlist map[string]string) {
	t.Helper()
	problems, err := checkTagCoverage(dirs, allowlist)
	report(t, problems, err)
}

func report(t testing.TB, problems []string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
