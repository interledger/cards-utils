package redactcheck

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The guard must catch the leaks it exists for, and only those.
func TestCheckLogCalls_CatchesUnredactedValues(t *testing.T) {
	problems, err := checkLogCalls("testdata/logcalls", nil)
	require.NoError(t, err)

	got := strings.Join(problems, "\n")
	require.Len(t, problems, 4, got)
	for _, call := range []string{
		`Interface("card", c)`,
		`Any("card", c)`,
		`Fields(map[string]any{"pan": c.PAN})`,
		`Object("card", c)`,
	} {
		require.Contains(t, got, "logs a value without redaction: "+call+".")
	}
	require.NotContains(t, got, "leak_test.go")
}

func TestCheckLogCalls_Allowlist(t *testing.T) {
	problems, err := checkLogCalls("testdata/logcalls", map[string]string{
		`leak.go: Interface("card", c)`:                 "test",
		`leak.go: Any("card", c)`:                       "test",
		`leak.go: Fields(map[string]any{"pan": c.PAN})`: "test",
		`leak.go: Object("card", c)`:                    "test",
		`gone.go: Interface("x", x)`:                    "stale",
	})
	require.NoError(t, err)
	require.Equal(t, []string{`logging allowlist entry "gone.go: Interface(\"x\", x)" matches no call — remove it`}, problems)
}

func TestCheckLogCalls_FailsOnAnEmptyRoot(t *testing.T) {
	_, err := checkLogCalls(t.TempDir(), nil)
	require.Error(t, err)
}

func TestCheckTagCoverage(t *testing.T) {
	problems, err := checkTagCoverage([]string{"testdata/coverage"}, map[string]string{
		"model.Merchant.KCV": "KCV is a non-revealing check value",
		"model.Gone.Field":   "stale",
	})
	require.NoError(t, err)

	got := strings.Join(problems, "\n")
	require.Len(t, problems, 4, got)
	require.Contains(t, got, `model.Merchant.Email at`)
	require.Contains(t, got, `model.Merchant.Notes: invalid sensitive class "secret-ish"`)
	require.Contains(t, got, `field name "VatNumber" carries conflicting sensitive classes [confidential pii]`)
	require.Contains(t, got, `allowlist entry "model.Gone.Field" matches no scanned field`)
}
