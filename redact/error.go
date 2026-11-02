package redact

import "regexp"

var (
	// Go's HTTP client quotes the request target: Get "https://...": ...
	quotedRequestTarget = regexp.MustCompile(`\b(Get|Head|Post|Put|Patch|Delete|Options) "[^"]*"`)
	// Any other URL, such as a wallet address in an Open Payments error.
	urlPattern = regexp.MustCompile(`https?://[^\s"']+`)
)

// Error returns err's message with URLs and HTTP request targets replaced by
// Redacted, for logging an error. Wallet addresses are URLs, and errors from
// the HTTP and Open Payments clients include them.
func Error(err error) string {
	if err == nil {
		return ""
	}
	msg := quotedRequestTarget.ReplaceAllString(err.Error(), `$1 "`+Redacted+`"`)
	return urlPattern.ReplaceAllString(msg, Redacted)
}
