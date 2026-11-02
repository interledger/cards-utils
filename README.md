# cards-utils

Shared Go library for logic common to the Issuer API and Merchant API.

Module: `github.com/interledger/cards-utils`

## build
Run the below command to build the project.
```bash
go build ./...
```

## test
Run the below command to run the unit tests.
```bash
go test ./...
```

## Packages

### `redact`

Produces loggable copies of API and domain values with sensitive fields masked
or hidden, driven by `sensitive:"<class>"` struct tags. Classification follows
the ILF EMV Field Data v1.0 sensitivity key.

Never log a request/response/domain struct directly — always go through
`redact.Redact` or `redact.Object`:

```go
log.Info().Object("merchant", redact.Object(m)).Msg("merchant created")
```

Highlights:

- Tag-driven: `pii`/`confidential` are masked, `crypto_key`/`crypto_data`/`credential`/`pci` are hidden, `dynamic` maps are redacted by key rules.
- `ProfileApp` (default) masks identifiers; `ProfileAudit` fails closed and hides everything classified.
- `redact.JSON` redacts raw JSON bodies by key rules for byte-level logging.
- `redact.Object` integrates with zerolog structured logging; `redact.AuditObject` does the same under `ProfileAudit`, for audit events.
- `redact.Error` returns an error's message with URLs and HTTP request targets redacted.

[docs/sensitive-data.md](docs/sensitive-data.md) explains when to use each
class, with examples. Read it before you add or classify a field.

Each consuming service keeps its own sentinel/property tests (under
`internal/redact`) that assert its own types are classified correctly; the
reusable redaction engine lives here.

### `redact/redactcheck`

Static checks a service runs from its tests, with its own allowlists of
justified exceptions:

- `redactcheck.LogCalls` fails on a zerolog `.Interface`, `.Any`, `.Fields` or
  `.Object` call whose value is not a `redact.*` call.
- `redactcheck.TagCoverage` fails on a struct field that looks sensitive but
  has no `sensitive:"<class>"` tag.

```go
func TestZerologCallsAreRedacted(t *testing.T) {
	redactcheck.LogCalls(t, "../..", loggingAllowlist)
}
```

### `logging`

The services' zerolog setup and echo middleware: `Init`, a request-scoped
logger (`WithLogger`, `FromContext`), `ZerologMiddleware` (one
`request_completed` line per successful request), `BodyMiddleware` (redacted
JSON bodies at debug, behind a flag), `LogPanic` for echo's Recover
middleware, and `Audit` for audit events. See the package doc for the
conventions, including the middleware order.

### `tlv`

Validates the EMV authorized amount (`9F02`) in BER-TLV payloads and provides
numeric BCD conversion:

```go
err := tlv.ValidateAmount(payload, "100")
```

Validation errors can be classified with `errors.Is` using the exported
sentinels such as `tlv.ErrParsingTLV` and `tlv.ErrAmountMismatch`.

## Local development

The module has no tagged releases yet, so services pin a commit with a
pseudo-version:

```bash
go get github.com/interledger/cards-utils@<commit>
```

To try local changes in a service before they are merged, point it at a
sibling checkout with a `replace` directive, and remove it before you commit:

```
replace github.com/interledger/cards-utils => ../cards-utils
```
