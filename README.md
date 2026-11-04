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

It also has its own BER-TLV decoder and encoder, which replace
`github.com/moov-io/bertlv`:

```go
decoded, err := tlv.Decode(payload)
pan, ok := tlv.FindFirstTag(decoded, "5A")
encoded, err := tlv.Encode([]tlv.TLV{tlv.NewTag("8A", []byte("00"))})
```

`Decode` is safe for untrusted input, such as SRED decrypted under the wrong
key. It never panics, and every error is a `*tlv.DecodeError` that wraps one
of these sentinels. The error gives only the offset: when a length is wrong,
what looks like the next tag is part of a value, possibly a PAN, so no input
bytes are ever put in an error.

| Error | Cause |
|---|---|
| `ErrTruncated` | Input ends inside a tag or length field |
| `ErrLengthOutOfRange` | Declared length is longer than the remaining data |
| `ErrUnsupportedLength` | Indefinite length (`80`), reserved `FF`, or more than four length bytes |
| `ErrTagTooLong` | Tag longer than four bytes |
| `ErrMaxDepth` | Constructed tags nested deeper than `tlv.MaxDepth` (16) |
| `ErrInputTooLarge` | Input larger than `tlv.MaxInputSize` (64 KiB) |

The size limit bounds memory: each decoded TLV costs far more than the two
bytes it can be encoded in. `Encode` enforces the same limits, and checks that
raw content given for a constructed tag decodes, so `Decode` accepts
everything `Encode` writes.

Like moov, it skips `00` padding between data objects (EMV Book 3 Annex B)
and accepts non-minimal lengths. `FF` is not treated as padding. It differs
from moov in these ways:

- `FindFirstTag` keeps searching after a constructed tag that doesn't contain
  the tag. moov stopped there, so it missed tags that come after a template.
  Where moov found a tag, both return the same TLV. The tag is also compared
  without regard to case.
- Long-form lengths of five to eight bytes, tags longer than four bytes,
  input over 64 KiB and nesting deeper than 16 are rejected. moov accepted
  them; no real EMV payload uses them.
- `Encode` rejects tag `00`, which moov wrote and which decodes as padding.
- `Value` slices share memory with the input, but their capacity is capped,
  so appending to one can't overwrite the bytes after it.
- Errors are `*tlv.DecodeError` with the sentinels above, not moov's
  untyped errors.
- `FindTagByPath`, `PrettyPrint`, `Unmarshal` and `CopyTags` are not
  provided; neither service uses them.

`FuzzDecode` and `FuzzEncode` run in CI. They check that `Decode` never
panics, that whatever it decodes survives `Encode` and a second `Decode`
unchanged, and that `Decode` reads back whatever `Encode` writes.

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
