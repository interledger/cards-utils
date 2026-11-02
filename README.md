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
- `redact.Object` integrates with zerolog structured logging.

Each consuming service keeps its own coverage lint and sentinel/property tests
(under `internal/redact`) that assert its own types are classified correctly;
the reusable redaction engine lives here.

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
key. It never panics, and every error is a `*tlv.DecodeError` that gives the
offset and tag (never value bytes) and wraps one of these sentinels:

| Error | Cause |
|---|---|
| `ErrTruncated` | Input ends inside a tag or length field |
| `ErrLengthOutOfRange` | Declared length is longer than the remaining data |
| `ErrUnsupportedLength` | Indefinite length (`80`), reserved `FF`, or more than four length bytes |
| `ErrTagTooLong` | Tag longer than four bytes |
| `ErrMaxDepth` | Constructed tags nested deeper than `tlv.MaxDepth` (16) |

Like moov, it skips `00` padding between data objects and accepts
non-minimal lengths. Two things differ from moov:

- `FindFirstTag` keeps searching after a constructed tag that doesn't contain
  the tag. moov stopped there, so it missed tags that come after a template.
- `Value` slices share memory with the input, but their capacity is capped,
  so appending to one can't overwrite the bytes after it.

`FuzzDecode` runs in CI and checks that `Decode` never panics and that
whatever it decodes survives `Encode` and a second `Decode` unchanged.

## Local development

Until this module is tagged and published, consuming services reference it with
a `replace` directive pointing at a sibling checkout:

```
replace github.com/interledger/cards-utils => ../cards-utils
```
