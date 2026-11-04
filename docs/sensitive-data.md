# Sensitive data classification

How to classify the fields of API and domain models, so that `redact` keeps
sensitive data out of logs and audit events. Every service that uses
cards-utils follows these rules.

## How it works

Each field that holds sensitive data carries a `sensitive:"<class>"` struct
tag. The class decides what `redact` does with the value when it is logged.

- **Generated API types:** the tag comes from the OpenAPI spec
  ([cards-openapi-specifications](https://github.com/interledger/cards-openapi-specifications)),
  through `x-oapi-codegen-extra-tags`. Classify the field in the spec and
  regenerate. Never edit the generated tag.
- **Hand-written structs** (domain, config, commands): put the tag on the
  field directly.

A field without a tag is logged in clear. Untagged is a decision too, so make
it on purpose.

## Classes

| Class          | Use it for                                                                                                              | App logs (`redact.Object`) | Audit events (`redact.AuditObject`)              |
| -------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------------------ |
| `pii`          | Data that identifies a person or an account: names, addresses, city, postal code, email, phone, wallet addresses        | Masked                     | Hidden                                           |
| `confidential` | Business identifiers that are not public: VAT, tax and company registration numbers                                     | Masked                     | Hidden                                           |
| `pci`          | Card data in PCI DSS scope: the PAN in any form (clear, encrypted, hashed), track data                                  | Hidden                     | Hidden                                           |
| `crypto_key`   | Key material: BDK, IPEK, PWK, ZMK, PVK, private keys, key blocks, keys wrapped under another key                        | Hidden                     | Hidden                                           |
| `crypto_data`  | Data produced by or for cryptography: SRED cipher data, EMV TLV data, cryptograms (ARQC/ARPC), CSRs, encrypted payloads | Hidden                     | Hidden                                           |
| `credential`   | Anything that grants access: PIN blocks, tokens, passwords, API keys, webhook secrets, connection strings               | Hidden                     | Hidden                                           |
| `dynamic`      | A free-form object whose keys are only known at runtime                                                                 | Each key by the key rules  | Each key by the key rules; unmatched keys hidden |

**Masked** keeps the first and last three characters of a string longer than
eight characters (`SI12345678` → `SI1****678`) and replaces anything shorter,
or any other kind of value, with `****`. That is enough to tell two records
apart in a log without revealing the value. **Hidden** replaces the value with
`[REDACTED]`. A `[]byte` value, masked or hidden, becomes `[REDACTED <n>B]`,
which keeps only its length. Audit records are kept for a long time, so the audit profile
hides everything that is classified.

An unknown class is treated as hidden at runtime, and `redactcheck.TagCoverage`
fails the build on it.

## Choosing a class

Ask these questions in order and stop at the first yes:

1. **Is it card data in PCI scope (a PAN, track data), in any form?** → `pci`.
   An encrypted or hashed PAN is still `pci`.
2. **Is it a key, or does it contain one (even wrapped)?** → `crypto_key`.
3. **Does it grant access to something** (a PIN block, token, password, shared
   secret)? → `credential`.
4. **Is it ciphertext, a cryptogram or raw EMV/TLV data?** → `crypto_data`.
5. **Does it identify a person or their account?** → `pii`.
6. **Is it a non-public business identifier?** → `confidential`.
7. **Is it an object whose keys you don't know in advance?** → `dynamic`.
8. Otherwise, leave it untagged.

### Classes that are easy to mix up

- **`pii` vs `confidential`:** both are masked. `pii` is about a person (a
  merchant's address, a wallet address), `confidential` about a business (its
  VAT number). The audit profile hides both.
- **`crypto_key` vs `crypto_data`:** a key decrypts or signs other data;
  `crypto_data` is what was encrypted or signed. Both are hidden, but the class
  tells a reviewer, and a future retention or access policy, what the field is.
- **`crypto_key` vs `credential`:** a PIN block is encrypted, but it stands in
  for something the cardholder knows, so it is a `credential`. A PWK is a
  `crypto_key`, even though it protects PINs.
- **`dynamic` vs a fixed class:** use `dynamic` only when the keys vary. If the
  whole object is sensitive whatever its keys (for example a webhook `data`
  object that carries EMV data), give it that class instead, so nothing in it
  is ever logged.

### Safe to leave untagged

- IDs (UUIDs, resource IDs) and timestamps.
- Key Check Values (KCVs): a KCV identifies a key without revealing it.
- Identifiers that name a thing rather than hold it, such as a key name or a
  form field key.
- Country codes, currencies, amounts, statuses and enums.
- Infrastructure settings such as listen addresses and hostnames.

If such a field's name looks sensitive (for example `KCV` or `Address`),
`redactcheck.TagCoverage` asks you to classify it. Add it to the service's
allowlist with the reason instead.

## Examples

OpenAPI: a merchant's VAT number.

```yaml
vatNumber:
  type: string
  x-oapi-codegen-extra-tags:
    sensitive: confidential
```

OpenAPI: an encrypted PIN block.

```yaml
pinBlock:
  type: string
  format: byte
  x-oapi-codegen-extra-tags:
    sensitive: credential
```

OpenAPI: a free-form onboarding form submission.

```yaml
data:
  type: object
  x-oapi-codegen-extra-tags:
    sensitive: dynamic
```

Go: hand-written domain and config structs.

```go
type Card struct {
	ID           uuid.UUID
	PanEncrypted []byte `sensitive:"pci"`
	PanHashed    []byte `sensitive:"pci"`
}

type CardKey struct {
	KeyEncryptedKb []byte `sensitive:"crypto_key"`
	KCV            string // safe: identifies the key without revealing it
}

type WebhookConfig struct {
	Secret string `sensitive:"credential"`
}
```

Logging them:

```go
log.Info().
	Str("merchant_id", m.ID).
	Object("merchant", redact.Object(m)).
	Msg("merchant_created")
```

With `vatNumber: "SI12345678"`, the app log has `"vatNumber":"SI1****678"`, and
the audit event (`redact.AuditObject`) has `"vatNumber":"[REDACTED]"`.

## Nested objects, lists and maps

`redact` walks into nested structs, pointers, slices and maps. Classify the
leaf fields, not the container: an `Address` field needs no tag when
`addressLineOne`, `city` and `postalCode` are classified. A tag on a container
applies to the whole value: a hiding class replaces it with `[REDACTED]`, and
`pii` or `confidential` replaces it with `****`.

## Key rules

Raw JSON (`redact.JSON`, used for logged request and response bodies) and the
keys of a `dynamic` object have no struct tags, so they are classified by key
name. A key is hidden when it contains a word such as `pin`, `token`,
`secret`, `password`, `key`, `ksn`, `pwk`, `bdk`, `sred`, `cipher`, `tlv`,
`emv`, `cryptogram` or `cardholder`, or starts or ends with `pan`. It is
masked when it contains a word such as `vat`, `email`, `phone`, `address`,
`wallet`, `name`, `serial` or `account`. The full list is `keyRules` in
[`redact/json.go`](../redact/json.go).

The match is on substrings, so it hides too much rather than too little. Keep
JSON field names descriptive (`pinBlock`, not `pb`) so the rules can find them.

## Enforcement

Each service runs these checks from its tests (see `internal/redact` in each
service):

- `redactcheck.TagCoverage` fails when a field name looks sensitive but has
  no tag, when a tag names an unknown class, or when one field name carries
  different classes in different structs (for example `pii` in the spec and
  `confidential` in the domain).
- `redactcheck.LogCalls` fails on a zerolog `.Interface`, `.Any`, `.Fields`
  or `.Object` call whose value is not a `redact.*` call.

Both take an allowlist of `package.Struct.Field` (or call site) entries, and
every entry needs a reason. An allowlist entry that no longer matches anything
fails the test, so remove it when the field goes away.

## Checklist for a new field

- [ ] Classified in the spec (generated types) or on the struct (hand-written
      types), using the questions above.
- [ ] The same field name has the same class everywhere.
- [ ] Anything that looks sensitive but isn't is allowlisted, with the reason.
- [ ] Logged through `redact.Object` (or `redact.AuditObject` on an audit
      event), never with `.Interface` or a bare `.Object`.
- [ ] Never logged as a separate scalar (`.Str`, `.Bytes`) unless it is safe to
      log in clear, such as an ID or a KCV.
