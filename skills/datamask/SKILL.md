---
name: datamask
description: >
  Integrate DataMask into Go applications for privacy-by-default data protection.
  Use this skill whenever the user asks about masking PII, redacting secrets in
  logs/traces, preventing data leaks in observability, adding mask tags to Go
  structs, wrapping slog handlers, or protecting OpenTelemetry spans. Also use
  when the user mentions "datamask", "mask PII", "redact logs", "secret detection
  in Go", or asks how to prevent sensitive data from reaching telemetry backends.
compatibility: go-1.22+
---

# DataMask — Privacy-by-default for Go

## What DataMask does

DataMask sits between your application and observability sinks. It redacts
sensitive data before it leaves process memory.

```
Application → DataMask → logs, traces, metrics, events
```

## When to use which feature

| Concern | Use | Mechanism |
|---|---|---|
| PII on specific struct fields | `mask:"..."` tags + `datamask.Redact` | Struct tags, explicit |
| Secrets in log attributes | `maskslog.NewHandler` | Automatic, transparent |
| Secrets in span attributes | `maskotel.RedactAttr` | Explicit, per-attribute |
| Secrets in struct values logged via `slog.Any` | `maskslog` with `WithRedactStructs` | Automatic detection |
| Scanning values for secrets programmatically | `secret.Detect` / `secret.DetectAll` | On-demand |

## How to add struct tags

Declare sensitivity at the type level with the `mask` tag:

```go
type Customer struct {
    Name  string              // no tag → passed through
    Email string `mask:"email"`   // → [REDACTED]
    Phone string `mask:"phone"`   // → [REDACTED]
    SSN   string `mask:"secret"`  // → [REDACTED]
    Alias string `mask:"secret,hash"`    // → sha256:abc...
    Card  string `mask:"credit-card,partial"` // → ****-****-****-1234
}
```

Tag values map to strategies:

| Tag value | Strategy | Output example |
|---|---|---|
| `email`, `phone`, `secret`, `ssn`, `credit-card` | Redact | `[REDACTED]` |
| `hash` | SHA-256 hash | `sha256:f83aa...` |
| `partial` | Partial mask | `j***@example.com` |
| `tokenize` | HMAC pseudonym (needs key) | `tok:9c8d2a...` |
| `-` | Skip | (passed through) |

## Import paths

DataMask is split across modules to keep the core stdlib-only:

| Package | Import | Module |
|---|---|---|
| Core (Masker, Policy, tags) | `github.com/datamaskio/datamask` | `datamask` |
| Secret detection | `github.com/datamaskio/datamask/secret` | `datamask` |
| slog handler | `github.com/datamaskio/datamask/maskslog` | `datamask` |
| OTel span processor | `github.com/datamaskio/maskotel` | `maskotel` (separate) |

## How to use the Masker

```go
import "github.com/datamaskio/datamask"

masker := datamask.New(
    datamask.WithSecretDetection(true),
    datamask.WithTokenizeKey("my-hmac-key"),
)

masked, err := datamask.Redact(masker, customer)
// masked is Customer, not any — generics preserve the type
```

`Redact` handles structs, slices (`[]T`), arrays (`[N]T`), and pointers (`*T`).
It recursively walks nested struct fields and slice elements.

## How to wrap slog

One line. Works with any `slog.Handler`:

```go
logger := slog.New(maskslog.NewHandler(
    slog.NewJSONHandler(os.Stdout, nil),
))
```

This automatically scans every log attribute for secrets (API keys, tokens,
JWTs, credit card numbers) and replaces them with `[TYPENAME]`. No code
changes to existing `logger.Info(...)` calls.

**When a secret is in a struct field** (e.g., `Config{Token: "ghp_..."}`),
the handler runs `secret.DetectAll` and replaces the entire value with
`[SECRETS_DETECTED]`.

**To also apply mask-tag redaction to structs**, use `WithRedactStructs()` and
`WithMasker()` together:

```go
masker := datamask.New()
handler := maskslog.NewHandler(base,
    maskslog.WithMasker(masker),      // share a Masker instance
    maskslog.WithRedactStructs(),     // also walk mask tags on struct fields
)
```

## How to use with OpenTelemetry

```go
import "github.com/datamaskio/maskotel"

// Prevent secrets before SetAttributes:
span.SetAttributes(maskotel.RedactAttr(masker, "token", rawToken))

// Or scan all attributes on span end:
processor := maskotel.NewProcessor(
    trace.NewSimpleSpanProcessor(exporter),
)
tp := trace.NewTracerProvider(trace.WithSpanProcessor(processor))
```

## Secret types detected automatically

Eight high-confidence patterns, zero false positives on normal text:

| Pattern | Format | Example |
|---|---|---|
| AWSKey | `AKIA...` or `ASIA...` | `AKIAIOSFODNN7EXAMPLE` |
| GitHubPAT | `ghp_...` (36+ chars) | `ghp_abc123...` |
| GitHubFineGrained | `github_pat_...` | `github_pat_abc...` |
| OpenAIKey | `sk-...` or `sk-proj-...` | `sk-abc123...` |
| StripeLiveKey | `sk_live_...` | `sk_live_abc...` |
| StripeTestKey | `sk_test_...` | `sk_test_abc...` |
| PAN | Credit card numbers | `4111-1111-1111-1111` |
| JWT | Three base64url segments | `eyJ...` |

## Common patterns

**Pattern 1: Redact before logging**

```go
masked, _ := datamask.Redact(masker, customer)
logger.Info("customer", slog.Any("data", masked))
```

**Pattern 2: slog handler for existing codebases**

Add one line at startup to protect every log call without changing call sites:

```go
slog.SetDefault(slog.New(maskslog.NewHandler(
    slog.NewJSONHandler(os.Stdout, nil),
)))
```

**Pattern 3: Struct tags for domain types**

Add tags to your domain models once, and every log/trace/event that includes
them is protected:

```go
type User struct {
    ID    string
    Email string `mask:"email"`
}
```

**Pattern 4: Detect secrets in CI**

```go
findings := secret.DetectAll(config)
for _, f := range findings {
    fmt.Printf("WARNING: %s in field %s\n", f.Type, f.Field)
    os.Exit(1)
}
```

## What NOT to do

- **Don't use `slog.Any` for sensitive flat values.** Log structured fields
  instead: `logger.Info("auth", "token", token)` not
  `logger.Info("auth", slog.Any("token", token))`. The handler scans flat
  string attrs directly.
- **Don't rely on detection for PII.** Secret patterns catch API keys and
  tokens, not emails or phone numbers. Use struct tags for PII.
- **Don't create a new Masker per request.** Create one at startup and reuse
  it — the type cache amortizes reflection cost.
- **Don't pass maps to Redact.** Maps are not walked in v0.1. Use structs.
