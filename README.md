# datamask

Privacy-by-default data protection for Go. The core library.

[![Go Reference](https://pkg.go.dev/badge/github.com/datamaskio/datamask.svg)](https://pkg.go.dev/github.com/datamaskio/datamask)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Install

```bash
go get github.com/datamaskio/datamask@latest
```

## Usage

```go
masker := datamask.New()

type User struct {
    Email string `mask:"email"`
    SSN   string `mask:"secret"`
}

user := User{Email: "john@example.com", SSN: "123-45-6789"}
masked, _ := datamask.Redact(masker, user)
// masked.Email == "[REDACTED]"
// masked.SSN   == "[REDACTED]"
```

### slog handler

```go
logger := slog.New(maskslog.NewHandler(
    slog.NewJSONHandler(os.Stdout, nil),
))
```

## Packages

| Package | Purpose |
|---|---|
| (root) | Core API — `Masker`, `Redact`, `Config`, `Policy` |
| `secret/` | Secret detection — `Detect`, `DetectAll` |
| `maskslog/` | `slog.Handler` wrapper — automatic log redaction |

## Dependencies

Zero non-stdlib dependencies. The core module uses only the Go standard
library.

## License

MIT
