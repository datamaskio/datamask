// Package reflectx provides reflection helpers for struct field walking
// and type-metadata caching. It is an internal package — only imported by
// the datamask package within the datamask module.
package reflectx

// DataType identifies the kind of data a field holds.
// The zero value (0) is an unexported internal sentinel.
type DataType uint8

const (
	DataTypeUnknown DataType = iota // unexported — not a valid user selection

	// PII — direct identifiers
	DataTypeEmail
	DataTypePhone
	DataTypeSSN

	// Financial
	DataTypeCreditCard

	// Credentials
	DataTypePassword
	DataTypeSecret
	DataTypeAPIKey
	DataTypeJWT
)

// String returns the string representation of the DataType.
func (d DataType) String() string {
	switch d {
	case DataTypeEmail:
		return "email"
	case DataTypePhone:
		return "phone"
	case DataTypeSSN:
		return "ssn"
	case DataTypeCreditCard:
		return "credit-card"
	case DataTypePassword:
		return "password"
	case DataTypeSecret:
		return "secret"
	case DataTypeAPIKey:
		return "api-key"
	case DataTypeJWT:
		return "jwt"
	default:
		return "unknown"
	}
}

// Transform controls how a masked field is transformed.
// The zero value is TransformRedact (the safest default — data destroyed).
type Transform uint8

const (
	TransformRedact    Transform = iota // replace with placeholder (e.g. "[EMAIL]")
	TransformHash                       // replace with SHA-256 hash
	TransformTokenize                   // replace with stable pseudonym
	TransformPartial                    // partially mask (e.g. "j***@example.com")
)

// String returns the string representation of the Transform.
func (t Transform) String() string {
	switch t {
	case TransformRedact:
		return "redact"
	case TransformHash:
		return "hash"
	case TransformTokenize:
		return "tokenize"
	case TransformPartial:
		return "partial"
	default:
		return "unknown"
	}
}