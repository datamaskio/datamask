package datamask

import (
	"time"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// DataType identifies the kind of data a field holds.
// It is a type alias for the canonical definition in internal/reflectx.
type DataType = reflectx.DataType

// Transform controls how a masked field is transformed.
// It is a type alias for the canonical definition in internal/reflectx.
type Transform = reflectx.Transform

// DataType constants re-exported from internal/reflectx.
const (
	DataTypeEmail      = reflectx.DataTypeEmail
	DataTypePhone      = reflectx.DataTypePhone
	DataTypeSSN        = reflectx.DataTypeSSN
	DataTypeCreditCard = reflectx.DataTypeCreditCard
	DataTypePassword   = reflectx.DataTypePassword
	DataTypeSecret     = reflectx.DataTypeSecret
	DataTypeAPIKey     = reflectx.DataTypeAPIKey
	DataTypeJWT        = reflectx.DataTypeJWT
)

// Transform constants re-exported from internal/reflectx.
const (
	TransformRedact   = reflectx.TransformRedact
	TransformHash     = reflectx.TransformHash
	TransformTokenize = reflectx.TransformTokenize
	TransformPartial  = reflectx.TransformPartial
)

// CompileWarning describes a non-fatal issue found during Schema compilation:
// a field whose masking cannot be verified at compile time.
type CompileWarning struct {
	FieldPath string // "User.Payload"
	Reason    string // human-readable explanation
}

// SchemaMetadata holds lifecycle information about a compiled Schema.
type SchemaMetadata struct {
	TypeName  string    // type name, e.g. "User"
	MaskerID  uint64    // ID of the Masker that compiled the Schema
	Version   string    // library version that compiled the Schema
	CreatedAt time.Time // when the plan was first compiled
}
