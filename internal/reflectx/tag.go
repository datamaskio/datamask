package reflectx

import (
	"errors"
	"strings"
)

// Errors returned by ParseTag. The datamask package maps them to its public
// ErrUnknownDataType and ErrUnknownTransform sentinels.
var (
	ErrUnknownDataType  = errors.New("reflectx: unknown data type")
	ErrUnknownTransform = errors.New("reflectx: unknown transform")
)

// ParseTag parses the value of a mask struct tag (without the "-" opt-out,
// which callers handle first) into a DataType and Transform. It is the single
// definition of tag syntax, shared by the runtime and the code generator
// (ADR-0023):
//
//	"<dataType>"                       transform defaults to redact
//	"<dataType>,<transform>[,opts...]" whitespace trimmed; key=value options on
//	                                   the transform token are ignored
//
// An unknown or empty data type (including v0.1 transform-only tags such as
// "hash") returns ErrUnknownDataType; an unknown or empty transform returns
// ErrUnknownTransform.
func ParseTag(tag string) (DataType, Transform, error) {
	dtStr, rest, hasTransform := strings.Cut(tag, ",")
	dt := dataTypeFromString(strings.TrimSpace(dtStr))
	if dt == DataTypeUnknown {
		return DataTypeUnknown, 0, ErrUnknownDataType
	}
	if !hasTransform {
		return dt, TransformRedact, nil
	}

	// Only the first token after the data type is the transform; the rest
	// are options and are ignored.
	trStr, _, _ := strings.Cut(rest, ",")
	trStr, _, _ = strings.Cut(trStr, "=")
	tr, ok := transformFromString(strings.TrimSpace(trStr))
	if !ok {
		return DataTypeUnknown, 0, ErrUnknownTransform
	}
	return dt, tr, nil
}

func dataTypeFromString(s string) DataType {
	switch strings.ToLower(s) {
	case "email":
		return DataTypeEmail
	case "phone":
		return DataTypePhone
	case "ssn":
		return DataTypeSSN
	case "credit-card", "creditcard":
		return DataTypeCreditCard
	case "password":
		return DataTypePassword
	case "secret":
		return DataTypeSecret
	case "api-key", "apikey":
		return DataTypeAPIKey
	case "jwt":
		return DataTypeJWT
	default:
		return DataTypeUnknown
	}
}

func transformFromString(s string) (Transform, bool) {
	switch strings.ToLower(s) {
	case "redact":
		return TransformRedact, true
	case "hash":
		return TransformHash, true
	case "tokenize":
		return TransformTokenize, true
	case "partial":
		return TransformPartial, true
	}
	return TransformRedact, false
}
