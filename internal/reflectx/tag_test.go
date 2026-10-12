package reflectx

import (
	"errors"
	"testing"
)

func TestParseTag(t *testing.T) {
	tests := []struct {
		tag  string
		dt   DataType
		tr   Transform
		want error
	}{
		{"email", DataTypeEmail, TransformRedact, nil},
		{"EMAIL", DataTypeEmail, TransformRedact, nil},
		{" phone , Partial ", DataTypePhone, TransformPartial, nil},
		{"credit-card", DataTypeCreditCard, TransformRedact, nil},
		{"creditcard,hash", DataTypeCreditCard, TransformHash, nil},
		{"api-key,tokenize", DataTypeAPIKey, TransformTokenize, nil},
		{"apikey", DataTypeAPIKey, TransformRedact, nil},
		{"password", DataTypePassword, TransformRedact, nil},
		{"jwt,redact", DataTypeJWT, TransformRedact, nil},
		{"ssn,hash,key=value", DataTypeSSN, TransformHash, nil},
		{"ssn,hash=x", DataTypeSSN, TransformHash, nil},
		{"hash", 0, 0, ErrUnknownDataType},
		{"tokenize", 0, 0, ErrUnknownDataType},
		{"", 0, 0, ErrUnknownDataType},
		{",hash", 0, 0, ErrUnknownDataType},
		{"bogus,hash", 0, 0, ErrUnknownDataType},
		{"email,hsah", 0, 0, ErrUnknownTransform},
		{"email,", 0, 0, ErrUnknownTransform},
		{"email,,hash", 0, 0, ErrUnknownTransform},
	}
	for _, tt := range tests {
		dt, tr, err := ParseTag(tt.tag)
		if !errors.Is(err, tt.want) {
			t.Errorf("ParseTag(%q) err = %v, want %v", tt.tag, err, tt.want)
			continue
		}
		if err == nil && (dt != tt.dt || tr != tt.tr) {
			t.Errorf("ParseTag(%q) = (%v, %v), want (%v, %v)", tt.tag, dt, tr, tt.dt, tt.tr)
		}
	}
}
