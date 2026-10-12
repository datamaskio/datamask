package datamask

import (
	"testing"
)

func TestDataTypeString(t *testing.T) {
	tests := []struct {
		dt   DataType
		want string
	}{
		{DataTypeEmail, "email"},
		{DataTypePhone, "phone"},
		{DataTypeSSN, "ssn"},
		{DataTypeCreditCard, "credit-card"},
		{DataTypePassword, "password"},
		{DataTypeSecret, "secret"},
		{DataTypeAPIKey, "api-key"},
		{DataTypeJWT, "jwt"},
		{DataType(99), "unknown"}, // unknown value
		{DataType(0), "unknown"},  // zero value (dataTypeUnknown, unexported)
	}

	for _, tt := range tests {
		got := tt.dt.String()
		if got != tt.want {
			t.Errorf("DataType(%d).String() = %q, want %q", tt.dt, got, tt.want)
		}
	}
}

func TestTransformString(t *testing.T) {
	tests := []struct {
		tr   Transform
		want string
	}{
		{TransformRedact, "redact"},
		{TransformHash, "hash"},
		{TransformTokenize, "tokenize"},
		{TransformPartial, "partial"},
		{Transform(99), "unknown"}, // unknown value
	}

	for _, tt := range tests {
		got := tt.tr.String()
		if got != tt.want {
			t.Errorf("Transform(%d).String() = %q, want %q", tt.tr, got, tt.want)
		}
	}
}

func TestTransformZeroValueIsRedact(t *testing.T) {
	var zero Transform
	if zero != TransformRedact {
		t.Error("zero value of Transform should be TransformRedact (safe default)")
	}
}

func TestDataTypeUserVisibleStartAtOne(t *testing.T) {
	// Verify DataTypeEmail is 1 (not 0 — zero is dataTypeUnknown, unexported).
	if DataTypeEmail != 1 {
		t.Errorf("DataTypeEmail = %d, want 1 (zero is reserved for dataTypeUnknown)", DataTypeEmail)
	}
}
