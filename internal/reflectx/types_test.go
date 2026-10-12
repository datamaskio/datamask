package reflectx

import "testing"

func TestDataTypeString(t *testing.T) {
	tests := map[DataType]string{
		DataTypeEmail:      "email",
		DataTypePhone:      "phone",
		DataTypeSSN:        "ssn",
		DataTypeCreditCard: "credit-card",
		DataTypePassword:   "password",
		DataTypeSecret:     "secret",
		DataTypeAPIKey:     "api-key",
		DataTypeJWT:        "jwt",
		DataTypeUnknown:    "unknown",
		DataType(200):      "unknown",
	}
	for dt, want := range tests {
		if got := dt.String(); got != want {
			t.Errorf("DataType(%d).String() = %q, want %q", dt, got, want)
		}
	}
}

func TestTransformString(t *testing.T) {
	tests := map[Transform]string{
		TransformRedact:   "redact",
		TransformHash:     "hash",
		TransformTokenize: "tokenize",
		TransformPartial:  "partial",
		Transform(200):    "unknown",
	}
	for tr, want := range tests {
		if got := tr.String(); got != want {
			t.Errorf("Transform(%d).String() = %q, want %q", tr, got, want)
		}
	}
}
