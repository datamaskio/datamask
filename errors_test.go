package datamask

import (
	"errors"
	"testing"
)

func TestSentinelErrorsDistinct(t *testing.T) {
	errs := []error{
		ErrInvalidInput, ErrUnsupportedType, ErrNilReceiver, ErrUninitialized,
		ErrUnknownDataType, ErrUnknownTransform, ErrInvalidSchema,
		ErrMaskFailed, ErrCyclicReference, ErrMaxDepthExceeded,
	}
	for i, a := range errs {
		for j, b := range errs {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %d (%v) matches sentinel %d", i, a, j)
			}
		}
	}
}
