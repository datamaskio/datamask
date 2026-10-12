package datamask

import "errors"

// Sentinel errors for the DataMask public API.
// Callers check with errors.Is.
//
// Error categories (ADR-0030):
//
//	Input validation:     ErrInvalidInput, ErrUnsupportedType
//	Receiver validation:  ErrNilReceiver, ErrUninitialized
//	Tag validation:       ErrUnknownDataType, ErrUnknownTransform
//	Schema validation:    ErrInvalidSchema
//	Masking failure:      ErrMaskFailed
//	Traversal:            ErrCyclicReference, ErrMaxDepthExceeded
var (
	// ErrInvalidInput is returned when a caller-provided value doesn't meet
	// the function's requirements (non-pointer, nil pointer).
	ErrInvalidInput = errors.New("datamask: invalid input")

	// ErrUnsupportedType is returned when a type cannot be processed by the
	// library (pointer to int, chan, func, unsafe.Pointer).
	ErrUnsupportedType = errors.New("datamask: unsupported type")

	// ErrNilReceiver is returned when a method is called on a nil *Masker.
	ErrNilReceiver = errors.New("datamask: nil receiver")

	// ErrUninitialized is returned when a method is called on a zero-value
	// Masker or Schema. Use New() or Compile[T]() to create a valid instance.
	ErrUninitialized = errors.New("datamask: uninitialized; use New() or Compile[T]()")

	// ErrUnknownDataType is returned when a struct tag references a data type
	// that is not in the built-in vocabulary.
	ErrUnknownDataType = errors.New("datamask: unknown data type")

	// ErrUnknownTransform is returned when a struct tag references a transform
	// that is not recognized.
	ErrUnknownTransform = errors.New("datamask: unknown transform")

	// ErrInvalidSchema is returned when Schema compilation fails due to an
	// invalid struct (unexported tagged field, etc.).
	ErrInvalidSchema = errors.New("datamask: invalid schema")

	// ErrMaskFailed is returned when a Maskable.Mask() implementation returns
	// an error or a value of the wrong type. Redact returns the zero value of T;
	// RedactInPlace zeroes the failing field. The unmasked value is never
	// returned. errors.Is also matches the error from Mask().
	ErrMaskFailed = errors.New("datamask: masking failed")

	// ErrCyclicReference is returned when a cyclic struct graph is detected
	// during traversal.
	ErrCyclicReference = errors.New("datamask: cyclic reference detected")

	// ErrMaxDepthExceeded is returned when object graph traversal exceeds
	// Config.MaxTraversalDepth.
	ErrMaxDepthExceeded = errors.New("datamask: max traversal depth exceeded")
)
