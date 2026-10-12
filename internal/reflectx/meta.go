// Package reflectx provides reflection helpers for struct field walking
// and type metadata. It is an internal package — only imported by the
// datamask package within the datamask module.
package reflectx

// TypeMeta holds precomputed field metadata for a struct type.
// It is built once per type by parsing struct tags and stored in the
// compiled Schema.
type TypeMeta struct {
	Fields []FieldMeta
}

// FieldMeta describes one maskable field in a struct.
// Index is the reflect field-index path used with reflect.Value.FieldByIndex.
type FieldMeta struct {
	Index     []int
	DataType  DataType
	Transform Transform
	Path      string // dot-separated Go field path, e.g. "Contact.Email"
	GoType    string // field type as written in Go, e.g. "string", "*string"
	// Unexported is true when the leaf field is unexported, so it can never
	// be masked; Compile rejects such schemas (ErrInvalidSchema).
	Unexported bool
}
