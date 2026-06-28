package datamask

import (
	"reflect"
	"strings"

	"github.com/datamaskio/datamask/internal/reflectx"
)

// Strategy is a type alias for reflectx.Strategy. It controls how a masked
// field is transformed.
type Strategy = reflectx.Strategy

// Strategy constants re-exported from the internal reflection package.
const (
	RedactStrategy   = reflectx.RedactStrategy
	HashStrategy     = reflectx.HashStrategy
	TokenizeStrategy = reflectx.TokenizeStrategy
	PartialStrategy  = reflectx.PartialStrategy
)

// MaskTag is the struct tag key used to mark sensitive fields.
const MaskTag = "mask"

// TypeMeta is a type alias for the cached struct metadata.
type TypeMeta = reflectx.TypeMeta

// FieldMeta is a type alias for per-field masking metadata.
type FieldMeta = reflectx.FieldMeta

// Cache is a type alias for the thread-safe type metadata cache.
type Cache = reflectx.Cache

// NewCache returns a ready-to-use Cache.
func NewCache() *Cache {
	return &Cache{}
}

// parseTags walks the struct type t and returns metadata for every field
// tagged with mask:"...". Embedded structs are walked recursively;
// pointer fields are followed (dereferenced).
//
// Fields tagged mask:"-" are excluded. Unknown tag values default to
// RedactStrategy. Tag values are case-insensitive.
func parseTags(t reflect.Type) *TypeMeta {
	meta := &TypeMeta{}
	discoverFields(t, nil, func(index []int, tag string) {
		strategy := strategyFromTag(tag)
		if strategy < 0 {
			return // mask:"-" → skip
		}
		// Copy the index slice since the walk reuses the backing array.
		idx := make([]int, len(index))
		copy(idx, index)
		meta.Fields = append(meta.Fields, FieldMeta{
			Index:    idx,
			Strategy: strategy,
		})
	})
	return meta
}

// strategyFromTag maps a tag value to a Strategy. Returns -1 for mask:"-"
// (meaning skip the field).
func strategyFromTag(tag string) Strategy {
	switch strings.ToLower(tag) {
	case "-":
		return -1
	case "hash":
		return HashStrategy
	case "tokenize":
		return TokenizeStrategy
	case "partial":
		return PartialStrategy
	default:
		return RedactStrategy
	}
}

// discoverFields walks the struct type t and calls onField for each field
// that has a mask tag. Embedded (anonymous) struct fields are promoted:
// their fields are discovered with the index path traversing through the
// embedded struct. Pointer fields are dereferenced.
//
// prefix is the index path to the current struct within the root type.
func discoverFields(t reflect.Type, prefix []int, onField func(index []int, tag string)) {
	// Dereference pointer types.
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	for i := range t.NumField() {
		f := t.Field(i)
		index := append(prefix, i)

		if f.Anonymous {
			// Embedded struct — promote its fields.
			discoverFields(f.Type, index, onField)
			continue
		}

		tag, ok := f.Tag.Lookup(MaskTag)
		if !ok {
			continue
		}
		onField(index, tag)
	}
}
