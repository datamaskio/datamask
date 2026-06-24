// Package reflectx provides reflection helpers for struct field walking
// and type-metadata caching. It is an internal package — only imported by
// pkg/datamask and pkg/secret within the datamask module.
package reflectx

import (
	"reflect"
	"sync"
)

// TypeMeta holds precomputed field metadata for a struct type.
// It is built once per type by parsing struct tags, then cached.
type TypeMeta struct {
	Fields []FieldMeta
}

// FieldMeta describes one maskable field in a struct.
// Index is the reflect field-index path used with reflect.Value.FieldByIndex.
// Tag is the raw mask tag value (e.g. "email", "secret", "phone").
type FieldMeta struct {
	Index []int
	Tag   string
}

// Cache is a thread-safe, write-once-read-many store for
// reflect.Type → *TypeMeta lookups.
//
// The zero value is ready to use.
type Cache struct {
	m sync.Map
}

// Load returns the cached *TypeMeta for t, or (nil, false) if not present.
func (c *Cache) Load(t reflect.Type) (*TypeMeta, bool) {
	v, ok := c.m.Load(t)
	if !ok {
		return nil, false
	}
	return v.(*TypeMeta), true
}

// Store inserts meta into the cache keyed by t.
func (c *Cache) Store(t reflect.Type, meta *TypeMeta) {
	c.m.Store(t, meta)
}
