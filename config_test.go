package datamask

import (
	"testing"
)

func TestConfigMaxTraversalDepthDefault(t *testing.T) {
	var cfg Config
	cfg.initTokenizeMAC()
	if cfg.MaxTraversalDepth != 100 {
		t.Errorf("default MaxTraversalDepth = %d, want 100", cfg.MaxTraversalDepth)
	}
}

func TestWithMaxTraversalDepth(t *testing.T) {
	m := New(WithMaxTraversalDepth(7))
	if m.cfg.MaxTraversalDepth != 7 {
		t.Errorf("MaxTraversalDepth = %d, want 7", m.cfg.MaxTraversalDepth)
	}
	if d := New().cfg.MaxTraversalDepth; d != 100 {
		t.Errorf("default MaxTraversalDepth = %d, want 100", d)
	}
}
