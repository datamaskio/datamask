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
