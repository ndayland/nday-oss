package ghsa_test

import (
	"slices"
	"testing"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/ghsa"
	"nday.land/nday/internal/registry"
)

// test_registered: the CLI exposes "ghsa" with this collector.
func TestRegistered(t *testing.T) {
	f, ok := registry.Collectors["ghsa"]
	if !ok || slices.Contains(registry.PythonOnly, "ghsa") {
		t.Fatal("ghsa not registered")
	}
	c, err := f(collector.Deps{Env: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*ghsa.Collector); !ok || c.Name() != "ghsa" {
		t.Fatalf("%T %s", c, c.Name())
	}
}
