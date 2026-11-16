package nuclei_test

import (
	"testing"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/nuclei"
	"nday.land/nday/internal/testutil"
)

func TestGoldenParityWithPython(t *testing.T) {
	newC := func(ft *testutil.FakeTransport) collector.Collector {
		c, err := nuclei.New(feed.Options{Transport: ft})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, g := range []string{"cves", "feed_edge", "edge_records"} {
		t.Run(g, func(t *testing.T) {
			testutil.CheckGolden(t, "internal/collector/nuclei/testdata/golden/"+g+".golden.json", newC)
		})
	}
}
