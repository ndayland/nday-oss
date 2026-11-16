package metasploit_test

import (
	"testing"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/feed"
	"nday.land/nday/internal/collector/metasploit"
	"nday.land/nday/internal/testutil"
)

func TestGoldenParityWithPython(t *testing.T) {
	newC := func(ft *testutil.FakeTransport) collector.Collector {
		c, err := metasploit.New(feed.Options{Transport: ft})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, g := range []string{"modules_metadata_base", "feed_edge", "edge_records"} {
		t.Run(g, func(t *testing.T) {
			testutil.CheckGolden(t, "internal/collector/metasploit/testdata/golden/"+g+".golden.json", newC)
		})
	}
}
