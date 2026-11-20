// Package registry lists the collectors exposed by the CLI
// (Python: nday.collectors.COLLECTORS). Add a ported collector here.
package registry

import (
	"sort"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/collector/exploitdb"
	"nday.land/nday/internal/collector/ghsa"
	"nday.land/nday/internal/collector/kev"
	"nday.land/nday/internal/collector/metasploit"
	"nday.land/nday/internal/collector/nuclei"
	"nday.land/nday/internal/collector/nvd"
	"nday.land/nday/internal/collector/osssec"
	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/collector/zerowire"
)

// Collectors maps source name -> factory for the collectors ported to Go.
var Collectors = map[string]collector.Factory{
	kev.Name: kev.Factory,

	cvelist.Name: cvelist.Factory,

	ghsa.Name: ghsa.Factory,

	exploitdb.Name:  exploitdb.Factory,
	metasploit.Name: metasploit.Factory,
	nuclei.Name:     nuclei.Factory,

	xposts.Name: xposts.Factory, // Go only (no Python counterpart)

	nvd.Name: nvd.Factory, // Go only: streamed (nvd.Collector.Run), no events; docs/nvd.md

	osssec.Name: osssec.Factory, // Go only: oss-security posts from seclists.org; docs/osssec.md

	zerowire.Name: zerowire.Factory, // Go only: Cloudflare Radar Zero Wire advisories; docs/zerowire.md
}

// PythonOnly are sources the Python implementation has but Go does not yet.
// `nday collect` rejects them with a clear message instead of "invalid choice".
var PythonOnly = []string{}

// Names returns the registered source names, sorted (argparse choices order).
func Names() []string {
	out := make([]string, 0, len(Collectors))
	for n := range Collectors {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
