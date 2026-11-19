package pagefetch

import (
	"strings"
	"testing"
	"time"
)

func TestParsePublished(t *testing.T) {
	cases := []struct {
		in, want, prec string // want "" = not a time
	}{
		{"2026-11-09T22:15:00Z", "2026-11-09T22:15:00Z", PublishedExact},
		{" 2026-11-09T22:15:00.123+08:00 ", "2026-11-09T14:15:00.123Z", PublishedExact},
		{"2026-11-09T22:15:00+0800", "2026-11-09T14:15:00Z", PublishedExact},
		{"2026-11-09T22:15+02:00", "2026-11-09T20:15:00Z", PublishedExact},
		{"2026-11-09 22:15:00 +0000", "2026-11-09T22:15:00Z", PublishedExact},
		{"2026-11-09 22:15:00-05:00", "2026-11-10T03:15:00Z", PublishedExact},
		{"Mon, 09 Nov 2026 22:15:00 GMT", "2026-11-09T22:15:00Z", PublishedExact},
		{"Mon, 9 Nov 2026 22:15:00 -0500", "2026-11-10T03:15:00Z", PublishedExact},
		{"2026-11-09T22:15:00", "2026-11-09T00:00:00Z", PublishedDay}, // no zone: the date as written
		{"2026-11-09 23:59", "2026-11-09T00:00:00Z", PublishedDay},
		{"2026-11-09", "2026-11-09T00:00:00Z", PublishedDay},
		{"2026/11/09", "2026-11-09T00:00:00Z", PublishedDay},
		{"2026/1/2", "2026-01-02T00:00:00Z", PublishedDay},
		{"Mon, 09 Nov 2026 22:15:00 EST", "", ""}, // a zone name Go would guess
		{"2026", "", ""},
		{"2026-11", "", ""},
		{"November 9, 2026", "", ""},
		{"2026-13-01", "", ""},
		{"2026-11-09T22:15:00Z trailing", "", ""},
		{"", "", ""},
		{strings.Repeat("2", 100), "", ""},
	}
	for _, c := range cases {
		at, prec, ok := ParsePublished(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("%q: parsed as %v %s", c.in, at, prec)
			}
			continue
		}
		if !ok || at.Format(time.RFC3339Nano) != c.want || prec != c.prec || at.Location() != time.UTC {
			t.Errorf("%q: %v %q %v, want %s %s", c.in, at, prec, ok, c.want, c.prec)
		}
	}
}

func TestExtractPublished(t *testing.T) {
	fetched := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ld := func(s string) string { return `<script type="application/ld+json">` + s + `</script>` }
	cases := []struct {
		name, body, want, prec, source string // want "" = none
	}{
		// real-world shapes
		{"yoast @graph", `<head>` + ld(`{"@context":"https://schema.org","@graph":[{"@type":"WebPage","@id":"x","datePublished":"2026-10-01T08:00:00+00:00","dateModified":"2026-11-15T08:00:00+00:00"},`+
			`{"@type":"Article","headline":"CVE-2026-1 analysis","datePublished":"2026-11-02T09:30:00+00:00","dateModified":"2026-11-16T00:00:00+00:00"}]}`) + `</head>`,
			"2026-11-02T09:30:00Z", PublishedExact, "json-ld"},
		{"array of objects, type list", `<head>` + ld(`[{"@type":"Organization","name":"x"},{"@type":["BlogPosting","Thing"],"datePublished":"2026-11-03"}]`) + `</head>`,
			"2026-11-03T00:00:00Z", PublishedDay, "json-ld"},
		{"schema.org prefixed type", `<body>` + ld(`{"@type":"http://schema.org/TechArticle","datePublished":"2026-11-04T01:02:03Z"}`) + `</body>`,
			"2026-11-04T01:02:03Z", PublishedExact, "json-ld"},
		{"mainEntity", ld(`{"@type":"WebPage","mainEntity":{"@type":"NewsArticle","datePublished":"2026-11-05T00:00:00Z"}}`),
			"2026-11-05T00:00:00Z", PublishedExact, "json-ld"},
		{"any object when no article", ld(`{"@type":"WebPage","datePublished":"2026-11-06"}`), "2026-11-06T00:00:00Z", PublishedDay, "json-ld"},
		{"article in a later block wins over another object", ld(`{"@type":"WebSite","datePublished":"2020-01-01"}`) + ld(`{"@type":"Report","datePublished":"2026-11-07"}`),
			"2026-11-07T00:00:00Z", PublishedDay, "json-ld"},
		{"junk around JSON-LD", ld("\n<!--\n{\"@type\":\"Article\",\"datePublished\":\"2026-11-08\"};\n-->\n"), "2026-11-08T00:00:00Z", PublishedDay, "json-ld"},
		{"broken JSON-LD falls through to meta", ld(`{"@type":"Article","datePublished":"2026-11-08",,}`) +
			`<meta property="article:published_time" content="2026-11-09T10:00:00+01:00">`, "2026-11-09T09:00:00Z", PublishedExact, "meta:article:published_time"},
		{"type attribute case and spaces", `<script type=" Application/LD+JSON ">{"@type":"Article","datePublished":"2026-11-08"}</script>`,
			"2026-11-08T00:00:00Z", PublishedDay, "json-ld"},
		{"other script ignored", `<script>var x = {"@type":"Article","datePublished":"2026-11-08"}</script>`, "", "", ""},
		{"commented JSON-LD ignored", `<!-- ` + ld(`{"@type":"Article","datePublished":"2026-11-08"}`) + ` -->`, "", "", ""},
		{"dateModified never", ld(`{"@type":"Article","dateModified":"2026-11-08"}`) + `<meta property="article:modified_time" content="2026-11-08">`, "", "", ""},
		{"JSON-LD beats meta", `<meta property="article:published_time" content="2026-11-01T00:00:00Z">` + ld(`{"@type":"Article","datePublished":"2026-11-02T00:00:00Z"}`),
			"2026-11-02T00:00:00Z", PublishedExact, "json-ld"},
		{"article:published_time beats meta names", `<meta name="date" content="2026-11-01"><meta property="article:published_time" content="2026-11-02T03:04:05Z">`,
			"2026-11-02T03:04:05Z", PublishedExact, "meta:article:published_time"},
		{"meta name order (date before citation)", `<meta name="citation_publication_date" content="2026/11/03"><meta name="DC.date" content="2026-11-01">`,
			"2026-11-01T00:00:00Z", PublishedDay, "meta:dc.date"},
		{"citation date", `<meta name="citation_publication_date" content="2026/11/03">`, "2026-11-03T00:00:00Z", PublishedDay, "meta:citation_publication_date"},
		{"parsely", `<meta name="parsely-pub-date" content="2026-11-03T12:00:00Z">`, "2026-11-03T12:00:00Z", PublishedExact, "meta:parsely-pub-date"},
		{"sailthru", `<meta name="sailthru.date" content="2026-11-03 12:00:00">`, "2026-11-03T00:00:00Z", PublishedDay, "meta:sailthru.date"},
		{"dc.date.issued", `<meta name="dc.date.issued" content="2026-11-03">`, "2026-11-03T00:00:00Z", PublishedDay, "meta:dc.date.issued"},
		{"itemprop meta", `<meta itemprop="datePublished" content="2026-11-03T01:00:00Z">`, "2026-11-03T01:00:00Z", PublishedExact, "meta:itemprop"},
		{"itemprop beats time", `<time pubdate datetime="2026-11-01"></time><meta itemprop="datePublished" content="2026-11-03">`,
			"2026-11-03T00:00:00Z", PublishedDay, "meta:itemprop"},
		{"time pubdate", `<body><article><time datetime="2026-11-04T05:06:07Z" pubdate>Nov 4</time>`, "2026-11-04T05:06:07Z", PublishedExact, "time"},
		{"time itemprop", `<time itemprop="datePublished" datetime="2026-11-04">Nov 4</time>`, "2026-11-04T00:00:00Z", PublishedDay, "time"},
		{"plain time ignored", `<time datetime="2026-11-04">Nov 4</time>`, "", "", ""},
		{"meta unknown name ignored", `<meta name="last-modified" content="2026-11-04">`, "", "", ""},
		// plausibility: a bad value falls through to the next source
		{"future falls through", ld(`{"@type":"Article","datePublished":"2027-01-01"}`) + `<meta name="date" content="2026-11-01">`,
			"2026-11-01T00:00:00Z", PublishedDay, "meta:date"},
		{"one day after the fetch accepted", `<meta name="date" content="2026-11-18T11:59:00Z">`, "2026-11-18T11:59:00Z", PublishedExact, "meta:date"},
		{"more than a day after rejected", `<meta name="date" content="2026-11-18T12:01:00Z">`, "", "", ""},
		{"before 1995 rejected", `<meta name="date" content="1994-12-31">`, "", "", ""},
		{"1995 accepted", `<meta name="date" content="1995-01-01">`, "1995-01-01T00:00:00Z", PublishedDay, "meta:date"},
		{"unparsable rejected", `<meta property="article:published_time" content="yesterday">`, "", "", ""},
		{"too deep JSON-LD skipped", ld(strings.Repeat("[", 40) + `{"@type":"Article","datePublished":"2026-11-08"}` + strings.Repeat("]", 40)), "", "", ""},
		{"deeply nested object not walked", ld(`[[[[[[[[{"@type":"Article","datePublished":"2026-11-08"}]]]]]]]]`), "", "", ""},
		{"entities in attributes decoded once", `<meta name="date" content="2026-11-01T10:00:00&#43;01:00">`, "2026-11-01T09:00:00Z", PublishedExact, "meta:date"},
	}
	for _, c := range cases {
		p, ok := ExtractPublished(html200(c.body, ""), fetched)
		if c.want == "" {
			if ok {
				t.Errorf("%s: got %+v", c.name, p)
			}
			continue
		}
		if !ok || p.At.Format(time.RFC3339Nano) != c.want || p.Precision != c.prec || p.Source != c.source {
			t.Errorf("%s: got %+v %v, want %s %s %s", c.name, p, ok, c.want, c.prec, c.source)
		}
	}
	// not HTML, empty, undecodable
	for _, p := range []*Page{nil, {Status: 200, ContentType: "application/json", Body: []byte(`<meta name="date" content="2026-11-01">`)},
		{Status: 404, ContentType: "text/html", Body: []byte(`<meta name="date" content="2026-11-01">`)},
		html200(`<meta name="date" content="2026-11-01">`, "utf-16le")} {
		if got, ok := ExtractPublished(p, fetched); ok {
			t.Errorf("%+v: %+v", p, got)
		}
	}
	// bounds: blocks beyond maxLDBlocks and oversized blocks are not read
	var b strings.Builder
	for i := 0; i < maxLDBlocks; i++ {
		b.WriteString(ld(`{"@type":"Thing"}`))
	}
	b.WriteString(ld(`{"@type":"Article","datePublished":"2026-11-08"}`))
	if got, ok := ExtractPublished(html200(b.String(), ""), fetched); ok {
		t.Errorf("block %d read: %+v", maxLDBlocks+1, got)
	}
	big := ld(`{"@type":"Article","datePublished":"2026-11-08","x":"` + strings.Repeat("a", maxLDBytes) + `"}`)
	if got, ok := ExtractPublished(html200(big, ""), fetched); ok {
		t.Errorf("oversized block read: %+v", got)
	}
}

func FuzzExtractPublished(f *testing.F) {
	f.Add(`<script type="application/ld+json">{"@graph":[{"@type":"Article","datePublished":"2026-11-02"}]}</script>`)
	f.Add(`<meta name="date" content="2026/11/02"><time pubdate datetime="x">`)
	fetched := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		if p, ok := ExtractPublished(html200(s, ""), fetched); ok && !Plausible(p.At, fetched) {
			t.Errorf("implausible %+v", p)
		}
	})
}
