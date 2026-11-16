package webui

import (
	"bytes"
	"encoding/json"
	"time"

	"nday.land/nday/internal/site"
)

// JSONTok is a piece of pretty-printed JSON; Key marks object keys (shown
// brighter). Text is escaped by html/template like any other value.
type JSONTok struct {
	Text string
	Key  bool
}

// rawEvent is the event as shown in "raw": the stored fields plus detail.
type rawEvent struct {
	ID         int64           `json:"id"`
	Type       string          `json:"type"`
	Source     string          `json:"source"`
	URL        *string         `json:"url"`
	OccurredAt *time.Time      `json:"occurred_at"`
	ObservedAt time.Time       `json:"observed_at"`
	IsBackfill bool            `json:"is_backfill"`
	DedupeKey  string          `json:"dedupe_key"`
	Detail     json.RawMessage `json:"detail"`
}

// RawEventJSON pretty-prints an event for the raw view.
func RawEventJSON(e site.Event) []JSONTok {
	det := e.Detail
	if len(det) == 0 || !json.Valid(det) {
		det = json.RawMessage("null")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rawEvent{ID: e.ID, Type: e.Type, Source: e.Source, URL: e.URL, OccurredAt: e.OccurredAt,
		ObservedAt: e.ObservedAt, IsBackfill: e.IsBackfill, DedupeKey: e.DedupeKey, Detail: det}); err != nil {
		return []JSONTok{{Text: "(detail could not be rendered)"}}
	}
	return TokenizeJSON(bytes.TrimRight(buf.Bytes(), "\n"))
}

// TokenizeJSON splits valid JSON text into runs, marking object keys (a
// string followed, after optional whitespace, by ':').
func TokenizeJSON(b []byte) []JSONTok {
	var out []JSONTok
	var plain bytes.Buffer
	flush := func() {
		if plain.Len() > 0 {
			out = append(out, JSONTok{Text: plain.String()})
			plain.Reset()
		}
	}
	for i := 0; i < len(b); {
		if b[i] != '"' {
			plain.WriteByte(b[i])
			i++
			continue
		}
		j := i + 1
		for j < len(b) && b[j] != '"' {
			if b[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(b) {
			plain.Write(b[i:])
			break
		}
		s := b[i : j+1]
		k := j + 1
		for k < len(b) && (b[k] == ' ' || b[k] == '\n' || b[k] == '\t' || b[k] == '\r') {
			k++
		}
		if k < len(b) && b[k] == ':' {
			flush()
			out = append(out, JSONTok{Text: string(s), Key: true})
		} else {
			plain.Write(s)
		}
		i = j + 1
	}
	flush()
	return out
}
