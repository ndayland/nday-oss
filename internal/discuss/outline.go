package discuss

import (
	"context"
	"unicode/utf8"
)

// What a signed-out visitor may know about a discussion (docs/discuss.md
// §4.1): how many visible comments there are and the coarse shape of the
// first page — per comment only its status, a size class of its source
// length and where it sits (top level or reply). Never a body, an author,
// a language, an id or a time.

// OutlineMaxReplies caps the replies listed per thread in an outline (the
// rest are counted in MoreReplies).
const OutlineMaxReplies = 20

// Size classes of an outline entry ("" for placeholders).
const (
	SizeShort  = "s"
	SizeMedium = "m"
	SizeLong   = "l"
)

// BodySizeClass coarsens a body length in characters.
func BodySizeClass(n int) string {
	switch {
	case n <= 120:
		return SizeShort
	case n <= 600:
		return SizeMedium
	}
	return SizeLong
}

// OutlineComment is one entry of an outline.
type OutlineComment struct {
	Status      string           `json:"status"`         // visible | hidden | deleted
	Size        string           `json:"size,omitempty"` // visible only: s | m | l
	Replies     []OutlineComment `json:"replies,omitempty"`
	MoreReplies int              `json:"more_replies,omitempty"`
}

// Outline is the shape of the first page of a vulnerability's discussion.
type Outline struct {
	Count   int              `json:"count"` // visible comments (all pages)
	Threads []OutlineComment `json:"threads"`
	More    bool             `json:"more"` // threads beyond the first page exist
}

func outlineOf(r *Row) OutlineComment {
	o := OutlineComment{Status: r.Status}
	if r.Status == StatusVisible {
		o.Size = BodySizeClass(utf8.RuneCountInString(r.Body))
	}
	return o
}

func buildOutline(p *Page) *Outline {
	o := &Outline{Count: p.Visible, Threads: []OutlineComment{}, More: p.Next != nil}
	for _, t := range p.Top {
		c := outlineOf(t)
		for k, r := range p.Replies[t.ID] {
			if k >= OutlineMaxReplies {
				c.MoreReplies++
				continue
			}
			c.Replies = append(c.Replies, outlineOf(r))
		}
		o.Threads = append(o.Threads, c)
	}
	return o
}

// Outline returns the signed-out outline of cve's discussion (first page of
// PageDefault threads). Independent of any request: cache it under Version.
func (s *Service) Outline(ctx context.Context, cve string) (*Outline, error) {
	p, err := s.store.Page(ctx, nil, cve, nil, PageDefault)
	if err != nil {
		return nil, err
	}
	return buildOutline(p), nil
}
