package md

import (
	"errors"
	"strings"
)

// Elem is an element node of Nodes.
type Elem struct {
	E    string `json:"e"`
	Href string `json:"href,omitempty"`
	C    []any  `json:"c"`
}

// Nodes turns Render's output into a tree that a script can build with DOM
// methods alone (createElement, textContent), never parsing HTML: a text
// node is a JSON string; an element is {"e": name, "c": [children]}, a link
// also has "href" (keys in that order). Only the elements Render emits are
// accepted (p br pre code blockquote ul ol li em strong a, with a's href and
// the fixed rel),
// and only its five entities; anything else is an error (Render's output is
// always accepted; a fuzz test checks that).
func Nodes(h string) ([]any, error) {
	allowed := map[string]bool{"p": true, "br": true, "pre": true, "code": true, "blockquote": true, "ul": true,
		"ol": true, "li": true, "em": true, "strong": true, "a": true}
	type frame struct {
		name string
		el   *Elem
		kids []any
	}
	stack := []*frame{{}}
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			top := stack[len(stack)-1]
			top.kids = append(top.kids, text.String())
			text.Reset()
		}
	}
	for i := 0; i < len(h); {
		switch c := h[i]; c {
		case '<':
			j := strings.IndexByte(h[i:], '>')
			if j < 0 {
				return nil, errors.New("md: unterminated tag")
			}
			tag := h[i+1 : i+j]
			i += j + 1
			flush()
			if name, ok := strings.CutPrefix(tag, "/"); ok {
				top := stack[len(stack)-1]
				if len(stack) == 1 || top.name != name {
					return nil, errors.New("md: misnested closing tag")
				}
				stack = stack[:len(stack)-1]
				top.el.C = append([]any{}, top.kids...)
				parent := stack[len(stack)-1]
				parent.kids = append(parent.kids, top.el)
				continue
			}
			name, attrs, _ := strings.Cut(tag, " ")
			if !allowed[name] {
				return nil, errors.New("md: element not allowed")
			}
			el := &Elem{E: name}
			if name == "a" {
				const prefix = `href="`
				rest, ok := strings.CutPrefix(attrs, prefix)
				q := strings.IndexByte(rest, '"')
				if !ok || q < 0 || rest[q+1:] != ` rel="`+Rel+`"` {
					return nil, errors.New("md: bad link attributes")
				}
				href := unescapeEntities(rest[:q])
				if !(strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "http://") || SafePath(href)) {
					return nil, errors.New("md: bad href")
				}
				el.Href = href
			} else if attrs != "" {
				return nil, errors.New("md: attributes not allowed")
			}
			if name == "br" {
				el.C = []any{}
				top := stack[len(stack)-1]
				top.kids = append(top.kids, el)
				continue
			}
			stack = append(stack, &frame{name: name, el: el})
		case '&':
			j := strings.IndexByte(h[i:], ';')
			if j < 0 {
				return nil, errors.New("md: bare &")
			}
			r, ok := map[string]string{"&amp;": "&", "&lt;": "<", "&gt;": ">", "&#34;": `"`, "&#39;": "'"}[h[i:i+j+1]]
			if !ok {
				return nil, errors.New("md: unknown entity")
			}
			text.WriteString(r)
			i += j + 1
		case '>', '"':
			return nil, errors.New("md: raw markup character in text")
		default:
			text.WriteByte(c)
			i++
		}
	}
	flush()
	if len(stack) != 1 {
		return nil, errors.New("md: unclosed element")
	}
	out := stack[0].kids
	if out == nil {
		out = []any{}
	}
	return out, nil
}

func unescapeEntities(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'").Replace(s)
}
