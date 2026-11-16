package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed static/*.css static/*.js static/*.svg static/*.png static/fonts/*.woff2
var staticFS embed.FS

//go:embed templates/*.tmpl templates/debug/*.tmpl
var templateFS embed.FS

// asset is one static file served under /static/<Hashed>.
type asset struct {
	Logical string // "app.css", "fonts/JetBrainsMono-Regular.woff2"
	Hashed  string // "app.3f2a1b9c0d12.css" (flat name)
	Hash    string // "3f2a1b9c0d12"
	Type    string
	Body    []byte
}

// Assets holds the content-hashed static files.
type Assets struct {
	byLogical map[string]*asset
	byHashed  map[string]*asset
}

const staticPrefix = "/static/"

// loadAssets reads the embedded files, hashes them and rewrites references
// to other assets inside CSS ("/static/fonts/x.woff2" -> hashed URL). CSS is
// processed last so its hash covers the rewritten text.
//
// extraCSS (the generated per-locale font rules) is appended to app.css.
func loadAssets(extraCSS string) (*Assets, error) {
	a := &Assets{byLogical: map[string]*asset{}, byHashed: map[string]*asset{}}
	var names []string
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		names = append(names, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(names, func(i, j int) bool { // CSS last
		return !strings.HasSuffix(names[i], ".css") && strings.HasSuffix(names[j], ".css")
	})
	for _, p := range names {
		body, err := staticFS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		logical := strings.TrimPrefix(p, "static/")
		if strings.HasSuffix(p, ".css") {
			s := string(body)
			if logical == "app.css" {
				s += extraCSS
			}
			for l, o := range a.byLogical {
				s = strings.ReplaceAll(s, staticPrefix+l, staticPrefix+o.Hashed)
			}
			body = []byte(s)
		}
		sum := sha256.Sum256(body)
		base := path.Base(logical)
		ext := path.Ext(base)
		hash := hex.EncodeToString(sum[:6])
		hashed := strings.TrimSuffix(base, ext) + "." + hash + ext
		typ := mime.TypeByExtension(ext)
		switch ext {
		case ".woff2":
			typ = "font/woff2"
		case ".svg":
			typ = "image/svg+xml"
		case ".png":
			typ = "image/png"
		case ".css":
			typ = "text/css; charset=utf-8"
		case ".js":
			typ = "text/javascript; charset=utf-8"
		}
		as := &asset{Logical: logical, Hashed: hashed, Hash: hash, Type: typ, Body: body}
		a.byLogical[logical] = as
		a.byHashed[hashed] = as
	}
	return a, nil
}

// URL returns the hashed URL of a logical asset name (panics on a typo,
// which the template tests catch).
func (a *Assets) URL(logical string) string {
	as, ok := a.byLogical[logical]
	if !ok {
		panic("webui: unknown asset " + logical)
	}
	return staticPrefix + as.Hashed
}

// TotalSize is the sum of all asset sizes.
func (a *Assets) TotalSize() (n int) {
	for _, as := range a.byLogical {
		n += len(as.Body)
	}
	return n
}

// ServeHTTP serves /static/<hashed name>; anything else is 404.
func (a *Assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, staticPrefix)
	as, ok := a.byHashed[name]
	if !ok {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	a.serve(w, r, as, "public, max-age=31536000, immutable")
}

func (a *Assets) serve(w http.ResponseWriter, r *http.Request, as *asset, cc string) {
	h := w.Header()
	h.Set("Content-Type", as.Type)
	h.Set("Cache-Control", cc)
	etag := `"` + as.Hash + `"`
	h.Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(as.Body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(as.Body)
	}
}
