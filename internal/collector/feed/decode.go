package feed

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// decodingTransport decodes Content-Encoding like httpx's Response does
// (_models.Response._get_content_decoder): the comma-split, stripped,
// lower-cased Content-Encoding values that httpx supports without optional
// packages (identity, gzip, deflate) are applied in reverse order; unknown
// values are ignored. resp.ContentLength is left as declared by the server
// (the compressed size), which is what Python compares with the cap first.
type decodingTransport struct{ base http.RoundTripper }

func (t decodingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp == nil {
		return resp, err
	}
	var codings []string
	for _, v := range resp.Header.Values("Content-Encoding") {
		for _, part := range strings.Split(v, ",") {
			switch c := strings.ToLower(strings.TrimSpace(part)); c {
			case "gzip", "deflate":
				codings = append(codings, c)
			case "br", "zstd":
				// httpx without the brotli/zstandard packages ignores these
				// too; we never ask for them (Accept-Encoding: gzip).
			}
		}
	}
	if len(codings) == 0 {
		return resp, nil
	}
	var body io.Reader = resp.Body
	for i := len(codings) - 1; i >= 0; i-- {
		body = &lazyDecoder{src: body, coding: codings[i]}
	}
	resp.Body = readCloser{Reader: body, Closer: resp.Body}
	return resp, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// lazyDecoder creates the decompressor on first read so that an empty body
// decodes to nothing (zlib.decompressobj().flush() == b"" in Python) instead
// of failing on a missing header.
type lazyDecoder struct {
	src    io.Reader
	coding string
	r      io.Reader
	err    error
}

func (d *lazyDecoder) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.r == nil {
		br := bufio.NewReader(d.src)
		if _, err := br.Peek(1); err == io.EOF {
			d.err = io.EOF
			return 0, io.EOF
		}
		switch d.coding {
		case "gzip":
			// zlib.decompressobj(MAX_WBITS | 16) decodes ONE gzip member and
			// ignores trailing data: no multistream.
			zr, err := gzip.NewReader(br)
			if err != nil {
				d.err = fmt.Errorf("gzip decoding: %w", err)
				return 0, d.err
			}
			zr.Multistream(false)
			d.r = zr
		case "deflate":
			// httpx DeflateDecoder: zlib-wrapped first, raw deflate fallback.
			if hdr, err := br.Peek(2); err == nil && (uint16(hdr[0])<<8|uint16(hdr[1]))%31 == 0 && hdr[0]&0x0f == 8 {
				zr, err := zlib.NewReader(br)
				if err != nil {
					d.err = fmt.Errorf("deflate decoding: %w", err)
					return 0, d.err
				}
				d.r = zr
			} else {
				d.r = flate.NewReader(br)
			}
		}
	}
	n, err := d.r.Read(p)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("%s decoding: %w", d.coding, err)
		d.err = err
	}
	return n, err
}
