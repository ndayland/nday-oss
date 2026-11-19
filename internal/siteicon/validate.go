package siteicon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/webp"
)

// Limits of a stored icon.
const (
	// MaxBytes is the largest icon stored (and the body cap of an icon
	// request).
	MaxBytes = 64 << 10
	// MaxDim is the largest width or height accepted, in pixels.
	MaxDim = 512
	// maxICOEntries bounds the directory of an ICO file.
	maxICOEntries = 64
)

// Content types of stored icons (site_icon.content_type), decided from
// the bytes, never from the response header.
const (
	TypeICO  = "image/x-icon"
	TypePNG  = "image/png"
	TypeGIF  = "image/gif"
	TypeJPEG = "image/jpeg"
	TypeWebP = "image/webp"
)

// ErrInvalid is wrapped by every Validate error.
var ErrInvalid = errors.New("siteicon: not a usable icon")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

var pngSig = []byte("\x89PNG\r\n\x1a\n")

// Validate decides whether b may be stored and served as an icon from the
// site's own origin, and returns its content type. Accepted: ICO, PNG,
// GIF, JPEG and WebP, recognised by their magic bytes AND a successful
// header decode (image.DecodeConfig with the format's own decoder; for ICO
// a parse of the directory whose every entry must point inside the file at
// a PNG (decoded the same way) or a BITMAPINFOHEADER), 1..MaxDim pixels
// wide and high, 1..MaxBytes bytes. Everything else, SVG and HTML
// included, is refused with an error wrapping ErrInvalid.
func Validate(b []byte) (contentType string, err error) {
	if len(b) == 0 {
		return "", invalid("empty")
	}
	if len(b) > MaxBytes {
		return "", invalid("%d bytes, over %d", len(b), MaxBytes)
	}
	var decode func(io.Reader) (image.Config, error)
	switch {
	case bytes.HasPrefix(b, pngSig):
		contentType, decode = TypePNG, png.DecodeConfig
	case bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a")):
		contentType, decode = TypeGIF, gif.DecodeConfig
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		contentType, decode = TypeJPEG, jpeg.DecodeConfig
	case len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		contentType, decode = TypeWebP, webp.DecodeConfig
	case len(b) >= 6 && binary.LittleEndian.Uint16(b[0:]) == 0 && binary.LittleEndian.Uint16(b[2:]) == 1:
		if err := validateICO(b); err != nil {
			return "", err
		}
		return TypeICO, nil
	default:
		return "", invalid("unknown format")
	}
	if err := checkConfig(b, decode); err != nil {
		return "", err
	}
	return contentType, nil
}

// checkConfig decodes the image header of b and checks its dimensions.
func checkConfig(b []byte, decode func(io.Reader) (image.Config, error)) (err error) {
	defer func() { // a decoder must never take the job down
		if r := recover(); r != nil {
			err = invalid("decoder panic")
		}
	}()
	cfg, err := decode(bytes.NewReader(b))
	if err != nil {
		return invalid("header: %v", err)
	}
	return checkDims(cfg.Width, cfg.Height)
}

func checkDims(w, h int) error {
	if w < 1 || h < 1 || w > MaxDim || h > MaxDim {
		return invalid("%dx%d pixels", w, h)
	}
	return nil
}

// validateICO checks an ICO file: the 6-byte header (reserved 0, type 1 =
// icon, 1..maxICOEntries images), the 16-byte directory entries, each
// image's offset and size inside the file and after the directory, and
// each image's own header: a PNG (decoded) or a BITMAPINFOHEADER (40-byte
// header size, width 1..256, height 1..512 since it counts the mask too).
func validateICO(b []byte) error {
	n := int(binary.LittleEndian.Uint16(b[4:]))
	if n < 1 || n > maxICOEntries {
		return invalid("ico: %d images", n)
	}
	dirEnd := 6 + 16*n
	if len(b) < dirEnd {
		return invalid("ico: short directory")
	}
	for i := 0; i < n; i++ {
		e := b[6+16*i : 6+16*i+16]
		size := int64(binary.LittleEndian.Uint32(e[8:]))
		off := int64(binary.LittleEndian.Uint32(e[12:]))
		if size < 1 || off < int64(dirEnd) || off+size > int64(len(b)) {
			return invalid("ico: image %d outside the file", i)
		}
		img := b[off : off+size]
		switch {
		case bytes.HasPrefix(img, pngSig):
			if err := checkConfig(img, png.DecodeConfig); err != nil {
				return err
			}
		case len(img) >= 40 && binary.LittleEndian.Uint32(img) == 40:
			w := int32(binary.LittleEndian.Uint32(img[4:]))
			h := int32(binary.LittleEndian.Uint32(img[8:]))
			planes := binary.LittleEndian.Uint16(img[12:])
			bits := binary.LittleEndian.Uint16(img[14:])
			if w < 1 || w > 256 || h < 1 || h > 512 || planes > 1 {
				return invalid("ico: bitmap %d is %dx%d", i, w, h)
			}
			switch bits {
			case 1, 4, 8, 16, 24, 32:
			default:
				return invalid("ico: bitmap %d has %d bits a pixel", i, bits)
			}
		default:
			return invalid("ico: image %d is neither PNG nor a bitmap", i)
		}
	}
	return nil
}
