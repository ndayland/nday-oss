package cveimport

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nday.land/nday/internal/collector/cvelist"
)

// DefaultMaxInnerBytes caps the extracted inner archive (today ~732 MB).
const DefaultMaxInnerBytes int64 = 8 << 30

// Member is one CVE record file of the baseline.
type Member struct {
	CVE  string
	Year int
	Num  string // sequence digits, for ordering
	file *zip.File
}

// Size is the uncompressed size declared in the zip.
func (m Member) Size() uint64 { return m.file.UncompressedSize64 }

// Archive is an opened baseline: the zip of CVE records, read with random
// access from a file on disk (never loaded into memory).
type Archive struct {
	Members []Member
	// Ignored counts files that are not CVE records (delta.json, ...).
	Ignored  int
	zr       *zip.ReadCloser
	tempPath string // extracted inner archive, removed by Close
}

// Close closes the archive and removes the extracted inner zip, if any.
func (a *Archive) Close() error {
	err := a.zr.Close()
	if a.tempPath != "" {
		if rerr := os.Remove(a.tempPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) && err == nil {
			err = rerr
		}
	}
	return err
}

// OpenArchive opens a baseline file. Upstream ships a zip whose only member
// is another zip (cves.zip); that inner zip is streamed to tmpDir (with its
// CRC-32 verified by archive/zip and its size capped) and opened from disk,
// so memory stays bounded whatever the archive size. A file that already
// is the inner zip (CVE json members) is opened directly.
func OpenArchive(path, tmpDir string, maxInner int64, log *slog.Logger) (*Archive, error) {
	if maxInner <= 0 {
		maxInner = DefaultMaxInnerBytes
	}
	if log == nil {
		log = slog.Default()
	}
	outer, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if inner := nestedMember(outer); inner != nil {
		defer outer.Close()
		if inner.UncompressedSize64 > uint64(maxInner) {
			return nil, fmt.Errorf("inner archive %s declares %d bytes > cap %d", inner.Name, inner.UncompressedSize64, maxInner)
		}
		if tmpDir == "" {
			tmpDir = filepath.Dir(path)
		}
		tmp, err := os.CreateTemp(tmpDir, "cvelist-baseline-inner-*.zip")
		if err != nil {
			return nil, err
		}
		tmpPath := tmp.Name()
		fail := func(err error) (*Archive, error) {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, err
		}
		log.Info("extracting inner archive", "member", inner.Name, "bytes", inner.UncompressedSize64, "to", tmpPath)
		rc, err := inner.Open()
		if err != nil {
			return fail(err)
		}
		// archive/zip checks the CRC-32 and the declared size at EOF.
		n, err := io.Copy(tmp, io.LimitReader(rc, maxInner+1))
		rc.Close()
		if err != nil {
			return fail(fmt.Errorf("extract %s: %w", inner.Name, err))
		}
		if n > maxInner {
			return fail(fmt.Errorf("inner archive exceeds cap %d bytes", maxInner))
		}
		if err := tmp.Close(); err != nil {
			return fail(err)
		}
		zr, err := zip.OpenReader(tmpPath)
		if err != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("open inner archive: %w", err)
		}
		a := newArchive(zr)
		a.tempPath = tmpPath
		return a, nil
	}
	return newArchive(outer), nil
}

// nestedMember returns the single *.zip member of an archive that has no
// CVE records of its own.
func nestedMember(zr *zip.ReadCloser) *zip.File {
	var z *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if _, ok := cvelist.ZipMemberCVE(f.Name); ok {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			if z != nil {
				return nil
			}
			z = f
		}
	}
	return z
}

func newArchive(zr *zip.ReadCloser) *Archive {
	a := &Archive{zr: zr}
	for _, f := range zr.File {
		id, ok := cvelist.ZipMemberCVE(f.Name)
		if !ok {
			if !strings.HasSuffix(f.Name, "/") {
				a.Ignored++
			}
			continue
		}
		parts := strings.SplitN(id, "-", 3)
		year := 0
		for _, c := range parts[1] {
			if c < '0' || c > '9' { // a non-ASCII digit id: keep it, sorts first
				year = 0
				break
			}
			year = year*10 + int(c-'0')
		}
		a.Members = append(a.Members, Member{CVE: id, Year: year, Num: parts[2], file: f})
	}
	// Deterministic order: year, then numeric sequence, then name (the same
	// id can appear twice only in a malformed archive; both are kept and the
	// later one is skipped as already imported).
	sort.SliceStable(a.Members, func(i, j int) bool {
		x, y := a.Members[i], a.Members[j]
		if x.Year != y.Year {
			return x.Year < y.Year
		}
		if len(x.Num) != len(y.Num) {
			return len(x.Num) < len(y.Num)
		}
		if x.Num != y.Num {
			return x.Num < y.Num
		}
		return x.file.Name < y.file.Name
	})
	return a
}

// Read returns the member's bytes (at most max bytes; larger members are an
// error, like the collector skips members over cvelist.MaxMemberBytes).
func (m Member) Read(max int64) ([]byte, error) {
	if m.file.UncompressedSize64 > uint64(max) {
		return nil, fmt.Errorf("member %s is %d bytes > %d", m.file.Name, m.file.UncompressedSize64, max)
	}
	rc, err := m.file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// archive/zip verifies the CRC-32 and the declared size at EOF.
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("member %s exceeds %d bytes", m.file.Name, max)
	}
	return data, nil
}
