package domain

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// extractMMDBFromTar reads a tar stream and returns the contents of the first
// file matching "<edition>/*.mmdb". MaxMind distributes databases as gzipped
// tarballs with the .mmdb file inside a version-named directory.
// maxMMDBBytes is a safety cap to prevent memory blowup from malformed archives.
const maxMMDBBytes int64 = 128 << 20 // 128 MiB

func extractMMDBFromTar(r io.Reader, edition string) ([]byte, error) {
	tr := tar.NewReader(r)
	suffix := ".mmdb"

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no .mmdb file found in %s archive", edition)
		}
		if err != nil {
			return nil, fmt.Errorf("read tar header: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(hdr.Name, suffix) {
			continue
		}
		if hdr.Size <= 0 || hdr.Size > maxMMDBBytes {
			return nil, fmt.Errorf("invalid %s size in tar: %d bytes", hdr.Name, hdr.Size)
		}

		var buf bytes.Buffer
		buf.Grow(int(hdr.Size))
		if _, err := io.CopyN(&buf, tr, hdr.Size); err != nil {
			return nil, fmt.Errorf("read %s from tar: %w", hdr.Name, err)
		}
		return buf.Bytes(), nil
	}
}
