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

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil {
			return nil, fmt.Errorf("read %s from tar: %w", hdr.Name, err)
		}
		return buf.Bytes(), nil
	}
}
