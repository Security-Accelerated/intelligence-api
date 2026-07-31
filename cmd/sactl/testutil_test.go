package main

import (
	"io"
	"os"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// The render helpers print directly rather than taking a writer, which keeps
// their call sites short; this keeps them testable anyway.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	w.Close()
	return <-done
}
