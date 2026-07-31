package main

import (
	"io"
	"os"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// The render helpers print directly rather than taking a writer, which keeps
// their call sites short; this keeps them testable anyway.
//
// It replaces a process-global, so tests using it must not call t.Parallel():
// two running at once would each capture part of the other's output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Both ends close even if fn panics, so a failing test does not leak a
	// descriptor and leave the reader goroutine blocked forever.
	defer r.Close()

	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	func() {
		defer w.Close()
		fn()
	}()
	return <-done
}
