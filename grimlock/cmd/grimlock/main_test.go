package main

import (
	"io"
	"log"
	"os"
	"testing"
)

// TestMain silences the daemon's operational logging during tests and benchmarks
// (no test asserts on log output), keeping benchmark output clean.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}
