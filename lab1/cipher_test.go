package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"kmzi/cipher"
)

func TestExamples(t *testing.T) {
	spec := readSpecFile(t, "instructions_8.in")
	key, err := os.ReadFile("example_key.in")
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		name := fmt.Sprintf("example%d", n)
		plain, err := os.ReadFile(name + ".in")
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(name + ".out")
		if err != nil {
			t.Fatal(err)
		}
		got, err := cipher.Encrypt(spec, key, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("example%d: got %x want %x", n, got, want)
		}
	}
}

func readSpecFile(t *testing.T, path string) cipher.Spec {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := cipher.ParseSpec(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
