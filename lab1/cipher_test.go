package main

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestExamples(t *testing.T) {
	spec, err := readSpec("instructions_8.in")
	if err != nil {
		t.Fatal(err)
	}
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
		got, err := Encrypt(spec, key, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("example%d: got %x want %x", n, got, want)
		}
	}
}

func TestSchedule(t *testing.T) {
	k1 := uint16(0x6012)
	k2 := uint16(0x39E9)
	rounds, err := expandKeys("tfssl", "k2 (k1^7941)|(k2^13491),k2 k2<1,k2^29421 k1", k1, k2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rounds) != 5 {
		t.Fatalf("раундов %d", len(rounds))
	}
	if rounds[0].kind != 't' || rounds[0].key != 0 {
		t.Fatalf("tau: %+v", rounds[0])
	}
	if rounds[1].kind != 'f' || rounds[1].key != uint32(k2) {
		t.Fatalf("feistel key %04x", rounds[1].key)
	}
	hi := (k1 ^ 7941) | (k2 ^ 13491)
	wantS1 := uint32(hi)<<16 | uint32(k2)
	if rounds[2].key != wantS1 {
		t.Fatalf("s1 %08x want %08x", rounds[2].key, wantS1)
	}
	rot := uint16(k2<<1 | k2>>15)
	wantS2 := uint32(rot)<<16 | uint32(k2^29421)
	if rounds[3].key != wantS2 {
		t.Fatalf("s2 %08x want %08x", rounds[3].key, wantS2)
	}
	if rounds[4].kind != 'l' || rounds[4].key != uint32(k1) {
		t.Fatalf("lai key %04x", rounds[4].key)
	}
}
