package cipher

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

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

func TestEncryptBlockMatchesPaddedMessage(t *testing.T) {
	spec := readSpec(t, filepath.Join("..", "instructions_8.in"))
	key := readFile(t, filepath.Join("..", "example_key.in"))
	block, err := NewBlock(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		plain := readFile(t, filepath.Join("..", fmt.Sprintf("example%d.in", n)))
		want := readFile(t, filepath.Join("..", fmt.Sprintf("example%d.out", n)))
		got, err := Encrypt(spec, key, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("example%d: пакет не совпал с эталоном", n)
		}
		padded, err := pad(plain, spec.Pad)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(padded); i += 4 {
			word := uint32(padded[i])<<24 | uint32(padded[i+1])<<16 | uint32(padded[i+2])<<8 | uint32(padded[i+3])
			c := block.EncryptBlock(word)
			chunk := []byte{byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c)}
			if !bytes.Equal(chunk, want[i:i+4]) {
				t.Fatalf("example%d блок %d: %x want %x", n, i/4, chunk, want[i:i+4])
			}
		}
	}
}

func readSpec(t *testing.T, path string) Spec {
	t.Helper()
	spec, err := ParseSpec(string(readFile(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
