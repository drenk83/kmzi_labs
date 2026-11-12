package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"kmzi/cipher"
)

func TestModeIsOFB(t *testing.T) {
	mode, err := readMode("1job_Var8/mode8.in")
	if err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Fatalf("режим %d, для варианта 8 нужен OFB (2)", mode)
	}
}

func TestOFBGammaIsEncryptionOfIV(t *testing.T) {
	spec := loadSpec(t)
	key := readBytes(t, "../lab1/example_key.in")
	block, err := cipher.NewBlock(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := readWord("1job_Var8/IV1.in")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	got := OFB(block, iv, plain)
	if len(got) != len(plain) {
		t.Fatalf("длина %d", len(got))
	}
	gamma := block.EncryptBlock(iv)
	if gamma == iv {
		t.Fatal("F(IV) совпал с IV, проверка первого блока гаммы ничего не различает")
	}
	want0 := plain[0] ^ byte(gamma>>24)
	if got[0] != want0 {
		t.Fatalf("первый байт %02x, нужен F(IV)⊕X = %02x", got[0], want0)
	}
	if got[0] == plain[0]^byte(iv>>24) {
		t.Fatal("первый байт совпал с IV⊕X, гамма не зашифрована")
	}
	tail := plain[4] ^ byte(block.EncryptBlock(gamma)>>24)
	if got[4] != tail {
		t.Fatalf("неполный байт %02x, нужен %02x", got[4], tail)
	}
	if !bytes.Equal(OFB(block, iv, got), plain) {
		t.Fatal("повторный OFB не вернул открытый текст")
	}
}

func TestJobRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := encryptJob("../lab1", "1job_Var8", dir); err != nil {
		t.Fatal(err)
	}
	spec := loadSpec(t)
	for n := 1; n <= 10; n++ {
		plain := readBytes(t, filepath.Join("../lab1/in", fmt.Sprintf("test%d.in", n)))
		out := readBytes(t, filepath.Join(dir, fmt.Sprintf("test%d.out", n)))
		if len(out) != len(plain) {
			t.Fatalf("test%d: шифртекст %d байт, открытый текст %d", n, len(out), len(plain))
		}
		key := readBytes(t, filepath.Join("../lab1/key", fmt.Sprintf("key%d.in", n)))
		iv, err := readWord(filepath.Join("1job_Var8", fmt.Sprintf("IV%d.in", n)))
		if err != nil {
			t.Fatal(err)
		}
		block, err := cipher.NewBlock(spec, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(OFB(block, iv, out), plain) {
			t.Fatalf("test%d: расшифрование не сошлось", n)
		}
	}
}

func loadSpec(t *testing.T) cipher.Spec {
	t.Helper()
	b := readBytes(t, "../lab1/instructions_8.in")
	spec, err := cipher.ParseSpec(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
