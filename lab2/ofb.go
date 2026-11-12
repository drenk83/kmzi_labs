package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"kmzi/cipher"
)

// OFB — режим обратной связи по выходу на полном блоке.
// Γ0 — синхропосылка, Γi = F(Γi−1), Yi = Xi ⊕ Γi.
// Последний неполный блок забирает старшие байты гаммы, без дополнения.
func OFB(block cipher.Block, iv uint32, plain []byte) []byte {
	out := make([]byte, len(plain))
	gamma := iv
	for off := 0; off < len(plain); off += 4 {
		gamma = block.EncryptBlock(gamma)
		n := len(plain) - off
		if n > 4 {
			n = 4
		}
		for j := 0; j < n; j++ {
			out[off+j] = plain[off+j] ^ byte(gamma>>uint(24-8*j))
		}
	}
	return out
}

func readMode(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		n, err := strconv.Atoi(strings.Fields(line)[0])
		if err != nil {
			return 0, fmt.Errorf("%s: режим %q", path, line)
		}
		return n, nil
	}
	return 0, fmt.Errorf("%s: нет номера режима", path)
}

func readWord(path string) (uint32, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(b) != 4 {
		return 0, fmt.Errorf("%s: нужно 4 байта, получено %d", path, len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}

func encryptJob(lab1Dir, jobDir, outDir string) error {
	modePath, err := singleGlob(filepath.Join(jobDir, "mode*.in"))
	if err != nil {
		return err
	}
	mode, err := readMode(modePath)
	if err != nil {
		return err
	}
	if mode != 2 {
		return fmt.Errorf("в варианте режим %d, программа собирает OFB (2)", mode)
	}
	specPath, err := singleGlob(filepath.Join(lab1Dir, "instructions_*.in"))
	if err != nil {
		return err
	}
	specBytes, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	spec, err := cipher.ParseSpec(string(specBytes))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	fmt.Printf("режим OFB, инструкция %s\n", filepath.Base(specPath))
	for n := 1; n <= 10; n++ {
		plain, err := os.ReadFile(filepath.Join(lab1Dir, "in", fmt.Sprintf("test%d.in", n)))
		if err != nil {
			return err
		}
		key, err := os.ReadFile(filepath.Join(lab1Dir, "key", fmt.Sprintf("key%d.in", n)))
		if err != nil {
			return err
		}
		iv, err := readWord(filepath.Join(jobDir, fmt.Sprintf("IV%d.in", n)))
		if err != nil {
			return err
		}
		block, err := cipher.NewBlock(spec, key)
		if err != nil {
			return fmt.Errorf("test%d: %w", n, err)
		}
		out := OFB(block, iv, plain)
		outPath := filepath.Join(outDir, fmt.Sprintf("test%d.out", n))
		if err := os.WriteFile(outPath, out, 0o644); err != nil {
			return err
		}
		fmt.Printf("test%d.out  %d байт\n", n, len(out))
	}
	return nil
}

func singleGlob(pattern string) (string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("%s: ожидался один файл, найдено %d", pattern, len(matches))
	}
	return matches[0], nil
}
