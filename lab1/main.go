package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"kmzi/cipher"
)

func main() {
	dir := flag.String("dir", ".", "каталог лабы: инструкция и примеры рядом, тесты в in/, ключи в key/, шифртексты в out/")
	instr := flag.String("instr", "", "файл инструкции для одиночного запуска")
	inPath := flag.String("in", "", "открытый текст, один файл")
	keyPath := flag.String("key", "", "ключ, 4 байта")
	outPath := flag.String("out", "", "куда записать шифртекст")
	flag.Parse()

	if *inPath != "" {
		if err := encryptOne(*instr, *inPath, *keyPath, *outPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := encryptDir(*dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func encryptOne(instr, inPath, keyPath, outPath string) error {
	if instr == "" || keyPath == "" || outPath == "" {
		return fmt.Errorf("для одного файла нужны -instr, -in, -key и -out")
	}
	spec, err := readSpec(instr)
	if err != nil {
		return err
	}
	plain, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	out, err := cipher.Encrypt(spec, key, plain)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, out, 0o644)
}

func encryptDir(dir string) error {
	specPath, err := findInstructions(dir)
	if err != nil {
		return err
	}
	spec, err := readSpec(specPath)
	if err != nil {
		return err
	}
	fmt.Printf("инструкция %s, раунды %s, дополнение %d\n", filepath.Base(specPath), spec.Rounds, spec.Pad)

	if err := checkExamples(dir, spec); err != nil {
		return err
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for n := 1; n <= 10; n++ {
		inPath := filepath.Join(dir, "in", fmt.Sprintf("test%d.in", n))
		keyPath := filepath.Join(dir, "key", fmt.Sprintf("key%d.in", n))
		outPath := filepath.Join(outDir, fmt.Sprintf("test%d.out", n))
		plain, err := os.ReadFile(inPath)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		out, err := cipher.Encrypt(spec, key, plain)
		if err != nil {
			return fmt.Errorf("test%d: %w", n, err)
		}
		if err := os.WriteFile(outPath, out, 0o644); err != nil {
			return err
		}
		fmt.Printf("test%d.out  %d байт\n", n, len(out))
	}
	return nil
}

func findInstructions(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "instructions_*.in"))
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("в %s ожидался один instructions_*.in, найдено %d", dir, len(matches))
	}
	return matches[0], nil
}

func readSpec(path string) (cipher.Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cipher.Spec{}, err
	}
	return cipher.ParseSpec(string(b))
}

func checkExamples(dir string, spec cipher.Spec) error {
	key, err := os.ReadFile(filepath.Join(dir, "example_key.in"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for n := 1; n <= 3; n++ {
		plain, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("example%d.in", n)))
		if err != nil {
			return err
		}
		want, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("example%d.out", n)))
		if err != nil {
			return err
		}
		got, err := cipher.Encrypt(spec, key, plain)
		if err != nil {
			return fmt.Errorf("example%d: %w", n, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("example%d: шифртекст не совпал с эталоном", n)
		}
		fmt.Printf("example%d OK\n", n)
	}
	return nil
}
