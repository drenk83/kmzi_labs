package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Spec — параметры варианта из instructions_<N>.in.
type Spec struct {
	S        [16]byte
	A, B     int
	Rounds   string
	Pad      int
	Schedule string
}

type roundKey struct {
	kind byte
	key  uint32
}

// ParseSpec читает первые пять строк инструкции. Пояснение на cp1251 не используется.
func ParseSpec(text string) (Spec, error) {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		lines = append(lines, line)
		if len(lines) == 5 {
			break
		}
	}
	if len(lines) < 5 {
		return Spec{}, fmt.Errorf("в инструкции меньше пяти строк параметров")
	}

	var spec Spec
	parts := strings.Fields(lines[0])
	if len(parts) != 16 {
		return Spec{}, fmt.Errorf("S-блок: нужно 16 чисел, получено %d", len(parts))
	}
	seen := [16]bool{}
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 15 {
			return Spec{}, fmt.Errorf("S-блок: элемент %q", p)
		}
		if seen[v] {
			return Spec{}, fmt.Errorf("S-блок: значение %d повторяется", v)
		}
		seen[v] = true
		spec.S[i] = byte(v)
	}

	ab := strings.Fields(lines[1])
	if len(ab) != 2 {
		return Spec{}, fmt.Errorf("P-блок: нужны два числа A и B")
	}
	var err error
	spec.A, err = strconv.Atoi(ab[0])
	if err != nil {
		return Spec{}, fmt.Errorf("P-блок: A")
	}
	spec.B, err = strconv.Atoi(ab[1])
	if err != nil {
		return Spec{}, fmt.Errorf("P-блок: B")
	}

	spec.Rounds = lines[2]
	for _, c := range spec.Rounds {
		switch c {
		case 's', 'f', 'l', 't', 'w':
		default:
			return Spec{}, fmt.Errorf("неизвестная подстановка %q", c)
		}
	}

	spec.Pad, err = strconv.Atoi(lines[3])
	if err != nil || spec.Pad < 1 || spec.Pad > 3 {
		return Spec{}, fmt.Errorf("тип дополнения: %q", lines[3])
	}
	spec.Schedule = lines[4]
	return spec, nil
}

// expandKeys строит раундовые ключи из K = k1 || k2.
// Пробел разделяет раунды, запятая — половины 32-битного ключа.
// Первое слово до запятой — старшие 16 бит.
func expandKeys(rounds, schedule string, k1, k2 uint16) ([]roundKey, error) {
	tokens := strings.Fields(schedule)
	var keys []roundKey
	ti := 0
	for _, kind := range rounds {
		rk := roundKey{kind: byte(kind)}
		switch kind {
		case 't':
			keys = append(keys, rk)
			continue
		case 'f', 'l':
			if ti >= len(tokens) {
				return nil, fmt.Errorf("не хватает ключа для раунда %q", kind)
			}
			v, err := evalExpr(tokens[ti], k1, k2)
			if err != nil {
				return nil, fmt.Errorf("ключ %q: %w", tokens[ti], err)
			}
			if strings.Contains(tokens[ti], ",") {
				return nil, fmt.Errorf("раунд %q ждёт 16-битный ключ, получено %q", kind, tokens[ti])
			}
			rk.key = uint32(v)
			ti++
		case 's', 'w':
			if ti >= len(tokens) {
				return nil, fmt.Errorf("не хватает ключа для раунда %q", kind)
			}
			halves, err := splitComma(tokens[ti])
			if err != nil {
				return nil, err
			}
			if len(halves) != 2 {
				return nil, fmt.Errorf("раунд %q ждёт 32-битный ключ из двух слов, получено %q", kind, tokens[ti])
			}
			hi, err := evalExpr(halves[0], k1, k2)
			if err != nil {
				return nil, fmt.Errorf("ключ %q: %w", tokens[ti], err)
			}
			lo, err := evalExpr(halves[1], k1, k2)
			if err != nil {
				return nil, fmt.Errorf("ключ %q: %w", tokens[ti], err)
			}
			rk.key = uint32(hi)<<16 | uint32(lo)
			ti++
		}
		keys = append(keys, rk)
	}
	if ti != len(tokens) {
		return nil, fmt.Errorf("в расписании лишние ключи: %s", strings.Join(tokens[ti:], " "))
	}
	return keys, nil
}

func splitComma(tok string) ([]string, error) {
	depth := 0
	for i := 0; i < len(tok); i++ {
		switch tok[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("лишняя скобка в %q", tok)
			}
		case ',':
			if depth == 0 {
				return []string{tok[:i], tok[i+1:]}, nil
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("незакрытая скобка в %q", tok)
	}
	return []string{tok}, nil
}

func evalExpr(expr string, k1, k2 uint16) (uint16, error) {
	p := &parser{s: expr, k1: k1, k2: k2}
	v, err := p.parseOr()
	if err != nil {
		return 0, err
	}
	p.skip()
	if p.i != len(p.s) {
		return 0, fmt.Errorf("лишний хвост %q", p.s[p.i:])
	}
	return v, nil
}

type parser struct {
	s      string
	i      int
	k1, k2 uint16
}

func (p *parser) skip() {
	for p.i < len(p.s) && unicode.IsSpace(rune(p.s[p.i])) {
		p.i++
	}
}

func (p *parser) parseOr() (uint16, error) {
	v, err := p.parseAnd()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '|' {
			return v, nil
		}
		p.i++
		r, err := p.parseAnd()
		if err != nil {
			return 0, err
		}
		v |= r
	}
}

func (p *parser) parseAnd() (uint16, error) {
	v, err := p.parseXor()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '&' {
			return v, nil
		}
		p.i++
		r, err := p.parseXor()
		if err != nil {
			return 0, err
		}
		v &= r
	}
}

func (p *parser) parseXor() (uint16, error) {
	v, err := p.parseRot()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '^' {
			return v, nil
		}
		p.i++
		r, err := p.parseRot()
		if err != nil {
			return 0, err
		}
		v ^= r
	}
}

func (p *parser) parseRot() (uint16, error) {
	v, err := p.parseAtom()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != '<' {
			return v, nil
		}
		p.i++
		r, err := p.parseAtom()
		if err != nil {
			return 0, err
		}
		n := int(r) & 15
		v = (v << uint(n)) | (v >> uint(16-n))
	}
}

func (p *parser) parseAtom() (uint16, error) {
	p.skip()
	if p.i >= len(p.s) {
		return 0, fmt.Errorf("оборванное выражение")
	}
	if p.s[p.i] == '(' {
		p.i++
		v, err := p.parseOr()
		if err != nil {
			return 0, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ')' {
			return 0, fmt.Errorf("нужна закрывающая скобка")
		}
		p.i++
		return v, nil
	}
	if strings.HasPrefix(p.s[p.i:], "k1") {
		p.i += 2
		return p.k1, nil
	}
	if strings.HasPrefix(p.s[p.i:], "k2") {
		p.i += 2
		return p.k2, nil
	}
	start := p.i
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	if start == p.i {
		return 0, fmt.Errorf("непонятный фрагмент %q", p.s[p.i:])
	}
	n, err := strconv.ParseUint(p.s[start:p.i], 10, 16)
	if err != nil {
		return 0, fmt.Errorf("число %q: %w", p.s[start:p.i], err)
	}
	return uint16(n), nil
}

// pad добавляет маркер — бит 1 — и нули до кратности блока.
// Текст читается байтами, внутри байта сначала старший бит, поэтому маркер
// становится байтом 0x80, а дальше идут нулевые байты.
func pad(data []byte, kind int) ([]byte, error) {
	switch kind {
	case 2:
		out := make([]byte, len(data)+1, len(data)+4)
		copy(out, data)
		out[len(data)] = 0x80
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("дополнение типа %d в этой программе не реализовано", kind)
	}
}

// sp — один такт SP-сети ширины width бит (16 или 32).
// Бит i — коэффициент при 2^i. Он переходит на позицию A*i+B (mod width).
func sp(x, key uint32, width int, sbox [16]byte, A, B int) uint32 {
	x ^= key
	var y uint32
	for shift := 0; shift < width; shift += 4 {
		nib := (x >> uint(shift)) & 0xF
		y |= uint32(sbox[nib]) << uint(shift)
	}
	var z uint32
	for i := 0; i < width; i++ {
		p := (A*i + B) % width
		if (y>>uint(i))&1 == 1 {
			z |= 1 << uint(p)
		}
	}
	return z
}

func encryptBlock(block uint32, rounds []roundKey, sbox [16]byte, A, B int) uint32 {
	for _, r := range rounds {
		switch r.kind {
		case 't':
			block = block<<16 | block>>16
		case 'w':
			block ^= r.key
		case 's':
			block = sp(block, r.key, 32, sbox, A, B)
		case 'f':
			x1 := uint16(block >> 16)
			x2 := uint16(block)
			f := uint16(sp(uint32(x2), r.key, 16, sbox, A, B))
			block = uint32(x2)<<16 | uint32(x1^f)
		case 'l':
			x1 := uint16(block >> 16)
			x2 := uint16(block)
			f := uint16(sp(uint32(x1^x2), r.key, 16, sbox, A, B))
			block = uint32(x1^f)<<16 | uint32(x2^f)
		}
	}
	return block
}

// Encrypt шифрует открытый текст. Ключ — 4 байта, k1 || k2, старший байт первый.
func Encrypt(spec Spec, key, plain []byte) ([]byte, error) {
	if len(key) != 4 {
		return nil, fmt.Errorf("ключ должен быть 4 байта, получено %d", len(key))
	}
	k1 := uint16(key[0])<<8 | uint16(key[1])
	k2 := uint16(key[2])<<8 | uint16(key[3])
	rounds, err := expandKeys(spec.Rounds, spec.Schedule, k1, k2)
	if err != nil {
		return nil, err
	}
	padded, err := pad(plain, spec.Pad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 4 {
		block := uint32(padded[i])<<24 | uint32(padded[i+1])<<16 | uint32(padded[i+2])<<8 | uint32(padded[i+3])
		c := encryptBlock(block, rounds, spec.S, spec.A, spec.B)
		out[i] = byte(c >> 24)
		out[i+1] = byte(c >> 16)
		out[i+2] = byte(c >> 8)
		out[i+3] = byte(c)
	}
	return out, nil
}
