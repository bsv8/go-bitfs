// Package cddltool implements a real parser and structural validator for the
// CDDL subset used by spec/v1/wire-messages.cddl. It is not a general-purpose
// CDDL implementation: it deliberately supports exactly the constructs the
// protocol truth uses — rule definitions with '=' and '/=', unions, arrays
// with labelled entries and occurrence indicators, integer/text literals,
// numeric ranges, and the .size/.cbor/.le/.gt control operators — so that a
// grammar mistake, an undefined reference, or a wire message violating the
// published shape fails loudly instead of silently.
//
// The validator decodes CBOR strictly (no tags, no indefinite lengths, no
// trailing bytes) before matching it against a rule, which makes golden
// positives and hand-built negatives meaningful conformance signals.
package cddltool

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

type nodeKind int

const (
	kindArray   nodeKind = iota // [ ... ]
	kindRef                     // reference to another rule
	kindUintLit                 // unsigned integer literal
	kindTextLit                 // text literal
	kindBuiltin                 // uint / int / bstr / tstr
)

// entry is one array element: optional label, occurrence bound (default
// exactly one), and value type.
type entry struct {
	label  string
	occMin int
	occMax int // -1 means unbounded (*)
	typ    *node
}

// node is one parsed alternative.
type node struct {
	kind    nodeKind
	entries []entry // kindArray
	name    string  // kindRef / kindBuiltin
	litU    uint64  // kindUintLit
	litS    string  // kindTextLit

	rMinSet bool
	rMin    uint64
	rMaxSet bool
	rMax    uint64

	sizeSet bool
	sizeMin int
	sizeMax int // -1 unbounded

	cborRef string

	leSet bool
	le    uint64
	gtSet bool
	gt    uint64
}

type cdlRule struct {
	name string
	alts []*node
}

// Spec is a fully parsed CDDL document.
type Spec struct {
	rules map[string]*cdlRule
	order []string
}

func (s *Spec) RuleNames() []string { return s.order }

func (s *Spec) rule(name string) *cdlRule { return s.rules[name] }

// Parse parses complete CDDL source. Duplicate rules, undefined references,
// and unsupported constructs are errors.
func Parse(source string) (*Spec, error) {
	toks, err := tokenize(source)
	if err != nil {
		return nil, err
	}
	bodies, order, err := splitRules(toks)
	if err != nil {
		return nil, err
	}
	s := &Spec{rules: map[string]*cdlRule{}}
	for _, name := range order {
		s.rules[name] = &cdlRule{name: name}
	}
	s.order = order
	for _, name := range order {
		p := &parser{toks: bodies[name]}
		for p.pos < len(p.toks) {
			alt, err := p.parseAlt()
			if err != nil {
				return nil, fmt.Errorf("cddl: rule %q: %w", name, err)
			}
			s.rules[name].alts = append(s.rules[name].alts, alt)
			if p.pos < len(p.toks) {
				if err := p.expect("/"); err != nil {
					return nil, fmt.Errorf("cddl: rule %q: %w", name, err)
				}
			}
		}
		if len(s.rules[name].alts) == 0 {
			return nil, fmt.Errorf("cddl: rule %q has no alternatives", name)
		}
	}
	if err := s.resolve(); err != nil {
		return nil, err
	}
	return s, nil
}

// resolve verifies every referenced rule exists.
func (s *Spec) resolve() error {
	var walk func(n *node, via string) error
	walk = func(n *node, via string) error {
		switch n.kind {
		case kindRef:
			if _, ok := s.rules[n.name]; !ok {
				return fmt.Errorf("cddl: reference to undefined rule %q (via %s)", n.name, via)
			}
		case kindArray:
			for _, e := range n.entries {
				if err := walk(e.typ, via); err != nil {
					return err
				}
			}
		case kindBuiltin:
			switch n.name {
			case "uint", "int", "bstr", "tstr":
			default:
				return fmt.Errorf("cddl: unsupported builtin %q", n.name)
			}
			if n.cborRef != "" {
				if _, ok := s.rules[n.cborRef]; !ok {
					return fmt.Errorf("cddl: .cbor references undefined rule %q", n.cborRef)
				}
			}
		}
		return nil
	}
	for _, name := range s.order {
		for _, alt := range s.rules[name].alts {
			if err := walk(alt, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// tokenize strips comments and splits source into identifiers, numbers, text
// literals, and single-character punctuation.
func tokenize(src string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ';':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '"':
			j := i + 1
			for j < len(src) && src[j] != '"' {
				if src[j] == '\n' {
					return nil, fmt.Errorf("unterminated text literal")
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated text literal")
			}
			toks = append(toks, src[i:j+1])
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			toks = append(toks, src[i:j])
			i = j
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			toks = append(toks, src[i:j])
			i = j
		case c == '.':
			if i+1 < len(src) && src[i+1] == '.' {
				toks = append(toks, "..")
				i += 2
				continue
			}
			j := i
			for j < len(src) && (src[j] == '.' || isIdentChar(src[j])) {
				j++
			}
			control := src[i:j]
			switch control {
			case ".size", ".cbor", ".le", ".gt":
				toks = append(toks, control)
			default:
				return nil, fmt.Errorf("unexpected token %q", control)
			}
			i = j
		case c == ':':
			toks = append(toks, string(c))
			i++
		case strings.IndexByte("=[]()/,*", c) >= 0:
			toks = append(toks, string(c))
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q", string(c))
		}
	}
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentChar(c byte) bool { return isIdentCharBase(c) }

func isIdentCharBase(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '-'
}

// splitRules finds every "name =" / "name /=" header and returns the token
// body belonging to each rule.
func splitRules(toks []string) (map[string][]string, []string, error) {
	type header struct {
		name     string
		bodyFrom int
		extend   bool
	}
	var headers []header
	for i := 0; i < len(toks)-1; i++ {
		t := toks[i]
		if !isIdentStart(t[0]) || (t[0] >= '0' && t[0] <= '9') {
			continue
		}
		if toks[i+1] == "=" || toks[i+1] == "/=" {
			headers = append(headers, header{name: t, bodyFrom: i + 2, extend: toks[i+1] == "/="})
			i++
		}
	}
	bodies := map[string][]string{}
	var order []string
	for idx, h := range headers {
		bodyEnd := len(toks)
		if idx+1 < len(headers) {
			bodyEnd = headers[idx+1].bodyFrom - 2
		}
		body := toks[h.bodyFrom:bodyEnd]
		if h.extend {
			if _, ok := bodies[h.name]; !ok {
				return nil, nil, fmt.Errorf("/= extension of undefined rule %q", h.name)
			}
			merged := append([]string{}, bodies[h.name]...)
			merged = append(merged, "/")
			merged = append(merged, body...)
			bodies[h.name] = merged
			continue
		}
		if _, ok := bodies[h.name]; ok {
			return nil, nil, fmt.Errorf("duplicate rule %q", h.name)
		}
		bodies[h.name] = body
		order = append(order, h.name)
	}
	if len(order) == 0 {
		return nil, nil, fmt.Errorf("no CDDL rules found")
	}
	return bodies, order, nil
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expect(want string) error {
	if got := p.next(); got != want {
		return fmt.Errorf("expected %q, got %q", want, got)
	}
	return nil
}

// parseAlt parses one union alternative: either an array group, a parenthesized
// expression, or a single term with controls.
func (p *parser) parseAlt() (*node, error) {
	switch p.peek() {
	case "[":
		p.pos++
		n := &node{kind: kindArray}
		for {
			if p.peek() == "]" {
				p.pos++
				return n, nil
			}
			e, err := p.parseEntry()
			if err != nil {
				return nil, err
			}
			n.entries = append(n.entries, e)
			switch p.peek() {
			case ",":
				p.pos++
			case "]":
				p.pos++
				return n, nil
			default:
				return nil, fmt.Errorf("expected ',' or ']' in array, got %q", p.peek())
			}
		}
	case "(":
		p.pos++
		inner, err := p.parseAlt()
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		return inner, nil
	default:
		return p.parseTerm()
	}
}

func (p *parser) parseEntry() (entry, error) {
	e := entry{occMin: 1, occMax: 1}
	// Optional member label: IDENT ':'.
	if isIdentToken(p.peek()) && p.at(1) == ":" {
		e.label = p.toks[p.pos]
		p.pos += 2
	}
	// Occurrence indicator: NUM? '*' NUM?
	if p.peek() == "*" {
		p.pos++
		e.occMin, e.occMax = 0, -1
	} else if isNumber(p.peek()) && p.at(1) == "*" {
		minN, err := parseUint(p.next())
		if err != nil {
			return e, err
		}
		p.pos++ // '*'
		if isNumber(p.peek()) {
			maxN, err := parseUint(p.next())
			if err != nil {
				return e, err
			}
			e.occMin, e.occMax = int(minN), int(maxN)
		} else {
			e.occMin, e.occMax = int(minN), -1
		}
	}
	typ, err := p.parseTerm()
	if err != nil {
		return e, err
	}
	e.typ = typ
	return e, nil
}

func (p *parser) at(offset int) string {
	if p.pos+offset < len(p.toks) {
		return p.toks[p.pos+offset]
	}
	return ""
}

func (p *parser) parseTerm() (*node, error) {
	n := &node{}
	tok := p.next()
	switch {
	case tok == "":
		return nil, fmt.Errorf("unexpected end of rule")
	case strings.HasPrefix(tok, "\""):
		n.kind = kindTextLit
		n.litS = strings.Trim(tok, "\"")
		return n, nil
	case isNumber(tok):
		value, err := parseUint(tok)
		if err != nil {
			return nil, err
		}
		n.kind = kindUintLit
		n.litU = value
		// Numeric range: a .. b
		if p.peek() == ".." {
			p.pos++
			hiTok := p.next()
			hi, err := parseUint(hiTok)
			if err != nil {
				return nil, fmt.Errorf("invalid range upper bound %q", hiTok)
			}
			n.rMinSet, n.rMin = true, value
			n.rMaxSet, n.rMax = true, hi
		}
		return n, nil
	case isIdentToken(tok):
		switch tok {
		case "uint", "int", "bstr", "tstr":
			n.kind = kindBuiltin
		default:
			n.kind = kindRef
		}
		n.name = tok
		if p.peek() == ".." {
			// Range over a numeric alias (e.g. wire-kind = 1..13 handled at
			// literal level; aliases with ranges are not supported).
			return nil, fmt.Errorf("ranges over rule references are not supported")
		}
	default:
		return nil, fmt.Errorf("unexpected token %q", tok)
	}
	// Controls apply to builtins and refs alike.
	for p.pos < len(p.toks) {
		switch p.peek() {
		case ".size":
			p.pos++
			n.sizeSet = true
			n.sizeMax = -1
			if p.peek() == "(" {
				p.pos++
				loTok := p.next()
				lo, err := parseUint(loTok)
				if err != nil {
					return nil, err
				}
				n.sizeMin = int(lo)
				if p.peek() == ".." {
					p.pos++
					hiTok := p.next()
					hi, err := parseUint(hiTok)
					if err != nil {
						return nil, err
					}
					n.sizeMax = int(hi)
				} else {
					n.sizeMax = n.sizeMin
				}
				if err := p.expect(")"); err != nil {
					return nil, err
				}
			} else {
				loTok := p.next()
				lo, err := parseUint(loTok)
				if err != nil {
					return nil, err
				}
				n.sizeMin, n.sizeMax = int(lo), int(lo)
			}
		case ".cbor":
			p.pos++
			ref := p.next()
			if !isIdentToken(ref) {
				return nil, fmt.Errorf(".cbor requires a rule name, got %q", ref)
			}
			n.cborRef = ref
		case ".le":
			p.pos++
			v, err := parseUint(p.next())
			if err != nil {
				return nil, err
			}
			n.leSet, n.le = true, v
		case ".gt":
			p.pos++
			v, err := parseUint(p.next())
			if err != nil {
				return nil, err
			}
			n.gtSet, n.gt = true, v
		default:
			return n, nil
		}
	}
	return n, nil
}

func isIdentToken(t string) bool {
	if t == "" {
		return false
	}
	if !isIdentStart(t[0]) {
		return false
	}
	for i := 0; i < len(t); i++ {
		if !isIdentChar(t[i]) {
			return false
		}
	}
	return true
}

func isNumber(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	return true
}

func parseUint(t string) (uint64, error) {
	if !isNumber(t) {
		return 0, fmt.Errorf("expected number, got %q", t)
	}
	var v uint64
	for i := 0; i < len(t); i++ {
		v = v*10 + uint64(t[i]-'0')
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// decoded is the strict-CBOR value model used during matching.
type decoded struct {
	kind  decodedKind
	u     uint64
	i     int64
	bytes []byte
	text  string
	arr   []decoded
}

type decodedKind int

const (
	dUint decodedKind = iota
	dInt
	dBytes
	dText
	dArray
)

var strictDec, _ = (&cbor.DecOptions{
	IndefLength:      cbor.IndefLengthForbidden,
	TagsMd:           cbor.TagsForbidden,
	MaxNestedLevels:  16,
	MaxArrayElements: 1024,
	MaxMapPairs:      0,
	UTF8:             cbor.UTF8RejectInvalid,
}).DecMode()

// detEnc 是 RFC 8949 core deterministic 编码器：整数与长度头一律取最短形式。
var detEnc, _ = cbor.CoreDetEncOptions().EncMode()

func decodeStrict(data []byte) (decoded, error) {
	var any interface{}
	if err := strictDec.Unmarshal(data, &any); err != nil {
		return decoded{}, fmt.Errorf("strict CBOR decode: %w", err)
	}
	// Deterministic re-encode equality: any non-shortest integer, non-shortest
	// bstr/array length head, or other non-canonical encoding is rejected even
	// though it decodes cleanly. This mirrors wire discipline rule §18.1.
	reencoded, err := detEnc.Marshal(any)
	if err != nil {
		return decoded{}, fmt.Errorf("deterministic re-encode: %w", err)
	}
	if !bytes.Equal(reencoded, data) {
		return decoded{}, fmt.Errorf("input is not core-deterministic CBOR (%d bytes, re-encodes to %d)", len(data), len(reencoded))
	}
	return fromAny(any)
}

func fromAny(v interface{}) (decoded, error) {
	switch value := v.(type) {
	case uint64:
		return decoded{kind: dUint, u: value}, nil
	case int64:
		if value >= 0 {
			return decoded{kind: dUint, u: uint64(value)}, nil
		}
		return decoded{kind: dInt, i: value}, nil
	case uint32:
		return decoded{kind: dUint, u: uint64(value)}, nil
	case int:
		if value >= 0 {
			return decoded{kind: dUint, u: uint64(value)}, nil
		}
		return decoded{kind: dInt, i: int64(value)}, nil
	case []byte:
		return decoded{kind: dBytes, bytes: value}, nil
	case string:
		return decoded{kind: dText, text: value}, nil
	case []interface{}:
		out := decoded{kind: dArray, arr: make([]decoded, 0, len(value))}
		for _, item := range value {
			child, err := fromAny(item)
			if err != nil {
				return decoded{}, err
			}
			out.arr = append(out.arr, child)
		}
		return out, nil
	default:
		return decoded{}, fmt.Errorf("unsupported CBOR value type %T", v)
	}
}

// Validate decodes data strictly and matches it against the named rule. When
// the rule is a union, any matching alternative succeeds; otherwise the first
// failure description is returned.
func (s *Spec) Validate(ruleName string, data []byte) error {
	r := s.rules[ruleName]
	if r == nil {
		return fmt.Errorf("cddl: unknown rule %q", ruleName)
	}
	value, err := decodeStrict(data)
	if err != nil {
		return fmt.Errorf("%s: %w", ruleName, err)
	}
	var firstErr error
	for _, alt := range r.alts {
		if err := matchNode(s, alt, value, ruleName, 0); err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func describe(v decoded) string {
	switch v.kind {
	case dUint:
		return fmt.Sprintf("uint %d", v.u)
	case dInt:
		return fmt.Sprintf("negative int %d", v.i)
	case dBytes:
		return fmt.Sprintf("bstr(%d)", len(v.bytes))
	case dText:
		return fmt.Sprintf("tstr %q", v.text)
	default:
		return fmt.Sprintf("array(%d)", len(v.arr))
	}
}

func matchNode(s *Spec, n *node, v decoded, path string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("%s: CDDL nesting too deep", path)
	}
	switch n.kind {
	case kindUintLit:
		if v.kind != dUint || v.u != n.litU {
			return fmt.Errorf("%s: expected literal %d, got %s", path, n.litU, describe(v))
		}
		return nil
	case kindTextLit:
		if v.kind != dText || v.text != n.litS {
			return fmt.Errorf("%s: expected literal %q, got %s", path, n.litS, describe(v))
		}
		return nil
	case kindRef:
		r := s.rules[n.name]
		var firstErr error
		for _, alt := range r.alts {
			if err := matchNode(s, alt, v, path+"/"+n.name, depth+1); err == nil {
				return nil
			} else if firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	case kindBuiltin:
		return matchBuiltin(s, n, v, path, depth)
	case kindArray:
		if v.kind != dArray {
			return fmt.Errorf("%s: expected array, got %s", path, describe(v))
		}
		if !matchEntries(s, n.entries, 0, v.arr, 0, path, depth) {
			return fmt.Errorf("%s: array of %d elements does not match the CDDL group", path, len(v.arr))
		}
		return nil
	}
	return fmt.Errorf("%s: unsupported node", path)
}

func matchBuiltin(s *Spec, n *node, v decoded, path string, depth int) error {
	switch n.name {
	case "uint", "int":
		isUnsigned := v.kind == dUint
		isAnyInt := n.name == "int" && v.kind == dInt
		if !isUnsigned && !isAnyInt {
			return fmt.Errorf("%s: expected %s, got %s", path, n.name, describe(v))
		}
		number := v.u
		if v.kind == dInt {
			if n.rMinSet || n.leSet || n.gtSet {
				return fmt.Errorf("%s: negative value out of supported range checks", path)
			}
			return nil
		}
		if n.rMinSet && v.u < n.rMin {
			return fmt.Errorf("%s: %d below range minimum %d", path, number, n.rMin)
		}
		if n.rMaxSet && v.u > n.rMax {
			return fmt.Errorf("%s: %d above range maximum %d", path, number, n.rMax)
		}
		if n.leSet && v.u > n.le {
			return fmt.Errorf("%s: %d exceeds .le bound %d", path, number, n.le)
		}
		if n.gtSet && v.u <= n.gt {
			return fmt.Errorf("%s: %d violates .gt %d", path, number, n.gt)
		}
		return nil
	case "bstr":
		if v.kind != dBytes {
			return fmt.Errorf("%s: expected bstr, got %s", path, describe(v))
		}
		if n.sizeSet {
			if len(v.bytes) < n.sizeMin || (n.sizeMax >= 0 && len(v.bytes) > n.sizeMax) {
				return fmt.Errorf("%s: bstr(%d) outside size bounds [%d,%d]", path, len(v.bytes), n.sizeMin, n.sizeMax)
			}
		}
		if n.cborRef != "" {
			inner, err := decodeStrict(v.bytes)
			if err != nil {
				return fmt.Errorf("%s: embedded CBOR invalid: %w", path, err)
			}
			return matchRuleValue(s, n.cborRef, inner, path, depth)
		}
		return nil
	case "tstr":
		if v.kind != dText {
			return fmt.Errorf("%s: expected tstr, got %s", path, describe(v))
		}
		if n.sizeSet {
			if len(v.text) < n.sizeMin || (n.sizeMax >= 0 && len(v.text) > n.sizeMax) {
				return fmt.Errorf("%s: tstr length outside size bounds", path)
			}
		}
		return nil
	}
	return fmt.Errorf("%s: unsupported builtin %q", path, n.name)
}

func matchRuleValue(s *Spec, ruleName string, v decoded, path string, depth int) error {
	r := s.rules[ruleName]
	var firstErr error
	for _, alt := range r.alts {
		if err := matchNode(s, alt, v, path+"/"+ruleName, depth+1); err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// matchEntries backtracks across array entries honoring occurrence counts.
func matchEntries(s *Spec, entries []entry, idx int, values []decoded, pos int, path string, depth int) bool {
	if idx == len(entries) {
		return pos == len(values)
	}
	e := entries[idx]
	max := e.occMax
	if max < 0 {
		max = len(values) - pos
	}
	for count := max; count >= e.occMin; count-- {
		if pos+count > len(values) {
			continue
		}
		ok := true
		for i := 0; i < count; i++ {
			if err := matchNode(s, e.typ, values[pos+i], path+"["+e.label+"]", depth+1); err != nil {
				ok = false
				break
			}
		}
		if ok && matchEntries(s, entries, idx+1, values, pos+count, path, depth) {
			return true
		}
	}
	return false
}
