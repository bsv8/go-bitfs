package cddltool

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const sample = `
; comment line
version = 1
kind-range = 1..11
pubkey = bstr .size 33
sig = bstr .size (1..256)
hashes = [1*64 sha256]
sha256 = bstr .size 32
keys = [* pubkey]
label = "bitfs/wire-signature"

msg-1 = [
  version,
  1,
  payload-id: sha256,
  seller-key: pubkey,
  seller-signature: sig
]

msg-union = msg-1 / other
other = [version, 2, count: uint .le 10, positive: uint .gt 0]
`

func mustEnc(t *testing.T, v interface{}) []byte {
	t.Helper()
	raw, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAndValidateSample(t *testing.T) {
	spec, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(spec.RuleNames()); got != 11 {
		t.Fatalf("rule count = %d, want 11", got)
	}
	key := make([]byte, 33)
	hash := make([]byte, 32)
	signature := make([]byte, 70)

	// Positive: exact msg-1 shape.
	good := mustEnc(t, []interface{}{uint64(1), uint64(1), hash, key, signature})
	if err := spec.Validate("msg-1", good); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	// Union dispatch works.
	if err := spec.Validate("msg-union", good); err != nil {
		t.Fatalf("union dispatch failed: %v", err)
	}
	// Wrong kind inside union still matches `other`? No: shape differs.
	wrongKind := mustEnc(t, []interface{}{uint64(1), uint64(9), hash, key, signature})
	if err := spec.Validate("msg-1", wrongKind); err == nil {
		t.Fatal("wrong literal accepted")
	}
	// Oversized signature.
	bad := mustEnc(t, []interface{}{uint64(1), uint64(1), hash, key, make([]byte, 300)})
	if err := spec.Validate("msg-1", bad); err == nil {
		t.Fatal("oversized signature accepted")
	}
	// Short hash.
	shortHash := mustEnc(t, []interface{}{uint64(1), uint64(1), hash[:31], key, signature})
	if err := spec.Validate("msg-1", shortHash); err == nil {
		t.Fatal("31-byte hash accepted")
	}
	// Occurrence bounds: zero hashes rejected by 1*64.
	noHashes := mustEnc(t, []interface{}{})
	if err := spec.Validate("hashes", noHashes); err == nil {
		t.Fatal("empty hashes accepted")
	}
	// * occurrence allows empty.
	if err := spec.Validate("keys", mustEnc(t, []interface{}{})); err != nil {
		t.Fatalf("* occurrence rejected empty list: %v", err)
	}
	if err := spec.Validate("keys", mustEnc(t, []interface{}{key, key})); err != nil {
		t.Fatalf("* occurrence rejected two keys: %v", err)
	}
	// Range and control operators.
	if err := spec.Validate("other", mustEnc(t, []interface{}{uint64(1), uint64(2), uint64(10), uint64(1)})); err != nil {
		t.Fatalf(".le/.gt bounds rejected valid values: %v", err)
	}
	if err := spec.Validate("other", mustEnc(t, []interface{}{uint64(1), uint64(2), uint64(11), uint64(1)})); err == nil {
		t.Fatal(".le bound violated without rejection")
	}
	if err := spec.Validate("other", mustEnc(t, []interface{}{uint64(1), uint64(2), uint64(9), uint64(0)})); err == nil {
		t.Fatal(".gt bound violated without rejection")
	}
	// Text literal rule.
	if err := spec.Validate("label", mustEnc(t, "bitfs/wire-signature")); err != nil {
		t.Fatalf("text literal rejected: %v", err)
	}
	if err := spec.Validate("label", mustEnc(t, "bitfs/other")); err == nil {
		t.Fatal("wrong text literal accepted")
	}
}

func TestParseRejectsUndefinedReference(t *testing.T) {
	_, err := Parse("a = [1*4 missing]")
	if err == nil || !strings.Contains(err.Error(), "undefined") {
		t.Fatalf("undefined reference error = %v", err)
	}
}

func TestParseRejectsDuplicateRule(t *testing.T) {
	_, err := Parse("a = 1\nb = bstr\na = 2\n")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate rule error = %v", err)
	}
}

func TestValidateRejectsNonCanonicalCBORStructures(t *testing.T) {
	spec, err := Parse("h = bstr .size 32\npair = [h, h]\n")
	if err != nil {
		t.Fatal(err)
	}
	// Trailing garbage after the array.
	raw := mustEnc(t, []interface{}{make([]byte, 32), make([]byte, 32)})
	if err := spec.Validate("pair", append(raw, 0xff)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	// Indefinite-length arrays must fail strict decode (manually built:
	// 0x9f ... 0xff is CBOR indefinite array of two 32-byte bstrs).
	indefinite := append([]byte{0x9f}, append(mustEnc(t, make([]byte, 32)), mustEnc(t, make([]byte, 32))...)...)
	indefinite = append(indefinite, 0xff)
	if err := spec.Validate("pair", indefinite); err == nil {
		t.Fatal("indefinite-length array accepted")
	}
	// 非最短整数头（uint 1 写成三字节 0x19 0x00 0x01）必须被确定性重编码比较拒绝。
	nonShortest := append([]byte{0x83, 0x19, 0x00, 0x01},
		append(mustEnc(t, make([]byte, 32)), mustEnc(t, make([]byte, 32))...)...)
	if err := spec.Validate("pair", nonShortest); err == nil || !strings.Contains(err.Error(), "core-deterministic") {
		t.Fatalf("non-shortest integer head error = %v", err)
	}
}
