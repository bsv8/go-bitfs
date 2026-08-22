package crosslang_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bsv8/go-bitfs/bitfs"
)

// TestMessageSignatureVector 回验 TS 生成的共享向量（TS 签 / Go 固定 verifier 验）：digest 必须等于对消息的
// 单次 SHA-256，DER 签名必须通过固定 verifier。TS 侧用 ../verify.mjs 验证同
// 一份 JSON，防止任何一侧对摘要二次哈希。
func TestMessageSignatureVector(t *testing.T) {
	raw, err := os.ReadFile("ts_to_go_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		MessageHex string `json:"messageHex"`
		DigestHex  string `json:"digestHex"`
		PubkeyHex  string `json:"pubkeyHex"`
		DERSigHex  string `json:"derSigHex"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	message, err := hex.DecodeString(vector.MessageHex)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(vector.DigestHex)
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := hex.DecodeString(vector.PubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(vector.DERSigHex)
	if err != nil {
		t.Fatal(err)
	}
	computed := sha256.Sum256(message)
	if computed != ([32]byte(digest)) {
		t.Fatalf("digest is not the single SHA-256 of the message: %x", computed)
	}
	if err := bitfs.VerifySignature(pubkey, message, signature); err != nil {
		t.Fatalf("fixed Go verifier rejected the shared vector: %v", err)
	}
}
