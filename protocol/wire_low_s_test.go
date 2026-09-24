package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func lowSKey(t *testing.T, repeat string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(repeat), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// lowSSigner 把私钥包装成受约束 Signer（新统一签名入口只接受 Signer）。
func lowSSigner(t *testing.T, key *ec.PrivateKey) *PrivateKeySigner {
	t.Helper()
	signer, err := NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestSignWireDocumentProducesLowS 确认统一签名入口只产出 low-S DER。
func TestSignWireDocumentProducesLowS(t *testing.T) {
	key := lowSKey(t, "21")
	doc := bytes.Repeat([]byte{7}, 64)
	signer := lowSSigner(t, key)
	for kind := uint64(1); kind <= 11; kind++ {
		signature, err := SignWireDocument(context.Background(), signer, WireVersion, kind, doc)
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		parsed, err := ec.ParseDERSignature(signature)
		if err != nil {
			t.Fatal(err)
		}
		halfOrder := new(big.Int).Rsh(ec.S256().Params().N, 1)
		if parsed.S.Cmp(halfOrder) > 0 {
			t.Fatalf("kind %d produced a high-S signature", kind)
		}
		if err := VerifyWireDocument(key.PubKey().Compressed(), WireVersion, kind, doc, signature); err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
	}
}

// TestEveryOrdinaryKindRejectsHighS 遍历全部 11 个 Kind：同一文档的 S' = N-S
// 可延展变体必须被统一验证器作为 ErrHighSSignature 拒绝——任何 Kind 都不得
// 为同一认证文档保留第二份有效 wire 签名。
func TestEveryOrdinaryKindRejectsHighS(t *testing.T) {
	key := lowSKey(t, "22")
	pubkey := key.PubKey().Compressed()
	doc := bytes.Repeat([]byte{9}, 48)

	lowS, err := SignWireDocument(context.Background(), lowSSigner(t, key), WireVersion, 1, doc)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ec.ParseDERSignature(lowS)
	if err != nil {
		t.Fatal(err)
	}
	highS, err := (&ec.Signature{R: base.R, S: new(big.Int).Sub(ec.S256().N, base.S)}).ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(highS, lowS) {
		t.Fatal("test premise broken: the flipped signature is byte-identical")
	}

	for kind := uint64(1); kind <= 11; kind++ {
		if err := VerifyWireDocument(pubkey, WireVersion, kind, doc, highS); !errors.Is(err, ErrHighSSignature) {
			t.Fatalf("kind %d accepted a high-S signature: %v", kind, err)
		}
		// 裸消息路径（交易域之外的固定 SignMessage 对应验证器）同样拒绝。
		digest := sha256.Sum256(doc)
		if err := VerifyMessageSignature(pubkey, digest[:], highS); !errors.Is(err, ErrHighSSignature) {
			t.Fatalf("bare-payload path accepted high-S: %v", err)
		}
	}
}

// TestZeroSNeverAccepted 补齐边界：S = 0 不是合法 ECDSA 签名。
func TestZeroSNeverAccepted(t *testing.T) {
	key := lowSKey(t, "23")
	pubkey := key.PubKey().Compressed()
	doc := []byte("payload")
	signature, err := SignWireDocument(context.Background(), lowSSigner(t, key), WireVersion, 3, doc)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ec.ParseDERSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	zeroS, err := (&ec.Signature{R: base.R, S: big.NewInt(0)}).ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWireDocument(pubkey, WireVersion, 3, doc, zeroS); err == nil || errors.Is(err, ErrHighSSignature) {
		t.Fatalf("zero-S verification result = %v", err)
	}
}

func TestDERWithTrailingBytesIsRejected(t *testing.T) {
	key := lowSKey(t, "24")
	publicKey := key.PubKey().Compressed()
	payload := []byte("strict DER payload")
	messageSignature, err := SignWireDocument(context.Background(), lowSSigner(t, key), WireVersion, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(bytes.Clone(messageSignature), 0)
	if err := VerifyWireDocument(publicKey, WireVersion, 1, payload, trailing); err == nil {
		t.Fatal("ordinary wire signature accepted trailing DER byte")
	}
	messageDigest := sha256.Sum256(payload)
	ordinarySignature, err := key.Sign(messageDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	ordinaryDER, err := ordinarySignature.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessageSignature(publicKey, payload, ordinaryDER); err != nil {
		t.Fatalf("canonical message signature rejected: %v", err)
	}
	if err := VerifyMessageSignature(publicKey, payload, append(ordinaryDER, 0)); err == nil {
		t.Fatal("message signature accepted trailing DER byte")
	}
	digest, err := WireSignatureDigest(WireVersion, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := PublicKeyFromBytes(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigestSignature(parsedKey, digest, trailing); err == nil {
		t.Fatal("transaction digest signature accepted trailing DER byte")
	}
}
