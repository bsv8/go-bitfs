package bitfs

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// quoteDeadline returns a delivery deadline safely in the future; deadline vs
// expiry relations are tested with dedicated fixtures.
func quoteDeadline(t *testing.T) int64 {
	t.Helper()
	return time.Now().UTC().Add(55 * time.Minute).Unix()
}

func constructorOtherKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte("33"), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func constructorRequestTerms(t *testing.T) *ContentRequestTerms {
	t.Helper()
	quoteHash, err := FileQuoteTermsHash(mustConstructorQuote(t).TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := EncodeContentHashes([][]byte{bytes.Repeat([]byte{5}, sha256.Size)})
	if err != nil {
		t.Fatal(err)
	}
	return &ContentRequestTerms{
		QuoteTermsHash:       quoteHash[:],
		RefundTemplateTxID:   bytes.Repeat([]byte{1}, sha256.Size),
		PaymentSequence:      3,
		SellerAmountAfterSat: 10,
		ContentHashesCBOR:    hashesCBOR,
		DeliveryDeadlineUnix: quoteDeadline(t),
	}
}

func mustConstructorQuote(t *testing.T) *SignedFileQuote {
	t.Helper()
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestKey(), "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

// 003 买方签名必须精确覆盖 TermsCBOR：对同一字节验签成功，对外壳、哈希或
// 任何其他字节都不成立。
func TestBuyerSignatureCoversExactlyTheTermsCBOR(t *testing.T) {
	terms := constructorRequestTerms(t)
	request, err := NewSignedContentRequest(terms, quoteTestKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(quoteTestPubkey(), request.TermsCBOR, request.BuyerSignature); err != nil {
		t.Fatalf("buyer signature does not verify over the exact terms CBOR: %v", err)
	}
	outer, err := EncodeSignedContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(quoteTestPubkey(), outer, request.BuyerSignature); err == nil {
		t.Fatal("buyer signature verified over the 003 wire shell")
	}
	authHash := sha256.Sum256(request.TermsCBOR)
	if err := VerifySignature(quoteTestPubkey(), authHash[:], request.BuyerSignature); err == nil {
		t.Fatal("buyer signature verified over the authorization hash")
	}
}

// 004 卖方签名是裸消息签名：精确 32 字节 PaymentAuthorizationHash 经过固定
// SignMessage（内部再 SHA-256 一次）后验证成功；对 CBOR 包装、hex 文本、
// 预先再哈希的摘要或 payload 都不成立。
func TestSellerSignatureCoversExactlyTheAuthorizationHash(t *testing.T) {
	authHash := sha256.Sum256([]byte("authorization bytes"))
	delivery, err := NewSignedContentDelivery(authHash[:], [][]byte{[]byte("payload")}, constructorOtherKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pubkey := constructorOtherKey(t).PubKey().Compressed()
	if err := VerifySignature(pubkey, authHash[:], delivery.SellerPaymentAuthorizationHashSignature); err != nil {
		t.Fatalf("seller signature does not verify over the bare hash: %v", err)
	}
	wrapped, err := canonicalEnc.Marshal([]any{contentProtocolVersion, bstr(authHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(pubkey, wrapped, delivery.SellerPaymentAuthorizationHashSignature); err == nil {
		t.Fatal("seller signature verified over a CBOR-wrapped hash")
	}
	if err := VerifySignature(pubkey, []byte(toHex(authHash[:])), delivery.SellerPaymentAuthorizationHashSignature); err == nil {
		t.Fatal("seller signature verified over hex text")
	}
	doubleDigest := sha256.Sum256(authHash[:])
	if err := VerifySignature(pubkey, doubleDigest[:], delivery.SellerPaymentAuthorizationHashSignature); err == nil {
		t.Fatal("seller signature verified over a pre-hashed digest")
	}
	if err := VerifySignature(pubkey, []byte("payload"), delivery.SellerPaymentAuthorizationHashSignature); err == nil {
		t.Fatal("seller signature verified over payload bytes")
	}
}

func toHex(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(value)*2)
	for _, b := range value {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

func TestDeliveryConstructorRejectsWrongHashLengths(t *testing.T) {
	if _, err := NewSignedContentDelivery(bytes.Repeat([]byte{1}, sha256.Size-1), [][]byte{[]byte("payload")}, constructorOtherKey(t)); err == nil {
		t.Fatal("31-byte authorization hash accepted")
	}
	if _, err := NewSignedContentDelivery(nil, [][]byte{[]byte("payload")}, constructorOtherKey(t)); err == nil {
		t.Fatal("nil authorization hash accepted")
	}
	if _, err := NewSignedContentDelivery(bytes.Repeat([]byte{1}, sha256.Size), [][]byte{}, constructorOtherKey(t)); err == nil {
		t.Fatal("empty payload batch accepted")
	}
}
