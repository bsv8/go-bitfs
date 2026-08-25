package content

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/protocol"
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

func constructorSigner(t *testing.T, key *ec.PrivateKey) *protocol.PrivateKeySigner {
	t.Helper()
	signer, err := protocol.NewPrivateKeySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func constructorRequestTerms(t *testing.T) *PaymentAuthorization {
	t.Helper()
	quoteID, err := FileQuoteTermsID(mustConstructorQuote(t).FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hashesCBOR, err := EncodeContentHashes([][]byte{bytes.Repeat([]byte{5}, sha256.Size)})
	if err != nil {
		t.Fatal(err)
	}
	return &PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          bytes.Repeat([]byte{1}, sha256.Size),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   10,
		ContentHashesCBOR:           hashesCBOR,
		DeliveryDeadlineUnixSeconds: quoteDeadline(t),
	}
}

func mustConstructorQuote(t *testing.T) *SignedFileQuote {
	t.Helper()
	// 新构造器签名：ctx + terms（filename 已在 RecommendedFilename 中）+
	// 受约束 Signer。
	quote, err := NewSignedFileQuote(context.Background(), quoteTestTerms(t), constructorSigner(t, quoteTestKey()))
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

// 003 买方签名必须通过统一 helper 精确覆盖 payment_authorization_cbor：对同一
// 字节验签成功，对外壳、哈希或任何其他字节都不成立。
func TestBuyerSignatureCoversExactlyTheAuthorizationCBOR(t *testing.T) {
	authorization := constructorRequestTerms(t)
	request, err := NewSignedContentRequest(context.Background(), authorization, constructorSigner(t, quoteTestKey()))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyWireDocument(quoteTestPubkey(), protocol.WireVersion, 5, request.PaymentAuthorizationCBOR, request.BuyerPaymentAuthorizationSignature); err != nil {
		t.Fatalf("buyer signature does not verify over the exact authorization CBOR: %v", err)
	}
	outer, err := EncodeSignedContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyMessageSignature(quoteTestPubkey(), outer, request.BuyerPaymentAuthorizationSignature); err == nil {
		t.Fatal("buyer signature verified over the Kind 5 wire shell")
	}
	authID := sha256.Sum256(request.PaymentAuthorizationCBOR)
	if err := protocol.VerifyMessageSignature(quoteTestPubkey(), authID[:], request.BuyerPaymentAuthorizationSignature); err == nil {
		t.Fatal("buyer signature verified over the authorization ID")
	}
	// 跨 Kind 换壳必须失败：同一文档拿到 Kind 6 签名域下验证不成立。
	if err := protocol.VerifyWireDocument(quoteTestPubkey(), protocol.WireVersion, 6, request.PaymentAuthorizationCBOR, request.BuyerPaymentAuthorizationSignature); err == nil {
		t.Fatal("Kind 5 signature verified inside the Kind 6 signing context")
	}
	// 跨版本换壳必须失败。
	if err := protocol.VerifyWireDocument(quoteTestPubkey(), protocol.WireVersion+1, 5, request.PaymentAuthorizationCBOR, request.BuyerPaymentAuthorizationSignature); err == nil {
		t.Fatal("signature verified under a future wire version")
	}
}

// 004 卖方签名通过统一 helper 覆盖精确 content_delivery_cbor；对裸授权 ID、
// hex 文本、预先再哈希的摘要或 payload 都不成立。
func TestSellerSignatureCoversExactlyTheDeliveryDocument(t *testing.T) {
	authID := sha256.Sum256([]byte("authorization bytes"))
	delivery, err := NewSignedContentDelivery(context.Background(), authID, [][]byte{[]byte("payload")}, constructorSigner(t, constructorOtherKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	pubkey := constructorOtherKey(t).PubKey().Compressed()
	if err := protocol.VerifyWireDocument(pubkey, protocol.WireVersion, 6, delivery.ContentDeliveryCBOR, delivery.SellerContentDeliverySignature); err != nil {
		t.Fatalf("seller signature does not verify over the exact delivery document: %v", err)
	}
	if err := protocol.VerifyMessageSignature(pubkey, authID[:], delivery.SellerContentDeliverySignature); err == nil {
		t.Fatal("seller signature verified over the bare authorization ID")
	}
	if err := protocol.VerifyMessageSignature(pubkey, []byte(toHex(authID[:])), delivery.SellerContentDeliverySignature); err == nil {
		t.Fatal("seller signature verified over hex text")
	}
	doubleDigest := sha256.Sum256(authID[:])
	if err := protocol.VerifyMessageSignature(pubkey, doubleDigest[:], delivery.SellerContentDeliverySignature); err == nil {
		t.Fatal("seller signature verified over a pre-hashed digest")
	}
	if err := protocol.VerifyMessageSignature(pubkey, []byte("payload"), delivery.SellerContentDeliverySignature); err == nil {
		t.Fatal("seller signature verified over payload bytes")
	}
	// content_delivery_cbor 必须恰好编码被引用的授权 ID。
	bound, err := DecodeContentDeliveryDocument(delivery.ContentDeliveryCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if bound != authID {
		t.Fatal("delivery document does not bind the supplied authorization ID")
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

func TestDeliveryConstructorRejectsZeroOrMismatchedAuthorizationID(t *testing.T) {
	// 31 字节/nil 等错误宽度的 payment_authorization_id 已被 named type 在
	// 编译期排除；运行时唯一必须拒绝的是全零哨兵 ID。
	if _, err := NewSignedContentDelivery(context.Background(), protocol.PaymentAuthorizationID{}, [][]byte{[]byte("payload")}, constructorSigner(t, constructorOtherKey(t))); !errors.Is(err, protocol.ErrZeroIdentifier) {
		t.Fatalf("all-zero authorization id error = %v, want protocol.ErrZeroIdentifier", err)
	}
	zeroSlice := make([]byte, sha256.Size)
	var zeroID protocol.PaymentAuthorizationID
	copy(zeroID[:], zeroSlice)
	if !zeroID.IsZero() {
		t.Fatal("test premise broken: zero id is not the zero sentinel")
	}
	if _, err := NewSignedContentDelivery(context.Background(), zeroID, [][]byte{[]byte("payload")}, constructorSigner(t, constructorOtherKey(t))); !errors.Is(err, protocol.ErrZeroIdentifier) {
		t.Fatalf("all-zero authorization id error = %v, want protocol.ErrZeroIdentifier", err)
	}
	// 空 payload 批次仍按 payload 校验拒绝，与零 ID 检查相互独立。
	if _, err := NewSignedContentDelivery(context.Background(), zeroID, [][]byte{}, constructorSigner(t, constructorOtherKey(t))); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("empty payload batch error = %v, want invalid_evidence", err)
	}
}
