package pool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bsv8/go-bitfs/protocol"
)

func TestPaymentUpdateRoundTripAndIsolation(t *testing.T) {
	update := &PaymentUpdate{
		PaymentAuthorizationID:           protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, sha256.Size)),
		BuyerPaymentTransactionSignature: []byte{5, 6},
	}
	raw, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x84 {
		t.Fatalf("005 payment update must be a four-element array: %x", raw)
	}
	decoded, err := DecodePaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.PaymentAuthorizationID[0] = 9
	decoded.BuyerPaymentTransactionSignature[0] = 9
	if update.PaymentAuthorizationID[0] != 1 || update.BuyerPaymentTransactionSignature[0] != 5 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
	}
}

func TestPaymentUpdateRejectsLegacyAndMalformedShapes(t *testing.T) {
	authID := protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, sha256.Size))
	signature := []byte{5, 6}
	refundHash := bytes.Repeat([]byte{7}, sha256.Size)
	unsigned := []byte{2, 3, 4}

	update := &PaymentUpdate{PaymentAuthorizationID: authID, BuyerPaymentTransactionSignature: signature}
	canonical, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePaymentUpdate(canonical); err != nil {
		t.Fatal(err)
	}

	marshal := func(values ...any) []byte {
		t.Helper()
		raw, err := poolEnc.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// Pre-switch v4 five-element 005 must be rejected outright.
	fiveElement := marshal(uint64(4), refundHash, authID[:], unsigned, signature)
	if _, err := DecodePaymentUpdate(fiveElement); err == nil {
		t.Fatal("pre-switch five-element v4 payment update decoded")
	}
	// Old three-element minimal v4 shape must also fail.
	threeElement := marshal(uint64(4), authID[:], signature)
	if _, err := DecodePaymentUpdate(threeElement); err == nil {
		t.Fatal("legacy three-element payment update decoded")
	}
	// Missing fields.
	twoElement := marshal(protocol.WireVersion, uint64(7), authID[:])
	if _, err := DecodePaymentUpdate(twoElement); err == nil {
		t.Fatal("two-element payment update decoded")
	}
	// Extra fields.
	sixElement := marshal(protocol.WireVersion, uint64(7), authID[:], signature, signature, signature)
	if _, err := DecodePaymentUpdate(sixElement); err == nil {
		t.Fatal("six-element payment update decoded")
	}
	// Wrong outer version.
	wrongVersion := marshal(uint64(2), uint64(7), authID[:], signature)
	if _, err := DecodePaymentUpdate(wrongVersion); err == nil {
		t.Fatal("wrong wire version payment update decoded")
	}
	// Wrong inner kind.
	wrongKind := marshal(protocol.WireVersion, uint64(6), authID[:], signature)
	if _, err := DecodePaymentUpdate(wrongKind); err == nil {
		t.Fatal("wrong wire kind payment update decoded")
	}
	// Short authorization hash.
	shortHash := marshal(protocol.WireVersion, uint64(7), bytes.Repeat([]byte{1}, 31), signature)
	if _, err := DecodePaymentUpdate(shortHash); err == nil {
		t.Fatal("31-byte authorization hash accepted")
	}
	// Long authorization hash.
	longHash := marshal(protocol.WireVersion, uint64(7), bytes.Repeat([]byte{1}, 33), signature)
	if _, err := DecodePaymentUpdate(longHash); err == nil {
		t.Fatal("33-byte authorization hash accepted")
	}
	// Empty buyer signature.
	emptySig := marshal(protocol.WireVersion, uint64(7), authID[:], []byte{})
	if _, err := DecodePaymentUpdate(emptySig); err == nil {
		t.Fatal("empty buyer transaction signature accepted")
	}
	// Trailing bytes after a canonical container.
	if _, err := DecodePaymentUpdate(append(canonical, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

// TestPaymentUpdateRejectsTagsIndefiniteAndNonShortestLengths pins the strict
// decoder against raw CBOR encodings that carry the same logical value but
// violate the deterministic profile: tags, indefinite-length arrays and
// strings, and non-shortest length headers.
func TestPaymentUpdateRejectsTagsIndefiniteAndNonShortestLengths(t *testing.T) {
	authID := protocol.PaymentAuthorizationID(bytes.Repeat([]byte{1}, sha256.Size))
	signature := []byte{5, 6}
	update := &PaymentUpdate{PaymentAuthorizationID: authID, BuyerPaymentTransactionSignature: signature}
	canonical, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		// Tag content 8 wrapping the whole array.
		"tagged array": append([]byte{0xc8}, canonical...),
	}
	// Indefinite-length array with definite members and a stop byte.
	indefArray := append([]byte{0x9f, 0x01, 0x07, 0x58, 0x20}, authID[:]...)
	indefArray = append(indefArray, 0x42, 0x05, 0x06, 0xff)
	cases["indefinite-length array"] = indefArray
	for name, raw := range cases {
		if _, err := DecodePaymentUpdate(raw); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// Non-shortest (two-byte) length header for the four-element array.
	nonShortest := append([]byte{0x98, 0x04, 0x01, 0x07, 0x58, 0x20}, append(bytes.Repeat([]byte{1}, sha256.Size), 0x42, 0x05, 0x06)...)
	if _, err := DecodePaymentUpdate(nonShortest); err == nil {
		t.Fatal("non-shortest array length header accepted")
	}
	// Non-shortest bstr length for the authorization hash.
	nonShortestBstr := append([]byte{0x84, 0x01, 0x07, 0x59, 0x00, 0x20}, append(bytes.Repeat([]byte{1}, sha256.Size), 0x42, 0x05, 0x06)...)
	if _, err := DecodePaymentUpdate(nonShortestBstr); err == nil {
		t.Fatal("non-shortest bstr length header accepted")
	}
}

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	if _, err := EncodePaymentUpdate(&PaymentUpdate{PaymentAuthorizationID: protocol.PaymentAuthorizationID{}, BuyerPaymentTransactionSignature: []byte{3}}); err == nil {
		t.Fatal("payment update with all-zero authorization ID was accepted")
	}
	if _, err := EncodePaymentUpdate(&PaymentUpdate{PaymentAuthorizationID: protocol.PaymentAuthorizationID{}, BuyerPaymentTransactionSignature: nil}); err == nil {
		t.Fatal("payment update without buyer signature was accepted")
	}
}

func TestPoolCloseDecodeClassifiesCBORFieldTypeErrors(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, sha256.Size)
	encode := func(values ...any) []byte {
		t.Helper()
		raw, err := poolEnc.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	request := encode(uint64(1), uint64(12), hash, "transaction must be a byte string", []byte{1})
	if _, err := DecodePoolCloseRequest(request); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("Kind 12 field type error = %v, want malformed_wire", err)
	}
	response := encode(uint64(1), uint64(13), hash, uint64(42))
	if _, err := DecodePoolCloseResponse(response); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("Kind 13 field type error = %v, want malformed_wire", err)
	}
}

func TestPoolCloseRejectsIntegerArraysInsteadOfByteStrings(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, 32)
	array := make([]any, 32)
	for index := range array {
		array[index] = uint64(1)
	}
	for _, test := range []struct {
		name   string
		kind   uint64
		fields []any
	}{
		{"request pool ID", 12, []any{array, []byte{1}, []byte{1}}},
		{"request transaction", 12, []any{hash, []any{uint64(1)}, []byte{1}}},
		{"request signature", 12, []any{hash, []byte{1}, []any{uint64(1)}}},
		{"response pool ID", 13, []any{array, []byte{1}}},
		{"response transaction", 13, []any{hash, []any{uint64(1)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := append([]any{uint64(1), test.kind}, test.fields...)
			raw, err := poolEnc.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if test.kind == 12 {
				_, err = DecodePoolCloseRequest(raw)
			} else {
				_, err = DecodePoolCloseResponse(raw)
			}
			if !protocol.IsCode(err, protocol.CodeMalformedWire) {
				t.Fatalf("integer array field = %v, want malformed_wire", err)
			}
		})
	}
}

func TestPoolCloseRejectsOversizedTransactions(t *testing.T) {
	hash := RefundTemplateTxID(bytes.Repeat([]byte{1}, 32))
	oversized := bytes.Repeat([]byte{1}, maxPoolCloseTransactionBytes+1)
	if _, err := EncodePoolCloseRequest(&PoolCloseRequest{RefundTemplateTxID: hash, UnsignedCloseTransactionRaw: oversized, BuyerCloseTransactionSignature: []byte{1}}); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("oversized close request = %v, want malformed_wire", err)
	}
	if _, err := EncodePoolCloseResponse(&PoolCloseResponse{RefundTemplateTxID: hash, CompleteCloseTransactionRaw: oversized}); !protocol.IsCode(err, protocol.CodeMalformedWire) {
		t.Fatalf("oversized close response = %v, want malformed_wire", err)
	}
}

func TestOpeningProofRoundTrip(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100)
	raw, err := EncodeOpeningProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpeningProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x88 {
		t.Fatalf("opening proof must be an eight-element array: %x", raw)
	}
	if !bytes.Equal(decoded.FundingTransactionRaw, proof.FundingTransactionRaw) || !bytes.Equal(decoded.RefundTemplateRaw, proof.RefundTemplateRaw) {
		t.Fatalf("decoded proof = %#v", decoded)
	}
	details, err := DeriveOpeningDetails(decoded)
	if err != nil || details.PoolOutputSatoshis == 0 || details.FundingTxID == (Hash32{}) {
		t.Fatalf("derived opening details = %#v, err = %v", details, err)
	}
}

func TestRefundPresignRequestRoundTripUsesDerivedPoolTerms(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		RefundTemplateRaw: []byte{1, 2, 3}, BuyerPublicKey: buyer, SellerPublicKey: seller, ArbiterPublicKey: arbiter,
		MinerFeeRateSatoshisPerKilobyte: 100, BuyerRefundTransactionSignature: []byte{4, 5, 6},
	}
	raw, err := EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x88 {
		t.Fatalf("refund presign request must be an eight-element [1,2,...] array: %x", raw)
	}
	if raw[1] != 0x01 || raw[2] != 0x02 {
		t.Fatalf("refund presign request must start with [1, 2]: %x", raw)
	}
	decoded, err := DecodeRefundPresignRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTemplateRaw, request.RefundTemplateRaw) || decoded.MinerFeeRateSatoshisPerKilobyte != request.MinerFeeRateSatoshisPerKilobyte {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestRoleKeyValidationHasStableBuyerPriority(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		RefundTemplateRaw: []byte{1}, BuyerRefundTransactionSignature: []byte{4},
		BuyerPublicKey: buyer, SellerPublicKey: seller, ArbiterPublicKey: arbiter,
	}
	request.BuyerPublicKey = []byte{1}
	request.SellerPublicKey = []byte{2}
	request.ArbiterPublicKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateRefundPresignRequest(request)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("request validation error = %v, want stable buyer error", err)
		}
	}

	proof := &OpeningProof{
		RefundTemplateRaw: []byte{1}, BuyerRefundTransactionSignature: []byte{7}, SellerRefundTransactionSignature: []byte{8},
		BuyerPublicKey: buyer, SellerPublicKey: seller, ArbiterPublicKey: arbiter,
	}
	proof.BuyerPublicKey = []byte{1}
	proof.SellerPublicKey = []byte{2}
	proof.ArbiterPublicKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateOpeningProof(proof)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("proof validation error = %v, want stable buyer error", err)
		}
	}
}

func TestRefundPresignResponseGoldenBytesAndLegacyRejection(t *testing.T) {
	response := &RefundPresignResponse{
		RefundTemplateTxID:               RefundTemplateTxID(bytes.Repeat([]byte{0xab}, sha256.Size)),
		SellerRefundTransactionSignature: []byte{1, 2},
	}
	raw, err := EncodeRefundPresignResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("8401035820" + strings.Repeat("ab", 32) + "420102")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("002 response golden bytes changed: %x", raw)
	}
	if _, err := DecodeRefundPresignResponse(raw); err != nil {
		t.Fatal(err)
	}
	// Legacy four-element shape with the retired inner kind must fail strictly.
	legacy := append([]byte{0x84, 0x04, 0x0d, 0x58, 0x20}, 0x42, 0x01, 0x02)
	if _, err := DecodeRefundPresignResponse(legacy[:len(legacy)-1]); err == nil {
		t.Fatal("legacy presign response decoded")
	}
	// Same payload under a wrong wire kind is rejected.
	wrongKind, err := poolEnc.Marshal([]any{protocol.WireVersion, uint64(4), response.RefundTemplateTxID[:], response.SellerRefundTransactionSignature})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRefundPresignResponse(wrongKind); err == nil {
		t.Fatal("presign response decoded under wrong kind")
	}
}

func TestFundingTransactionDeliveryGoldenBytesAndLegacyRejection(t *testing.T) {
	delivery := &FundingTransactionDelivery{
		RefundTemplateTxID:    RefundTemplateTxID(bytes.Repeat([]byte{0xab}, sha256.Size)),
		FundingTransactionRaw: []byte{0xaa, 0xbb, 0xcc},
	}
	raw, err := EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("8401045820" + strings.Repeat("ab", 32) + "43aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("funding delivery golden bytes changed: %x", raw)
	}
	if _, err := DecodeFundingTransactionDelivery(raw); err != nil {
		t.Fatal(err)
	}
	// Legacy four-element shape with the retired inner kind must fail strictly.
	legacy := append([]byte{0x84, 0x04, 0x0e, 0x58, 0x20}, 0x43, 0xaa, 0xbb, 0xcc)
	if _, err := DecodeFundingTransactionDelivery(append(legacy, 0xaa)); err == nil {
		t.Fatal("legacy funding delivery decoded")
	}
	// Same payload under a wrong wire kind is rejected.
	wrongKind, err := poolEnc.Marshal([]any{protocol.WireVersion, uint64(3), delivery.RefundTemplateTxID[:], delivery.FundingTransactionRaw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFundingTransactionDelivery(wrongKind); err == nil {
		t.Fatal("funding delivery decoded under wrong kind")
	}
}

func TestPoolHashFieldsRejectBadLengthsAndZero(t *testing.T) {
	unsigned := []byte{2}
	build := func(id []byte) []byte {
		raw, err := poolEnc.Marshal([]any{protocol.WireVersion, uint64(4), id, unsigned})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// 31-byte refund hash on the wire.
	if _, err := DecodeFundingTransactionDelivery(build(bytes.Repeat([]byte{7}, 31))); err == nil {
		t.Fatal("31-byte refund_template_txid accepted")
	}
	// 33-byte refund hash on the wire.
	if _, err := DecodeFundingTransactionDelivery(build(bytes.Repeat([]byte{7}, 33))); err == nil {
		t.Fatal("33-byte refund_template_txid accepted")
	}
	// All-zero refund hash on the wire.
	if _, err := DecodeFundingTransactionDelivery(build(make([]byte, sha256.Size))); err == nil {
		t.Fatal("all-zero refund_template_txid accepted")
	}
	// Encode paths reject the all-zero sentinel structurally; the fixed-size
	// Go array cannot represent 31/33-byte hashes, so those are wire-only.
	if _, err := EncodeFundingTransactionDelivery(&FundingTransactionDelivery{RefundTemplateTxID: RefundTemplateTxID{}, FundingTransactionRaw: unsigned}); err == nil {
		t.Fatal("delivery encoder accepted all-zero refund hash")
	}
	if _, err := EncodeRefundPresignResponse(&RefundPresignResponse{RefundTemplateTxID: RefundTemplateTxID{}, SellerRefundTransactionSignature: []byte{1}}); err == nil {
		t.Fatal("response encoder accepted all-zero refund hash")
	}
}
