package pool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPaymentUpdateRoundTripAndIsolation(t *testing.T) {
	update := &PaymentUpdate{
		Version:                   MajorVersion,
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, sha256.Size),
		BuyerTransactionSignature: []byte{5, 6},
	}
	raw, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x83 {
		t.Fatalf("005 payment update must be a three-element array: %x", raw)
	}
	decoded, err := DecodePaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.PaymentAuthorizationHash[0] = 9
	decoded.BuyerTransactionSignature[0] = 9
	if update.PaymentAuthorizationHash[0] != 1 || update.BuyerTransactionSignature[0] != 5 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
	}
}

func TestPaymentUpdateRejectsPreSwitchAndMalformedShapes(t *testing.T) {
	authHash := bytes.Repeat([]byte{1}, sha256.Size)
	signature := []byte{5, 6}
	refundHash := bytes.Repeat([]byte{7}, sha256.Size)
	unsigned := []byte{2, 3, 4}

	update := &PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: authHash, BuyerTransactionSignature: signature}
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
	fiveElement := marshal(MajorVersion, refundHash, authHash, unsigned, signature)
	if _, err := DecodePaymentUpdate(fiveElement); err == nil {
		t.Fatal("pre-switch five-element v4 payment update decoded")
	}
	// Old four-element v3 shape must also fail.
	fourElement := marshal(uint64(3), refundHash, authHash, unsigned)
	if _, err := DecodePaymentUpdate(fourElement); err == nil {
		t.Fatal("legacy four-element payment update decoded")
	}
	// Missing fields.
	twoElement := marshal(MajorVersion, authHash)
	if _, err := DecodePaymentUpdate(twoElement); err == nil {
		t.Fatal("two-element payment update decoded")
	}
	// Extra fields.
	sixElement := marshal(MajorVersion, refundHash, authHash, signature, signature, signature)
	if _, err := DecodePaymentUpdate(sixElement); err == nil {
		t.Fatal("six-element payment update decoded")
	}
	// Wrong major version.
	wrongMajor := marshal(uint64(5), authHash, signature)
	if _, err := DecodePaymentUpdate(wrongMajor); err == nil {
		t.Fatal("wrong major payment update decoded")
	}
	// Short authorization hash.
	shortHash := marshal(MajorVersion, bytes.Repeat([]byte{1}, 31), signature)
	if _, err := DecodePaymentUpdate(shortHash); err == nil {
		t.Fatal("31-byte authorization hash accepted")
	}
	// Long authorization hash.
	longHash := marshal(MajorVersion, bytes.Repeat([]byte{1}, 33), signature)
	if _, err := DecodePaymentUpdate(longHash); err == nil {
		t.Fatal("33-byte authorization hash accepted")
	}
	// Empty buyer signature.
	emptySig := marshal(MajorVersion, authHash, []byte{})
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
	authHash := bytes.Repeat([]byte{1}, sha256.Size)
	signature := []byte{5, 6}
	update := &PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: authHash, BuyerTransactionSignature: signature}
	canonical, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	body := canonical[2:] // strip the 0x83 array header

	cases := map[string][]byte{
		// Tag content 8 wrapping the whole array.
		"tagged array": append([]byte{0xc8}, canonical...),
	}
	// Indefinite-length array with definite members and a stop byte.
	indefArray := append([]byte{0x9f, 0x04, 0x58, 0x20}, authHash...)
	indefArray = append(indefArray, 0x42, 0x05, 0x06, 0xff)
	cases["indefinite-length array"] = indefArray
	// Definite array header but an indefinite-length bstr member.
	indefHash := append([]byte{0x83, 0x04, 0x5f, 0x58, 0x20}, authHash[:16]...)
	indefHash = append(indefHash, 0xff)
	cases["indefinite-length hash"] = indefHash
	for name, raw := range cases {
		if _, err := DecodePaymentUpdate(raw); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// Non-shortest (two-byte) length header for the three-element array.
	nonShortest := append([]byte{0x98, 0x03, 0x04, 0x58, 0x20}, body...)
	if _, err := DecodePaymentUpdate(nonShortest); err == nil {
		t.Fatal("non-shortest array length header accepted")
	}
	// Non-shortest bstr length for the authorization hash.
	nonShortestBstr := append([]byte{0x83, 0x04, 0x59, 0x00, 0x20}, append(bytes.Repeat([]byte{1}, sha256.Size), 0x42, 0x05, 0x06)...)
	if _, err := DecodePaymentUpdate(nonShortestBstr); err == nil {
		t.Fatal("non-shortest bstr length header accepted")
	}
}

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	if _, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: bytes.Repeat([]byte{1}, 31), BuyerTransactionSignature: []byte{3}}); err == nil {
		t.Fatal("payment update with short request hash was accepted")
	}
	if _, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: make([]byte, sha256.Size), BuyerTransactionSignature: []byte{3}}); err == nil {
		t.Fatal("payment update with all-zero request hash was accepted")
	}
	if _, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: bytes.Repeat([]byte{1}, sha256.Size), BuyerTransactionSignature: nil}); err == nil {
		t.Fatal("payment update without buyer signature was accepted")
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
	if len(raw) == 0 || raw[0] != 0x89 {
		t.Fatalf("opening proof must be a nine-element array: %x", raw)
	}
	if !bytes.Equal(decoded.FundingTx, proof.FundingTx) || !bytes.Equal(decoded.RefundTx, proof.RefundTx) {
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
		Version:  MajorVersion,
		RefundTx: []byte{1, 2, 3}, BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
		MinerFeeRateSatPerKB: 100, BuyerRefundSignature: []byte{4, 5, 6},
	}
	raw, err := EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x87 {
		t.Fatalf("refund presign request must be a seven-element array: %x", raw)
	}
	decoded, err := DecodeRefundPresignRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.RefundTx, request.RefundTx) || decoded.MinerFeeRateSatPerKB != request.MinerFeeRateSatPerKB {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestRoleKeyValidationHasStableBuyerPriority(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		Version:  MajorVersion,
		RefundTx: []byte{1}, BuyerRefundSignature: []byte{4},
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	}
	request.BuyerPubKey = []byte{1}
	request.SellerPubKey = []byte{2}
	request.ArbiterPubKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateRefundPresignRequest(request)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("request validation error = %v, want stable buyer error", err)
		}
	}

	proof := &OpeningProof{
		Version: MajorVersion, RefundTx: []byte{1}, BuyerRefundSignature: []byte{7}, SellerRefundSignature: []byte{8},
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	}
	proof.BuyerPubKey = []byte{1}
	proof.SellerPubKey = []byte{2}
	proof.ArbiterPubKey = []byte{3}
	for i := 0; i < 20; i++ {
		err := ValidateOpeningProof(proof)
		if err == nil || !strings.Contains(err.Error(), "buyer public key") {
			t.Fatalf("proof validation error = %v, want stable buyer error", err)
		}
	}
}

func TestRefundPresignResponseGoldenBytesAndLegacyRejection(t *testing.T) {
	response := &RefundPresignResponse{
		Version:               MajorVersion,
		RefundTemplateTxID:    RefundTemplateTxID(bytes.Repeat([]byte{0xab}, sha256.Size)),
		SellerRefundSignature: []byte{1, 2},
	}
	raw, err := EncodeRefundPresignResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("84040d5820" + strings.Repeat("ab", 32) + "420102")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("002 response golden bytes changed: %x", raw)
	}
	if _, err := DecodeRefundPresignResponse(raw); err != nil {
		t.Fatal(err)
	}
	// Legacy three-element shape must fail strictly.
	legacy := append([]byte{0x83, 0x04, 0x0d}, 0x42, 0x01, 0x02)
	if _, err := DecodeRefundPresignResponse(legacy); err == nil {
		t.Fatal("legacy three-element presign response decoded")
	}
}

func TestFundingTxDeliveryGoldenBytesAndLegacyRejection(t *testing.T) {
	delivery := &FundingTxDelivery{
		Version:            MajorVersion,
		RefundTemplateTxID: RefundTemplateTxID(bytes.Repeat([]byte{0xab}, sha256.Size)),
		FundingTx:          []byte{0xaa, 0xbb, 0xcc},
	}
	raw, err := EncodeFundingTxDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("84040e5820" + strings.Repeat("ab", 32) + "43aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("funding delivery golden bytes changed: %x", raw)
	}
	if _, err := DecodeFundingTxDelivery(raw); err != nil {
		t.Fatal(err)
	}
	// Legacy three-element shape must fail strictly.
	legacy := append([]byte{0x83, 0x04, 0x0e}, 0x43, 0xaa, 0xbb, 0xcc)
	if _, err := DecodeFundingTxDelivery(legacy); err == nil {
		t.Fatal("legacy three-element funding delivery decoded")
	}
}

func TestPoolHashFieldsRejectBadLengthsAndZero(t *testing.T) {
	validSig := []byte{1}
	unsigned := []byte{2}
	// 31-byte refund hash on the wire.
	short, err := poolEnc.Marshal([]any{MajorVersion, 0x0e, bytes.Repeat([]byte{7}, 31), unsigned})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFundingTxDelivery(short); err == nil {
		t.Fatal("31-byte refund_template_txid accepted")
	}
	// 33-byte refund hash on the wire.
	long, err := poolEnc.Marshal([]any{MajorVersion, 0x0e, bytes.Repeat([]byte{7}, 33), unsigned})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFundingTxDelivery(long); err == nil {
		t.Fatal("33-byte refund_template_txid accepted")
	}
	// All-zero refund hash on the wire.
	zero, err := poolEnc.Marshal([]any{MajorVersion, 0x0e, make([]byte, sha256.Size), unsigned})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFundingTxDelivery(zero); err == nil {
		t.Fatal("all-zero refund_template_txid accepted")
	}
	// Encode paths reject the all-zero sentinel structurally; the fixed-size
	// Go array cannot represent 31/33-byte hashes, so those are wire-only.
	if _, err := EncodeFundingTxDelivery(&FundingTxDelivery{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID{}, FundingTx: unsigned}); err == nil {
		t.Fatal("delivery encoder accepted all-zero refund hash")
	}
	if _, err := EncodeRefundPresignResponse(&RefundPresignResponse{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID{}, SellerRefundSignature: validSig}); err == nil {
		t.Fatal("response encoder accepted all-zero refund hash")
	}
}
