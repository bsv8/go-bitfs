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
		RefundTemplateTxID:        RefundTemplateTxID(bytes.Repeat([]byte{7}, sha256.Size)),
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, sha256.Size),
		UnsignedStateTxRaw:        []byte{2, 3, 4},
		BuyerTransactionSignature: []byte{5, 6},
	}
	raw, err := EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != 0x85 {
		t.Fatalf("005 payment update must be a five-element array: %x", raw)
	}
	decoded, err := DecodePaymentUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded.UnsignedStateTxRaw[0] = 9
	if update.UnsignedStateTxRaw[0] != 2 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
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

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	_, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID(bytes.Repeat([]byte{7}, sha256.Size)), PaymentAuthorizationHash: bytes.Repeat([]byte{1}, 31), UnsignedStateTxRaw: []byte{2}, BuyerTransactionSignature: []byte{3}})
	if err == nil {
		t.Fatal("payment update with short request hash was accepted")
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

func hashOfLength(t *testing.T, length int) []byte {
	t.Helper()
	return bytes.Repeat([]byte{7}, length)
}

func TestPoolHashFieldsRejectBadLengthsAndZero(t *testing.T) {
	validSig := []byte{1}
	unsigned := []byte{2}
	// 31-byte refund hash on the wire.
	short, err := poolEnc.Marshal([]any{MajorVersion, bytes.Repeat([]byte{7}, 31), bytes.Repeat([]byte{1}, sha256.Size), unsigned, validSig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePaymentUpdate(short); err == nil {
		t.Fatal("31-byte refund_template_txid accepted")
	}
	// 33-byte refund hash on the wire.
	long, err := poolEnc.Marshal([]any{MajorVersion, bytes.Repeat([]byte{7}, 33), bytes.Repeat([]byte{1}, sha256.Size), unsigned, validSig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePaymentUpdate(long); err == nil {
		t.Fatal("33-byte refund_template_txid accepted")
	}
	// All-zero refund hash on the wire.
	zero, err := poolEnc.Marshal([]any{MajorVersion, make([]byte, sha256.Size), bytes.Repeat([]byte{1}, sha256.Size), unsigned, validSig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePaymentUpdate(zero); err == nil {
		t.Fatal("all-zero refund_template_txid accepted")
	}
	// Encode paths reject the all-zero sentinel structurally; the fixed-size
	// Go array cannot represent 31/33-byte hashes, so those are wire-only.
	if _, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID{}, PaymentAuthorizationHash: bytes.Repeat([]byte{1}, sha256.Size), UnsignedStateTxRaw: unsigned, BuyerTransactionSignature: validSig}); err == nil {
		t.Fatal("encoder accepted all-zero refund hash")
	}
	if _, err := EncodeFundingTxDelivery(&FundingTxDelivery{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID{}, FundingTx: unsigned}); err == nil {
		t.Fatal("delivery encoder accepted all-zero refund hash")
	}
	if _, err := EncodeRefundPresignResponse(&RefundPresignResponse{Version: MajorVersion, RefundTemplateTxID: RefundTemplateTxID{}, SellerRefundSignature: validSig}); err == nil {
		t.Fatal("response encoder accepted all-zero refund hash")
	}
	legacy, err := poolEnc.Marshal([]any{MajorVersion, bytes.Repeat([]byte{1}, sha256.Size), unsigned, validSig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePaymentUpdate(legacy); err == nil {
		t.Fatal("legacy four-element 005 payment update decoded")
	}
}
