package pool

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestPaymentUpdateRoundTripAndIsolation(t *testing.T) {
	update := &PaymentUpdate{
		Version:                   MajorVersion,
		PaymentAuthorizationHash:  bytes.Repeat([]byte{1}, sha256.Size),
		UnsignedStateTxRaw:        []byte{2, 3, 4},
		BuyerTransactionSignature: []byte{5, 6},
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
	decoded.UnsignedStateTxRaw[0] = 9
	if update.UnsignedStateTxRaw[0] != 2 {
		t.Fatal("decoded payment update aliases input data")
	}
	if _, err := DecodePaymentUpdate(append(raw, 0)); err == nil {
		t.Fatal("payment decoder accepted trailing bytes")
	}
}

func TestOpeningProofRoundTrip(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	proof := &OpeningProof{
		Version:               MajorVersion,
		RefundTx:              []byte("refund"),
		SpendTxID:             bytes.Repeat([]byte{2}, sha256.Size),
		FundingTxID:           bytes.Repeat([]byte{1}, sha256.Size),
		PoolOutputIndex:       2,
		PoolOutputSatoshis:    1000,
		PoolLockingScript:     []byte("2of3"),
		MultisigProtocol:      MultisigProtocol,
		MultisigVersion:       MultisigVersion,
		SellerPubKey:          seller,
		BuyerPubKey:           buyer,
		ArbiterPubKey:         arbiter,
		BuyerRefundSignature:  []byte("buyer"),
		SellerRefundSignature: []byte("seller"),
		FundingTx:             []byte("funding"),
	}
	raw, err := EncodeOpeningProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOpeningProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.FundingTx, proof.FundingTx) || !bytes.Equal(decoded.FundingTxID, proof.FundingTxID) {
		t.Fatalf("decoded proof = %#v", decoded)
	}
}

func TestPaymentUpdateRejectsInvalidReference(t *testing.T) {
	_, err := EncodePaymentUpdate(&PaymentUpdate{Version: MajorVersion, PaymentAuthorizationHash: []byte{1}, UnsignedStateTxRaw: []byte{2}, BuyerTransactionSignature: []byte{3}})
	if err == nil {
		t.Fatal("payment update with short request hash was accepted")
	}
}

func TestRoleKeyValidationHasStableBuyerPriority(t *testing.T) {
	buyer, seller, arbiter := poolTestPubkeys(t)
	request := &RefundPresignRequest{
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx: []byte{1}, FundingTxID: bytes.Repeat([]byte{2}, sha256.Size),
		PoolOutputSatoshis: 1, PoolLockingScript: []byte{3}, BuyerRefundSignature: []byte{4},
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
		Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion,
		RefundTx: []byte{1}, SpendTxID: bytes.Repeat([]byte{4}, sha256.Size), FundingTxID: bytes.Repeat([]byte{5}, sha256.Size),
		PoolOutputSatoshis: 1, PoolLockingScript: []byte{6}, BuyerRefundSignature: []byte{7}, SellerRefundSignature: []byte{8},
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
