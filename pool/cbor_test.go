package pool

import (
	"bytes"
	"crypto/sha256"
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
		SellerPubKey:          []byte("seller"),
		BuyerPubKey:           []byte("buyer-key"),
		ArbiterPubKey:         []byte("arbiter"),
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
