package pool

import (
	"bytes"
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/pkg"
)

type testPrivateKeyProvider struct{ key *ec.PrivateKey }

func (provider testPrivateKeyProvider) PrivateKey(context.Context) (*ec.PrivateKey, error) {
	return provider.key, nil
}

func TestMultisigPoolAdapterUsesServerABRoleOrder(t *testing.T) {
	server, err := ec.PrivateKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ec.PrivateKeyFromHex("2222222222222222222222222222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ec.PrivateKeyFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	roles := PoolRoles{Server: server.PubKey(), A: a.PubKey(), B: b.PubKey()}
	got, err := BuildPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	wantScript, err := mp.TripleFeePoolSpentScript(roles.Server, roles.A, roles.B)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantScript.Bytes()) {
		t.Fatal("adapter changed canonical server/A/B locking script")
	}
	if _, err := MergePoolServerA("00", nil, nil); err == nil {
		t.Fatal("server+A merge accepted missing signatures")
	}
	if _, err := MergePoolServerB("00", nil, nil); err == nil {
		t.Fatal("server+B merge accepted missing signatures")
	}
}

func TestMultisigPoolEngineCanonicalNormalAndArbitrationFlow(t *testing.T) {
	ctx := context.Background()
	server := mustPoolTestKey(t, "11")
	a := mustPoolTestKey(t, "22")
	b := mustPoolTestKey(t, "33")
	lock, err := mp.BuildTriplePoolLock(server.PubKey(), a.PubKey(), b.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock.Bytes())})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{
		BuyerPubKey: a.PubKey().Compressed(), SellerPubKey: server.PubKey().Compressed(), ArbiterPubKey: b.PubKey().Compressed(),
		BuyerKey: testPrivateKeyProvider{a}, ServerKey: testPrivateKeyProvider{server}, ArbiterKey: testPrivateKeyProvider{b},
	})
	if err != nil {
		t.Fatal(err)
	}
	opening, err := engine.BuildRefundPresignRequest(ctx, OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500, MinerFeeRateSatPerKB: 1, SellerPubKey: server.PubKey().Compressed(), ArbiterPubKey: b.PubKey().Compressed()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sellerRefundSig, err := (PoolRefundSigner{Engine: engine}).SignRefundTx(ctx, opening)
	if err != nil {
		t.Fatal(err)
	}
	spendID, err := engine.TransactionID(opening.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{Version: MajorVersion, RefundTx: opening.RefundTx, SpendTxID: spendID[:], FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: 0, PoolOutputSatoshis: 100000, PoolLockingScript: opening.PoolLockingScript, ServerPubKey: opening.ServerPubKey, BuyerPubKey: opening.BuyerPubKey, ArbiterPubKey: opening.ArbiterPubKey, MinerFeeRateSatPerKB: 1, BuyerRefundSignature: opening.BuyerRefundSignature, SellerRefundSignature: sellerRefundSig, FundingTx: funding.Bytes()}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	refund, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, refund, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(previous, proof); err != nil {
		t.Fatal(err)
	}

	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 2, SellerAmountAfterSat: 1000})
	if err != nil {
		t.Fatal(err)
	}
	buyerState, err := engine.SignBuyerPayment(ctx, unsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyBuyerPayment(buyerState, proof); err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.AddSellerSignature(ctx, buyerState, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(&accepted.State, proof); err != nil {
		t.Fatal(err)
	}

	arbUnsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 2, SellerAmountAfterSat: 2000})
	if err != nil {
		t.Fatal(err)
	}
	serverSig, err := engine.SignSellerArbitrationCandidate(ctx, arbUnsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	unsignedState := stateFromUnsigned(arbUnsigned)
	if err := engine.VerifySellerPaymentSignature(unsignedState, serverSig, proof); err != nil {
		t.Fatal(err)
	}
	serverState, err := engine.AttachSellerArbitrationSignature(ctx, unsignedState, serverSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerPayment(serverState, proof); err != nil {
		t.Fatal(err)
	}
	bSig, err := engine.SignArbiterPayment(ctx, serverState, nil)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := engine.AddArbitrationSignature(ctx, serverState, bSig)
	if err != nil {
		t.Fatal(err)
	}
	if len(arbitrated.RawTx) == 0 || !bytes.Equal(arbitrated.State.RawTx, arbitrated.RawTx) {
		t.Fatal("arbitrated payment was not returned as a stable server+B transaction")
	}
}

func mustPoolTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(hexByte), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func stateFromUnsigned(unsigned *UnsignedPayment) *PaymentState {
	return &PaymentState{SpendTxID: unsigned.SpendTxID, RawTx: append([]byte(nil), unsigned.RawTx...), PoolOutputSatoshis: unsigned.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), unsigned.PoolLockingScript...)}
}
