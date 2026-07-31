package pool

import (
	"context"
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	bsvtx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

type finalRecordingBackend struct {
	engine *BSVEngine
	calls  int
	rawTx  []byte
}

func (backend *finalRecordingBackend) SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error) {
	return nil, fmt.Errorf("unexpected non-final submission")
}

func (backend *finalRecordingBackend) SubmitFinal(_ context.Context, rawTx []byte) (Hash32, error) {
	backend.calls++
	backend.rawTx = append([]byte(nil), rawTx...)
	return backend.engine.TransactionID(rawTx)
}

func TestVerifiedNonFinalPoolNodeValidatesFinalCloseAndRefundBeforeForwarding(t *testing.T) {
	buyerKey, _ := ec.PrivateKeyFromBytes(bytes32(11))
	sellerKey, _ := ec.PrivateKeyFromBytes(bytes32(12))
	arbiterKey, _ := ec.PrivateKeyFromBytes(bytes32(13))
	lockingScript, err := Build2of3LockingScript([][]byte{
		buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}

	funding := bsvtx.NewTransaction()
	zero, _ := chainhash.NewHash(make([]byte, 32))
	funding.AddInput(&bsvtx.TransactionInput{SourceTXID: zero, SourceTxOutIndex: 0, SequenceNumber: bsvtx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&bsvtx.TransactionOutput{Satoshis: 10000, LockingScript: script.NewFromBytes(lockingScript)})
	refund := bsvtx.NewTransaction()
	refund.LockTime = 500
	refundInput := &bsvtx.TransactionInput{SourceTXID: funding.TxID(), SourceTxOutIndex: 0, SequenceNumber: 1, UnlockingScript: script.NewFromBytes(nil)}
	refund.AddInputWithOutput(refundInput, &bsvtx.TransactionOutput{Satoshis: 10000, LockingScript: script.NewFromBytes(lockingScript)})
	refund.AddOutput(&bsvtx.TransactionOutput{Satoshis: 0, LockingScript: p2pkhForTest(sellerKey.PubKey())})
	refund.AddOutput(&bsvtx.TransactionOutput{Satoshis: 9900, LockingScript: p2pkhForTest(buyerKey.PubKey())})
	digest, err := refund.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatal(err)
	}
	buyerRefund, _ := buyerKey.Sign(digest)
	sellerRefund, _ := sellerKey.Sign(digest)
	proof := &OpeningProof{
		Version:               MajorVersion,
		RefundTx:              refund.Bytes(),
		FundingTxID:           funding.TxID().CloneBytes(),
		PoolOutputIndex:       0,
		PoolOutputSatoshis:    10000,
		PoolLockingScript:     lockingScript,
		BuyerRefundSignature:  append(buyerRefund.Serialize(), bitcoinSignatureHashType),
		SellerRefundSignature: append(sellerRefund.Serialize(), bitcoinSignatureHashType),
		FundingTx:             funding.Bytes(),
	}
	engine, err := NewBSVEngine(BSVEngineConfig{
		BuyerPubKey:   buyerKey.PubKey().Compressed(),
		SellerPubKey:  sellerKey.PubKey().Compressed(),
		ArbiterPubKey: arbiterKey.PubKey().Compressed(),
		BlockHeight:   func() uint32 { return 500 },
	})
	if err != nil {
		t.Fatal(err)
	}
	calculator := BSVTransactionIDCalculator{Engine: engine}
	store, err := NewMemoryStore(calculator)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOpeningProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	backend := &finalRecordingBackend{engine: engine}
	adapter, err := NewVerifiedNonFinalPoolNode(engine, store, backend)
	if err != nil {
		t.Fatal(err)
	}

	initial, err := engine.InitialPaymentState(proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(context.Background(), CloseInput{
		Opening:              proof,
		Latest:               initial,
		SellerAmountAfterSat: 1000,
		MinerFeeSat:          100,
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerState, err := engine.SignBuyerPayment(context.Background(), unsigned, testKeySigner{key: buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := engine.AddSellerSignature(context.Background(), buyerState, testKeySigner{key: sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	acceptedID, err := adapter.SubmitFinal(context.Background(), completed.RawTx)
	if err != nil {
		t.Fatalf("valid final close was rejected: %v", err)
	}
	closeID, err := engine.TransactionID(completed.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if acceptedID != closeID || backend.calls != 1 {
		t.Fatalf("unexpected final close acceptance: id=%v calls=%d", acceptedID, backend.calls)
	}

	if _, err := adapter.SubmitFinal(context.Background(), buyerState.RawTx); err == nil {
		t.Fatal("buyer-only final transaction was forwarded")
	}
	if backend.calls != 1 {
		t.Fatalf("invalid final transaction reached backend: calls=%d", backend.calls)
	}

	refundRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.SubmitFinal(context.Background(), refundRaw); err != nil {
		t.Fatalf("expired refund was rejected: %v", err)
	}
	if backend.calls != 2 {
		t.Fatalf("valid refund was not forwarded: calls=%d", backend.calls)
	}
}
