package pool

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvhash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	bsvtx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

type testKeySigner struct{ key *ec.PrivateKey }

func (signer testKeySigner) PublicKey(context.Context) ([]byte, error) {
	return signer.key.PubKey().Compressed(), nil
}

func (signer testKeySigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := signer.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func TestBSVEngineValidatesAndSignsCumulativePayment(t *testing.T) {
	buyerKey, _ := ec.PrivateKeyFromBytes(bytes32(1))
	sellerKey, _ := ec.PrivateKeyFromBytes(bytes32(2))
	arbiterKey, _ := ec.PrivateKeyFromBytes(bytes32(3))
	buyerPub := buyerKey.PubKey().Compressed()
	sellerPub := sellerKey.PubKey().Compressed()
	arbiterPub := arbiterKey.PubKey().Compressed()
	lockingScript, err := Build2of3LockingScript([][]byte{buyerPub, sellerPub, arbiterPub})
	if err != nil {
		t.Fatal(err)
	}

	funding := bsvtx.NewTransaction()
	zero, _ := chainhash.NewHash(make([]byte, 32))
	funding.AddInput(&bsvtx.TransactionInput{SourceTXID: zero, SourceTxOutIndex: 0, SequenceNumber: bsvtx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&bsvtx.TransactionOutput{Satoshis: 10000, LockingScript: script.NewFromBytes(lockingScript)})
	fundingID := funding.TxID().CloneBytes()

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
		FundingTxID:           fundingID,
		PoolOutputIndex:       0,
		PoolOutputSatoshis:    10000,
		PoolLockingScript:     lockingScript,
		BuyerRefundSignature:  append(buyerRefund.Serialize(), bitcoinSignatureHashType),
		SellerRefundSignature: append(sellerRefund.Serialize(), bitcoinSignatureHashType),
		FundingTx:             funding.Bytes(),
	}
	engine, err := NewBSVEngine(BSVEngineConfig{BuyerPubKey: buyerPub, SellerPubKey: sellerPub, ArbiterPubKey: arbiterPub})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	broadcastRefund, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	broadcastRefundTx, err := parseTransaction(broadcastRefund)
	if err != nil {
		t.Fatal(err)
	}
	refundChunks, err := broadcastRefundTx.Inputs[0].UnlockingScript.Chunks()
	if err != nil || len(refundChunks) != 3 || refundChunks[0].Op != script.Op0 {
		t.Fatalf("refund submission did not combine both signatures: %v", err)
	}
	initial, err := engine.InitialPaymentState(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(initial, proof); err != nil {
		t.Fatalf("initial refund was not accepted as pool state: %v", err)
	}
	forgedInitial := *initial
	forgedInitial.SellerAmountSat = 1
	if err := engine.VerifyAcceptedPayment(&forgedInitial, proof); err == nil {
		t.Fatal("forged persisted initial state was accepted")
	}
	unsigned, err := engine.BuildPaymentUpdate(context.Background(), PaymentUpdateInput{
		Opening:              proof,
		Previous:             initial,
		PaymentSequenceAfter: 2,
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
	if err := engine.VerifyBuyerPayment(buyerState, proof); err != nil {
		t.Fatal(err)
	}
	signed, err := engine.AddSellerSignature(context.Background(), buyerState, testKeySigner{key: sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	if signed.State.SellerAmountSat != 1000 || signed.State.ClientAmountSat != 8900 || signed.State.PaymentSequence != 2 {
		t.Fatalf("unexpected signed payment state: %+v", signed.State)
	}
	if err := engine.VerifyAcceptedPayment(&signed.State, proof); err != nil {
		t.Fatalf("seller-signed accepted state did not verify: %v", err)
	}
	arbiterSignature, err := engine.SignArbiterPayment(context.Background(), buyerState, testKeySigner{key: arbiterKey})
	if err != nil {
		t.Fatal(err)
	}
	arbiterSigned, err := engine.AddArbiterSignature(context.Background(), buyerState, arbiterSignature)
	if err != nil {
		t.Fatal(err)
	}
	if len(arbiterSigned.RawTx) == 0 {
		t.Fatal("arbiter signed transaction is empty")
	}
	if err := engine.VerifyAcceptedPayment(&arbiterSigned.State, proof); err != nil {
		t.Fatalf("arbiter-signed accepted state did not verify: %v", err)
	}
	if err := engine.CheckPaymentCapacity(context.Background(), PaymentUpdateInput{Opening: proof, Previous: initial, PaymentSequenceAfter: 2, SellerAmountAfterSat: 1000, MinerFeeSat: 9900}); err == nil {
		t.Fatal("expected insufficient balance")
	}
	closeTx, err := engine.BuildImmediateClose(context.Background(), CloseInput{Opening: proof, Latest: initial, SellerAmountAfterSat: 1000, MinerFeeSat: 100})
	if err != nil {
		t.Fatal(err)
	}
	parsedClose, err := parseTransaction(closeTx.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if parsedClose.LockTime != bsvtx.DefaultSequenceNumber || parsedClose.Inputs[0].SequenceNumber != bsvtx.DefaultSequenceNumber {
		t.Fatalf("immediate close is not final: locktime=%d sequence=%d", parsedClose.LockTime, parsedClose.Inputs[0].SequenceNumber)
	}
	closeState, err := engine.SignBuyerPayment(context.Background(), closeTx, testKeySigner{key: buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyFinalPayment(closeState, proof); err != nil {
		t.Fatal(err)
	}
	completedClose, err := engine.AddSellerSignature(context.Background(), closeState, testKeySigner{key: sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyCompletedFinalPayment(completedClose, proof); err != nil {
		t.Fatalf("completed final payment did not verify: %v", err)
	}
}

func bytes32(last byte) []byte {
	result := make([]byte, 32)
	result[31] = last
	return result
}

func p2pkhForTest(key *ec.PublicKey) *script.Script {
	result := script.NewFromBytes(nil)
	_ = result.AppendOpcodes(script.OpDUP, script.OpHASH160)
	_ = result.AppendPushData(bsvhash.Hash160(key.Compressed()))
	_ = result.AppendOpcodes(script.OpEQUALVERIFY, script.OpCHECKSIG)
	return result
}
