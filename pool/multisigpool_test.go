package pool

import (
	"bytes"
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
)

type testPrivateKeyProvider struct{ key *ec.PrivateKey }

func (provider testPrivateKeyProvider) PrivateKey(context.Context) (*ec.PrivateKey, error) {
	return provider.key, nil
}

func TestMultisigPoolV4NormalAndArbitrationDetachedSignatures(t *testing.T) {
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: buyer.PubKey().Compressed(), SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	buyerPool := NewBuyerPoolAdapter(engine, testPrivateKeyProvider{buyer})
	sellerPool := NewSellerPoolAdapter(engine, testPrivateKeyProvider{seller})
	arbiterPool := NewArbiterPoolAdapter(engine, testPrivateKeyProvider{arbiter})
	request, err := buyerPool.BuildRefundPresignRequest(ctx, OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500, MinerFeeRateSatPerKB: 1, SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := (PoolRefundSigner{Adapter: sellerPool}).SignRefundTx(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	spend, err := engine.TransactionID(request.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion, RefundTx: request.RefundTx, SpendTxID: spend[:], FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: 0, PoolOutputSatoshis: 100000, PoolLockingScript: request.PoolLockingScript, BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey, MinerFeeRateSatPerKB: 1, BuyerRefundSignature: request.BuyerRefundSignature, SellerRefundSignature: sellerRefund, FundingTx: funding.Bytes()}
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
	if previous.PaymentSequence != 2 || previous.ArbiterAmountSat != 0 {
		t.Fatalf("opening state = %+v", previous)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 3, SellerAmountAfterSat: 1000})
	if err != nil {
		t.Fatal(err)
	}
	buyerSig, err := buyerPool.SignBuyerPayment(ctx, unsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsigned.RawTx, mustRawUnsigned(t, unsigned)) {
		t.Fatal("buyer signing changed unsigned transaction")
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, proof); err != nil {
		t.Fatal(err)
	}
	sellerSig, err := sellerPool.SignSellerPayment(ctx, unsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sellerPool.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(&accepted.State, proof); err != nil {
		t.Fatal(err)
	}
	parsedAccepted, err := engine.ParsePaymentState(ctx, accepted.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedAccepted.BuyerTransactionSignature) == 0 || len(parsedAccepted.SellerTransactionSignature) == 0 || len(parsedAccepted.ArbiterTransactionSignature) != 0 {
		t.Fatalf("normal signature metadata = %+v", parsedAccepted)
	}

	arbitrationUnsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 3, SellerAmountAfterSat: 2000})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationSellerSig, err := sellerPool.SignSellerArbitrationCandidate(ctx, arbitrationUnsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerPayment(arbitrationUnsigned, arbitrationSellerSig, proof); err != nil {
		t.Fatal(err)
	}
	arbitrationArbiterSig, err := arbiterPool.SignArbiterPayment(ctx, arbitrationUnsigned, nil)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := sellerPool.MergeSellerArbiterPayment(arbitrationUnsigned, arbitrationSellerSig, arbitrationArbiterSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&arbitrated.State, proof); err != nil {
		t.Fatal(err)
	}
	parsedArbitrated, err := engine.ParsePaymentState(ctx, arbitrated.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedArbitrated.BuyerTransactionSignature) != 0 || len(parsedArbitrated.SellerTransactionSignature) == 0 || len(parsedArbitrated.ArbiterTransactionSignature) == 0 {
		t.Fatalf("arbitrated signature metadata = %+v", parsedArbitrated)
	}
	malformed, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Outputs = malformed.Outputs[:1]
	malformedUnsigned := *arbitrationUnsigned
	malformedUnsigned.RawTx = malformed.Bytes()
	if err := engine.VerifyBuyerPayment(&malformedUnsigned, buyerSig, proof); err == nil {
		t.Fatal("malformed detached verification unexpectedly succeeded")
	}
}

func mustRawUnsigned(t *testing.T, unsigned *UnsignedPayment) []byte {
	t.Helper()
	value, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	return value.Bytes()
}

func mustPoolTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(hexByte), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
