package pool

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	bsvtx "github.com/bsv-blockchain/go-sdk/transaction"
)

type testFundingSubmitter struct{ engine *BSVEngine }

func (submitter testFundingSubmitter) SubmitTransaction(_ context.Context, rawTx []byte) (Hash32, error) {
	return submitter.engine.TransactionID(rawTx)
}

func TestPoolOpeningWorkflowSavesBeforeFundingSubmission(t *testing.T) {
	ctx := context.Background()
	buyerKey, _ := ec.PrivateKeyFromBytes(bytes32(11))
	sellerKey, _ := ec.PrivateKeyFromBytes(bytes32(12))
	arbiterKey, _ := ec.PrivateKeyFromBytes(bytes32(13))
	engine, err := NewBSVEngine(BSVEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	lockingScript, err := Build2of3LockingScript([][]byte{buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := bsvtx.NewTransaction()
	zero, _ := chainhash.NewHash(make([]byte, 32))
	funding.AddInput(&bsvtx.TransactionInput{SourceTXID: zero, SequenceNumber: bsvtx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&bsvtx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lockingScript)})
	input := OpeningInput{
		FundingTx:         funding.Bytes(),
		PoolOutputIndex:   0,
		ExpiryLockTime:    500000100,
		RefundMinerFeeSat: 100,
		SellerPubKey:      sellerKey.PubKey().Compressed(),
		ArbiterPubKey:     arbiterKey.PubKey().Compressed(),
	}
	request, err := engine.BuildRefundPresignRequest(ctx, input, testKeySigner{key: buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	calculator := BSVTransactionIDCalculator{Engine: engine}
	store, err := NewMemoryStore(calculator)
	if err != nil {
		t.Fatal(err)
	}
	sellerPort := SellerOpeningPort{
		Store:            store,
		RefundSigner:     BSVRefundSigner{Engine: engine, Signer: testKeySigner{key: sellerKey}},
		Calculator:       calculator,
		FundingVerifier:  engine,
		FundingSubmitter: testFundingSubmitter{engine: engine},
	}
	response, err := SellerPresignRefund(ctx, request, sellerPort)
	if err != nil {
		t.Fatal(err)
	}
	buyerPort := BuyerOpeningPort{Store: store, Verifier: engine, Calculator: calculator}
	proof, err := BuyerAcceptRefundPresign(ctx, request, response, funding.Bytes(), buyerPort)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.FundingTx) == 0 {
		t.Fatal("buyer proof did not retain funding transaction")
	}
	complete, err := SellerAcceptFundingTx(ctx, &FundingTxDelivery{Version: MajorVersion, FundingTx: funding.Bytes()}, sellerPort)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.FundingTx) == 0 {
		t.Fatal("seller proof did not retain funding transaction")
	}
}
