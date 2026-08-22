// Cross-pool isolation tests: two pools' state is held explicitly by the
// test application in separate variables, and any evidence swap between the
// pools must be refused by the SDK.
package integration

import (
	"testing"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

// poolState holds one pool's explicit local state for both roles.
type poolState struct {
	funding    []byte
	buyerState *buyer.BuyerOpeningState
	presign    *pool.OpeningProof
	buyerAcc   *buyer.RefundPresignAcceptance
	sellerAcc  *seller.PoolFundingAcceptance
}

func (f *protocolFixture) openNamedPool(t *testing.T, satoshis uint64) *poolState {
	t.Helper()
	state := &poolState{funding: f.buildFunding(t, satoshis)}
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: state.funding, ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	state.buyerState = preparation.State // app saves per pool
	result, err := f.seller.PresignPoolOpening(f.ctx, preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	state.presign = result.Opening // app saves per pool
	state.buyerAcc, err = f.buyer.AcceptRefundPresign(f.ctx, state.buyerState, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.buyer.BuildFundingTxDelivery(f.ctx, state.buyerAcc.Opening)
	if err != nil {
		t.Fatal(err)
	}
	state.sellerAcc, err = f.seller.AcceptPoolFunding(f.ctx, state.presign, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestTwoPoolsKeepTheirExplicitStatesSeparate(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	if poolA.buyerAcc.Reference.RefundTemplateTxID == poolB.buyerAcc.Reference.RefundTemplateTxID {
		t.Fatal("distinct pools produced identical correlation IDs")
	}
	if poolA.sellerAcc.InitialPayment.RawTx == nil || poolB.sellerAcc.InitialPayment.RawTx == nil {
		t.Fatal("initial states missing")
	}
}

func TestCrossPoolResponseHashMismatchIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	preparationB, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: f.buildFunding(t, 120000), ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := f.seller.PresignPoolOpening(f.ctx, preparationB.Request)
	if err != nil {
		t.Fatal(err)
	}
	// Pool B's response must not satisfy pool A's saved local state.
	if _, err := f.buyer.AcceptRefundPresign(f.ctx, poolA.buyerState, resultB.Response); err == nil {
		t.Fatal("cross-pool response was accepted")
	}
}

func TestCrossPoolFundingDeliveryIsRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	// Deliver pool A's proof against pool B's presign evidence.
	delivery, err := f.buyer.BuildFundingTxDelivery(f.ctx, poolA.buyerAcc.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.seller.AcceptPoolFunding(f.ctx, poolB.presign, delivery); err == nil {
		t.Fatal("cross-pool funding delivery was accepted")
	}
}

func TestCrossPoolContentAndArbitrationEvidenceAreRefused(t *testing.T) {
	f := newProtocolFixture(t)
	poolA := f.openNamedPool(t, 100000)
	poolB := f.openNamedPool(t, 110000)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	requestA, err := f.buyer.BuildContentRequest(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// A request bound to pool A must not be delivered against pool B's state.
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, poolB.sellerAcc.Opening, poolB.sellerAcc.InitialPayment, requestA, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("content request crossed pools")
	}
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, poolA.sellerAcc.Opening, poolA.sellerAcc.InitialPayment, requestA, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err != nil {
		t.Fatalf("in-pool delivery failed: %v", err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, poolA.sellerAcc.Opening, requestA, poolA.sellerAcc.InitialPayment, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	if arbitrationRequest.RefundTemplateTxID == poolB.buyerAcc.Reference.RefundTemplateTxID {
		t.Fatal("arbitration request bound to the wrong pool")
	}
}
