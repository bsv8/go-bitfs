// Documented API smoke test: this file mirrors the exact public signatures
// used by the pseudo-code in docs/complete-file-purchase/README.md. If a
// Workflow signature changes, the documentation examples and this test break
// together, so the guide can never silently drift from the code.
package integration

import (
	"testing"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
	"github.com/bsv8/go-bitfs/wire"
)

// TestDocumentedPoolOpeningWireCodecsCompileAndRun mirrors README §6.1
// (0201–0205): every wire Marshal/Unmarshal returns ([]byte, error) or
// (*T, error), so the smoke test round-trips each message exactly as the
// guide shows before handing it to the next workflow step.
func TestDocumentedPoolOpeningWireCodecsCompileAndRun(t *testing.T) {
	f := newProtocolFixture(t)
	ctx := f.ctx

	// 0201 (README §6.1): buyer prepares the presign request; the application
	// saves State, marshals the Request, and sends the bytes.
	preparation, err := f.buyer.PreparePoolOpening(ctx, pool.OpeningInput{
		FundingTx:            f.buildFunding(t, 100000),
		ExpiryLockTime:       f.expiry,
		MinerFeeRateSatPerKB: 1,
		SellerPubKey:         f.sellerKey.PubKey().Compressed(),
		ArbiterPubKey:        f.arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := wire.MarshalPoolRefundPresignRequest(preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := wire.UnmarshalPoolRefundPresignRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}

	// 0202 (README §6.1): seller verifies and presigns; the application saves
	// Opening, marshals the Response, and sends the bytes.
	presignResult, err := f.seller.PresignPoolOpening(ctx, decodedRequest)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, err := wire.MarshalPoolRefundPresignResponse(presignResult.Response)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := wire.UnmarshalPoolRefundPresignResponse(rawResponse)
	if err != nil {
		t.Fatal(err)
	}

	// 0203 (README §6.1): buyer loads its saved state by the response's
	// RefundTemplateTxID and accepts the presign.
	acceptance, err := f.buyer.AcceptRefundPresign(ctx, preparation.State, decodedResponse)
	if err != nil {
		t.Fatal(err)
	}

	// 0204 (README §6.1): funding delivery is marshaled before sending.
	delivery, err := f.buyer.BuildFundingTxDelivery(ctx, acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	rawDelivery, err := wire.MarshalPoolFundingTxDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}

	// 0205 (README §6.1): seller decodes the received delivery and completes
	// the opening against its saved presign proof.
	decodedDelivery, err := wire.UnmarshalPoolFundingTxDelivery(rawDelivery)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := f.seller.AcceptPoolFunding(ctx, presignResult.Opening, decodedDelivery)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.FundingTx) == 0 || opened.Opening == nil || opened.InitialPayment == nil {
		t.Fatal("pool opening completion returned incomplete evidence")
	}
}

// TestDocumentedPurchaseAPISignaturesCompileAndRun walks the complete
// documented purchase flow (003 request → 004 delivery → 005 payment → 006
// close → refund path → 007 arbitration) with the same argument shapes as the
// README: every call takes the explicitly loaded quote/opening/state plus a
// caller-provided blockHeight.
func TestDocumentedPurchaseAPISignaturesCompileAndRun(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	blockHeight := uint32(900000)
	ctx := f.ctx

	opening := f.completed.Opening
	previous := f.completed.InitialPayment

	// 003 (README §6.2): buyer.ContentRequestInput with BlockHeight field.
	input := buyer.ContentRequestInput{
		Content:          bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: masterseed.Sum256(f.seed).Bytes()},
		ContentSize:      1,
		DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(30 * time.Minute).Unix()),
		Seed:             nil,
		BlockHeight:      blockHeight,
	}
	request, err := f.buyer.BuildContentRequest(ctx, f.quote, opening, previous, input)
	if err != nil {
		t.Fatal(err)
	}

	// README §6.2: wire.MarshalContentRequest returns ([]byte, error).
	rawRequest, err := wire.MarshalContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decodedRequest, err := wire.UnmarshalContentRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}

	// 004 (README §6.2): seller.BuildContentDelivery returns wire + state.
	delivery, deliveryState, err := f.seller.BuildContentDelivery(ctx, f.quote, opening, previous, decodedRequest, seller.ContentDeliveryInput{
		Content:     append([]byte(nil), f.seed...),
		Seed:        nil,
		BlockHeight: blockHeight,
	})
	if err != nil {
		t.Fatal(err)
	}

	// README §6.2: wire.MarshalContentDelivery also returns ([]byte, error);
	// the buyer decodes the received bytes before AcceptDelivery.
	rawDelivery, err := wire.MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	decodedDelivery, err := wire.UnmarshalContentDelivery(rawDelivery)
	if err != nil {
		t.Fatal(err)
	}

	// Buyer verifies the delivery through buyer.AcceptDelivery.
	verified, err := f.buyer.AcceptDelivery(ctx, f.quote, opening, previous, decodedRequest, decodedDelivery, buyer.ContentDeliveryInput{
		Seed:        nil,
		BlockHeight: blockHeight,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 005 (README §6.2): seller.AcceptPayment takes the saved delivery state.
	signedPayment, err := f.seller.AcceptPayment(ctx, opening, previous, deliveryState, verified.Update, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	base := &signedPayment.State

	// 006 (README §6.3): immediate close with base state and height.
	unsigned, buyerSig, err := f.buyer.BuildImmediateClose(ctx, opening, base, base.SellerAmountSat, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.seller.SignImmediateClose(ctx, opening, unsigned, buyerSig, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.CompleteImmediateClose(ctx, opening, closed); err != nil {
		t.Fatal(err)
	}

	// Refund path (README §6.3).
	if _, _, err := f.buyer.BuildRefundAfterExpiry(ctx, opening, blockHeight); err == nil {
		t.Fatal("refund build succeeded before expiry; expected protocol rejection")
	}

	// 007 (README §6.4): arbitration request/response/completion. The README
	// marshals the request, sends it, and the arbiter decodes the received bytes.
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(ctx, opening, request, previous, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	rawArbitrationRequest, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	decodedArbitrationRequest, err := arbitration.UnmarshalRequest(rawArbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	var arbiterWorkflow *arbitration.Workflow = f.arbiter
	response, err := arbiterWorkflow.SignPayment(ctx, decodedArbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.seller.CompleteArbitratedPayment(ctx, opening, previous, arbitrationRequest, response, blockHeight); err != nil {
		t.Fatal(err)
	}
}
