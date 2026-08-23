// Documented API smoke test: this file mirrors the exact public signatures
// used by the pseudo-code in docs/complete-file-purchase/README.md. If a
// Workflow signature changes, the documentation examples and this test break
// together, so the guide can never silently drift from the code.
package integration

import (
	"crypto/rand"
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

	// 003 (README §6.2): buyer.ContentRequestInput with an ordered hash batch.
	input := buyer.ContentRequestInput{
		ContentHashes:    [][]byte{masterseed.Sum256(f.seed).Bytes()},
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
		ContentPayloads: [][]byte{append([]byte(nil), f.seed...)},
		Seed:            nil,
		BlockHeight:     blockHeight,
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

	// 005 (README §6.2): the application first looks up the exact original
	// signed 003 by the wire authorization hash, then seller.AcceptPayment
	// takes it together with the saved delivery state.
	rawUpdate, err := wire.MarshalPaymentUpdate(verified.Update)
	if err != nil {
		t.Fatal(err)
	}
	decodedUpdate, err := wire.UnmarshalPaymentUpdate(rawUpdate)
	if err != nil {
		t.Fatal(err)
	}
	signedPayment, err := f.seller.AcceptPayment(ctx, opening, previous, decodedRequest, deliveryState, decodedUpdate, blockHeight)
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
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(ctx, opening, request, delivery, blockHeight)
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
	// README §6.4: the application prices the arbitration fee first, then
	// hands the explicit amount to PreparePayment; the SDK never quotes.
	arbiterAmountSat := uint64(500)
	prepared, err := arbiterWorkflow.PreparePayment(ctx, decodedArbitrationRequest, blockHeight, arbiterAmountSat)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbiterWorkflow.SignPreparedPayment(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	signedArbitrated, err := f.seller.CompleteArbitratedPayment(ctx, arbitrationRequest, response, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := arbitration.UnmarshalReceipt(response.ReceiptCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArbiterAmountSat != arbiterAmountSat || signedArbitrated.State.ArbiterAmountSat != arbiterAmountSat {
		t.Fatal("documented arbitration flow lost the explicit positive fee")
	}
}

// TestDocumentedArbitrationRetrievalAPISignaturesCompileAndRun mirrors the
// 008 pseudo-code in docs/complete-file-purchase/README.md: the buyer builds
// a Kind 10 from opening + signed 003 with an application-generated nonce,
// the application looks up its custody store and answers with exact Kind 11,
// and the buyer accepts without ever producing a payment update. Public API
// access never needs arbitration package internals.
func TestDocumentedArbitrationRetrievalAPISignaturesCompileAndRun(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	store := newMemoryArbitrationCustodyStore()
	ctx := f.ctx
	blockHeight := uint32(900000)

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(30 * time.Minute).Unix())}
	request003, err := f.buyer.BuildContentRequest(ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.seller.BuildContentDelivery(ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(ctx, f.completed.Opening, request003, delivery, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	rawKind8, err := arbitration.MarshalRequest(arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.handleArbitrationRequest(rawKind8, f.arbiter, blockHeight); err != nil {
		t.Fatal(err)
	}

	// README §6.5: nonce comes from the application's crypto/rand source.
	nonce := make([]byte, arbitration.RetrievalNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	retrievalRequest, err := f.buyer.BuildArbitrationContentRequest(ctx, f.completed.Opening, request003, nonce)
	if err != nil {
		t.Fatal(err)
	}
	rawKind10, err := arbitration.MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	decodedKind10, err := wire.UnmarshalArbitrationContentRequest(rawKind10)
	if err != nil {
		t.Fatal(err)
	}
	rawKind11, err := store.handleContentRetrieval(rawKind10, f.arbiter)
	if err != nil {
		t.Fatal(err)
	}
	decodedKind11, err := wire.UnmarshalArbitrationContentResponse(rawKind11)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.buyer.AcceptArbitratedContent(ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request003, decodedKind10, decodedKind11, buyer.ArbitratedContentInput{})
	if err != nil {
		t.Fatal(err)
	}
	receipt := verified.Receipt
	if receipt == nil || receipt.ArbiterAmountSat == 0 || len(verified.Payloads) == 0 {
		t.Fatal("documented retrieval flow returned incomplete audit data")
	}
}
