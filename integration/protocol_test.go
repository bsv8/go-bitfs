// Package integration exercises the complete BitFS v4 protocol lifecycle
// 001–007 with the test acting as the calling application. Every quote,
// opening state, proof, payment state, and delivery context is held in local
// variables and passed explicitly into each SDK call; there are no stores,
// node adapters, restart simulations, or reconciliation assertions.
package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

type integrationSigner struct{ key *ec.PrivateKey }

func (s integrationSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s integrationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	sig, err := s.key.Sign(payload)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func integrationKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// protocolFixture is the application-side state holder for one pool across
// the full 001–007 lifecycle. Every field would live in an application
// database in production; here it lives in test variables.
type protocolFixture struct {
	ctx        context.Context
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey
	buyer      *buyer.Workflow
	seller     *seller.Workflow
	arbiter    *arbitration.Workflow
	quote      *bitfs.SignedFileQuote
	seed       []byte
	source     []byte

	// Pool A (main lifecycle).
	fundingTx    []byte
	openingState *buyer.BuyerOpeningState
	presignProof *pool.OpeningProof
	acceptance   *buyer.RefundPresignAcceptance
	completed    *seller.PoolFundingAcceptance
	now          time.Time
	expiry       uint32
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	return newProtocolFixtureWithExpiry(t, uint32(time.Now().UTC().Add(time.Hour).Unix()))
}

func newProtocolFixtureWithExpiry(t *testing.T, expiry uint32) *protocolFixture {
	f := &protocolFixture{
		ctx:        context.Background(),
		buyerKey:   integrationKey(t, "11"),
		sellerKey:  integrationKey(t, "22"),
		arbiterKey: integrationKey(t, "33"),
		now:        time.Now().UTC(),
		expiry:     expiry,
	}
	var err error
	f.buyer, err = buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: f.buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.seller, err = seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: f.sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.arbiter, err = arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}
	f.seedContent(t)

	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	// 001: seller creates the quote, buyer verifies and accepts it; both sides
	// keep their own copy as application state.
	quote, err := f.seller.CreateQuote(f.ctx, bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.seed).Bytes(), BuyerPubkey: f.buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(f.source)), QuoteExpiresAtUnix: f.now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.quote = quote
	if _, err := f.buyer.AcceptQuote(f.ctx, quote); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *protocolFixture) seedContent(t *testing.T) {
	t.Helper()
	f.source = bytes.Repeat([]byte{7}, 4096)
	var buffer bytes.Buffer
	if _, err := masterseed.CreateSeed(f.ctx, bytes.NewReader(f.source), &buffer); err != nil {
		t.Fatal(err)
	}
	f.seed = buffer.Bytes()
}

func (f *protocolFixture) buildFunding(t *testing.T, satoshis uint64) []byte {
	t.Helper()
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPubKey: f.buyerKey.PubKey().Compressed(), SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: satoshis, LockingScript: script.NewFromBytes(lock)})
	return funding.Bytes()
}

// preparePool runs 0201+0202+0203+0204+0205 for a fresh funding transaction
// and returns every intermediate value explicitly.
func (f *protocolFixture) openPool(t *testing.T, fundingTx []byte) (*buyer.RefundPresignAcceptance, *seller.PoolFundingAcceptance, *pool.OpeningProof) {
	t.Helper()
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: fundingTx, ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.seller.PresignPoolOpening(f.ctx, preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := f.buyer.AcceptRefundPresign(f.ctx, preparation.State, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := f.buyer.BuildFundingTxDelivery(f.ctx, acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.seller.AcceptPoolFunding(f.ctx, result.Opening, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return acceptance, completed, result.Opening
}

// openMainPool opens the fixture's primary pool and stores its state on the
// fixture, mirroring how an application would persist these values.
func (f *protocolFixture) openMainPool(t *testing.T) {
	t.Helper()
	f.fundingTx = f.buildFunding(t, 100000)
	acceptance, completed, presignProof := f.openPool(t, f.fundingTx)
	f.acceptance = acceptance
	f.completed = completed
	f.presignProof = presignProof
}

func (f *protocolFixture) facts() uint32 { return 900000 }

func TestFullLifecycleWithExplicitStatePassing(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(f.completed.InitialPayment, f.completed.Opening); err != nil {
		t.Fatalf("initial payment invalid: %v", err)
	}

	// 003: buyer builds the content request from explicit state.
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// 004: seller delivers from caller-provided content bytes.
	delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	// Buyer accepts delivery; verified payload is data the app must save.
	verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.seed) {
		t.Fatal("verified payload mismatch")
	}
	// 005: the application routes the minimal credential by its authorization
	// hash back to the exact original signed 003, then the seller merges
	// signatures over the locally rebuilt transaction.
	signedPayment, err := f.seller.AcceptPayment(f.ctx, f.completed.Opening, f.completed.InitialPayment, request, deliveryState, verified.Update, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	latest := &signedPayment.State
	if err := engine.VerifyAcceptedPayment(latest, f.completed.Opening); err != nil {
		t.Fatalf("accepted payment invalid: %v", err)
	}
	if latest.SellerAmountSat != 100 {
		t.Fatalf("seller amount = %d, want seed price 100", latest.SellerAmountSat)
	}

	// 006: immediate close from explicit latest state.
	unsigned, buyerSig, err := f.buyer.BuildImmediateClose(f.ctx, f.completed.Opening, latest, latest.SellerAmountSat, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.seller.SignImmediateClose(f.ctx, f.completed.Opening, unsigned, buyerSig, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	final, err := f.buyer.CompleteImmediateClose(f.ctx, f.completed.Opening, closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyFinalPayment(&final.State, f.completed.Opening); err != nil {
		t.Fatalf("final payment invalid: %v", err)
	}
}

func TestArbitrationLifecycleWithExplicitStatePassing(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.seller.BuildArbitrationRequest(f.ctx, f.completed.Opening, request, f.completed.InitialPayment, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.arbiter.SignPayment(f.ctx, arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.seller.CompleteArbitratedPayment(f.ctx, f.completed.Opening, f.completed.InitialPayment, arbitrationRequest, response, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, f.completed.Opening); err != nil {
		t.Fatalf("arbitrated payment invalid: %v", err)
	}
}

func TestWrongBuyerCannotActOnAnotherBuyersPool(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	wrongBuyer, err := buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: integrationKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongBuyer.BuildFundingTxDelivery(f.ctx, f.acceptance.Opening); err == nil {
		t.Fatal("wrong buyer delivered another buyer's funding transaction")
	}
	if _, _, err := wrongBuyer.BuildImmediateClose(f.ctx, f.completed.Opening, f.completed.InitialPayment, f.completed.InitialPayment.SellerAmountSat, f.facts()); err == nil {
		t.Fatal("wrong buyer signed an immediate close")
	}
}

func TestWrongSellerCannotPresignOrDeliverForAnotherSellersPool(t *testing.T) {
	f := newProtocolFixture(t)
	preparation, err := f.buyer.PreparePoolOpening(f.ctx, pool.OpeningInput{FundingTx: f.buildFunding(t, 100000), ExpiryLockTime: f.expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	wrongSeller, err := seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: integrationKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongSeller.PresignPoolOpening(f.ctx, preparation.Request); err == nil {
		t.Fatal("wrong seller presigned another seller's opening")
	}
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongSeller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("wrong seller delivered content")
	}
}

func TestExpiredFactsRejectForwardOperationsButEnableRefundBuild(t *testing.T) {
	expiry := uint32(time.Now().UTC().Add(-time.Hour).Unix())
	f := newProtocolFixtureWithExpiry(t, expiry)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	if _, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input); err == nil {
		t.Fatal("content request accepted after refund expiry")
	}
	// With the refund expired the template becomes computable from stored
	// evidence; whether to broadcast remains the application's decision. The
	// fixture's timestamp-lock refund only needs a trusted height placeholder.
	raw, state, err := f.buyer.BuildRefundAfterExpiry(f.ctx, f.completed.Opening, f.facts())
	if err != nil {
		t.Fatalf("refund build after expiry failed: %v", err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.completed.Opening.BuyerPubKey, SellerPubKey: f.completed.Opening.SellerPubKey, ArbiterPubKey: f.completed.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := engine.ParsePaymentState(f.ctx, raw, f.completed.Opening)
	if err != nil || parsed.PaymentSequence != 2 || state.PaymentSequence != 2 {
		t.Fatalf("refund state parse = %v", err)
	}
}

func TestStaleSequenceAndTamperedEvidenceAreRejected(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	stalePrevious := &pool.PaymentState{}
	*stalePrevious = *f.completed.InitialPayment
	stalePrevious.PaymentSequence--
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, stalePrevious, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("stale previous state accepted for delivery")
	}
	// Tampered authorization hash must not be accepted at payment time.
	delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, f.completed.Opening, f.completed.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	tampered := &pool.PaymentUpdate{Version: verified.Update.Version, PaymentAuthorizationHash: append([]byte(nil), verified.Update.PaymentAuthorizationHash...), BuyerTransactionSignature: append([]byte(nil), verified.Update.BuyerTransactionSignature...)}
	tampered.PaymentAuthorizationHash[0] ^= 0xff
	if _, err := f.seller.AcceptPayment(f.ctx, f.completed.Opening, f.completed.InitialPayment, request, deliveryState, tampered, f.facts()); err == nil {
		t.Fatal("tampered authorization hash was accepted")
	}
}

// TestConsecutiveCumulativePaymentRoundsShareConfirmedState runs two full
// 003→004→005 rounds. After each round the application verifies the complete
// dual-signed payment (the "node confirmed" candidate) and saves the SAME
// confirmed state on both the buyer and seller sides; the second round must
// consume the first round's state so sequence and cumulative amount keep
// advancing. Using a stale buyer-side previous in round two must fail.
func TestConsecutiveCumulativePaymentRoundsShareConfirmedState(t *testing.T) {
	f := newProtocolFixture(t)
	f.openMainPool(t)
	opening := f.completed.Opening
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: opening.BuyerPubKey, SellerPubKey: opening.SellerPubKey, ArbiterPubKey: opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}

	input := func(deadline time.Time) buyer.ContentRequestInput {
		return buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(deadline.Add(30 * time.Minute).Unix())}
	}
	runRound := func(previous *pool.PaymentState, deadline time.Time) (*pool.SignedPayment, *bitfs.SignedContentRequest) {
		request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, previous, input(deadline))
		if err != nil {
			t.Fatal(err)
		}
		delivery, deliveryState, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, previous, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := f.buyer.AcceptDelivery(f.ctx, f.quote, opening, previous, request, delivery, buyer.ContentDeliveryInput{})
		if err != nil {
			t.Fatal(err)
		}
		signedPayment, err := f.seller.AcceptPayment(f.ctx, opening, previous, request, deliveryState, verified.Update, f.facts())
		if err != nil {
			t.Fatal(err)
		}
		return signedPayment, request
	}

	// Round one.
	confirmed := f.completed.InitialPayment
	signed1, _ := runRound(confirmed, f.now)
	if err := engine.VerifyAcceptedPayment(&signed1.State, opening); err != nil {
		t.Fatalf("round-one confirmed payment invalid: %v", err)
	}
	// Node policy accepted the candidate: BOTH roles now persist the same
	// complete dual-signed state as their latest.
	buyerLatest := &signed1.State
	sellerLatest := &signed1.State
	if buyerLatest.PaymentSequence != sellerLatest.PaymentSequence || buyerLatest.SellerAmountSat != sellerLatest.SellerAmountSat {
		t.Fatal("buyer and seller persisted different confirmed states")
	}
	if buyerLatest.PaymentSequence != confirmed.PaymentSequence+1 || buyerLatest.SellerAmountSat != 100 {
		t.Fatalf("round-one state = seq %d amount %d, want seq %d amount 100", buyerLatest.PaymentSequence, buyerLatest.SellerAmountSat, confirmed.PaymentSequence+1)
	}

	// Round two must consume round one's confirmed state.
	signed2, _ := runRound(buyerLatest, f.now.Add(time.Minute))
	if err := engine.VerifyAcceptedPayment(&signed2.State, opening); err != nil {
		t.Fatalf("round-two confirmed payment invalid: %v", err)
	}
	if signed2.State.PaymentSequence != buyerLatest.PaymentSequence+1 {
		t.Fatalf("round-two sequence = %d, want %d", signed2.State.PaymentSequence, buyerLatest.PaymentSequence+1)
	}
	if signed2.State.SellerAmountSat != buyerLatest.SellerAmountSat+100 {
		t.Fatalf("round-two cumulative amount = %d, want %d", signed2.State.SellerAmountSat, buyerLatest.SellerAmountSat+100)
	}
	if !bytes.Equal(signed2.RawTx, signed2.State.RawTx) {
		t.Fatal("round-two merged transaction does not match its parsed state")
	}
	// Round two's confirmed state replaces the shared record on both sides.
	buyerLatest = &signed2.State
	sellerLatest = &signed2.State

	// A buyer whose journal still holds the round-one previous cannot start
	// the next round against the advanced seller state: the request it signs
	// targets an already-consumed sequence and must be refused.
	if _, _, err := f.seller.BuildContentDelivery(f.ctx, f.quote, opening, sellerLatest, mustStaleRoundRequest(t, f, opening, &signed1.State), seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.seed...)}}); err == nil {
		t.Fatal("stale previous state was accepted for the next round's delivery")
	}
}

func mustStaleRoundRequest(t *testing.T, f *protocolFixture, opening *pool.OpeningProof, stale *pool.PaymentState) *bitfs.SignedContentRequest {
	t.Helper()
	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(f.now.Add(30 * time.Minute).Unix())}
	request, err := f.buyer.BuildContentRequest(f.ctx, f.quote, opening, stale, input)
	if err != nil {
		t.Fatalf("build stale next-round request: %v", err)
	}
	return request
}
