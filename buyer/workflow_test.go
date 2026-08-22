// Buyer workflow tests treat the test itself as the calling application:
// every quote, opening state, proof, and payment state is held in local
// variables and passed explicitly into each SDK call. No fake stores or
// backends exist; the workflow must produce identical results from identical
// explicit inputs alone.
package buyer

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

type buyerTestSigner struct{ key *ec.PrivateKey }

func (s buyerTestSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s buyerTestSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := s.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func buyerTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// buyerFixture is the application-side state holder for one full 001–0204 run.
type buyerFixture struct {
	buyerKey     *ec.PrivateKey
	sellerKey    *ec.PrivateKey
	arbiterKey   *ec.PrivateKey
	Buyer        *Workflow
	Seller       *seller.Workflow
	Quote        *bitfs.SignedFileQuote
	Seed         []byte
	FundingTx    []byte
	State        *BuyerOpeningState
	PresignProof *pool.OpeningProof
	Acceptance   *RefundPresignAcceptance
	Expiry       uint32
}

func newBuyerFixture(t *testing.T) *buyerFixture {
	t.Helper()
	f := &buyerFixture{
		buyerKey:   buyerTestKey(t, "11"),
		sellerKey:  buyerTestKey(t, "22"),
		arbiterKey: buyerTestKey(t, "33"),
	}
	var err error
	f.Buyer, err = NewWorkflow(WorkflowConfig{PrivateKey: f.buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = seller.NewWorkflow(seller.WorkflowConfig{PrivateKey: f.sellerKey})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.Repeat([]byte{7}, 4096)
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(source), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	seed := seedBuffer.Bytes()
	seedHash := masterseed.Sum256(seed)
	f.Seed = seed
	f.Quote, err = f.Seller.CreateQuote(context.Background(), bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPubkey: f.buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(source)), QuoteExpiresAtUnix: now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.AcceptQuote(context.Background(), f.Quote); err != nil {
		t.Fatal(err)
	}

	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPubKey: f.buyerKey.PubKey().Compressed(), SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	f.FundingTx = funding.Bytes()
	f.Expiry = uint32(now.Add(time.Hour).Unix())
	return f
}

// prepare runs 0201 + 0202 + 0203 with the test acting as the persistence
// layer: returned states are saved into fixture fields explicitly.
func (f *buyerFixture) prepare(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	preparation, err := f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: f.FundingTx, ExpiryLockTime: f.Expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	f.State = preparation.State // caller saves before sending
	result, err := f.Seller.PresignPoolOpening(ctx, preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.PresignProof = result.Opening // caller saves before responding
	acceptance, err := f.Buyer.AcceptRefundPresign(ctx, f.State, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	f.Acceptance = acceptance // caller saves proof + initial payment
}

func TestPreparePoolOpeningReturnsWireRequestAndPrivateLocalState(t *testing.T) {
	f := newBuyerFixture(t)
	preparation, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTx: f.FundingTx, ExpiryLockTime: f.Expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := pool.DeriveRefundTemplateTxIDFromRequest(preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.State == nil || preparation.State.Request == nil || preparation.State.RefundTemplateTxID != requestHash {
		t.Fatalf("local state does not bind the request hash: %+v", preparation.State)
	}
	if !bytes.Equal(preparation.State.FundingTx, f.FundingTx) {
		t.Fatal("buyer private state lost the funding transaction")
	}
	if bytes.Contains(mustEncodeRequest(t, preparation.Request), f.FundingTx) {
		t.Fatal("wire request leaked the private funding transaction")
	}
	// Same explicit input reproduces the same wire request: pure function.
	repeat, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTx: f.FundingTx, ExpiryLockTime: f.Expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	first := mustEncodeRequest(t, preparation.Request)
	second := mustEncodeRequest(t, repeat.Request)
	if !bytes.Equal(first, second) {
		t.Fatal("identical inputs produced different requests")
	}
}

func TestAcceptRefundPresignRejectsMismatchedLocalStateOrResponse(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	wrongState := &BuyerOpeningState{RefundTemplateTxID: f.State.RefundTemplateTxID, Request: f.State.Request, FundingTx: append([]byte(nil), f.FundingTx...)}
	wrongState.Request.BuyerRefundSignature[0] ^= 0xff
	if _, err := f.Buyer.AcceptRefundPresign(context.Background(), wrongState, &pool.RefundPresignResponse{}); err == nil {
		t.Fatal("tampered local request was accepted")
	}
	// A response whose hash points at another pool must be refused.
	forgedResponse := &pool.RefundPresignResponse{Version: pool.MajorVersion}
	for i := range forgedResponse.RefundTemplateTxID {
		forgedResponse.RefundTemplateTxID[i] = byte(i + 1)
	}
	if _, err := f.Buyer.AcceptRefundPresign(context.Background(), f.State, forgedResponse); err == nil {
		t.Fatal("response hash mismatch was accepted")
	}
}

func TestAcceptRefundPresignProducesCompleteProofAndInitialState(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	if len(f.Acceptance.Opening.FundingTx) == 0 {
		t.Fatal("accepted opening proof is missing the funding transaction")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.Acceptance.Opening.BuyerPubKey, SellerPubKey: f.Acceptance.Opening.SellerPubKey, ArbiterPubKey: f.Acceptance.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(f.Acceptance.Opening); err != nil {
		t.Fatalf("returned proof is invalid: %v", err)
	}
	initial := f.Acceptance.InitialPayment
	if initial.PaymentSequence != 2 || initial.SellerAmountSat != 0 || initial.ArbiterAmountSat != 0 {
		t.Fatalf("initial state = seq %d seller %d arbiter %d", initial.PaymentSequence, initial.SellerAmountSat, initial.ArbiterAmountSat)
	}
	if initial.RefundTemplateTxID != f.Acceptance.Reference.RefundTemplateTxID || f.Acceptance.Reference.PaymentSequence != 2 {
		t.Fatalf("reference = %+v", f.Acceptance.Reference)
	}
}

func TestBuildFundingTxDeliveryBindsExplicitProofOwnership(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	delivery, err := f.Buyer.BuildFundingTxDelivery(context.Background(), f.Acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivery.FundingTx, f.FundingTx) || delivery.RefundTemplateTxID != f.Acceptance.Reference.RefundTemplateTxID {
		t.Fatalf("delivery = %+v", delivery)
	}
	// Another buyer's signer cannot deliver this pool's funding transaction.
	other, err := NewWorkflow(WorkflowConfig{PrivateKey: buyerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.BuildFundingTxDelivery(context.Background(), f.Acceptance.Opening); err == nil {
		t.Fatal("wrong buyer signer was accepted for delivery")
	}
}

func TestContentRequestAndDeliveryRoundTripWithExplicitState(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptDelivery(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request, delivery, ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.Seed) {
		t.Fatal("verified payload batch does not match delivered seed content")
	}
	if deliveryState == nil || deliveryState.RefundTemplateTxID != f.Acceptance.Reference.RefundTemplateTxID {
		t.Fatal("delivery state does not bind the pool")
	}
	// Stale previous state must be rejected: the request is bound to the
	// base sequence of the real previous state.
	stale := &pool.PaymentState{}
	*stale = *f.Acceptance.InitialPayment
	stale.PaymentSequence--
	if _, err := f.Buyer.AcceptDelivery(ctx, f.Quote, f.Acceptance.Opening, stale, request, delivery, ContentDeliveryInput{}); err == nil {
		t.Fatal("stale previous payment state was accepted")
	}
	// Content requests after refund expiry must be rejected. The SDK reads
	// system UTC itself, so open a second pool whose refund lock time is
	// already in the past and build against its evidence.
	expiredPrep, err := f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: f.FundingTx, ExpiryLockTime: uint32(time.Now().UTC().Unix() - 3600), MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerResult, err := f.Seller.PresignPoolOpening(ctx, expiredPrep.Request)
	if err != nil {
		t.Fatal(err)
	}
	fundingDelivery := &pool.FundingTxDelivery{Version: pool.MajorVersion, RefundTemplateTxID: expiredPrep.State.RefundTemplateTxID, FundingTx: append([]byte(nil), expiredPrep.State.FundingTx...)}
	completedSeller, err := f.Seller.AcceptPoolFunding(ctx, sellerResult.Opening, fundingDelivery)
	if err != nil {
		t.Fatal(err)
	}
	expiredAcceptance, err := f.Buyer.AcceptRefundPresign(ctx, expiredPrep.State, sellerResult.Response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.BuildContentRequest(ctx, f.Quote, completedSeller.Opening, expiredAcceptance.InitialPayment, input); err == nil {
		t.Fatal("content request accepted after refund expiry")
	}
}

// The minimal 005 credential carries only the authorization hash and the
// buyer transaction signature; the signature must verify against the exact
// transaction rebuilt locally from the same explicit context, and must fail
// against any different opening/previous/target.
func TestAcceptDeliveryProducesMinimalCredentialVerifiableOverRebuiltTransaction(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	ctx := context.Background()
	now := time.Now().UTC()
	input := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.Seller.BuildContentDelivery(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptDelivery(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request, delivery, ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	update := verified.Update
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(update.PaymentAuthorizationHash, authHash[:]) {
		t.Fatal("005 credential does not carry SHA-256(003 TermsCBOR)")
	}
	rawUpdate, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawUpdate) == 0 || rawUpdate[0] != 0x83 {
		t.Fatalf("minimal 005 wire must be a three-element array: %x", rawUpdate)
	}
	opening := f.Acceptance.Opening
	previous := f.Acceptance.InitialPayment
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: opening.BuyerPubKey, SellerPubKey: opening.SellerPubKey, ArbiterPubKey: opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSat: terms.SellerAmountAfterSat})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyBuyerPayment(rebuilt, update.BuyerTransactionSignature, opening); err != nil {
		t.Fatalf("buyer credential does not verify over the independently rebuilt transaction: %v", err)
	}
	// Rebuilding twice from identical inputs must produce identical bytes:
	// determinism is what lets the seller verify without any wire raw.
	rebuiltAgain, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSat: terms.SellerAmountAfterSat})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.RawTx, rebuiltAgain.RawTx) {
		t.Fatal("payment state rebuild is not deterministic")
	}
	// Input mutation after acceptance cannot change returned results.
	mutatedPrevious := &pool.PaymentState{}
	*mutatedPrevious = *previous
	mutatedPrevious.SellerAmountSat += 1
	if _, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: mutatedPrevious, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSat: terms.SellerAmountAfterSat}); err == nil {
		t.Fatal("tampered previous state was accepted by the transaction core")
	}
}

func mustMarshalRequest(t *testing.T, request *pool.RefundPresignRequest) []byte {
	t.Helper()
	raw, err := pool.EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustEncodeRequest(t *testing.T, request *pool.RefundPresignRequest) []byte {
	t.Helper()
	raw, err := pool.EncodeRefundPresignRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
