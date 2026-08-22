// Seller workflow tests treat the test itself as the calling application:
// quotes, presign proofs, opening proofs, payment states, and delivery states
// are held in local variables and passed explicitly into every SDK call.
// There are no fake stores, leases, or backends; concurrency is not an SDK
// concern. Only pure protocol rejections (wrong hash, wrong role, wrong
// evidence, stale sequence) are asserted here.
package seller

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
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
)

type sellerTestSigner struct{ key *ec.PrivateKey }

func (s sellerTestSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s sellerTestSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := s.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func sellerTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(strings.Repeat(hexByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sellerFixture is the application-side state holder for a full 001–007 run.
type sellerFixture struct {
	buyerKey   *ec.PrivateKey
	sellerKey  *ec.PrivateKey
	arbiterKey *ec.PrivateKey
	Buyer      *buyer.Workflow
	Seller     *Workflow
	Arbiter    *arbitration.Workflow
	Quote      *bitfs.SignedFileQuote
	Seed       []byte
	FundingTx  []byte
	State      *buyer.BuyerOpeningState
	Presign    *SellerPresignResult
	Acceptance *buyer.RefundPresignAcceptance
	Expiry     uint32
}

func newSellerFixture(t *testing.T) *sellerFixture {
	t.Helper()
	f := &sellerFixture{
		buyerKey:   sellerTestKey(t, "11"),
		sellerKey:  sellerTestKey(t, "22"),
		arbiterKey: sellerTestKey(t, "33"),
	}
	var err error
	f.Buyer, err = buyer.NewWorkflow(buyer.WorkflowConfig{PrivateKey: f.buyerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.Seller, err = NewWorkflow(WorkflowConfig{PrivateKey: f.sellerKey})
	if err != nil {
		t.Fatal(err)
	}
	f.Arbiter, err = arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}

	source := bytes.Repeat([]byte{7}, 4096)
	var seedBuffer bytes.Buffer
	if _, err := masterseed.CreateSeed(context.Background(), bytes.NewReader(source), &seedBuffer); err != nil {
		t.Fatal(err)
	}
	f.Seed = seedBuffer.Bytes()
	now := time.Now().UTC()
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	f.Quote, err = f.Seller.CreateQuote(context.Background(), bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.Seed).Bytes(), BuyerPubkey: f.buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(source)), QuoteExpiresAtUnix: now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, "file.bin")
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

	preparation, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTx: f.FundingTx, ExpiryLockTime: f.Expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: f.sellerKey.PubKey().Compressed(), ArbiterPubKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	f.State = preparation.State
	result, err := f.Seller.PresignPoolOpening(context.Background(), preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.Presign = result
	acceptance, err := f.Buyer.AcceptRefundPresign(context.Background(), f.State, result.Response)
	if err != nil {
		t.Fatal(err)
	}
	f.Acceptance = acceptance
	return f
}

// openPool completes 0204 + 0205 with explicit state passing.
func (f *sellerFixture) openPool(t *testing.T) *PoolFundingAcceptance {
	t.Helper()
	delivery, err := f.Buyer.BuildFundingTxDelivery(context.Background(), f.Acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := f.Seller.AcceptPoolFunding(context.Background(), f.Presign.Opening, delivery)
	if err != nil {
		t.Fatal(err)
	}
	return acceptance
}

func TestCreateQuoteReturnsSignedCredentialWithoutSaving(t *testing.T) {
	f := newSellerFixture(t)
	if _, err := bitfs.VerifySignedFileQuote(f.Quote); err != nil {
		t.Fatalf("returned quote does not verify: %v", err)
	}
}

func TestPresignPoolOpeningReturnsResponseAndLocalProof(t *testing.T) {
	f := newSellerFixture(t)
	hash, err := pool.DeriveRefundTemplateTxID(nil, f.Presign.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if hash != f.State.RefundTemplateTxID || f.Presign.Response.RefundTemplateTxID != hash {
		t.Fatalf("presign result correlation mismatch: proof %x response %x state %x", hash, f.Presign.Response.RefundTemplateTxID, f.State.RefundTemplateTxID)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.Presign.Opening.BuyerPubKey, SellerPubKey: f.Presign.Opening.SellerPubKey, ArbiterPubKey: f.Presign.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	request, err := requestFromProofForSellerTest(f.Presign.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerRefundSignature(nil, request, f.Presign.Response.SellerRefundSignature); err != nil {
		t.Fatalf("seller refund signature invalid: %v", err)
	}
}

func TestAcceptPoolFundingReturnsCompleteProofStateAndRawFunding(t *testing.T) {
	f := newSellerFixture(t)
	acceptance := f.openPool(t)
	if len(acceptance.Opening.FundingTx) == 0 || !bytes.Equal(acceptance.FundingTx, f.FundingTx) {
		t.Fatal("funding acceptance lost the verified funding transaction")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: acceptance.Opening.BuyerPubKey, SellerPubKey: acceptance.Opening.SellerPubKey, ArbiterPubKey: acceptance.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(acceptance.InitialPayment, acceptance.Opening); err != nil {
		t.Fatalf("initial payment invalid: %v", err)
	}
	if acceptance.InitialPayment.PaymentSequence != 2 {
		t.Fatalf("initial sequence = %d, want 2", acceptance.InitialPayment.PaymentSequence)
	}
}

func TestAcceptPoolFundingRejectsWrongDeliveryHash(t *testing.T) {
	f := newSellerFixture(t)
	delivery := &pool.FundingTxDelivery{Version: pool.MajorVersion, RefundTemplateTxID: f.Presign.Response.RefundTemplateTxID, FundingTx: append([]byte(nil), f.FundingTx...)}
	delivery.RefundTemplateTxID[0] ^= 0xff
	if _, err := f.Seller.AcceptPoolFunding(context.Background(), f.Presign.Opening, delivery); err == nil {
		t.Fatal("delivery hash mismatch was accepted")
	}
	// A different seller's signer cannot accept funding for this pool.
	other, err := NewWorkflow(WorkflowConfig{PrivateKey: sellerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	good := &pool.FundingTxDelivery{Version: pool.MajorVersion, RefundTemplateTxID: f.Presign.Response.RefundTemplateTxID, FundingTx: append([]byte(nil), f.FundingTx...)}
	if _, err := other.AcceptPoolFunding(context.Background(), f.Presign.Opening, good); err == nil {
		t.Fatal("wrong seller signer was accepted")
	}
}

func TestContentPaymentCloseLifecycleWithExplicitState(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong-role delivery attempt must be refused before signing.
	wrongSeller, err := NewWorkflow(WorkflowConfig{PrivateKey: sellerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongSeller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}}); err == nil {
		t.Fatal("wrong seller signer delivered content")
	}
	delivery, deliveryState, err := f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, delivery, buyer.ContentDeliveryInput{})
	if err != nil {
		t.Fatal(err)
	}
	update := verified.Update
	// Minimal 005 carries only the authorization hash and buyer signature.
	if len(update.PaymentAuthorizationHash) != 32 || len(update.BuyerTransactionSignature) == 0 {
		t.Fatal("minimal 005 must carry a 32-byte hash and a non-empty buyer signature")
	}
	authHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(update.PaymentAuthorizationHash, authHash[:]) {
		t.Fatal("005 authorization hash does not match SHA-256 of the signed 003 terms")
	}

	accept := func(authorization *bitfs.SignedContentRequest, previous *pool.PaymentState, state *ContentDeliveryState, candidate *pool.PaymentUpdate) (*pool.SignedPayment, error) {
		return f.Seller.AcceptPayment(ctx, opened.Opening, previous, authorization, state, candidate, 900000)
	}

	// A missing original 003 can never be accepted: the SDK does not scan
	// pools or guess context from a bare hash.
	if _, err := accept(nil, opened.InitialPayment, deliveryState, update); err == nil {
		t.Fatal("missing signed content request was accepted")
	}
	// An authorization hashing to something else is the wrong reference.
	otherInput := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(20 * time.Minute).Unix())}
	otherRequest, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accept(otherRequest, opened.InitialPayment, deliveryState, update); err == nil {
		t.Fatal("authorization hash mismatch was accepted")
	}
	// A previous state that only fills the field shell must be rejected.
	if _, err := accept(request, &pool.PaymentState{RefundTemplateTxID: opened.InitialPayment.RefundTemplateTxID, PaymentSequence: opened.InitialPayment.PaymentSequence, SellerAmountSat: opened.InitialPayment.SellerAmountSat}, deliveryState, update); err == nil {
		t.Fatal("shell-only previous state was accepted")
	}
	// Delivery state targets must match the original 003 exactly.
	wrongAmountState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationHash: deliveryState.PaymentAuthorizationHash, PaymentSequence: deliveryState.PaymentSequence, SellerAmountAfterSat: deliveryState.SellerAmountAfterSat + 1}
	if _, err := accept(request, opened.InitialPayment, wrongAmountState, update); err == nil {
		t.Fatal("payment amount did not have to match the delivery state and 003")
	}
	staleState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationHash: deliveryState.PaymentAuthorizationHash, PaymentSequence: deliveryState.PaymentSequence - 1, SellerAmountAfterSat: deliveryState.SellerAmountAfterSat}
	if _, err := accept(request, opened.InitialPayment, staleState, update); err == nil {
		t.Fatal("stale base sequence was accepted")
	}
	wrongHashState := &ContentDeliveryState{RefundTemplateTxID: deliveryState.RefundTemplateTxID, PaymentAuthorizationHash: pool.Hash32(bytes.Repeat([]byte{9}, 32)), PaymentSequence: deliveryState.PaymentSequence, SellerAmountAfterSat: deliveryState.SellerAmountAfterSat}
	if _, err := accept(request, opened.InitialPayment, wrongHashState, update); err == nil {
		t.Fatal("delivery state hash mismatch was accepted")
	}
	// A buyer signature that is valid for a different transaction (here the
	// immediate-close candidate) must fail against the locally rebuilt
	// forward-payment transaction.
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: opened.Opening.BuyerPubKey, SellerPubKey: opened.Opening.SellerPubKey, ArbiterPubKey: opened.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	closeCandidate, closeSig, err := f.Buyer.BuildImmediateClose(ctx, opened.Opening, opened.InitialPayment, opened.InitialPayment.SellerAmountSat, 900000)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyBuyerPayment(closeCandidate, closeSig, opened.Opening); err != nil {
		t.Fatalf("close signature fixture invalid: %v", err)
	}
	mismatchedSignature := &pool.PaymentUpdate{Version: update.Version, PaymentAuthorizationHash: append([]byte(nil), update.PaymentAuthorizationHash...), BuyerTransactionSignature: append([]byte(nil), closeSig...)}
	if _, err := accept(request, opened.InitialPayment, deliveryState, mismatchedSignature); err == nil {
		t.Fatal("buyer signature over another transaction was accepted for the rebuilt state")
	}
	// Tampering with the wire hash breaks the binding to the supplied 003.
	tamperedHash := &pool.PaymentUpdate{Version: update.Version, PaymentAuthorizationHash: append([]byte(nil), update.PaymentAuthorizationHash...), BuyerTransactionSignature: append([]byte(nil), update.BuyerTransactionSignature...)}
	tamperedHash.PaymentAuthorizationHash[0] ^= 0xff
	if _, err := accept(request, opened.InitialPayment, deliveryState, tamperedHash); err == nil {
		t.Fatal("tampered authorization hash was accepted")
	}
	// Deep-copy contract: mutating caller inputs after acceptance cannot
	// change the returned signed payment.
	signed, err := accept(request, opened.InitialPayment, deliveryState, update)
	if err != nil {
		t.Fatal(err)
	}
	latest := &signed.State
	if err := engine.VerifyAcceptedPayment(latest, opened.Opening); err != nil {
		t.Fatalf("merged accepted state invalid: %v", err)
	}
	if latest.SellerAmountSat != deliveryState.SellerAmountAfterSat {
		t.Fatalf("accepted amount %d != authorized absolute amount %d", latest.SellerAmountSat, deliveryState.SellerAmountAfterSat)
	}
	if latest.PaymentSequence != deliveryState.PaymentSequence {
		t.Fatalf("accepted sequence %d != target %d", latest.PaymentSequence, deliveryState.PaymentSequence)
	}

	// Immediate close from explicit latest state.
	unsigned, buyerSig, err := f.Buyer.BuildImmediateClose(ctx, opened.Opening, latest, latest.SellerAmountSat, 900000)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.Seller.SignImmediateClose(ctx, opened.Opening, unsigned, buyerSig, 900000)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := f.Buyer.CompleteImmediateClose(ctx, opened.Opening, closed)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyFinalPayment(&completed.State, opened.Opening); err != nil {
		t.Fatalf("final close invalid: %v", err)
	}
}

func TestArbitrationLifecycleWithExplicitState(t *testing.T) {
	f := newSellerFixture(t)
	opened := f.openPool(t)
	ctx := context.Background()
	now := time.Now().UTC()

	input := buyer.ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	request, err := f.Buyer.BuildContentRequest(ctx, f.Quote, opened.Opening, opened.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.Seller.BuildContentDelivery(ctx, f.Quote, opened.Opening, opened.InitialPayment, request, ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := f.Seller.BuildArbitrationRequest(ctx, opened.Opening, request, opened.InitialPayment, 900000)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.Arbiter.SignPayment(ctx, arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.Seller.CompleteArbitratedPayment(ctx, opened.Opening, opened.InitialPayment, arbitrationRequest, response, 900000)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: opened.Opening.BuyerPubKey, SellerPubKey: opened.Opening.SellerPubKey, ArbiterPubKey: opened.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&signed.State, opened.Opening); err != nil {
		t.Fatalf("arbitrated state invalid: %v", err)
	}
	// Wrong previous state must be rejected.
	if _, err := f.Seller.CompleteArbitratedPayment(ctx, opened.Opening, &pool.PaymentState{RefundTemplateTxID: opened.InitialPayment.RefundTemplateTxID, PaymentSequence: 99}, arbitrationRequest, response, 900000); err == nil {
		t.Fatal("wrong previous state was accepted for arbitration completion")
	}
}

func requestFromProofForSellerTest(proof *pool.OpeningProof) (*pool.RefundPresignRequest, error) {
	return &pool.RefundPresignRequest{
		Version:              pool.MajorVersion,
		RefundTx:             append([]byte(nil), proof.RefundTx...),
		BuyerPubKey:          append([]byte(nil), proof.BuyerPubKey...),
		SellerPubKey:         append([]byte(nil), proof.SellerPubKey...),
		ArbiterPubKey:        append([]byte(nil), proof.ArbiterPubKey...),
		MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB,
		BuyerRefundSignature: append([]byte(nil), proof.BuyerRefundSignature...),
	}, nil
}
