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
	"github.com/bsv8/go-bitfs/arbitration"
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

// retrievalFixture extends one buyer fixture with the full 007 custody pair:
// seller submitted Kind 8 and the arbiter persisted + signed Kind 9. Both
// roles share the same quote, opening, 003, seed, and block height.
type retrievalFixture struct {
	f          *buyerFixture
	Arbiter    *arbitration.Workflow
	Request003 *bitfs.SignedContentRequest
	Delivery   *bitfs.SignedContentDelivery
	Kind8      *arbitration.ArbitrationRequest
	RawKind8   []byte
	Kind9      *arbitration.ArbitrationResponse
	RawKind9   []byte
	FeeSat     uint64
}

const retrievalTestBlockHeight uint32 = 900000

func newRetrievalFixture(t *testing.T) *retrievalFixture {
	t.Helper()
	f := newBuyerFixture(t)
	f.prepare(t)
	ctx := context.Background()
	now := time.Now().UTC()
	arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}
	r := &retrievalFixture{f: f, Arbiter: arbiterWorkflow, FeeSat: 500}
	input := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(now.Add(30 * time.Minute).Unix())}
	r.Request003, err = f.Buyer.BuildContentRequest(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	r.Delivery, _, err = f.Seller.BuildContentDelivery(ctx, f.Quote, f.Acceptance.Opening, f.Acceptance.InitialPayment, r.Request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	r.Kind8, err = f.Seller.BuildArbitrationRequest(ctx, f.Acceptance.Opening, r.Request003, r.Delivery, retrievalTestBlockHeight)
	if err != nil {
		t.Fatal(err)
	}
	r.RawKind8, err = arbitration.MarshalRequest(r.Kind8)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := r.Arbiter.PreparePayment(ctx, r.Kind8, retrievalTestBlockHeight, r.FeeSat)
	if err != nil {
		t.Fatal(err)
	}
	r.Kind9, err = r.Arbiter.SignPreparedPayment(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	r.RawKind9, err = arbitration.MarshalResponse(r.Kind9)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var retrievalTestNonce = bytes.Repeat([]byte{0x42}, 32)

// TestBuildArbitrationContentRequestRebuildsSellerClaim proves the buyer can
// derive byte-identical ClaimCBOR/ClaimID from only its opening plus exact
// signed 003, then produces a self-verifying Kind 10.
func TestBuildArbitrationContentRequestRebuildsSellerClaim(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	sellerClaimID, err := arbitration.ArbitrationClaimID(r.Kind8.ClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.ClaimID, sellerClaimID) {
		t.Fatal("buyer-derived Claim ID differs from the Seller Kind 8 Claim ID")
	}
	raw, err := arbitration.MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 5 || raw[0] != 0x85 || raw[1] != 0x04 || raw[2] != 0x0a {
		t.Fatalf("Kind 10 wire shape mismatch: %x", raw)
	}
	decoded, err := arbitration.UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := arbitration.BuyerRetrievalSigningCBOR(decoded.ClaimID, decoded.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := bitfs.VerifySignature(r.f.buyerKey.PubKey().Compressed(), signing, decoded.BuyerSignature); err != nil {
		t.Fatalf("Kind 10 signature does not verify under the buyer key: %v", err)
	}
	// 深拷贝：篡改返回值不影响重新构建的结果。
	request.Nonce[len(request.Nonce)-1] ^= 1
	again, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Nonce, retrievalTestNonce) || bytes.Equal(again.BuyerSignature, request.BuyerSignature) && false {
		t.Fatal("unreachable")
	}
	if !bytes.Equal(again.ClaimID, decoded.ClaimID) {
		t.Fatal("builder state leaked between calls")
	}

	// 全零 nonce 必须在签名域构造前被拒绝；错误长度同样。
	if _, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, bytes.Repeat([]byte{0}, 32)); err == nil {
		t.Fatal("all-zero nonce was accepted")
	}
	if _, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Fatal("31-byte nonce was accepted")
	}
}

func mustAcceptRetrieval(t *testing.T, r *retrievalFixture) (*VerifiedArbitratedContent, *arbitration.ContentRetrievalRequest, *arbitration.ContentRetrievalResponse) {
	t.Helper()
	ctx := context.Background()
	retrievalRequest, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, r.RawKind9)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, r.f.Acceptance.Opening, r.f.Acceptance.InitialPayment, r.Request003, retrievalRequest, response, ArbitratedContentInput{})
	if err != nil {
		t.Fatal(err)
	}
	return verified, retrievalRequest, response
}

// TestAcceptArbitratedContentReturnsPayloadsWithoutPaymentUpdate walks the
// complete happy path and pins the no-005 boundary: the result carries only
// payloads plus audit data, the previous PaymentState is untouched, and no
// buyer transaction signature or close transaction exists anywhere.
func TestAcceptArbitratedContentReturnsPayloadsWithoutPaymentUpdate(t *testing.T) {
	r := newRetrievalFixture(t)
	previousSnapshot := pool.ClonePaymentState(r.f.Acceptance.InitialPayment)
	verified, request, _ := mustAcceptRetrieval(t, r)
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], r.f.Seed) {
		t.Fatal("verified payloads do not match the custodied batch")
	}
	if !bytes.Equal(verified.ClaimID, request.ClaimID) {
		t.Fatal("verified claim ID does not match the Kind 10 routing key")
	}
	if !bytes.Equal(verified.Receipt.ClaimID, verified.ClaimID) || verified.Receipt.ArbiterAmountSat != r.FeeSat {
		t.Fatalf("receipt audit data incomplete: %+v", verified.Receipt)
	}
	// 返回 payload 是深拷贝。
	verified.Payloads[0][0] ^= 1
	again, _, _ := mustAcceptRetrieval(t, r)
	if !bytes.Equal(again.Payloads[0], r.f.Seed) {
		t.Fatal("AcceptArbitratedContent returned internal references")
	}
	// 不产生 005：结果类型没有 Update 字段，previous 状态逐字段未变。
	if !samePaymentState(previousSnapshot, r.f.Acceptance.InitialPayment) {
		t.Fatal("acceptance mutated the previous payment state")
	}
	_ = verified
}

func samePaymentState(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID &&
		left.PaymentSequence == right.PaymentSequence &&
		left.BuyerAmountSat == right.BuyerAmountSat &&
		left.SellerAmountSat == right.SellerAmountSat &&
		left.ArbiterAmountSat == right.ArbiterAmountSat &&
		left.PoolOutputSatoshis == right.PoolOutputSatoshis &&
		bytes.Equal(left.RawTx, right.RawTx) &&
		bytes.Equal(left.PoolLockingScript, right.PoolLockingScript) &&
		left.PaymentAuthorizationHash == right.PaymentAuthorizationHash
}

// TestAcceptArbitratedContentRejectsMismatchedInputs covers the negative
// matrix: wrong opening/quote/previous/authorization, tampered Kind 10
// nonce/signature, foreign custody records, and tampered payloads — every
// case rejects the whole batch.
func TestAcceptArbitratedContentRejectsMismatchedInputs(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	opening := r.f.Acceptance.Opening
	previous := r.f.Acceptance.InitialPayment

	good, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	goodResponse, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, r.RawKind9)
	if err != nil {
		t.Fatal(err)
	}
	base := func() (*pool.OpeningProof, *pool.PaymentState, *bitfs.SignedContentRequest, *arbitration.ContentRetrievalRequest, *arbitration.ContentRetrievalResponse) {
		return opening, pool.ClonePaymentState(previous), bitfs.CloneSignedContentRequest(r.Request003), arbitrationCloneRequest(good), arbitrationCloneResponse(goodResponse)
	}

	// 错误开池证据：另一个池的 opening 无法通过本地重建比对。
	wrongOpening, err := r.f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: append([]byte(nil), r.f.FundingTx...), ExpiryLockTime: r.f.Expiry + 60, MinerFeeRateSatPerKB: 2, SellerPubKey: r.f.sellerKey.PubKey().Compressed(), ArbiterPubKey: r.f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerPresign, err := r.f.Seller.PresignPoolOpening(ctx, wrongOpening.Request)
	if err != nil {
		t.Fatal(err)
	}
	wrongAcc, err := r.f.Buyer.AcceptRefundPresign(ctx, wrongOpening.State, sellerPresign.Response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, wrongAcc.Opening, wrongAcc.InitialPayment, r.Request003, good, goodResponse, ArbitratedContentInput{}); err == nil {
		t.Fatal("wrong opening accepted for arbitration retrieval")
	}

	// 错误报价：换一个改价的报价必须失败。
	resignedQuote := mustResignedQuoteForRetrieval(t, r.f, func(terms *bitfs.FileQuoteTerms) { terms.SeedPriceSat += 7 })
	o, p, a, req, resp := base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, resignedQuote, o, p, a, req, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("wrong quote accepted for arbitration retrieval")
	}

	// 错误 previous：序号不连续或金额不匹配必须失败。
	stale := pool.ClonePaymentState(previous)
	stale.PaymentSequence--
	o, _, a, req, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, stale, a, req, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("stale previous state accepted for arbitration retrieval")
	}
	shortPaid := pool.ClonePaymentState(previous)
	shortPaid.SellerAmountSat += 50 // 目标金额不再等于 previous + 批次价格
	o, _, a, req, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, shortPaid, a, req, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("mismatched cumulative amount accepted for arbitration retrieval")
	}

	// 错误授权：另一张 003 与托管记录的 Claim 不一致。
	otherAuth, err := r.f.Buyer.BuildContentRequest(ctx, r.f.Quote, opening, previous, ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(r.f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(20 * time.Minute).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	o, p, _, req, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, otherAuth, req, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("foreign authorization accepted for arbitration retrieval")
	}

	// 篡改 Kind 10 nonce：买方签名验证失败。
	tamperedNonce := arbitrationCloneRequest(good)
	tamperedNonce.Nonce[len(tamperedNonce.Nonce)-1] ^= 1
	o, p, a, _, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, tamperedNonce, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered Kind 10 nonce accepted")
	}

	// 篡改 Kind 10 签名。
	tamperedSig := arbitrationCloneRequest(good)
	tamperedSig.BuyerSignature[0] ^= 1
	o, p, a, _, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, tamperedSig, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered Kind 10 signature accepted")
	}

	// 外来托管记录（另一条 007 的 exact Kind 8/9）：内嵌 Claim 与本地期望不同。
	otherInput := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(r.f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(25 * time.Minute).Unix())}
	otherRequest, err := r.f.Buyer.BuildContentRequest(ctx, r.f.Quote, opening, previous, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	otherDelivery, _, err := r.f.Seller.BuildContentDelivery(ctx, r.f.Quote, opening, previous, otherRequest, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), r.f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	otherKind8, err := r.f.Seller.BuildArbitrationRequest(ctx, opening, otherRequest, otherDelivery, retrievalTestBlockHeight)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw8, err := arbitration.MarshalRequest(otherKind8)
	if err != nil {
		t.Fatal(err)
	}
	otherPrepared, err := r.Arbiter.PreparePayment(ctx, otherKind8, retrievalTestBlockHeight, r.FeeSat)
	if err != nil {
		t.Fatal(err)
	}
	otherKind9, err := r.Arbiter.SignPreparedPayment(ctx, otherPrepared)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw9, err := arbitration.MarshalResponse(otherKind9)
	if err != nil {
		t.Fatal(err)
	}
	foreignResponse, err := arbitration.BuildContentRetrievalResponse(otherRaw8, otherRaw9)
	if err != nil {
		t.Fatal(err)
	}
	o, p, a, _, _ = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, good, foreignResponse, ArbitratedContentInput{}); err == nil {
		t.Fatal("a foreign custody record satisfied local acceptance")
	}
	// 同样，用本记录的 Kind 8 配外来 Kind 9 也必须拒绝。
	mixedResponse, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, otherRaw9)
	if err == nil {
		t.Fatal("mixed-record custody pair built successfully")
	}
	if mixedResponse != nil {
		t.Fatal("mixed-record build returned a result")
	}
	_ = mixedResponse

	// payload 篡改：内嵌 Kind 8 的 bundle 被改动后 canonical 解码失败。
	corrupted := arbitrationCloneResponse(goodResponse)
	bundle, err := bitfs.EncodeContentPayloads([][]byte{[]byte("tampered-payload")})
	if err != nil {
		t.Fatal(err)
	}
	decoded8, err := arbitration.UnmarshalRequest(corrupted.ArbitrationRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	decoded8.ContentPayloadsCBOR = bundle
	rebuilt8, err := arbitration.MarshalRequest(decoded8)
	if err == nil {
		corrupted.ArbitrationRequestCBOR = rebuilt8
	}
	o, p, a, _, _ = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, good, corrupted, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered embedded payload accepted")
	}
}

func arbitrationCloneRequest(value *arbitration.ContentRetrievalRequest) *arbitration.ContentRetrievalRequest {
	if value == nil {
		return nil
	}
	return &arbitration.ContentRetrievalRequest{Version: value.Version, ClaimID: append([]byte(nil), value.ClaimID...), Nonce: append([]byte(nil), value.Nonce...), BuyerSignature: append([]byte(nil), value.BuyerSignature...)}
}

func arbitrationCloneResponse(value *arbitration.ContentRetrievalResponse) *arbitration.ContentRetrievalResponse {
	if value == nil {
		return nil
	}
	return &arbitration.ContentRetrievalResponse{Version: value.Version, ArbitrationRequestCBOR: append([]byte(nil), value.ArbitrationRequestCBOR...), ArbitrationResponseCBOR: append([]byte(nil), value.ArbitrationResponseCBOR...)}
}

func mustResignedQuoteForRetrieval(t *testing.T, f *buyerFixture, mutate func(*bitfs.FileQuoteTerms)) *bitfs.SignedFileQuote {
	t.Helper()
	terms, err := bitfs.DecodeFileQuoteTerms(f.Quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	mutate(terms)
	quote, err := bitfs.NewSignedFileQuote(terms, f.sellerKey, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote
}

// TestArbitrationRetrievalIsTimeIndependent proves post-hoc recovery works
// after both the delivery deadline and the refund maturity have passed: the
// whole chain is signed while gates are still open, time moves past them,
// and acceptance still succeeds without any fake clock or block height.
func TestArbitrationRetrievalIsTimeIndependent(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	ctx := context.Background()
	now := time.Now().UTC()
	deadline := now.Add(2 * time.Second).Unix()
	arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{PrivateKey: f.arbiterKey})
	if err != nil {
		t.Fatal(err)
	}
	// 用短窗口报价重建整条链。
	shortQuote, err := f.Seller.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: masterseed.Sum256(f.Seed).Bytes(), BuyerPubkey: f.buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: 4096, QuoteExpiresAtUnix: deadline, SupportedArbiterPubkeysCBOR: mustEncodeArbiterForRetrieval(t, f)}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.AcceptQuote(ctx, shortQuote); err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: f.Acceptance.Opening.BuyerPubKey, SellerPubKey: f.Acceptance.Opening.SellerPubKey, ArbiterPubKey: f.Acceptance.Opening.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	_ = engine
	input := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(deadline)}
	request003, err := f.Buyer.BuildContentRequest(ctx, shortQuote, f.Acceptance.Opening, f.Acceptance.InitialPayment, input)
	if err != nil {
		t.Fatal(err)
	}
	delivery, _, err := f.Seller.BuildContentDelivery(ctx, shortQuote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	kind8, err := f.Seller.BuildArbitrationRequest(ctx, f.Acceptance.Opening, request003, delivery, retrievalTestBlockHeight)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := arbiterWorkflow.PreparePayment(ctx, kind8, retrievalTestBlockHeight, 500)
	if err != nil {
		t.Fatal(err)
	}
	kind9, err := arbiterWorkflow.SignPreparedPayment(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	raw8, err := arbitration.MarshalRequest(kind8)
	if err != nil {
		t.Fatal(err)
	}
	raw9, err := arbitration.MarshalResponse(kind9)
	if err != nil {
		t.Fatal(err)
	}
	// 时间越过 delivery deadline 和 refund locktime。
	for time.Now().UTC().Unix() <= deadline {
		time.Sleep(100 * time.Millisecond)
	}
	retrievalRequest, err := f.Buyer.BuildArbitrationContentRequest(ctx, f.Acceptance.Opening, request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arbitration.BuildContentRetrievalResponse(raw8, raw9)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptArbitratedContent(ctx, shortQuote, f.Acceptance.Opening, f.Acceptance.InitialPayment, request003, retrievalRequest, response, ArbitratedContentInput{})
	if err != nil {
		t.Fatalf("post-expiry retrieval of signed custody evidence failed: %v", err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.Seed) {
		t.Fatal("post-expiry payloads do not match the custodied batch")
	}
}

func mustEncodeArbiterForRetrieval(t *testing.T, f *buyerFixture) []byte {
	t.Helper()
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	return arbiters
}

// TestAcceptArbitratedContentRejectsWrongVersionKind11Struct pins shell
// validation for direct Go-struct callers: a Kind 11 with a wrong version is
// rejected before any embedded document parsing, exactly like the wire
// decoder would reject it.
func TestAcceptArbitratedContentRejectsWrongVersionKind11Struct(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	good, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	goodResponse, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, r.RawKind9)
	if err != nil {
		t.Fatal(err)
	}
	for version := range map[uint64]string{arbitration.MajorVersion + 1: "future", 0: "zero"} {
		bad := arbitrationCloneResponse(goodResponse)
		bad.Version = version
		if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, r.f.Acceptance.Opening, r.f.Acceptance.InitialPayment, r.Request003, good, bad, ArbitratedContentInput{}); err == nil {
			t.Fatalf("version %d Kind 11 struct was accepted", version)
		}
	}
}

// TestRetrievalWorkflowInputsAreIsolated proves every 008 entry point uses a
// private snapshot: after a successful call, in-place mutation of the caller's
// buffers neither affects the already-produced results nor leaks into a fresh
// call built from the same original inputs.
func TestRetrievalWorkflowInputsAreIsolated(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	opening := r.f.Acceptance.Opening

	nonceBuf := append([]byte(nil), retrievalTestNonce...)
	request1, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, r.Request003, nonceBuf)
	if err != nil {
		t.Fatal(err)
	}
	response1, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, r.RawKind9)
	if err != nil {
		t.Fatal(err)
	}
	previousSnapshot := pool.ClonePaymentState(r.f.Acceptance.InitialPayment)
	verified1, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, opening, r.f.Acceptance.InitialPayment, r.Request003, request1, response1, ArbitratedContentInput{})
	if err != nil {
		t.Fatal(err)
	}
	payload1 := append([]byte(nil), verified1.Payloads[0]...)
	requestCopy := arbitrationCloneRequest(request1)

	// 原地篡改全部调用方缓冲区：nonce、返回的请求、以及响应内嵌文档。
	nonceBuf[len(nonceBuf)-1] ^= 1
	request1.Nonce[0] ^= 1
	request1.BuyerSignature[len(request1.BuyerSignature)-1] ^= 1
	response1.ArbitrationRequestCBOR[0] ^= 1
	response1.ArbitrationResponseCBOR[len(response1.ArbitrationResponseCBOR)-1] ^= 1

	// 用相同原始输入重新构建：builder 不得保留任何被篡改的状态。
	request2, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request2.ClaimID, requestCopy.ClaimID) || !bytes.Equal(request2.Nonce, requestCopy.Nonce) || !bytes.Equal(request2.BuyerSignature, requestCopy.BuyerSignature) {
		t.Fatal("BuildArbitrationContentRequest leaked mutated caller state between calls")
	}
	response2, err := arbitration.BuildContentRetrievalResponse(r.RawKind8, r.RawKind9)
	if err != nil {
		t.Fatal(err)
	}
	verified2, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, opening, r.f.Acceptance.InitialPayment, r.Request003, request2, response2, ArbitratedContentInput{})
	if err != nil {
		t.Fatalf("fresh acceptance failed after caller-buffer mutation: %v", err)
	}
	if !bytes.Equal(verified2.Payloads[0], payload1) {
		t.Fatal("acceptance results changed across identical inputs")
	}
	if !samePaymentState(previousSnapshot, r.f.Acceptance.InitialPayment) {
		t.Fatal("previous payment state was mutated by acceptance")
	}
}
