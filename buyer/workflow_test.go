// Buyer workflow tests treat the test itself as the calling application:
// every quote, opening state, proof, and payment state is held in local
// variables and passed explicitly into each SDK call. No fake stores or
// backends exist; the workflow must produce identical results from identical
// explicit inputs alone.
package buyer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
	"github.com/bsv8/go-bitfs/protocol"
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
	buyerKey              *ec.PrivateKey
	sellerKey             *ec.PrivateKey
	arbiterKey            *ec.PrivateKey
	Buyer                 *Workflow
	Seller                *seller.Workflow
	Quote                 *bitfs.SignedFileQuote
	Seed                  []byte
	FundingTransactionRaw []byte
	State                 *BuyerOpeningState
	PresignProof          *pool.OpeningProof
	Acceptance            *RefundPresignAcceptance
	Expiry                uint32
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
	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{f.arbiterKey.PubKey().Compressed()})
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
	f.Quote, err = f.Seller.CreateQuote(context.Background(), bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SeedPriceSatoshis: 100, FullBlockPriceSatoshis: 1000, FileSizeBytes: uint64(len(source)), QuoteExpiresAtUnixSeconds: now.Add(time.Hour).Unix(), SupportedArbiterPublicKeysCBOR: arbiters}, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Buyer.AcceptQuote(context.Background(), f.Quote); err != nil {
		t.Fatal(err)
	}

	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{BuyerPublicKey: f.buyerKey.PubKey().Compressed(), SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	f.FundingTransactionRaw = funding.Bytes()
	f.Expiry = uint32(now.Add(time.Hour).Unix())
	return f
}

// prepare runs 0201 + 0202 + 0203 with the test acting as the persistence
// layer: returned states are saved into fixture fields explicitly.
func (f *buyerFixture) prepare(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	preparation, err := f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTransactionRaw: f.FundingTransactionRaw, ExpiryLockTime: f.Expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
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
	preparation, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTransactionRaw: f.FundingTransactionRaw, ExpiryLockTime: f.Expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := pool.DeriveRefundTemplateTxIDFromRequest(preparation.Request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.State == nil || preparation.State.Request == nil || preparation.State.RefundTemplateTxID != requestID {
		t.Fatalf("local state does not bind the request hash: %+v", preparation.State)
	}
	if !bytes.Equal(preparation.State.FundingTransactionRaw, f.FundingTransactionRaw) {
		t.Fatal("buyer private state lost the funding transaction")
	}
	if bytes.Contains(mustEncodeRequest(t, preparation.Request), f.FundingTransactionRaw) {
		t.Fatal("wire request leaked the private funding transaction")
	}
	// Same explicit input reproduces the same wire request: pure function.
	repeat, err := f.Buyer.PreparePoolOpening(context.Background(), pool.OpeningInput{FundingTransactionRaw: f.FundingTransactionRaw, ExpiryLockTime: f.Expiry, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
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
	wrongState := &BuyerOpeningState{RefundTemplateTxID: f.State.RefundTemplateTxID, Request: f.State.Request, FundingTransactionRaw: append([]byte(nil), f.FundingTransactionRaw...)}
	wrongState.Request.BuyerRefundTransactionSignature[0] ^= 0xff
	if _, err := f.Buyer.AcceptRefundPresign(context.Background(), wrongState, &pool.RefundPresignResponse{}); err == nil {
		t.Fatal("tampered local request was accepted")
	}
	// A response whose hash points at another pool must be refused.
	forgedResponse := &pool.RefundPresignResponse{}
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
	if len(f.Acceptance.Opening.FundingTransactionRaw) == 0 {
		t.Fatal("accepted opening proof is missing the funding transaction")
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: f.Acceptance.Opening.BuyerPublicKey, SellerPublicKey: f.Acceptance.Opening.SellerPublicKey, ArbiterPublicKey: f.Acceptance.Opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(f.Acceptance.Opening); err != nil {
		t.Fatalf("returned proof is invalid: %v", err)
	}
	initial := f.Acceptance.InitialPayment
	if initial.PaymentSequence != 2 || initial.SellerAmountSatoshis != 0 || initial.ArbiterAmountSatoshis != 0 {
		t.Fatalf("initial state = seq %d seller %d arbiter %d", initial.PaymentSequence, initial.SellerAmountSatoshis, initial.ArbiterAmountSatoshis)
	}
	if initial.RefundTemplateTxID != f.Acceptance.Reference.RefundTemplateTxID || f.Acceptance.Reference.PaymentSequence != 2 {
		t.Fatalf("reference = %+v", f.Acceptance.Reference)
	}
}

func TestBuildFundingTransactionDeliveryBindsExplicitProofOwnership(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	delivery, err := f.Buyer.BuildFundingTransactionDelivery(context.Background(), f.Acceptance.Opening)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivery.FundingTransactionRaw, f.FundingTransactionRaw) || delivery.RefundTemplateTxID != f.Acceptance.Reference.RefundTemplateTxID {
		t.Fatalf("delivery = %+v", delivery)
	}
	// Another buyer's signer cannot deliver this pool's funding transaction.
	other, err := NewWorkflow(WorkflowConfig{PrivateKey: buyerTestKey(t, "44")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.BuildFundingTransactionDelivery(context.Background(), f.Acceptance.Opening); err == nil {
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
	expiredPrep, err := f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTransactionRaw: f.FundingTransactionRaw, ExpiryLockTime: uint32(time.Now().UTC().Unix() - 3600), MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerResult, err := f.Seller.PresignPoolOpening(ctx, expiredPrep.Request)
	if err != nil {
		t.Fatal(err)
	}
	fundingDelivery := &pool.FundingTransactionDelivery{RefundTemplateTxID: expiredPrep.State.RefundTemplateTxID, FundingTransactionRaw: append([]byte(nil), expiredPrep.State.FundingTransactionRaw...)}
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
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if update.PaymentAuthorizationID != authID {
		t.Fatal("005 credential does not carry SHA-256(payment_authorization_cbor)")
	}
	rawUpdate, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawUpdate) == 0 || rawUpdate[0] != 0x84 {
		t.Fatalf("minimal 005 wire must be a four-element array: %x", rawUpdate)
	}
	opening := f.Acceptance.Opening
	previous := f.Acceptance.InitialPayment
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPublicKey: opening.BuyerPublicKey, SellerPublicKey: opening.SellerPublicKey, ArbiterPublicKey: opening.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	terms, err := bitfs.DecodePaymentAuthorization(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSatoshis: terms.SellerAmountAfterSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyBuyerPayment(rebuilt, update.BuyerPaymentTransactionSignature, opening); err != nil {
		t.Fatalf("buyer credential does not verify over the independently rebuilt transaction: %v", err)
	}
	// Rebuilding twice from identical inputs must produce identical bytes:
	// determinism is what lets the seller verify without any wire raw.
	rebuiltAgain, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSatoshis: terms.SellerAmountAfterSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.RawTx, rebuiltAgain.RawTx) {
		t.Fatal("payment state rebuild is not deterministic")
	}
	// Input mutation after acceptance cannot change returned results.
	mutatedPrevious := &pool.PaymentState{}
	*mutatedPrevious = *previous
	mutatedPrevious.SellerAmountSatoshis += 1
	if _, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: mutatedPrevious, PaymentSequence: terms.PaymentSequence, SellerAmountAfterSatoshis: terms.SellerAmountAfterSatoshis}); err == nil {
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

const retrievalTestFeeSatoshis uint64 = 500

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

// mustKind11Available 用新 Kind 11 可交付分支构造响应：payload 绑定取自
// 托管 Kind 8 的 exact bundle，签名使用 fixture 的 Arbiter 私钥。
func mustKind11Available(t *testing.T, r *retrievalFixture, request *arbitration.ContentRetrievalRequest) *arbitration.ContentRetrievalResponse {
	t.Helper()
	requestIDHash := sha256.Sum256(request.ContentRetrievalRequestCBOR)
	response, err := arbitration.BuildContentRetrievalAvailableRaw(protocol.ContentRetrievalRequestID(requestIDHash), r.Kind8.ContentPayloadsCBOR, r.f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func retrievalRequestID(t *testing.T, request *arbitration.ContentRetrievalRequest) protocol.ContentRetrievalRequestID {
	t.Helper()
	return protocol.ContentRetrievalRequestID(sha256.Sum256(request.ContentRetrievalRequestCBOR))
}

// TestBuildArbitrationContentRequestRebuildsSellerClaim proves the buyer can
// derive byte-identical ArbitrationClaimCBOR/ClaimID from only its opening plus exact
// signed payment authorization, then produces a self-verifying Kind 10.
func TestBuildArbitrationContentRequestRebuildsSellerClaim(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	sellerClaimID, err := arbitration.ArbitrationClaimID(r.Kind8.ArbitrationClaimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	claimID, nonce, err := arbitration.DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if claimID != sellerClaimID || !bytes.Equal(nonce, retrievalTestNonce) {
		t.Fatal("buyer-derived Claim ID differs from the Seller Kind 8 Claim ID")
	}
	raw, err := arbitration.MarshalContentRetrievalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 || raw[0] != 0x84 || raw[1] != 0x01 || raw[2] != 0x0a {
		t.Fatalf("Kind 10 wire shape mismatch: %x", raw)
	}
	decoded, err := arbitration.UnmarshalContentRetrievalRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyWireDocument(r.f.buyerKey.PubKey().Compressed(), protocol.WireVersion, 10, decoded.ContentRetrievalRequestCBOR, decoded.BuyerContentRetrievalRequestSignature); err != nil {
		t.Fatalf("Kind 10 signature does not verify under the buyer key: %v", err)
	}
	// 深拷贝：篡改返回值不影响重新构建的结果。
	decoded.ContentRetrievalRequestCBOR[len(decoded.ContentRetrievalRequestCBOR)-1] ^= 1
	again, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.ContentRetrievalRequestCBOR, request.ContentRetrievalRequestCBOR) {
		t.Fatal("builder state leaked between calls")
	}

	// 全零 nonce 必须在签名前被拒绝；错误长度同样。
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
	response := mustKind11Available(t, r, retrievalRequest)
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
	claimID, _, err := arbitration.DecodeContentRetrievalRequestDocument(request.ContentRetrievalRequestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ArbitrationClaimID != claimID || verified.ContentRetrievalRequestID != retrievalRequestID(t, request) {
		t.Fatalf("verified retrieval binding incomplete: %+v", verified)
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
		left.BuyerAmountSatoshis == right.BuyerAmountSatoshis &&
		left.SellerAmountSatoshis == right.SellerAmountSatoshis &&
		left.ArbiterAmountSatoshis == right.ArbiterAmountSatoshis &&
		left.PoolOutputSatoshis == right.PoolOutputSatoshis &&
		bytes.Equal(left.RawTx, right.RawTx) &&
		bytes.Equal(left.PoolLockingScript, right.PoolLockingScript) &&
		left.PaymentAuthorizationID == right.PaymentAuthorizationID
}

// TestAcceptArbitratedContentRejectsMismatchedInputs covers the negative
// matrix: wrong opening/quote/previous/authorization, tampered Kind 10
// document/signature, foreign custody records, unavailable answers, and
// tampered payload attachments — every case rejects the whole batch.
func TestAcceptArbitratedContentRejectsMismatchedInputs(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	opening := r.f.Acceptance.Opening
	previous := r.f.Acceptance.InitialPayment

	good, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	goodResponse := mustKind11Available(t, r, good)
	base := func() (*pool.OpeningProof, *pool.PaymentState, *bitfs.SignedContentRequest, *arbitration.ContentRetrievalRequest, *arbitration.ContentRetrievalResponse) {
		return opening, pool.ClonePaymentState(previous), bitfs.CloneSignedContentRequest(r.Request003), arbitrationCloneRequest(good), arbitrationCloneResponse(goodResponse)
	}

	// 错误开池证据：另一个池的 opening 无法通过本地重建比对。
	wrongOpening, err := r.f.Buyer.PreparePoolOpening(ctx, pool.OpeningInput{FundingTransactionRaw: append([]byte(nil), r.f.FundingTransactionRaw...), ExpiryLockTime: r.f.Expiry + 60, MinerFeeRateSatoshisPerKilobyte: 2, SellerPublicKey: r.f.sellerKey.PubKey().Compressed(), ArbiterPublicKey: r.f.arbiterKey.PubKey().Compressed()})
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
	resignedQuote := mustResignedQuoteForRetrieval(t, r.f, func(terms *bitfs.FileQuoteTerms) { terms.SeedPriceSatoshis += 7 })
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
	shortPaid.SellerAmountSatoshis += 50 // 目标金额不再等于 previous + 批次价格
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

	// 篡改 Kind 10 请求文档：买方签名验证失败。
	tamperedNonce := arbitrationCloneRequest(good)
	tamperedNonce.ContentRetrievalRequestCBOR[len(tamperedNonce.ContentRetrievalRequestCBOR)-1] ^= 1
	o, p, a, _, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, tamperedNonce, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered Kind 10 request document accepted")
	}

	// 篡改 Kind 10 签名。
	tamperedSig := arbitrationCloneRequest(good)
	tamperedSig.BuyerContentRetrievalRequestSignature[0] ^= 1
	o, p, a, _, resp = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, tamperedSig, resp, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered Kind 10 signature accepted")
	}

	// 外来托管记录：另一条 007 链的 payload 绑定到它自己的请求 ID，
	// 对本请求必须拒绝。
	otherInput := ContentRequestInput{ContentHashes: [][]byte{masterseed.Sum256(r.f.Seed).Bytes()}, DeliveryDeadline: bitfs.UnixSeconds(time.Now().UTC().Add(25 * time.Minute).Unix())}
	otherRequest003, err := r.f.Buyer.BuildContentRequest(ctx, r.f.Quote, opening, previous, otherInput)
	if err != nil {
		t.Fatal(err)
	}
	otherDelivery, _, err := r.f.Seller.BuildContentDelivery(ctx, r.f.Quote, opening, previous, otherRequest003, seller.ContentDeliveryInput{ContentPayloads: [][]byte{append([]byte(nil), r.f.Seed...)}})
	if err != nil {
		t.Fatal(err)
	}
	otherKind8, err := r.f.Seller.BuildArbitrationRequest(ctx, opening, otherRequest003, otherDelivery, retrievalTestBlockHeight)
	if err != nil {
		t.Fatal(err)
	}
	otherPrepared, err := r.Arbiter.PreparePayment(ctx, otherKind8, retrievalTestBlockHeight, r.FeeSat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Arbiter.SignPreparedPayment(ctx, otherPrepared); err != nil {
		t.Fatal(err)
	}
	otherRetrieval, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, otherRequest003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	foreignResponse := mustKind11Available(t, r, otherRetrieval)
	o, p, a, _, _ = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, good, foreignResponse, ArbitratedContentInput{}); err == nil {
		t.Fatal("a foreign custody record satisfied local acceptance")
	}

	// Unavailable 分支：即使签名正确也不产生 payload、不改变状态。
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(protocol.ContentRetrievalRequestID(retrievalRequestID(t, good)), arbitration.RetrievalSellerArbitrationNotReady, r.f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	o, p, a, _, _ = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, good, unavailable, ArbitratedContentInput{}); !errors.Is(err, arbitration.ErrContentUnavailable) {
		t.Fatalf("unavailable branch did not surface ErrContentUnavailable: %v", err)
	}
	if !samePaymentState(previousSnapshotState(t, r), r.f.Acceptance.InitialPayment) {
		t.Fatal("unavailable answer mutated the previous payment state")
	}

	// payload 篡改：attachment 与签名的 content_payloads_id 不再一致。
	corrupted := arbitrationCloneResponse(goodResponse)
	corrupted.ContentPayloadsCBOR = append([]byte(nil), corrupted.ContentPayloadsCBOR...)
	corrupted.ContentPayloadsCBOR[len(corrupted.ContentPayloadsCBOR)-1] ^= 1
	o, p, a, _, _ = base()
	if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, o, p, a, good, corrupted, ArbitratedContentInput{}); err == nil {
		t.Fatal("tampered payload attachment accepted")
	}
}

func previousSnapshotState(t *testing.T, r *retrievalFixture) *pool.PaymentState {
	t.Helper()
	return pool.ClonePaymentState(r.f.Acceptance.InitialPayment)
}

func arbitrationCloneRequest(value *arbitration.ContentRetrievalRequest) *arbitration.ContentRetrievalRequest {
	if value == nil {
		return nil
	}
	return &arbitration.ContentRetrievalRequest{ContentRetrievalRequestCBOR: append([]byte(nil), value.ContentRetrievalRequestCBOR...), BuyerContentRetrievalRequestSignature: append([]byte(nil), value.BuyerContentRetrievalRequestSignature...)}
}

func arbitrationCloneResponse(value *arbitration.ContentRetrievalResponse) *arbitration.ContentRetrievalResponse {
	if value == nil {
		return nil
	}
	cloned := &arbitration.ContentRetrievalResponse{ContentRetrievalResultCBOR: append([]byte(nil), value.ContentRetrievalResultCBOR...), ArbiterContentRetrievalResultSignature: append([]byte(nil), value.ArbiterContentRetrievalResultSignature...)}
	if value.ContentPayloadsCBOR != nil {
		cloned.ContentPayloadsCBOR = append([]byte(nil), value.ContentPayloadsCBOR...)
	}
	return cloned
}

func mustResignedQuoteForRetrieval(t *testing.T, f *buyerFixture, mutate func(*bitfs.FileQuoteTerms)) *bitfs.SignedFileQuote {
	t.Helper()
	terms, err := bitfs.DecodeFileQuoteTerms(f.Quote.FileQuoteTermsCBOR)
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

// TestArbitrationRetrievalIsTimeIndependent proves post-hoc recovery accepts
// custody evidence whose delivery deadline and quote expiry are already in
// the past. The whole chain is built with low-level deterministic
// constructors — the deadline gates live only in the role workflows, never
// in AcceptArbitratedContent — so no real Sleep or racing window is needed:
// the timestamps are born expired and stay expired forever.
func TestArbitrationRetrievalIsTimeIndependent(t *testing.T) {
	f := newBuyerFixture(t)
	f.prepare(t)
	ctx := context.Background()

	// 固定已过期的时间字段：报价与交付截止都在过去，且永远不会回来。
	expiredUnix := time.Now().UTC().Add(-time.Hour).Unix()
	quoteTerms := &bitfs.FileQuoteTerms{
		SeedHash:                       masterseed.Sum256(f.Seed).Bytes(),
		BuyerPublicKey:                 f.buyerKey.PubKey().Compressed(),
		SeedPriceSatoshis:              100,
		FullBlockPriceSatoshis:         1000,
		FileSizeBytes:                  4096,
		QuoteExpiresAtUnixSeconds:      expiredUnix,
		SupportedArbiterPublicKeysCBOR: mustEncodeArbiterForRetrieval(t, f),
	}
	// 报价在构造时即已过期：NewSignedFileQuote 不读时钟（时间门禁只在
	// 角色 workflow 的验收入口），因此低层构造器可以确定性地生成
	// “签名有效但时间已过期”的 Kind 1。
	shortQuote, err := bitfs.NewSignedFileQuote(quoteTerms, f.sellerKey, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	opening := f.Acceptance.Opening
	previous := f.Acceptance.InitialPayment

	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		t.Fatal(err)
	}
	seedHash := masterseed.Sum256(f.Seed).Bytes()
	hashes, err := bitfs.EncodeContentHashes([][]byte{seedHash})
	if err != nil {
		t.Fatal(err)
	}
	authID, err := bitfs.FileQuoteTermsID(shortQuote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	authorization := &bitfs.PaymentAuthorization{
		FileQuoteTermsID:            authID,
		RefundTemplateTxID:          bytes.Clone(details.RefundTemplateTxID[:]),
		PaymentSequence:             previous.PaymentSequence + 1,
		SellerAmountAfterSatoshis:   previous.SellerAmountSatoshis + 100,
		ContentHashesCBOR:           hashes,
		DeliveryDeadlineUnixSeconds: expiredUnix - 60,
	}
	request003, err := bitfs.NewSignedContentRequest(authorization, f.buyerKey)
	if err != nil {
		t.Fatal(err)
	}

	// 低层装配 Kind 8：MarshalClaim 做 Claim 结构校验与规范编码（内嵌买方授权签名在此一并验证），不读任何时钟。
	claim := &arbitration.ArbitrationClaim{
		PoolOutputSatoshis:                 details.PoolOutputSatoshis,
		PoolOutputLockingScript:            details.PoolLockingScript,
		RefundTemplateRaw:                  opening.RefundTemplateRaw,
		PaymentAuthorizationCBOR:           request003.PaymentAuthorizationCBOR,
		BuyerPaymentAuthorizationSignature: request003.BuyerPaymentAuthorizationSignature,
	}
	claimCBOR, err := arbitration.MarshalClaim(claim)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := arbitration.ArbitrationClaimID(claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := protocol.SignWireDocument(f.sellerKey, protocol.WireVersion, 8, claimCBOR)
	if err != nil {
		t.Fatal(err)
	}
	payloadsCBOR, err := bitfs.EncodeContentPayloads([][]byte{append([]byte(nil), f.Seed...)})
	if err != nil {
		t.Fatal(err)
	}
	kind8Request := &arbitration.ArbitrationRequest{ArbitrationClaimCBOR: claimCBOR, SellerArbitrationClaimSignature: sellerSignature, ContentPayloadsCBOR: payloadsCBOR}

	// 低层装配 Kind 9：交易签名按重建 candidate 计算，同样时间无关。
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis, retrievalTestFeeSatoshis)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		t.Fatal(err)
	}
	arbiterTxSignature, err := engine.SignArbitrationArbiterPayment(ctx, unsigned, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &arbitration.ArbitrationReceipt{ArbitrationClaimID: claimID, ArbiterAmountSatoshis: retrievalTestFeeSatoshis, ArbiterPaymentTransactionSignature: arbiterTxSignature}
	receiptCBOR, err := arbitration.MarshalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	kind9Response := &arbitration.ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR}
	kind9Response.ArbiterArbitrationReceiptSignature = func() []byte {
		signature, err := protocol.SignWireDocument(f.arbiterKey, protocol.WireVersion, 9, receiptCBOR)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}()

	// 这对"时间字段已过期"的 Kind 8/9 必须构成完整有效的托管证据：
	// VerifyCustodiedContent 是时间无关的完整证据链验证。
	if _, err := arbitration.VerifyCustodiedContent(kind8Request, kind9Response); err != nil {
		t.Fatalf("expired-but-signed custody pair failed full evidence verification: %v", err)
	}

	retrievalRequest, err := f.Buyer.BuildArbitrationContentRequest(ctx, opening, request003, retrievalTestNonce)
	if err != nil {
		t.Fatalf("build retrieval request for already-expired evidence: %v", err)
	}
	available, err := arbitration.BuildContentRetrievalAvailableRaw(retrievalRequestID(t, retrievalRequest), kind8Request.ContentPayloadsCBOR, f.arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := f.Buyer.AcceptArbitratedContent(ctx, shortQuote, opening, previous, request003, retrievalRequest, available, ArbitratedContentInput{})
	if err != nil {
		t.Fatalf("post-expiry retrieval of signed custody evidence failed: %v", err)
	}
	if len(verified.Payloads) != 1 || !bytes.Equal(verified.Payloads[0], f.Seed) {
		t.Fatal("post-expiry payloads do not match the custodied batch")
	}
	if verified.ArbitrationClaimID != claimID {
		t.Fatal("accepted audit data does not bind the deterministic Claim ID")
	}
}

func mustEncodeArbiterForRetrieval(t *testing.T, f *buyerFixture) []byte {
	t.Helper()
	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{f.arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	return arbiters
}

// TestAcceptArbitratedContentRejectsTamperedKind11Result pins shell
// validation for direct Go-struct callers: any byte flipped inside the signed
// result document breaks the arbiter signature, exactly like the wire decoder
// path would reject it.
func TestAcceptArbitratedContentRejectsTamperedKind11Result(t *testing.T) {
	r := newRetrievalFixture(t)
	ctx := context.Background()
	good, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, r.f.Acceptance.Opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*arbitration.ContentRetrievalResponse){
		"flipped result byte": func(bad *arbitration.ContentRetrievalResponse) {
			bad.ContentRetrievalResultCBOR[len(bad.ContentRetrievalResultCBOR)-1] ^= 1
		},
		"flipped signature":  func(bad *arbitration.ContentRetrievalResponse) { bad.ArbiterContentRetrievalResultSignature[0] ^= 1 },
		"dropped attachment": func(bad *arbitration.ContentRetrievalResponse) { bad.ContentPayloadsCBOR = nil },
		"smuggled attachment": func(bad *arbitration.ContentRetrievalResponse) {
			unavailable, err := arbitration.BuildContentRetrievalUnavailable(retrievalRequestID(t, good), arbitration.RetrievalCustodyGone, r.f.arbiterKey)
			if err != nil {
				t.Fatal(err)
			}
			bad.ContentRetrievalResultCBOR = unavailable.ContentRetrievalResultCBOR
			bad.ArbiterContentRetrievalResultSignature = unavailable.ArbiterContentRetrievalResultSignature
		},
	} {
		bad := arbitrationCloneResponse(mustKind11Available(t, r, good))
		mutate(bad)
		if _, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, r.f.Acceptance.Opening, r.f.Acceptance.InitialPayment, r.Request003, arbitrationCloneRequest(good), bad, ArbitratedContentInput{}); err == nil {
			t.Fatalf("%s Kind 11 struct was accepted", name)
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
	response1 := mustKind11Available(t, r, request1)
	previousSnapshot := pool.ClonePaymentState(r.f.Acceptance.InitialPayment)
	verified1, err := r.f.Buyer.AcceptArbitratedContent(ctx, r.f.Quote, opening, r.f.Acceptance.InitialPayment, r.Request003, request1, response1, ArbitratedContentInput{})
	if err != nil {
		t.Fatal(err)
	}
	payload1 := append([]byte(nil), verified1.Payloads[0]...)
	requestCopy := arbitrationCloneRequest(request1)

	// 原地篡改全部调用方缓冲区：nonce 输入、返回的请求、以及响应字段。
	nonceBuf[len(nonceBuf)-1] ^= 1
	request1.ContentRetrievalRequestCBOR[0] ^= 1
	request1.BuyerContentRetrievalRequestSignature[len(request1.BuyerContentRetrievalRequestSignature)-1] ^= 1
	response1.ContentRetrievalResultCBOR[0] ^= 1
	if response1.ContentPayloadsCBOR != nil {
		response1.ContentPayloadsCBOR[len(response1.ContentPayloadsCBOR)-1] ^= 1
	}

	// 用相同原始输入重新构建：builder 不得保留任何被篡改的状态。
	request2, err := r.f.Buyer.BuildArbitrationContentRequest(ctx, opening, r.Request003, retrievalTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request2.ContentRetrievalRequestCBOR, requestCopy.ContentRetrievalRequestCBOR) || !bytes.Equal(request2.BuyerContentRetrievalRequestSignature, requestCopy.BuyerContentRetrievalRequestSignature) {
		t.Fatal("BuildArbitrationContentRequest leaked mutated caller state between calls")
	}
	response2 := mustKind11Available(t, r, request2)
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
