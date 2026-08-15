package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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

type countingSigner struct {
	key   *ec.PrivateKey
	signs int
}

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

func (s *countingSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}

func (s *countingSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	s.signs++
	sig, err := s.key.Sign(payload)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func verifyIntegrationSignature(pubkey, payload, signature []byte) error {
	key, err := ec.ParsePubKey(pubkey)
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !sig.Verify(digest[:], key) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

type integrationQuoteStore struct {
	quotes map[bitfs.Hash32]*bitfs.SignedFileQuote
}

func (s *integrationQuoteStore) SaveQuote(_ context.Context, quote *bitfs.SignedFileQuote) error {
	hash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return err
	}
	if s.quotes == nil {
		s.quotes = make(map[bitfs.Hash32]*bitfs.SignedFileQuote)
	}
	s.quotes[bitfs.Hash32(hash)] = cloneIntegrationQuote(quote)
	return nil
}

func (s *integrationQuoteStore) LoadQuote(_ context.Context, hash bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	quote := s.quotes[hash]
	if quote == nil {
		return nil, fmt.Errorf("quote not found")
	}
	return cloneIntegrationQuote(quote), nil
}

type integrationContent struct {
	payloads   map[masterseed.Digest][]byte
	seedLoads  *int
	blockLoads *int
}

func (s integrationContent) load(_ context.Context, hash masterseed.Digest) ([]byte, error) {
	payload, ok := s.payloads[hash]
	if !ok {
		return nil, fmt.Errorf("content not found")
	}
	return append([]byte(nil), payload...), nil
}

func (s integrationContent) LoadSeed(ctx context.Context, hash masterseed.Digest) ([]byte, error) {
	if s.seedLoads != nil {
		*s.seedLoads = *s.seedLoads + 1
	}
	return s.load(ctx, hash)
}

func (s integrationContent) LoadBlock(ctx context.Context, hash masterseed.Digest) ([]byte, error) {
	if s.blockLoads != nil {
		*s.blockLoads = *s.blockLoads + 1
	}
	return s.load(ctx, hash)
}

type badSeedSource struct{ raw []byte }

func (s badSeedSource) LoadSeed(context.Context, masterseed.Digest) ([]byte, error) {
	bad := append([]byte(nil), s.raw...)
	if len(bad) > 0 {
		bad[0] ^= 0xff
	}
	return bad, nil
}

type integrationNode struct {
	mu       sync.Mutex
	engine   *pool.MultisigPoolEngine
	store    pool.OpeningByFundingStore
	accepted map[pool.Hash32]*pool.PaymentState
	updates  int
	fundings int
	finals   int
}

type recordingPoolStore struct {
	pool.PoolStore
	pool.PendingRequestStore
	firstOpening *pool.OpeningProof
}

type failOncePoolStore struct {
	pool.PoolStore
	pool.PendingRequestStore
	failAccepted      bool
	uncertain         bool
	failedState       *pool.PaymentState
	saveAcceptedCalls int
	reconcileCalls    int
	forgedAnchor      bool
}

type failOncePendingStore struct {
	pool.PendingRequestStore
	failRelease bool
	releases    int
	override    *pool.PendingRequest
}

type failOnceClosingStore struct {
	pool.PoolStore
	failReconcile bool
	reconciles    int
}

func (store *failOnceClosingStore) ReconcilePoolClosing(ctx context.Context, spendTxID pool.Hash32) error {
	store.reconciles++
	if store.failReconcile {
		store.failReconcile = false
		return errors.New("injected close reconciliation failure")
	}
	return store.PoolStore.ReconcilePoolClosing(ctx, spendTxID)
}

func (store *failOncePendingStore) Load(ctx context.Context, spend pool.Hash32) (*pool.PendingRequest, error) {
	if store.override != nil {
		copy := *store.override
		return &copy, nil
	}
	return store.PendingRequestStore.Load(ctx, spend)
}

func (store *failOncePendingStore) Release(ctx context.Context, spend pool.Hash32, request pool.Hash32) error {
	store.releases++
	if store.failRelease {
		store.failRelease = false
		return errors.New("injected pending release failure")
	}
	return store.PendingRequestStore.Release(ctx, spend, request)
}

type uncertainUpdateNode struct {
	*integrationNode
	fail bool
}

func (node *uncertainUpdateNode) SubmitUpdate(ctx context.Context, raw []byte) (*pool.UpdateAcceptance, error) {
	accepted, err := node.integrationNode.SubmitUpdate(ctx, raw)
	if err != nil || !node.fail {
		return accepted, err
	}
	node.fail = false
	return accepted, errors.New("injected ambiguous backend response")
}

type protocolFixture struct {
	ctx          context.Context
	buyer        *buyer.Workflow
	seller       *seller.Workflow
	quotes       *integrationQuoteStore
	poolStore    *pool.MemoryStore
	pending      *failOncePendingStore
	node         *integrationNode
	quoteHash    bitfs.Hash32
	spend        pool.Hash32
	request      *bitfs.SignedContentRequest
	content      integrationContent
	contentHash  masterseed.Digest
	seedLoads    *int
	blockLoads   *int
	buyerKey     *ec.PrivateKey
	sellerKey    *ec.PrivateKey
	arbiterKey   *ec.PrivateKey
	sellerSigner *countingSigner
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	return newProtocolFixtureAt(t, uint32(time.Now().Unix()+1000))
}

func newProtocolFixtureAt(t *testing.T, expiry uint32) *protocolFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	buyerKey := integrationPrivateKey(t, 41)
	sellerKey := integrationPrivateKey(t, 42)
	arbiterKey := integrationPrivateKey(t, 43)
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	poolStore, err := pool.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	pendingBase, err := pool.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	pending := &failOncePendingStore{PendingRequestStore: pendingBase}
	quotes := &integrationQuoteStore{}
	payload := []byte("fixture-content")
	payloadHash := masterseed.Sum256(payload)
	var seedOutput bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(payload), &seedOutput); err != nil {
		t.Fatal(err)
	}
	seed := seedOutput.Bytes()
	seedHash := masterseed.Sum256(seed)
	seedLoads, blockLoads := 0, 0
	content := integrationContent{payloads: map[masterseed.Digest][]byte{payloadHash: payload, seedHash: seed}, seedLoads: &seedLoads, blockLoads: &blockLoads}
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	node := &integrationNode{engine: engine, store: poolStore, accepted: make(map[pool.Hash32]*pool.PaymentState)}
	sellerSigner := &countingSigner{key: sellerKey}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: sellerSigner, Quotes: quotes, Pools: poolStore, Pending: pending, Content: content, Backend: node})
	if err != nil {
		t.Fatal(err)
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{buyerKey}, Quotes: quotes, Pools: poolStore, Backend: node, SeedSource: content})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := sellerWorkflow.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPubkey: buyerKey.PubKey().Compressed(), SeedPriceSat: 5, FullBlockPriceSat: 100, FileSize: uint64(len(payload)), QuoteExpiresAtUnix: now.Unix() + 1000, SupportedArbiterPubkeysCBOR: arbiters}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buyerWorkflow.AcceptQuote(ctx, quote); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	opening, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: expiry, MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := sellerWorkflow.PresignPoolOpening(ctx, opening)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := buyerWorkflow.AcceptRefundPresign(ctx, opening, response, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatal(err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	var request *bitfs.SignedContentRequest
	if int64(expiry) > now.Unix() {
		request, err = buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: ref.SpendTxID, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		terms := &bitfs.ContentRequestTerms{QuoteTermsHash: quoteHash[:], SpendTxID: ref.SpendTxID[:], BasePaymentSequence: 2, PaymentSequenceAfter: 3, SellerAmountAfterSat: 100, MinerFeeRateSatPerKB: 1, BuyerPubkey: buyerKey.PubKey().Compressed(), SellerPubkey: sellerKey.PubKey().Compressed(), SelectedArbiterPubkey: arbiterKey.PubKey().Compressed(), ContentType: bitfs.ContentBlock, ContentHash: payloadHash.Bytes(), DeliveryDeadlineUnix: now.Unix() + 100}
		request, err = bitfs.NewSignedContentRequest(terms, func(raw []byte) ([]byte, error) {
			digest := sha256.Sum256(raw)
			sig, e := buyerKey.Sign(digest[:])
			if e != nil {
				return nil, e
			}
			return sig.Serialize(), nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return &protocolFixture{ctx: ctx, buyer: buyerWorkflow, seller: sellerWorkflow, quotes: quotes, poolStore: poolStore, pending: pending, node: node, quoteHash: bitfs.Hash32(quoteHash), spend: ref.SpendTxID, request: request, content: content, contentHash: payloadHash, seedLoads: &seedLoads, blockLoads: &blockLoads, buyerKey: buyerKey, sellerKey: sellerKey, arbiterKey: arbiterKey, sellerSigner: sellerSigner}
}

func TestAcceptPaymentRetryAfterPendingReleaseFailureWithSeparateStores(t *testing.T) {
	f := newProtocolFixture(t)
	delivery, err := f.seller.DeliverRequestedContent(f.ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	update, err := f.buyer.AcceptDelivery(f.ctx, f.request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	f.pending.failRelease = true
	signsBefore, updatesBefore := f.sellerSigner.signs, f.node.updates
	if _, err := f.seller.AcceptPayment(f.ctx, update); err == nil {
		t.Fatal("first release failure was not returned")
	}
	if f.sellerSigner.signs != signsBefore+1 || f.node.updates != updatesBefore+1 {
		t.Fatalf("first attempt side effects signs=%d updates=%d", f.sellerSigner.signs-signsBefore, f.node.updates-updatesBefore)
	}
	if f.pending.PendingRequestStore == f.poolStore {
		t.Fatal("pool and pending stores are not independent")
	}
	if _, err := f.seller.AcceptPayment(f.ctx, update); err != nil {
		t.Fatal(err)
	}
	if f.sellerSigner.signs != signsBefore+1 || f.node.updates != updatesBefore+1 {
		t.Fatalf("retry repeated side effects signs=%d updates=%d", f.sellerSigner.signs-signsBefore, f.node.updates-updatesBefore)
	}
	if f.pending.releases != 2 {
		t.Fatalf("release calls=%d, want 2", f.pending.releases)
	}

	// A hash-matching lease with a forged base/amount is not releasable.
	f2 := newProtocolFixture(t)
	delivery, err = f2.seller.DeliverRequestedContent(f2.ctx, f2.request)
	if err != nil {
		t.Fatal(err)
	}
	update, err = f2.buyer.AcceptDelivery(f2.ctx, f2.request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	f2.pending.failRelease = true
	if _, err := f2.seller.AcceptPayment(f2.ctx, update); err == nil {
		t.Fatal("expected injected release failure")
	}
	pending, err := f2.pending.PendingRequestStore.Load(f2.ctx, f2.spend)
	if err != nil || pending == nil {
		t.Fatal(err)
	}
	pending.BasePaymentSequence++
	f2.pending.override = pending
	releasesBefore := f2.pending.releases
	if _, err := f2.seller.AcceptPayment(f2.ctx, update); err == nil {
		t.Fatal("forged pending lease was accepted")
	}
	if f2.pending.releases != releasesBefore {
		t.Fatal("forged pending lease was released")
	}
}

func prepareArbitrationFixture(t *testing.T) (*protocolFixture, *arbitration.ArbitrationRequest, *arbitration.ArbitrationResponse) {
	t.Helper()
	f := newProtocolFixture(t)
	delivery, err := f.seller.DeliverRequestedContent(f.ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	update, err := f.buyer.AcceptDelivery(f.ctx, f.request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.seller.AcceptPayment(f.ctx, update); err != nil {
		t.Fatal(err)
	}
	second, err := f.buyer.RequestContent(f.ctx, buyer.ContentRequestInput{QuoteTermsHash: f.quoteHash, SpendTxID: f.spend, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: masterseed.Sum256([]byte("fixture-content")).Bytes()}, ContentSize: uint64(len("fixture-content")), DeliveryDeadline: bitfs.UnixSeconds(time.Now().Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.seller.DeliverRequestedContent(f.ctx, second); err != nil {
		t.Fatal(err)
	}
	request, err := f.seller.BuildArbitrationRequestFromAuthorization(f.ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{Signer: integrationSigner{f.arbiterKey}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := workflow.SignPayment(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	return f, request, response
}

func TestSubmitArbitratedPaymentRetryAfterPendingReleaseFailureWithSeparateStores(t *testing.T) {
	f, request, response := prepareArbitrationFixture(t)
	f.pending.failRelease = true
	signsBefore, updatesBefore := f.sellerSigner.signs, f.node.updates
	if _, err := f.seller.SubmitArbitratedPayment(f.ctx, request, response); err == nil {
		t.Fatal("first release failure was not returned")
	}
	pending, err := f.pending.PendingRequestStore.Load(f.ctx, f.spend)
	if err != nil || pending == nil {
		t.Fatal(err)
	}
	pending.ExpectedSellerAmountSat++
	f.pending.override = pending
	releasesBefore := f.pending.releases
	if _, err := f.seller.SubmitArbitratedPayment(f.ctx, request, response); err == nil {
		t.Fatal("forged 007 lease was accepted")
	}
	if f.pending.releases != releasesBefore {
		t.Fatal("forged 007 lease was released")
	}
	f.pending.override = nil
	if _, err := f.seller.SubmitArbitratedPayment(f.ctx, request, response); err != nil {
		t.Fatal(err)
	}
	if f.sellerSigner.signs != signsBefore || f.node.updates != updatesBefore+1 {
		t.Fatalf("007 retry side effects signs=%d updates=%d", f.sellerSigner.signs-signsBefore, f.node.updates-updatesBefore)
	}
	if f.pending.releases != 3 {
		t.Fatalf("007 release calls=%d, want 3", f.pending.releases)
	}
}

func TestSubmitArbitratedPaymentRetryAfterUncertainReconcileWithSeparateStores(t *testing.T) {
	f, request, response := prepareArbitrationFixture(t)
	uncertainNode := &uncertainUpdateNode{integrationNode: f.node, fail: true}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: f.sellerSigner, Quotes: f.quotes, Pools: f.poolStore, Pending: f.pending, Content: f.content, Backend: uncertainNode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.SubmitArbitratedPayment(f.ctx, request, response); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("uncertain error=%v", err)
	}
	// The backend already parsed/stored the exact accepted candidate; recover it
	// through the node's accepted map and reconcile the independent PoolStore.
	accepted := f.node.accepted[f.spend]
	if accepted == nil {
		t.Fatal("backend did not retain accepted candidate")
	}
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	accepted = cloneIntegrationPayment(accepted)
	accepted.PaymentAuthorizationHash = pool.Hash32(auth)
	if err := f.poolStore.ReconcileExternalState(f.ctx, f.spend, accepted); err != nil {
		t.Fatal(err)
	}
	// The exact retry must only release the independent pending lease.
	uncertainNode.fail = true
	updatesBefore := f.node.updates
	if _, err := sellerWorkflow.SubmitArbitratedPayment(f.ctx, request, response); err != nil {
		t.Fatal(err)
	}
	if f.node.updates != updatesBefore {
		t.Fatal("uncertain retry called backend")
	}
}

func TestDeliverRequestedContentConflictHasNoContentOrSignerSideEffects(t *testing.T) {
	f := newProtocolFixture(t)
	if result, err := f.pending.TryAcquire(f.ctx, pool.PendingRequest{SpendTxID: f.spend, BasePaymentSequence: 2, BaseSellerAmountSat: 0, ContentRequestHash: pool.Hash32{9}, ExpectedSellerAmountSat: 1}); err != nil || result != pool.PendingAcquired {
		t.Fatalf("seed conflicting lease = %v, %v", result, err)
	}
	seedBefore, blockBefore, signsBefore := *f.seedLoads, *f.blockLoads, f.sellerSigner.signs
	if _, err := f.seller.DeliverRequestedContent(f.ctx, f.request); !errors.Is(err, pool.ErrPoolBusy) {
		t.Fatalf("conflicting delivery error=%v", err)
	}
	if f.sellerSigner.signs != signsBefore || *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatalf("conflicting delivery caused side effects: signs=%d seed=%d block=%d", f.sellerSigner.signs-signsBefore, *f.seedLoads-seedBefore, *f.blockLoads-blockBefore)
	}
}

func TestPendingMissingBlocksArbitrationBeforeBackend(t *testing.T) {
	f, request, response := prepareArbitrationFixture(t)
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pending.Release(f.ctx, f.spend, pool.Hash32(hash)); err != nil {
		t.Fatal(err)
	}
	signsBefore := f.sellerSigner.signs
	if _, err := f.seller.BuildArbitrationRequestFromAuthorization(f.ctx, authorization); !errors.Is(err, pool.ErrPoolBusy) {
		t.Fatalf("missing pending build arbitration error=%v", err)
	}
	if f.sellerSigner.signs != signsBefore {
		t.Fatal("missing pending build arbitration signed")
	}
	updatesBefore := f.node.updates
	if _, err := f.seller.SubmitArbitratedPayment(f.ctx, request, response); !errors.Is(err, pool.ErrPoolBusy) {
		t.Fatalf("missing pending error=%v", err)
	}
	if f.node.updates != updatesBefore {
		t.Fatal("missing pending reached backend")
	}
}

func TestExpiredPoolRequestContentRejectsBeforeContentAndSignerSideEffects(t *testing.T) {
	f := newProtocolFixtureAt(t, uint32(time.Now().Unix()-1))
	seedBefore, blockBefore := *f.seedLoads, *f.blockLoads
	_, err := f.buyer.RequestContent(f.ctx, buyer.ContentRequestInput{QuoteTermsHash: f.quoteHash, SpendTxID: f.spend, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: f.contentHash.Bytes()}, ContentSize: 15, DeliveryDeadline: bitfs.UnixSeconds(time.Now().Unix() + 100)})
	if err == nil {
		t.Fatal("expired pool accepted content request")
	}
	if *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatal("expired request caused content I/O")
	}
	signsBefore := f.sellerSigner.signs
	if _, err := f.seller.DeliverRequestedContent(f.ctx, f.request); err == nil {
		t.Fatal("expired pool delivered content")
	}
	if *f.seedLoads != seedBefore || *f.blockLoads != blockBefore || f.sellerSigner.signs != signsBefore {
		t.Fatal("expired delivery caused content or signer side effects")
	}
	if _, _, err := f.buyer.BuildImmediateClose(f.ctx, f.spend); err == nil {
		t.Fatal("expired pool built immediate close")
	}
	// Build valid 004, 005, 006 and 007-shaped evidence so every role entry
	// reaches the same expiry gate rather than failing on malformed input.
	payload := append([]byte(nil), f.content.payloads[f.contentHash]...)
	delivery, err := bitfs.NewSignedContentDelivery(f.request, payload, func(raw []byte) ([]byte, error) {
		digest := sha256.Sum256(raw)
		sig, signErr := f.sellerKey.Sign(digest[:])
		if signErr != nil {
			return nil, signErr
		}
		return sig.Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	contentBefore := *f.seedLoads + *f.blockLoads
	if _, err := f.buyer.AcceptDelivery(f.ctx, f.request, delivery); err == nil {
		t.Fatal("expired pool accepted delivery")
	}
	if *f.seedLoads+*f.blockLoads != contentBefore {
		t.Fatal("expired delivery loaded content")
	}
	opening, err := f.poolStore.LoadOpeningProof(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	initialRaw, err := f.node.engine.BuildRefundSubmission(opening)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := f.node.engine.ParsePaymentState(f.ctx, initialRaw, opening)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := f.node.engine.BuildPaymentUpdate(f.ctx, pool.PaymentUpdateInput{Opening: opening, Previous: initial, PaymentSequenceAfter: initial.PaymentSequence + 1, SellerAmountAfterSat: initial.SellerAmountSat + 1})
	if err != nil {
		t.Fatal(err)
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(f.node.engine, integrationSigner{f.buyerKey}).SignBuyerPayment(f.ctx, unsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(f.request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	update := &pool.PaymentUpdate{Version: pool.MajorVersion, PaymentAuthorizationHash: authHash[:], UnsignedStateTxRaw: unsigned.RawTx, BuyerTransactionSignature: buyerSig}
	sellerSignsBefore, updatesBefore := f.sellerSigner.signs, f.node.updates
	if _, err := f.seller.AcceptPayment(f.ctx, update); err == nil {
		t.Fatal("expired pool accepted payment")
	}
	if f.sellerSigner.signs != sellerSignsBefore || f.node.updates != updatesBefore {
		t.Fatal("expired payment reached signer or backend")
	}
	if _, err := f.seller.BuildArbitrationRequestFromAuthorization(f.ctx, f.request); err == nil {
		t.Fatal("expired pool built arbitration request")
	}
	if f.sellerSigner.signs != sellerSignsBefore {
		t.Fatal("expired arbitration request reached signer")
	}
	openingCBOR, err := pool.EncodeOpeningProof(opening)
	if err != nil {
		t.Fatal(err)
	}
	authCBOR, err := bitfs.EncodeSignedContentRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	badCandidate := []byte{1}
	authDigest := sha256.Sum256(authCBOR)
	candidateDigest := sha256.Sum256(badCandidate)
	arbRequest := &arbitration.ArbitrationRequest{Version: arbitration.MajorVersion, PoolOpeningProofCBOR: openingCBOR, PaymentAuthorizationCBOR: authCBOR, UnsignedStateTxRaw: badCandidate, SellerTransactionSignature: []byte{1}}
	arbResponse := &arbitration.ArbitrationResponse{Version: arbitration.MajorVersion, PaymentAuthorizationHash: authDigest[:], UnsignedStateTxHash: candidateDigest[:], ArbiterTransactionSignature: []byte{1}}
	if _, err := f.seller.SubmitArbitratedPayment(f.ctx, arbRequest, arbResponse); err == nil {
		t.Fatal("expired pool submitted arbitration payment")
	}
	closeUnsigned, err := f.node.engine.BuildImmediateClose(f.ctx, pool.CloseInput{Opening: opening, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	closeBuyer, err := pool.NewBuyerPoolAdapter(f.node.engine, integrationSigner{f.buyerKey}).SignBuyerPayment(f.ctx, closeUnsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	closeSeller, err := pool.NewSellerPoolAdapter(f.node.engine, integrationSigner{f.sellerKey}).SignSellerPayment(f.ctx, closeUnsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	close, err := f.node.engine.MergeBuyerSellerPayment(closeUnsigned, closeBuyer, closeSeller, opening)
	if err != nil {
		t.Fatal(err)
	}
	sellerSignsBefore = f.sellerSigner.signs
	if _, err := f.seller.SignImmediateClose(f.ctx, closeUnsigned, closeBuyer); err == nil {
		t.Fatal("expired pool signed immediate close")
	}
	if f.sellerSigner.signs != sellerSignsBefore {
		t.Fatal("expired immediate close reached seller signer")
	}
	finalsBefore := f.node.finals
	if _, err := f.buyer.SubmitImmediateClose(f.ctx, close); err == nil {
		t.Fatal("expired pool submitted immediate close")
	}
	if f.node.finals != finalsBefore {
		t.Fatal("expired immediate close reached backend")
	}
}

func TestCloseIssuedBusinessGuardPersistsAcrossFileStoreRestart(t *testing.T) {
	f := newProtocolFixture(t)
	path := filepath.Join(t.TempDir(), "close-issued.json")
	fileStore, err := pool.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.poolStore.LoadOpeningProof(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.poolStore.LoadAcceptedPayment(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	if err := fileStore.SaveOpeningProof(f.ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := fileStore.SaveAcceptedPayment(f.ctx, state); err != nil {
		t.Fatal(err)
	}
	f.node.store = fileStore
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{f.buyerKey}, Quotes: f.quotes, Pools: fileStore, Backend: f.node, SeedSource: f.content})
	if err != nil {
		t.Fatal(err)
	}
	// Prepare a valid but unsubmitted 005 update before issuing the close. It
	// must remain rejected after the close marker is reloaded.
	engine := f.node.engine
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(f.ctx, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	updateUnsigned, err := engine.BuildPaymentUpdate(f.ctx, pool.PaymentUpdateInput{Opening: proof, Previous: initial, PaymentSequenceAfter: initial.PaymentSequence + 1, SellerAmountAfterSat: initial.SellerAmountSat + 1})
	if err != nil {
		t.Fatal(err)
	}
	updateBuyerSig, err := pool.NewBuyerPoolAdapter(engine, integrationSigner{f.buyerKey}).SignBuyerPayment(f.ctx, updateUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(f.request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	update := &pool.PaymentUpdate{Version: pool.MajorVersion, PaymentAuthorizationHash: authHash[:], UnsignedStateTxRaw: updateUnsigned.RawTx, BuyerTransactionSignature: updateBuyerSig}
	unsigned, closeBuyerSig, err := buyerWorkflow.BuildImmediateClose(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := pool.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	f.node.store = reloaded
	seedBefore, blockBefore := *f.seedLoads, *f.blockLoads
	buyerRestarted, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{f.buyerKey}, Quotes: f.quotes, Pools: reloaded, Backend: f.node, SeedSource: f.content})
	if err != nil {
		t.Fatal(err)
	}
	sellerRestarted, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: f.sellerSigner, Quotes: f.quotes, Pools: reloaded, Pending: reloaded, Content: f.content, Backend: f.node})
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), f.content.payloads[f.contentHash]...)
	delivery, err := bitfs.NewSignedContentDelivery(f.request, payload, func(raw []byte) ([]byte, error) {
		digest := sha256.Sum256(raw)
		sig, signErr := f.sellerKey.Sign(digest[:])
		if signErr != nil {
			return nil, signErr
		}
		return sig.Serialize(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buyerRestarted.RequestContent(f.ctx, buyer.ContentRequestInput{QuoteTermsHash: f.quoteHash, SpendTxID: f.spend, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: f.contentHash.Bytes()}, ContentSize: 15, DeliveryDeadline: bitfs.UnixSeconds(time.Now().Unix() + 100)}); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted request error=%v", err)
	}
	sellerSignsBefore := f.sellerSigner.signs
	if _, err := sellerRestarted.DeliverRequestedContent(f.ctx, f.request); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted delivery error=%v", err)
	}
	if f.sellerSigner.signs != sellerSignsBefore || *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatal("restarted delivery caused side effects")
	}
	updatesBefore := f.node.updates
	if _, err := sellerRestarted.AcceptPayment(f.ctx, update); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted payment acceptance error=%v", err)
	}
	if f.sellerSigner.signs != sellerSignsBefore || f.node.updates != updatesBefore {
		t.Fatal("restarted payment acceptance caused signer or backend side effects")
	}
	if _, err := buyerRestarted.AcceptDelivery(f.ctx, f.request, delivery); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted acceptance error=%v", err)
	}
	if *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatal("restarted acceptance loaded content")
	}
	if _, err := sellerRestarted.BuildArbitrationRequestFromAuthorization(f.ctx, f.request); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted arbitration build error=%v", err)
	}
	opening, err := reloaded.LoadOpeningProof(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	openingCBOR, err := pool.EncodeOpeningProof(opening)
	if err != nil {
		t.Fatal(err)
	}
	authCBOR, err := bitfs.EncodeSignedContentRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	authDigest := sha256.Sum256(authCBOR)
	badCandidate := []byte{1}
	candidateDigest := sha256.Sum256(badCandidate)
	arbRequest := &arbitration.ArbitrationRequest{Version: arbitration.MajorVersion, PoolOpeningProofCBOR: openingCBOR, PaymentAuthorizationCBOR: authCBOR, UnsignedStateTxRaw: badCandidate, SellerTransactionSignature: []byte{1}}
	arbResponse := &arbitration.ArbitrationResponse{Version: arbitration.MajorVersion, PaymentAuthorizationHash: authDigest[:], UnsignedStateTxHash: candidateDigest[:], ArbiterTransactionSignature: []byte{1}}
	updatesBefore, finalsBefore := f.node.updates, f.node.finals
	if _, err := sellerRestarted.SubmitArbitratedPayment(f.ctx, arbRequest, arbResponse); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted arbitration submit error=%v", err)
	}
	if f.node.updates != updatesBefore || f.node.finals != finalsBefore {
		t.Fatal("restarted arbitration reached backend")
	}
	if _, _, err := buyerRestarted.BuildImmediateClose(f.ctx, f.spend); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("restarted close rebuild error=%v", err)
	}
	if *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatal("restarted close guard caused content I/O")
	}
	// Completing an already-issued close is the one permitted close-path
	// operation: SignImmediateClose uses health (not open) and final submission
	// clears the durable closing marker after saving the final state.
	signedClose, err := sellerRestarted.SignImmediateClose(f.ctx, unsigned, closeBuyerSig)
	if err != nil {
		t.Fatalf("seller completion of issued close failed: %v", err)
	}
	finalsBefore = f.node.finals
	finalTxID, err := buyerRestarted.SubmitImmediateClose(f.ctx, signedClose)
	if err != nil {
		t.Fatalf("final close submission failed: %v", err)
	}
	if f.node.finals != finalsBefore+1 {
		t.Fatalf("final backend calls = %d, want %d", f.node.finals, finalsBefore+1)
	}
	finalStore, err := pool.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	finalState, err := finalStore.LoadAcceptedPayment(f.ctx, f.spend)
	if err != nil || finalState == nil || finalState.PaymentSequence != ^uint32(0) || !bytes.Equal(finalState.RawTx, signedClose.RawTx) {
		t.Fatalf("reloaded final state = %#v, err=%v", finalState, err)
	}
	if err := finalStore.EnsurePoolOpen(f.ctx, f.spend); err != nil {
		t.Fatalf("closing marker was not cleared: %v", err)
	}
	if err := finalStore.MarkPoolClosing(f.ctx, f.spend); err != nil {
		t.Fatal(err)
	}
	if err := finalStore.EnsurePoolOpen(f.ctx, f.spend); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("reissued closing marker was not enforced: %v", err)
	}
	if err := finalStore.MarkExternalStateUncertain(f.ctx, f.spend, finalTxID); err != nil {
		t.Fatal(err)
	}
	if err := finalStore.EnsurePoolHealthy(f.ctx, f.spend); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("final uncertainty gate = %v", err)
	}
	if err := finalStore.ReconcileExternalState(f.ctx, f.spend, finalState); err != nil {
		t.Fatalf("final reconciliation failed: %v", err)
	}
	if err := finalStore.EnsurePoolOpen(f.ctx, f.spend); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("closing guard was cleared by external reconciliation: %v", err)
	}
	if err := finalStore.ReconcilePoolClosing(f.ctx, f.spend); err != nil {
		t.Fatal(err)
	}
	if err := finalStore.EnsurePoolOpen(f.ctx, f.spend); err != nil {
		t.Fatalf("reconciled final pool did not reopen: %v", err)
	}
	f.node.store = finalStore
	finalBuyer, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{f.buyerKey}, Quotes: f.quotes, Pools: finalStore, Backend: f.node, SeedSource: f.content})
	if err != nil {
		t.Fatal(err)
	}
	seedBefore, blockBefore = *f.seedLoads, *f.blockLoads
	if _, err := finalBuyer.RequestContent(f.ctx, buyer.ContentRequestInput{QuoteTermsHash: f.quoteHash, SpendTxID: f.spend, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: f.contentHash.Bytes()}, ContentSize: 15, DeliveryDeadline: bitfs.UnixSeconds(time.Now().Unix() + 100)}); err == nil {
		t.Fatal("final cryptographic state accepted a new content request")
	}
	if *f.seedLoads != seedBefore || *f.blockLoads != blockBefore {
		t.Fatal("final cryptographic state caused content I/O")
	}
}

func TestSubmitImmediateCloseRetryAfterClosingReconcileFailureDoesNotResubmit(t *testing.T) {
	f := newProtocolFixture(t)
	store := &failOnceClosingStore{PoolStore: f.poolStore, failReconcile: true}
	workflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{f.buyerKey}, Quotes: f.quotes, Pools: store, Backend: f.node, SeedSource: f.content})
	if err != nil {
		t.Fatal(err)
	}
	unsigned, buyerSig, err := workflow.BuildImmediateClose(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	close, err := sellerSignCloseForTest(f, unsigned, buyerSig)
	if err != nil {
		t.Fatal(err)
	}
	finalsBefore := f.node.finals
	if _, err := workflow.SubmitImmediateClose(f.ctx, close); err == nil {
		t.Fatal("first close unexpectedly ignored reconciliation failure")
	}
	if f.node.finals != finalsBefore+1 {
		t.Fatalf("first final backend calls = %d, want %d", f.node.finals-finalsBefore, 1)
	}
	if _, err := workflow.SubmitImmediateClose(f.ctx, close); err != nil {
		t.Fatalf("idempotent close retry failed: %v", err)
	}
	if f.node.finals != finalsBefore+1 || store.reconciles != 2 {
		t.Fatalf("retry resubmitted or skipped reconcile: finals=%d reconciles=%d", f.node.finals-finalsBefore, store.reconciles)
	}
	bad := pool.CloneSignedPayment(close)
	bad.State.SellerAmountSat++
	if _, err := workflow.SubmitImmediateClose(f.ctx, bad); err == nil {
		t.Fatal("different final metadata was accepted as an idempotent retry")
	}
	if f.node.finals != finalsBefore+1 {
		t.Fatal("different final metadata reached backend")
	}
	badRaw := pool.CloneSignedPayment(close)
	badRaw.RawTx = append([]byte(nil), badRaw.RawTx...)
	badRaw.RawTx[0] ^= 1
	if _, err := workflow.SubmitImmediateClose(f.ctx, badRaw); err == nil {
		t.Fatal("different final raw transaction was accepted as an idempotent retry")
	}
	if f.node.finals != finalsBefore+1 {
		t.Fatal("different final raw transaction reached backend")
	}
}

func TestSubmitImmediateCloseExpiredCleanupRetryDoesNotResubmit(t *testing.T) {
	f := newProtocolFixtureAt(t, uint32(time.Now().Unix()-1))
	opening, err := f.poolStore.LoadOpeningProof(f.ctx, f.spend)
	if err != nil {
		t.Fatal(err)
	}
	engine := f.node.engine
	initialRaw, err := engine.BuildRefundSubmission(opening)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(f.ctx, initialRaw, opening)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(f.ctx, pool.CloseInput{Opening: opening, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(engine, integrationSigner{f.buyerKey}).SignBuyerPayment(f.ctx, unsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, integrationSigner{f.sellerKey}).SignSellerPayment(f.ctx, unsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	close, err := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, opening)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.poolStore.SaveAcceptedPayment(f.ctx, &close.State); err != nil {
		t.Fatal(err)
	}
	if err := f.poolStore.MarkPoolClosing(f.ctx, f.spend); err != nil {
		t.Fatal(err)
	}
	workflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{f.buyerKey}, Quotes: f.quotes, Pools: f.poolStore, Backend: f.node, SeedSource: f.content})
	if err != nil {
		t.Fatal(err)
	}
	finalsBefore := f.node.finals
	if _, err := workflow.SubmitImmediateClose(f.ctx, close); err != nil {
		t.Fatalf("expired cleanup-only retry failed: %v", err)
	}
	if f.node.finals != finalsBefore {
		t.Fatalf("expired cleanup retry called backend %d times", f.node.finals-finalsBefore)
	}
	if err := f.poolStore.EnsurePoolOpen(f.ctx, f.spend); err != nil {
		t.Fatalf("cleanup-only retry did not clear closing: %v", err)
	}
	bad := pool.CloneSignedPayment(close)
	bad.State.SellerAmountSat++
	if _, err := workflow.SubmitImmediateClose(f.ctx, bad); err == nil {
		t.Fatal("mismatched stored final was accepted after expiry")
	}
	if f.node.finals != finalsBefore {
		t.Fatal("mismatched expired final reached backend")
	}
}

func sellerSignCloseForTest(f *protocolFixture, unsigned *pool.UnsignedPayment, buyerSig []byte) (*pool.SignedPayment, error) {
	opening, err := f.poolStore.LoadOpeningProof(f.ctx, f.spend)
	if err != nil {
		return nil, err
	}
	return pool.NewSellerPoolAdapter(f.node.engine, integrationSigner{f.sellerKey}).SignImmediateClose(f.ctx, unsigned, buyerSig, opening)
}

func (store *failOncePoolStore) LoadOpeningProofByFundingTxID(ctx context.Context, fundingTxID pool.Hash32) (*pool.OpeningProof, error) {
	proof, err := store.PoolStore.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil || proof == nil || !store.forgedAnchor {
		return proof, err
	}
	forged := pool.CloneOpeningProof(proof)
	forged.SpendTxID[0] ^= 0xff
	return forged, nil
}

func (store *failOncePoolStore) SaveAcceptedPayment(ctx context.Context, state *pool.PaymentState) error {
	store.saveAcceptedCalls++
	if store.failAccepted {
		store.failAccepted = false
		store.failedState = pool.ClonePaymentState(state)
		return errors.New("injected initial-state persistence failure")
	}
	if store.uncertain {
		return errors.New("ordinary SaveAcceptedPayment is forbidden while uncertain")
	}
	return store.PoolStore.SaveAcceptedPayment(ctx, state)
}

func (store *failOncePoolStore) MarkExternalStateUncertain(ctx context.Context, spendTxID, txID pool.Hash32) error {
	store.uncertain = true
	return store.PoolStore.MarkExternalStateUncertain(ctx, spendTxID, txID)
}

func (store *failOncePoolStore) ReconcileExternalState(ctx context.Context, spendTxID pool.Hash32, state *pool.PaymentState) error {
	store.reconcileCalls++
	err := store.PoolStore.ReconcileExternalState(ctx, spendTxID, state)
	if err == nil {
		store.uncertain = false
	}
	return err
}

func (store *recordingPoolStore) SaveOpeningProof(ctx context.Context, proof *pool.OpeningProof) error {
	if store.firstOpening == nil {
		store.firstOpening = pool.CloneOpeningProof(proof)
	}
	return store.PoolStore.SaveOpeningProof(ctx, proof)
}

func (n *integrationNode) SubmitUpdate(ctx context.Context, raw []byte) (*pool.UpdateAcceptance, error) {
	fundingID, err := n.engine.FundingTxID(raw)
	if err != nil {
		return nil, err
	}
	proof, err := n.store.LoadOpeningProofByFundingTxID(ctx, fundingID)
	if err != nil || proof == nil {
		return nil, fmt.Errorf("opening lookup: %w", err)
	}
	state, err := n.engine.ParsePaymentState(ctx, raw, proof)
	if err != nil {
		return nil, err
	}
	if err := n.engine.VerifyAcceptedPayment(state, proof); err != nil {
		if arbitrationErr := n.engine.VerifyArbitratedPayment(state, proof); arbitrationErr != nil {
			return nil, err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if old := n.accepted[state.SpendTxID]; old != nil && state.PaymentSequence <= old.PaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	n.accepted[state.SpendTxID] = cloneIntegrationPayment(state)
	n.updates++
	txID, err := n.engine.TransactionID(raw)
	if err != nil {
		return nil, err
	}
	return &pool.UpdateAcceptance{TxID: txID, SpendTxID: state.SpendTxID, PaymentSequence: state.PaymentSequence}, nil
}

func (n *integrationNode) SubmitFinal(_ context.Context, raw []byte) (pool.Hash32, error) {
	n.finals++
	return n.engine.TransactionID(raw)
}

func (n *integrationNode) SubmitTransaction(_ context.Context, raw []byte) (pool.Hash32, error) {
	n.fundings++
	return n.engine.TransactionID(raw)
}

func TestCanonicalNormalPaymentAndSellerArbitration(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	buyerKey := integrationPrivateKey(t, 21)
	sellerKey := integrationPrivateKey(t, 22)
	arbiterKey := integrationPrivateKey(t, 23)
	buyerSigner := integrationSigner{buyerKey}
	sellerSigner := integrationSigner{sellerKey}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{
		BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	baseStore, err := pool.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingPoolStore{PoolStore: baseStore, PendingRequestStore: baseStore}
	node := &integrationNode{engine: engine, store: store, accepted: make(map[pool.Hash32]*pool.PaymentState)}
	quotes := &integrationQuoteStore{}
	payload := []byte("abc")
	payloadHash := masterseed.Sum256(payload)
	var seedBytes []byte
	var seedOutput bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(payload), &seedOutput); err != nil {
		t.Fatal(err)
	}
	seedBytes = seedOutput.Bytes()
	seedHash := masterseed.Sum256(seedBytes)
	seedLoads, blockLoads := 0, 0
	content := integrationContent{payloads: map[masterseed.Digest][]byte{payloadHash: payload, seedHash: seedBytes}, seedLoads: &seedLoads, blockLoads: &blockLoads}
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{
		Signer: sellerSigner, Quotes: quotes, Pools: store, Pending: store, Content: content, Backend: node,
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
		Signer: buyerSigner, Quotes: quotes, Pools: store, Backend: node, SeedSource: content,
	})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := sellerWorkflow.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPubkey: buyerKey.PubKey().Compressed(), SeedPriceSat: 5, FullBlockPriceSat: 100, FileSize: uint64(len(payload)), QuoteExpiresAtUnix: now.Unix() + 1000, SupportedArbiterPubkeysCBOR: arbiters}, "file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buyerWorkflow.AcceptQuote(ctx, quote); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	openingRequest, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: uint32(now.Unix() + 100), MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	openingResponse, err := sellerWorkflow.PresignPoolOpening(ctx, openingRequest)
	if err != nil {
		t.Fatal(err)
	}
	if store.firstOpening == nil || len(store.firstOpening.SpendTxID) != 32 {
		t.Fatalf("presign saved proof without a complete SpendTxID: %#v", store.firstOpening)
	}
	expectedSpend, err := engine.TransactionID(openingRequest.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(store.firstOpening.SpendTxID, expectedSpend[:]) {
		t.Fatalf("presign SpendTxID = %x, want %x", store.firstOpening.SpendTxID, expectedSpend)
	}
	reference, err := buyerWorkflow.AcceptRefundPresign(ctx, openingRequest, openingResponse, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatal(err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	beforeSizeCheck, err := store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
		QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: reference.SpendTxID,
		Content:     bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()},
		ContentSize: uint64(len(payload) + 1), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
	})
	if err == nil || !errors.Is(err, bitfs.ErrInvalidEvidence) {
		t.Fatalf("buyer accepted an invalid content size: %v", err)
	}
	afterSizeCheck, err := store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	if beforeSizeCheck == nil || afterSizeCheck == nil || beforeSizeCheck.PaymentSequence != afterSizeCheck.PaymentSequence || beforeSizeCheck.SellerAmountSat != afterSizeCheck.SellerAmountSat {
		t.Fatalf("invalid content-size request changed pool state: before=%+v after=%+v", beforeSizeCheck, afterSizeCheck)
	}
	badSeedWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
		Signer: buyerSigner, Quotes: quotes, Pools: store, Backend: node,
		SeedSource: badSeedSource{raw: seedBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = badSeedWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
		QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: reference.SpendTxID,
		Content:     bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()},
		ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
	})
	if err == nil || (!errors.Is(err, bitfs.ErrInvalidEvidence) && !errors.Is(err, pool.ErrInvalidEvidence)) || (masterseed.CodeOf(err) != masterseed.SeedHashMismatch && !errors.Is(err, pool.ErrInvalidEvidence)) {
		t.Fatalf("buyer trusted an invalid loaded seed: code=%q err=%v", masterseed.CodeOf(err), err)
	}
	request, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: reference.SpendTxID, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	seedLoadsBeforeInvalid, blockLoadsBeforeInvalid := seedLoads, blockLoads
	invalidRequest := bitfs.CloneSignedContentRequest(request)
	invalidRequest.BuyerSignature = []byte{0x00}
	if _, err := sellerWorkflow.DeliverRequestedContent(ctx, invalidRequest); err == nil || !errors.Is(err, bitfs.ErrInvalidEvidence) {
		t.Fatalf("seller accepted invalidly signed request: %v", err)
	}
	if seedLoads != seedLoadsBeforeInvalid || blockLoads != blockLoadsBeforeInvalid {
		t.Fatalf("invalid request caused content I/O: seed=%d->%d block=%d->%d", seedLoadsBeforeInvalid, seedLoads, blockLoadsBeforeInvalid, blockLoads)
	}
	seedRequest, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
		QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: reference.SpendTxID,
		Content:     bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: seedHash.Bytes()},
		ContentSize: 1, DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
	})
	if err != nil {
		t.Fatalf("build seed request: %v", err)
	}
	seedLoadsBeforeDelivery, blockLoadsBeforeDelivery := seedLoads, blockLoads
	if _, err := sellerWorkflow.DeliverRequestedContent(ctx, seedRequest); err != nil {
		t.Fatalf("deliver seed request: %v", err)
	}
	if seedLoads != seedLoadsBeforeDelivery+1 || blockLoads != blockLoadsBeforeDelivery {
		t.Fatalf("seed request routed to wrong content loader: seed=%d->%d block=%d->%d", seedLoadsBeforeDelivery, seedLoads, blockLoadsBeforeDelivery, blockLoads)
	}
	authorizationHash, err := bitfs.PaymentAuthorizationHash(seedRequest.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	var pendingHash pool.Hash32
	copy(pendingHash[:], authorizationHash[:])
	if err := store.Release(ctx, reference.SpendTxID, pendingHash); err != nil {
		t.Fatalf("release seed test pending request: %v", err)
	}
	delivery, err := sellerWorkflow.DeliverRequestedContent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	update, err := buyerWorkflow.AcceptDelivery(ctx, request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sellerWorkflow.AcceptPayment(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.PaymentSequence != 3 || accepted.SellerAmountSat == 0 || node.updates != 1 {
		t.Fatalf("normal payment = %+v, updates=%d", accepted, node.updates)
	}
	if _, err := buyerWorkflow.RefundAfterExpiry(ctx, reference.SpendTxID); !errors.Is(err, pool.ErrNonFinalRejected) && !errors.Is(err, pool.ErrNotExpired) {
		t.Fatalf("refund after sequence-3 payment error = %v, want a rejected refund", err)
	}
	if _, err := sellerWorkflow.AcceptPayment(ctx, update); err != nil {
		t.Fatalf("idempotent payment retry failed: %v", err)
	}
	if node.updates != 1 {
		t.Fatalf("idempotent retry submitted another update: %d", node.updates)
	}

	latest, err := store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	request2, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), SpendTxID: reference.SpendTxID, Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.DeliverRequestedContent(ctx, request2); err != nil {
		t.Fatal(err)
	}
	arbitrationWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{Signer: integrationSigner{arbiterKey}})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequestFromAuthorization(ctx, request2)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationResponse, err := arbitrationWorkflow.SignPayment(ctx, arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := sellerWorkflow.SubmitArbitratedPayment(ctx, arbitrationRequest, arbitrationResponse)
	if err != nil {
		t.Fatal(err)
	}
	if arbitrated.PaymentSequence != latest.PaymentSequence+1 || node.updates != 2 {
		t.Fatalf("arbitrated payment = %+v, updates=%d", arbitrated, node.updates)
	}
	if pending, err := store.Load(ctx, reference.SpendTxID); err != nil {
		t.Fatalf("load pending request after arbitration: %v", err)
	} else if pending != nil {
		t.Fatalf("pending request remained after arbitration: %+v", pending)
	}
	closeUnsigned, closeBuyerSig, err := buyerWorkflow.BuildImmediateClose(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatalf("build immediate close: %v", err)
	}
	closed, err := sellerWorkflow.SignImmediateClose(ctx, closeUnsigned, closeBuyerSig)
	if err != nil {
		t.Fatalf("seller sign immediate close: %v", err)
	}
	if _, err := buyerWorkflow.SubmitImmediateClose(ctx, closed); err != nil {
		t.Fatalf("submit immediate close: %v", err)
	}
	if closed.State.PaymentSequence != ^uint32(0) {
		t.Fatalf("close sequence = %d, want final", closed.State.PaymentSequence)
	}
	closedTxID, err := engine.TransactionID(closed.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExternalStateUncertain(ctx, reference.SpendTxID, closedTxID); err != nil {
		t.Fatal(err)
	}
	guardedBuyerSigner := &countingSigner{key: buyerKey}
	guardedSellerSigner := &countingSigner{key: sellerKey}
	guardedBuyer, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: guardedBuyerSigner, Quotes: quotes, Pools: store, Backend: node})
	if err != nil {
		t.Fatal(err)
	}
	guardedSeller, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: guardedSellerSigner, Quotes: quotes, Pools: store, Pending: store, Content: content, Backend: node})
	if err != nil {
		t.Fatal(err)
	}
	updatesBefore, finalsBefore := node.updates, node.finals
	if _, _, err := guardedBuyer.BuildImmediateClose(ctx, reference.SpendTxID); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("uncertain BuildImmediateClose() error = %v, want ErrPoolStateUncertain", err)
	}
	if _, err := guardedSeller.SignImmediateClose(ctx, closeUnsigned, closeBuyerSig); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("uncertain SignImmediateClose() error = %v, want ErrPoolStateUncertain", err)
	}
	if _, err := guardedSeller.BuildArbitrationRequestFromAuthorization(ctx, request2); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("uncertain BuildArbitrationRequest() error = %v, want ErrPoolStateUncertain", err)
	}
	if _, err := guardedBuyer.SubmitImmediateClose(ctx, closed); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("uncertain SubmitImmediateClose() error = %v, want ErrPoolStateUncertain", err)
	}
	if guardedBuyerSigner.signs != 0 || guardedSellerSigner.signs != 0 {
		t.Fatalf("uncertain workflows invoked signers: buyer=%d seller=%d", guardedBuyerSigner.signs, guardedSellerSigner.signs)
	}
	if node.updates != updatesBefore || node.finals != finalsBefore {
		t.Fatalf("uncertain workflows reached backend: updates=%d->%d finals=%d->%d", updatesBefore, node.updates, finalsBefore, node.finals)
	}
}

func TestFundingPersistenceFailureCanBeReconciled(t *testing.T) {
	ctx := context.Background()
	buyerKey := integrationPrivateKey(t, 41)
	sellerKey := integrationPrivateKey(t, 42)
	arbiterKey := integrationPrivateKey(t, 43)
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	baseStore, err := pool.NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	store := &failOncePoolStore{PoolStore: baseStore, PendingRequestStore: baseStore}
	node := &integrationNode{engine: engine, store: store, accepted: make(map[pool.Hash32]*pool.PaymentState)}
	quotes := &integrationQuoteStore{}
	content := integrationContent{}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: integrationSigner{sellerKey}, Quotes: quotes, Pools: store, Pending: store, Content: content, Backend: node})
	if err != nil {
		t.Fatal(err)
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: integrationSigner{buyerKey}, Quotes: quotes, Pools: store, Backend: node})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	funding.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	request, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: uint32(time.Now().Unix() + 100), MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := sellerWorkflow.PresignPoolOpening(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := buyerWorkflow.AcceptRefundPresign(ctx, request, response, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	store.saveAcceptedCalls = 0
	store.failAccepted = true
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("first AcceptPoolFunding() error = %v, want ErrPoolStateUncertain", err)
	}
	if store.failedState == nil {
		t.Fatal("failed initial payment state was not captured")
	}
	if err := store.EnsurePoolHealthy(ctx, reference.SpendTxID); !errors.Is(err, pool.ErrPoolStateUncertain) {
		t.Fatalf("EnsurePoolHealthy() = %v, want uncertainty", err)
	}
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatalf("reconciled AcceptPoolFunding() error = %v", err)
	}
	if err := store.EnsurePoolHealthy(ctx, reference.SpendTxID); err != nil {
		t.Fatalf("EnsurePoolHealthy() after reconciliation = %v", err)
	}
	state, err := store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil || state == nil || !bytes.Equal(state.RawTx, store.failedState.RawTx) {
		t.Fatalf("reconciled initial state = %#v, err = %v", state, err)
	}
	if node.fundings != 2 {
		t.Fatalf("funding backend calls = %d, want idempotent retry count 2", node.fundings)
	}
	if store.saveAcceptedCalls != 1 {
		t.Fatalf("ordinary SaveAcceptedPayment calls = %d, want only failed first attempt", store.saveAcceptedCalls)
	}
	if store.reconcileCalls != 1 {
		t.Fatalf("ReconcileExternalState calls = %d, want one retry reconciliation", store.reconcileCalls)
	}
	store.forgedAnchor = true
	previousFundings := node.fundings
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); !errors.Is(err, pool.ErrInvalidEvidence) {
		t.Fatalf("AcceptPoolFunding() with forged SpendTxID = %v, want ErrInvalidEvidence", err)
	}
	if node.fundings != previousFundings {
		t.Fatalf("forged SpendTxID reached funding backend: before=%d after=%d", previousFundings, node.fundings)
	}
}

func integrationPrivateKey(t *testing.T, value byte) *ec.PrivateKey {
	t.Helper()
	privateKey, err := ec.PrivateKeyFromHex(fmt.Sprintf("%064x", value))
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func cloneIntegrationQuote(quote *bitfs.SignedFileQuote) *bitfs.SignedFileQuote {
	if quote == nil {
		return nil
	}
	return &bitfs.SignedFileQuote{TermsCBOR: append([]byte(nil), quote.TermsCBOR...), SellerPubkey: append([]byte(nil), quote.SellerPubkey...), TermsSignature: append([]byte(nil), quote.TermsSignature...), RecommendedFilename: quote.RecommendedFilename}
}

func cloneIntegrationPayment(state *pool.PaymentState) *pool.PaymentState {
	if state == nil {
		return nil
	}
	copy := *state
	copy.RawTx = append([]byte(nil), state.RawTx...)
	copy.PoolLockingScript = append([]byte(nil), state.PoolLockingScript...)
	return &copy
}
