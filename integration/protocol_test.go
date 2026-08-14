package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

type integrationKeyProvider struct{ key *ec.PrivateKey }

func (p integrationKeyProvider) PrivateKey(context.Context) (*ec.PrivateKey, error) {
	return p.key, nil
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
	if !sig.Verify(payload, key) {
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
	store    *pool.MemoryStore
	accepted map[pool.Hash32]*pool.PaymentState
	updates  int
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
	return n.engine.TransactionID(raw)
}

func (n *integrationNode) SubmitTransaction(_ context.Context, raw []byte) (pool.Hash32, error) {
	return n.engine.TransactionID(raw)
}

func TestCanonicalNormalPaymentAndSellerArbitration(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
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
	calculator := pool.BSVTransactionIDCalculator{Engine: engine}
	buyerPool := pool.NewBuyerPoolAdapter(engine, integrationKeyProvider{buyerKey})
	sellerPool := pool.NewSellerPoolAdapter(engine, integrationKeyProvider{sellerKey})
	store, err := pool.NewMemoryStore(calculator)
	if err != nil {
		t.Fatal(err)
	}
	node := &integrationNode{engine: engine, store: store, accepted: make(map[pool.Hash32]*pool.PaymentState)}
	verifiedNode, err := pool.NewVerifiedNonFinalPoolNode(engine, store, node)
	if err != nil {
		t.Fatal(err)
	}
	openingPort := pool.BuyerOpeningPort{Store: store, Verifier: engine, Calculator: calculator}
	sellerOpeningPort := pool.SellerOpeningPort{Store: store, RefundSigner: pool.PoolRefundSigner{Adapter: sellerPool}, Calculator: calculator, FundingVerifier: engine, FundingSubmitter: node}
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
		Signer: sellerSigner, SignatureVerifier: verifyIntegrationSignature, QuoteVerifier: verifyIntegrationSignature, Clock: clock,
		Quotes: quotes, Pools: store, OpeningHooks: sellerOpeningPort, Pending: store, Content: content, Transactions: sellerPool, Participants: engine, Node: verifiedNode,
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{
		Signer: buyerSigner, QuoteVerifier: verifyIntegrationSignature, SignatureVerifier: verifyIntegrationSignature, Clock: clock,
		Quotes: quotes, Pools: store, Opening: openingPort, Participants: engine, Node: verifiedNode, Transactions: buyerPool, SeedSource: content,
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
	lock, err := pool.Build2of3LockingScript([][]byte{buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed()})
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
	openingRequest, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500000100, MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	openingResponse, err := sellerWorkflow.PresignPoolOpening(ctx, openingRequest)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := buyerWorkflow.AcceptRefundPresign(ctx, openingRequest, openingResponse, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatal(err)
	}
	if _, err := buyerWorkflow.RefundAfterExpiry(ctx, reference.SpendTxID); err != nil {
		t.Fatalf("initial sequence-2 refund: %v", err)
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
		QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference,
		SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(),
		Content:               bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()},
		ContentSize:           uint64(len(payload) + 1), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
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
		Signer: buyerSigner, QuoteVerifier: verifyIntegrationSignature, SignatureVerifier: verifyIntegrationSignature, Clock: clock,
		Quotes: quotes, Pools: store, Opening: openingPort, Participants: engine, Node: verifiedNode, Transactions: buyerPool,
		SeedSource: badSeedSource{raw: seedBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = badSeedWorkflow.RequestContent(ctx, buyer.ContentRequestInput{
		QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference,
		SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(),
		Content:               bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()},
		ContentSize:           uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
	})
	if err == nil || masterseed.CodeOf(err) != masterseed.SeedHashMismatch || !errors.Is(err, bitfs.ErrInvalidEvidence) {
		t.Fatalf("buyer trusted an invalid loaded seed: code=%q err=%v", masterseed.CodeOf(err), err)
	}
	request, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference, SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(), Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
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
		QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference,
		SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(),
		Content:               bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: seedHash.Bytes()},
		ContentSize:           1, DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100),
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
	if _, err := buyerWorkflow.RefundAfterExpiry(ctx, reference.SpendTxID); !errors.Is(err, pool.ErrNonFinalRejected) {
		t.Fatalf("refund after sequence-3 payment error = %v, want ErrNonFinalRejected", err)
	}
	if _, err := sellerWorkflow.AcceptPayment(ctx, update); err != nil {
		t.Fatalf("idempotent payment retry failed: %v", err)
	}
	if node.updates != 1 {
		t.Fatalf("idempotent retry submitted another update: %d", node.updates)
	}

	opening, err := store.LoadOpeningProof(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	request2, err := buyerWorkflow.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: pool.Reference{SpendTxID: reference.SpendTxID, BasePaymentSequence: latest.PaymentSequence}, SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(), Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash.Bytes()}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerWorkflow.DeliverRequestedContent(ctx, request2); err != nil {
		t.Fatal(err)
	}
	arbitrationWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{Signer: integrationSigner{arbiterKey}, Pool: &pool.MultisigPoolAdapter{Engine: engine, ArbiterKey: integrationKeyProvider{arbiterKey}}, AuthorizationVerifier: verifyIntegrationSignature})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := sellerWorkflow.BuildArbitrationRequestFromAuthorization(ctx, opening, request2, latest)
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
	closeUnsigned, closeBuyerSig, err := buyerWorkflow.BuildImmediateClose(ctx, pool.CloseInput{Opening: opening, Latest: arbitrated, SellerAmountAfterSat: arbitrated.SellerAmountSat})
	if err != nil {
		t.Fatalf("build immediate close: %v", err)
	}
	closed, err := sellerWorkflow.SignImmediateClose(ctx, closeUnsigned, closeBuyerSig, sellerSigner)
	if err != nil {
		t.Fatalf("seller sign immediate close: %v", err)
	}
	if _, err := buyerWorkflow.SubmitImmediateClose(ctx, closed); err != nil {
		t.Fatalf("submit immediate close: %v", err)
	}
	if closed.State.PaymentSequence != ^uint32(0) {
		t.Fatalf("close sequence = %d, want final", closed.State.PaymentSequence)
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
