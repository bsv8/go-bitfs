package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv8/go-bitfs/arbiter"
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

type integrationContent struct{ payloads map[bitfs.Hash32][]byte }

func (s integrationContent) LoadContent(_ context.Context, hash bitfs.Hash32) ([]byte, error) {
	payload := s.payloads[hash]
	if payload == nil {
		return nil, fmt.Errorf("content not found")
	}
	return append([]byte(nil), payload...), nil
}

func (s integrationContent) LoadSeed(ctx context.Context, hash bitfs.Hash32) ([]byte, error) {
	return s.LoadContent(ctx, hash)
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
	payloadHash := sha256.Sum256(payload)
	seed, err := bitfs.BuildSeedBytes([][]byte{payloadHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	seedHash := bitfs.SeedHash(seed)
	content := integrationContent{payloads: map[bitfs.Hash32][]byte{bitfs.Hash32(payloadHash): payload, bitfs.Hash32(seedHash): seed}}
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	service, err := seller.NewService(seller.ServiceConfig{
		Signer: sellerSigner, SignatureVerifier: verifyIntegrationSignature, QuoteVerifier: verifyIntegrationSignature, Clock: clock,
		Quotes: quotes, Pools: store, OpeningHooks: sellerOpeningPort, Pending: store, Content: content, Transactions: sellerPool, Participants: engine, Node: verifiedNode,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := buyer.NewClient(buyer.ClientConfig{
		Signer: buyerSigner, QuoteVerifier: verifyIntegrationSignature, SignatureVerifier: verifyIntegrationSignature, Clock: clock,
		Quotes: quotes, Pools: store, Opening: openingPort, Participants: engine, Node: verifiedNode, Transactions: buyerPool, SeedSource: content,
	})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := service.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: seedHash[:], BuyerPubkey: buyerKey.PubKey().Compressed(), SeedPriceSat: 5, FullBlockPriceSat: 100, FileSize: uint64(len(payload)), QuoteExpiresAtUnix: now.Unix() + 1000, SupportedArbiterPubkeysCBOR: arbiters}, "file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AcceptQuote(ctx, quote); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Build2of3LockingScript([][]byte{sellerKey.PubKey().Compressed(), buyerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed()})
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
	openingRequest, err := client.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500000100, MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	openingResponse, err := service.PresignPoolOpening(ctx, openingRequest)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := client.AcceptRefundPresign(ctx, openingRequest, openingResponse, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatal(err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference, SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(), Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash[:]}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := service.DeliverRequestedContent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	update, err := client.AcceptDelivery(ctx, request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := service.AcceptPayment(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.PaymentSequence != 2 || accepted.SellerAmountSat == 0 || node.updates != 1 {
		t.Fatalf("normal payment = %+v, updates=%d", accepted, node.updates)
	}
	if _, err := service.AcceptPayment(ctx, update); err != nil {
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
	request2, err := client.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: pool.Reference{SpendTxID: reference.SpendTxID, BasePaymentSequence: latest.PaymentSequence}, SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(), Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash[:]}, ContentSize: uint64(len(payload)), DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeliverRequestedContent(ctx, request2); err != nil {
		t.Fatal(err)
	}
	arbiterService, err := arbiter.NewService(arbiter.ServiceConfig{Signer: integrationSigner{arbiterKey}, Pool: &pool.MultisigPoolAdapter{Roles: pool.PoolRoles{Server: sellerKey.PubKey(), A: buyerKey.PubKey(), B: arbiterKey.PubKey()}, BKey: integrationKeyProvider{arbiterKey}}, AuthorizationVerifier: verifyIntegrationSignature})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationRequest, err := service.BuildArbitrationRequestFromAuthorization(ctx, opening, request2, latest)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationResponse, err := arbiterService.SignPayment(ctx, arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := service.SubmitArbitratedPayment(ctx, arbitrationRequest, arbitrationResponse)
	if err != nil {
		t.Fatal(err)
	}
	if arbitrated.PaymentSequence != latest.PaymentSequence+1 || node.updates != 2 {
		t.Fatalf("arbitrated payment = %+v, updates=%d", arbitrated, node.updates)
	}
	closeState, err := client.BuildImmediateClose(ctx, pool.CloseInput{Opening: opening, Latest: arbitrated, SellerAmountAfterSat: arbitrated.SellerAmountSat})
	if err != nil {
		t.Fatalf("build immediate close: %v", err)
	}
	closed, err := service.SignImmediateClose(ctx, closeState)
	if err != nil {
		t.Fatalf("seller sign immediate close: %v", err)
	}
	if _, err := client.SubmitImmediateClose(ctx, closed); err != nil {
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
