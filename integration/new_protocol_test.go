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
	bsvtx "github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/buyer"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/bsv8/go-bitfs/seller"
)

type protocolSigner struct{ key *ec.PrivateKey }

func (signer protocolSigner) PublicKey(context.Context) ([]byte, error) {
	return signer.key.PubKey().Compressed(), nil
}

func (signer protocolSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signature, err := signer.key.Sign(payload)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func verifyProtocolSignature(pubkey, payload, signature []byte) error {
	key, err := ec.ParsePubKey(pubkey)
	if err != nil {
		return err
	}
	parsed, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	if !parsed.Verify(payload, key) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

type quoteStore struct {
	quotes map[bitfs.Hash32]*bitfs.SignedFileQuote
}

func (store *quoteStore) SaveQuote(_ context.Context, quote *bitfs.SignedFileQuote) error {
	hash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return err
	}
	if store.quotes == nil {
		store.quotes = make(map[bitfs.Hash32]*bitfs.SignedFileQuote)
	}
	store.quotes[bitfs.Hash32(hash)] = cloneQuoteForTest(quote)
	return nil
}

func (store *quoteStore) LoadQuote(_ context.Context, hash bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	quote := store.quotes[hash]
	if quote == nil {
		return nil, fmt.Errorf("quote not found")
	}
	return cloneQuoteForTest(quote), nil
}

type contentSource struct{ payloads map[bitfs.Hash32][]byte }

func (source contentSource) LoadContent(_ context.Context, hash bitfs.Hash32) ([]byte, error) {
	payload := source.payloads[hash]
	if payload == nil {
		return nil, fmt.Errorf("content not found")
	}
	return append([]byte(nil), payload...), nil
}

func (source contentSource) LoadSeed(ctx context.Context, hash bitfs.Hash32) ([]byte, error) {
	return source.LoadContent(ctx, hash)
}

type protocolNode struct {
	mu       sync.Mutex
	engine   *pool.BSVEngine
	store    *pool.MemoryStore
	accepted map[pool.Hash32]*pool.PaymentState
	updates  int
}

func (node *protocolNode) SubmitUpdate(ctx context.Context, rawTx []byte) (*pool.UpdateAcceptance, error) {
	fundingID, err := node.engine.FundingTxID(rawTx)
	if err != nil {
		return nil, err
	}
	proof, err := node.store.LoadOpeningProofByFundingTxID(ctx, fundingID)
	if err != nil || proof == nil {
		return nil, fmt.Errorf("node opening lookup: %w", err)
	}
	state, err := node.engine.ParsePaymentState(ctx, rawTx, proof)
	if err != nil {
		return nil, err
	}
	if err := node.engine.VerifyAcceptedPayment(state, proof); err != nil {
		return nil, fmt.Errorf("node payment signature/state validation: %w", err)
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	previous := node.accepted[state.SpendTxID]
	if previous != nil && state.PaymentSequence <= previous.PaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	node.updates++
	if node.accepted == nil {
		node.accepted = make(map[pool.Hash32]*pool.PaymentState)
	}
	node.accepted[state.SpendTxID] = cloneNodePaymentState(state)
	txID, err := node.engine.TransactionID(rawTx)
	if err != nil {
		return nil, err
	}
	return &pool.UpdateAcceptance{TxID: txID, SpendTxID: state.SpendTxID, PaymentSequence: state.PaymentSequence}, nil
}

func cloneNodePaymentState(state *pool.PaymentState) *pool.PaymentState {
	if state == nil {
		return nil
	}
	copy := *state
	copy.RawTx = append([]byte(nil), state.RawTx...)
	copy.PoolLockingScript = append([]byte(nil), state.PoolLockingScript...)
	return &copy
}

func (node *protocolNode) SubmitFinal(_ context.Context, rawTx []byte) (pool.Hash32, error) {
	return node.engine.TransactionID(rawTx)
}

func (node *protocolNode) SubmitTransaction(_ context.Context, rawTx []byte) (pool.Hash32, error) {
	return node.engine.TransactionID(rawTx)
}

func TestNewProtocolQuoteContentPaymentAndRetry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	buyerKey, _ := ec.PrivateKeyFromBytes(testKeyBytes(21))
	sellerKey, _ := ec.PrivateKeyFromBytes(testKeyBytes(22))
	arbiterKey, _ := ec.PrivateKeyFromBytes(testKeyBytes(23))
	buyerSigner := protocolSigner{key: buyerKey}
	sellerSigner := protocolSigner{key: sellerKey}
	engine, err := pool.NewBSVEngine(pool.BSVEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	calculator := pool.BSVTransactionIDCalculator{Engine: engine}
	pools, err := pool.NewMemoryStore(calculator)
	if err != nil {
		t.Fatal(err)
	}
	node := &protocolNode{engine: engine, store: pools, accepted: make(map[pool.Hash32]*pool.PaymentState)}
	verifiedNode, err := pool.NewVerifiedNonFinalPoolNode(engine, pools, node)
	if err != nil {
		t.Fatal(err)
	}
	openingPort := pool.BuyerOpeningPort{Store: pools, Verifier: engine, Calculator: calculator}
	sellerOpeningPort := pool.SellerOpeningPort{
		Store:            pools,
		RefundSigner:     pool.BSVRefundSigner{Engine: engine, Signer: sellerSigner},
		Calculator:       calculator,
		FundingVerifier:  engine,
		FundingSubmitter: node,
	}
	quotes := &quoteStore{}
	payload := []byte("abc")
	payloadHash := sha256.Sum256(payload)
	seed, err := bitfs.BuildSeedBytes([][]byte{payloadHash[:]})
	if err != nil {
		t.Fatal(err)
	}
	seedHash := bitfs.SeedHash(seed)
	content := contentSource{payloads: map[bitfs.Hash32][]byte{bitfs.Hash32(payloadHash): payload, bitfs.Hash32(seedHash): seed}}
	terms, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerService, err := seller.NewService(seller.ServiceConfig{
		Signer:            sellerSigner,
		SignatureVerifier: verifyProtocolSignature,
		QuoteVerifier: func(pubkey, payload, signature []byte) error {
			return verifyProtocolSignature(pubkey, payload, signature)
		},
		Clock:        clock,
		Quotes:       quotes,
		Pools:        pools,
		OpeningHooks: sellerOpeningPort,
		Pending:      pools,
		Content:      content,
		Transactions: engine,
		Participants: engine,
		Node:         verifiedNode,
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerClient, err := buyer.NewClient(buyer.ClientConfig{
		Signer: buyerSigner,
		QuoteVerifier: func(pubkey, payload, signature []byte) error {
			return verifyProtocolSignature(pubkey, payload, signature)
		},
		SignatureVerifier: verifyProtocolSignature,
		Clock:             clock,
		Quotes:            quotes,
		Pools:             pools,
		Opening:           openingPort,
		Participants:      engine,
		Node:              verifiedNode,
		Transactions:      engine,
		SeedSource:        content,
	})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := sellerService.CreateQuote(ctx, bitfs.FileQuoteTerms{
		SeedHash:                    seedHash[:],
		BuyerPubkey:                 buyerKey.PubKey().Compressed(),
		SeedPriceSat:                5,
		FullBlockPriceSat:           100,
		FileSize:                    uint64(len(payload)),
		QuoteExpiresAtUnix:          now.Unix() + 1000,
		SupportedArbiterPubkeysCBOR: terms,
	}, "file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buyerClient.AcceptQuote(ctx, quote); err != nil {
		t.Fatal(err)
	}
	lockingScript, err := pool.Build2of3LockingScript([][]byte{buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := bsvtx.NewTransaction()
	zero, _ := chainhash.NewHash(make([]byte, 32))
	funding.AddInput(&bsvtx.TransactionInput{SourceTXID: zero, SequenceNumber: bsvtx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&bsvtx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lockingScript)})
	requestToSign, err := buyerClient.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500000100, RefundMinerFeeSat: 100, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := sellerService.PresignPoolOpening(ctx, requestToSign)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := buyerClient.AcceptRefundPresign(ctx, requestToSign, response, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerService.AcceptPoolFunding(ctx, &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: funding.Bytes()}); err != nil {
		t.Fatal(err)
	}
	quoteHash, _ := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	request, err := buyerClient.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: bitfs.Hash32(quoteHash), Pool: *reference, SelectedArbiterPubKey: arbiterKey.PubKey().Compressed(), Content: bitfs.ContentRef{Type: bitfs.ContentBlock, Hash: payloadHash[:]}, DeliveryDeadline: bitfs.UnixSeconds(now.Unix() + 100)})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := sellerService.DeliverRequestedContent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	openingForUnderpayment, err := pools.LoadOpeningProof(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	previousForUnderpayment, err := pools.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, bitfs.ContentBlock, uint64(len(payload)))
	if err != nil || price == 0 {
		t.Fatalf("unexpected test content price: %d, %v", price, err)
	}
	underpaymentUnsigned, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{
		Opening:              openingForUnderpayment,
		Previous:             previousForUnderpayment,
		PaymentSequenceAfter: previousForUnderpayment.PaymentSequence + 1,
		SellerAmountAfterSat: previousForUnderpayment.SellerAmountSat + price - 1,
		MinerFeeSat:          100,
	})
	if err != nil {
		t.Fatal(err)
	}
	underpaymentState, err := engine.SignBuyerPayment(ctx, underpaymentUnsigned, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	underpaymentUpdate := &pool.PaymentUpdate{Version: pool.MajorVersion, ContentRequestTermsHash: requestHashForTest(t, request), PartialSpendTx: underpaymentState.RawTx}
	if _, err := sellerService.AcceptPayment(ctx, underpaymentUpdate); err == nil {
		t.Fatal("seller accepted a buyer-signed underpayment")
	}
	update, err := buyerClient.AcceptDelivery(ctx, request, delivery)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sellerService.AcceptPayment(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.PaymentSequence != 2 || accepted.SellerAmountSat == 0 || node.updates != 1 {
		t.Fatalf("unexpected accepted state: %+v, node updates=%d", accepted, node.updates)
	}
	if _, err := sellerService.AcceptPayment(ctx, update); err != nil {
		t.Fatalf("idempotent payment retry failed: %v", err)
	}
	if node.updates != 1 {
		t.Fatalf("idempotent retry submitted a second update: %d", node.updates)
	}

	// 007 signs and accepts the exact next non-final cumulative payment. It
	// must not be routed through SubmitFinal or change the payment amount.
	opening, err := pools.LoadOpeningProof(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := pools.LoadAcceptedPayment(ctx, reference.SpendTxID)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             latest,
		PaymentSequenceAfter: latest.PaymentSequence + 1,
		SellerAmountAfterSat: latest.SellerAmountSat + 1,
		MinerFeeSat:          100,
	})
	if err != nil {
		t.Fatal(err)
	}
	buyerState, err := engine.SignBuyerPayment(ctx, unsigned, buyerSigner)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationHash := sha256.Sum256([]byte("arbitration"))
	arbitrationUpdate := &pool.PaymentUpdate{Version: pool.MajorVersion, ContentRequestTermsHash: arbitrationHash[:], PartialSpendTx: buyerState.RawTx}
	arbitrationRequest, err := sellerService.BuildArbitrationRequest(ctx, opening, arbitrationUpdate)
	if err != nil {
		t.Fatal(err)
	}
	arbiterService, err := arbiter.NewService(arbiter.ServiceConfig{Signer: protocolSigner{key: arbiterKey}, Transactions: engine})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationResponse, err := arbiterService.SignPayment(ctx, arbitrationRequest)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := sellerService.SubmitArbitratedPayment(ctx, arbitrationRequest, arbitrationResponse)
	if err != nil {
		t.Fatal(err)
	}
	if arbitrated.PaymentSequence != latest.PaymentSequence+1 || node.updates != 2 {
		t.Fatalf("unexpected arbitrated state: %+v, node updates=%d", arbitrated, node.updates)
	}
}

func requestHashForTest(t *testing.T, request *bitfs.SignedContentRequest) []byte {
	t.Helper()
	hash, err := bitfs.ContentRequestTermsHash(request.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), hash[:]...)
}

func testKeyBytes(last byte) []byte {
	result := make([]byte, 32)
	result[31] = last
	return result
}

func cloneQuoteForTest(quote *bitfs.SignedFileQuote) *bitfs.SignedFileQuote {
	if quote == nil {
		return nil
	}
	return &bitfs.SignedFileQuote{TermsCBOR: append([]byte(nil), quote.TermsCBOR...), SellerPubkey: append([]byte(nil), quote.SellerPubkey...), TermsSignature: append([]byte(nil), quote.TermsSignature...), RecommendedFilename: quote.RecommendedFilename}
}
