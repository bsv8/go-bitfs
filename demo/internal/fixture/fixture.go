// Package fixture provides a deterministic-in-shape, in-memory demo fixture.
// It is for learning and observation only; DemoBackend is not a BSV node.
package fixture

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
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

type Signer struct{ Key *ec.PrivateKey }

func (s Signer) PublicKey(context.Context) ([]byte, error) { return s.Key.PubKey().Compressed(), nil }
func (s Signer) Sign(_ context.Context, digest []byte) ([]byte, error) {
	signature, err := s.Key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

type QuoteStore struct {
	Quotes map[bitfs.Hash32]*bitfs.SignedFileQuote
}

func (s *QuoteStore) SaveQuote(_ context.Context, quote *bitfs.SignedFileQuote) error {
	hash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return err
	}
	if s.Quotes == nil {
		s.Quotes = make(map[bitfs.Hash32]*bitfs.SignedFileQuote)
	}
	s.Quotes[bitfs.Hash32(hash)] = bitfs.CloneSignedFileQuote(quote)
	return nil
}

func (s *QuoteStore) LoadQuote(_ context.Context, hash bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	quote := s.Quotes[hash]
	if quote == nil {
		return nil, fmt.Errorf("quote %x not found", hash)
	}
	return bitfs.CloneSignedFileQuote(quote), nil
}

type Content struct {
	Seed  []byte
	Block []byte
}

func (c Content) LoadSeed(context.Context, masterseed.Digest) ([]byte, error) {
	return append([]byte(nil), c.Seed...), nil
}
func (c Content) LoadBlock(context.Context, masterseed.Digest) ([]byte, error) {
	if len(c.Block) == 0 {
		return nil, fmt.Errorf("demo block is not configured")
	}
	return append([]byte(nil), c.Block...), nil
}
func (c Content) SaveVerifiedContent(_ context.Context, _ bitfs.Hash32, payload []byte) error {
	return nil
}

// DemoBackend accepts canonical transactions after the verified node adapter
// has checked them. It records call counts but does not broadcast to BSV.
type DemoBackend struct {
	Store    *pool.MemoryStore
	Updates  int
	Fundings int
	Finals   int
}

func (b *DemoBackend) SubmitTransaction(_ context.Context, raw []byte) (pool.Hash32, error) {
	b.Fundings++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return pool.Hash32{}, err
	}
	return poolHash(transaction.TxID().CloneBytes()), nil
}

func (b *DemoBackend) SubmitUpdate(ctx context.Context, raw []byte) (*pool.UpdateAcceptance, error) {
	b.Updates++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return nil, err
	}
	if len(transaction.Inputs) != 1 || transaction.Inputs[0].SourceTXID == nil {
		return nil, fmt.Errorf("demo update has no funding outpoint")
	}
	fundingID := poolHash(transaction.Inputs[0].SourceTXID.CloneBytes())
	proof, err := b.Store.LoadOpeningProofByFundingTxID(ctx, fundingID)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	state, err := engine.ParseNonFinalPaymentState(ctx, raw, proof)
	if err != nil {
		return nil, err
	}
	return &pool.UpdateAcceptance{TxID: poolHash(transaction.TxID().CloneBytes()), SpendTxID: state.SpendTxID, PaymentSequence: state.PaymentSequence}, nil
}

func (b *DemoBackend) SubmitFinal(_ context.Context, raw []byte) (pool.Hash32, error) {
	b.Finals++
	transaction, err := pool.ParseCanonicalTransaction(raw)
	if err != nil {
		return pool.Hash32{}, err
	}
	return poolHash(transaction.TxID().CloneBytes()), nil
}

type Fixture struct {
	Buyer         *buyer.Workflow
	Seller        *seller.Workflow
	Arbiter       *arbitration.Workflow
	BuyerSigner   Signer
	SellerSigner  Signer
	ArbiterSigner Signer
	Quotes        *QuoteStore
	Pools         *pool.MemoryStore
	Content       Content
	Backend       *DemoBackend
	Quote         *bitfs.SignedFileQuote
	QuoteHash     bitfs.Hash32
	Seed          []byte
	SeedHash      masterseed.Digest
	FundingTx     []byte
	Opening       *pool.OpeningProof
	Reference     *pool.Reference
}

// New creates a complete in-memory state through 002. Later demos can focus on
// 003, 004, 005, 006, or 007 without repeating application wiring by hand.
func New(ctx context.Context) (*Fixture, error) {
	filePath := envOr("FILE_PATH", "demo/file.bin")
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read demo file %q: %w", filePath, err)
	}
	var seedOutput bytes.Buffer
	if _, err := masterseed.CreateSeed(ctx, bytes.NewReader(fileBytes), &seedOutput); err != nil {
		return nil, fmt.Errorf("create demo seed: %w", err)
	}
	seed := seedOutput.Bytes()
	seedHash := masterseed.Sum256(seed)

	buyerKey, err := loadKey("BUYER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	sellerKey, err := loadKey("SELLER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	arbiterKey, err := loadKey("ARBITER_PRIVATE_KEY_HEX")
	if err != nil {
		return nil, err
	}
	quotes := &QuoteStore{Quotes: make(map[bitfs.Hash32]*bitfs.SignedFileQuote)}
	pools, err := pool.NewMemoryStore()
	if err != nil {
		return nil, err
	}
	backend := &DemoBackend{Store: pools}
	content := Content{Seed: seed, Block: fileBytes}
	buyerSigner := Signer{Key: buyerKey}
	sellerSigner := Signer{Key: sellerKey}
	arbiterSigner := Signer{Key: arbiterKey}
	sellerWorkflow, err := seller.NewWorkflow(seller.WorkflowConfig{Signer: sellerSigner, Quotes: quotes, Pools: pools, Pending: pools, Content: content, Backend: backend})
	if err != nil {
		return nil, err
	}
	buyerWorkflow, err := buyer.NewWorkflow(buyer.WorkflowConfig{Signer: buyerSigner, Quotes: quotes, Pools: pools, Backend: backend, SeedSource: content, ContentSink: content})
	if err != nil {
		return nil, err
	}
	arbiterWorkflow, err := arbitration.NewWorkflow(arbitration.WorkflowConfig{Signer: arbiterSigner})
	if err != nil {
		return nil, err
	}
	arbiters, err := bitfs.EncodeSupportedArbiterPubkeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	quote, err := sellerWorkflow.CreateQuote(ctx, bitfs.FileQuoteTerms{SeedHash: seedHash.Bytes(), BuyerPubkey: buyerKey.PubKey().Compressed(), SeedPriceSat: 100, FullBlockPriceSat: 1000, FileSize: uint64(len(fileBytes)), QuoteExpiresAtUnix: now.Add(time.Hour).Unix(), SupportedArbiterPubkeysCBOR: arbiters}, "file.bin")
	if err != nil {
		return nil, fmt.Errorf("create fixture quote: %w", err)
	}
	if _, err := buyerWorkflow.AcceptQuote(ctx, quote); err != nil {
		return nil, fmt.Errorf("accept fixture quote: %w", err)
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	funding, err := buildFundingTx(buyerKey.PubKey().Compressed(), sellerKey.PubKey().Compressed(), arbiterKey.PubKey().Compressed())
	if err != nil {
		return nil, err
	}
	openingRequest, err := buyerWorkflow.PreparePoolOpening(ctx, pool.OpeningInput{FundingTx: funding, PoolOutputIndex: 0, ExpiryLockTime: uint32(now.Add(time.Hour).Unix()), MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		return nil, fmt.Errorf("prepare fixture opening: %w", err)
	}
	openingResponse, err := sellerWorkflow.PresignPoolOpening(ctx, openingRequest)
	if err != nil {
		return nil, fmt.Errorf("presign fixture opening: %w", err)
	}
	ref, err := buyerWorkflow.AcceptRefundPresign(ctx, openingRequest, openingResponse, funding)
	if err != nil {
		return nil, fmt.Errorf("accept fixture refund presign: %w", err)
	}
	delivery, err := buyerWorkflow.BuildFundingTxDelivery(funding)
	if err != nil {
		return nil, err
	}
	opening, err := sellerWorkflow.AcceptPoolFunding(ctx, delivery)
	if err != nil {
		return nil, fmt.Errorf("accept fixture funding: %w", err)
	}
	return &Fixture{Buyer: buyerWorkflow, Seller: sellerWorkflow, Arbiter: arbiterWorkflow, BuyerSigner: buyerSigner, SellerSigner: sellerSigner, ArbiterSigner: arbiterSigner, Quotes: quotes, Pools: pools, Content: content, Backend: backend, Quote: quote, QuoteHash: bitfs.Hash32(quoteHash), Seed: seed, SeedHash: seedHash, FundingTx: funding, Opening: opening, Reference: ref}, nil
}

func (f *Fixture) BuildSeedRequest(ctx context.Context) (*bitfs.SignedContentRequest, error) {
	return f.Buyer.RequestContent(ctx, buyer.ContentRequestInput{QuoteTermsHash: f.QuoteHash, SpendTxID: f.Reference.SpendTxID, Content: bitfs.ContentRef{Type: bitfs.ContentSeed, Hash: f.SeedHash.Bytes()}, ContentSize: 1, DeliveryDeadline: bitfs.UnixSeconds(time.Now().Add(30 * time.Minute).Unix())})
}

func (f *Fixture) DeliverAndBuildPayment(ctx context.Context) (*bitfs.SignedContentRequest, *bitfs.SignedContentDelivery, *pool.PaymentUpdate, error) {
	request, err := f.BuildSeedRequest(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	delivery, err := f.Seller.DeliverRequestedContent(ctx, request)
	if err != nil {
		return nil, nil, nil, err
	}
	update, err := f.Buyer.AcceptDelivery(ctx, request, delivery)
	if err != nil {
		return nil, nil, nil, err
	}
	return request, delivery, update, nil
}

func buildFundingTx(buyer, seller, arbiter []byte) ([]byte, error) {
	lock, err := pool.Build2of3LockingScript(pool.MultisigPoolPublicKeys{
		BuyerPubKey: buyer, SellerPubKey: seller, ArbiterPubKey: arbiter,
	})
	if err != nil {
		return nil, err
	}
	transaction := tx.NewTransaction()
	zero, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		return nil, err
	}
	transaction.AddInput(&tx.TransactionInput{SourceTXID: zero, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	transaction.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	return transaction.Bytes(), nil
}

func loadKey(name string) (*ec.PrivateKey, error) {
	key, err := ec.PrivateKeyFromHex(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", name, err)
	}
	return key, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func poolHash(raw []byte) pool.Hash32 {
	var value pool.Hash32
	copy(value[:], raw)
	return value
}

var _ pool.PoolBackend = (*DemoBackend)(nil)
var _ buyer.QuoteStore = (*QuoteStore)(nil)
var _ seller.QuoteStore = (*QuoteStore)(nil)
var _ seller.ContentSource = Content{}
var _ buyer.SeedSource = Content{}
var _ buyer.ContentSink = Content{}
