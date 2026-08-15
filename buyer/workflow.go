package buyer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// QuoteStore stores complete seller-signed 001 quote credentials. Implementations
// must return the credential addressed by its canonical terms hash.
type QuoteStore interface {
	SaveQuote(context.Context, *bitfs.SignedFileQuote) error
	LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

// ContentSink receives verified content bytes after request and delivery validation succeeds.
type ContentSink interface {
	SaveVerifiedContent(context.Context, bitfs.Hash32, []byte) error
}

// SeedSource supplies raw seed bytes. The workflow re-verifies the seed hash,
// structure, source-size binding, and block membership before use.
type SeedSource interface {
	LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
}

// WorkflowConfig supplies the buyer signer, stores, narrow raw BSV backend,
// and optional content/seed adapters. The workflow wraps the backend in the
// verified node adapter before any transaction can be submitted.
type WorkflowConfig struct {
	Signer      pool.Signer
	Quotes      QuoteStore
	Pools       pool.PoolStore
	Backend     pool.NonFinalPoolBackend
	ContentSink ContentSink
	SeedSource  SeedSource
}

// Workflow implements the buyer side of 001–006. It validates seller credentials,
// persists accepted pool/payment state, signs requests and payment updates, and
// uses the fixed transaction core with application-owned stores and a verified
// backend boundary.
type Workflow struct {
	signer      pool.Signer
	quotes      QuoteStore
	pools       pool.PoolStore
	node        *pool.VerifiedNonFinalPoolNode
	contentSink ContentSink
	seedSource  SeedSource
}

func (workflow *Workflow) engineFor(proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	return pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
}
func (workflow *Workflow) engineForExpiry(ctx context.Context, proof *pool.OpeningProof) (*pool.MultisigPoolEngine, error) {
	if proof == nil {
		return nil, fmt.Errorf("%w: opening proof is required", pool.ErrInvalidEvidence)
	}
	config := pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey}
	needsHeight, err := pool.RefundUsesBlockHeight(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	if needsHeight {
		h, err := workflow.node.BlockHeight(ctx)
		if err != nil {
			return nil, err
		}
		config.BlockHeight = func() uint32 { return h }
	}
	return pool.NewMultisigPoolEngine(config)
}

func fixedQuoteVerify(pub, payload, sig []byte) error {
	return bitfs.VerifySignature(pub, payload, sig)
}

// NewWorkflow validates the buyer dependencies and builds the fixed verified
// node boundary. Production expiry checks use the SDK's canonical UTC rules.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Signer == nil || config.Quotes == nil || config.Pools == nil || config.Backend == nil {
		return nil, errors.New("buyer workflow requires signer, quote store, pool store, and backend")
	}
	node, err := pool.NewVerifiedNonFinalPoolNode(config.Pools, config.Backend)
	if err != nil {
		return nil, err
	}
	return &Workflow{
		signer:      config.Signer,
		quotes:      config.Quotes,
		pools:       config.Pools,
		node:        node,
		contentSink: config.ContentSink,
		seedSource:  config.SeedSource,
	}, nil
}

// AcceptQuote verifies the seller signature, terms, and expiry before storing the quote.
func (workflow *Workflow) AcceptQuote(ctx context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	now := time.Now().UTC()
	terms, err := bitfs.VerifySignedFileQuoteAt(localQuote, now, fixedQuoteVerify)
	if err != nil {
		return nil, err
	}
	if err := workflow.quotes.SaveQuote(ctx, localQuote); err != nil {
		return nil, fmt.Errorf("save quote: %w", err)
	}
	return terms, nil
}

// AcceptRefundPresign verifies and durably records the complete pool proof,
// then records RefundTx as the initial accepted payment state (sequence 2,
// seller amount 0).  The caller may reveal fundingTx only after this method
// succeeds, matching the 002 message ordering.
func (workflow *Workflow) AcceptRefundPresign(ctx context.Context, request *pool.RefundPresignRequest, response *pool.RefundPresignResponse, fundingTx []byte) (*pool.Reference, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localRequest := pool.CloneRefundPresignRequest(request)
	localResponse := pool.CloneRefundPresignResponse(response)
	localFundingTx := append([]byte(nil), fundingTx...)
	if err := pool.ValidateRefundPresignRequest(localRequest); err != nil {
		return nil, err
	}
	if err := pool.ValidateRefundPresignResponse(localResponse); err != nil {
		return nil, err
	}
	if len(localFundingTx) == 0 {
		return nil, fmt.Errorf("%w: funding transaction is required", pool.ErrInvalidEvidence)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: localRequest.BuyerPubKey, SellerPubKey: localRequest.SellerPubKey, ArbiterPubKey: localRequest.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	if err := engine.VerifySellerRefundSignature(ctx, localRequest, localResponse.SellerRefundSignature); err != nil {
		return nil, fmt.Errorf("verify seller refund signature: %w", err)
	}
	fundingID, err := engine.TransactionID(localFundingTx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(fundingID[:], localRequest.FundingTxID) {
		return nil, fmt.Errorf("%w: funding transaction ID does not match request", pool.ErrInvalidEvidence)
	}
	spendID, err := engine.TransactionID(localRequest.RefundTx)
	if err != nil {
		return nil, err
	}
	proof := &pool.OpeningProof{Version: pool.MajorVersion, MultisigProtocol: pool.MultisigProtocol, MultisigVersion: pool.MultisigVersion, RefundTx: append([]byte(nil), localRequest.RefundTx...), SpendTxID: spendID[:], FundingTxID: localRequest.FundingTxID, PoolOutputIndex: localRequest.PoolOutputIndex, PoolOutputSatoshis: localRequest.PoolOutputSatoshis, PoolLockingScript: localRequest.PoolLockingScript, BuyerPubKey: localRequest.BuyerPubKey, SellerPubKey: localRequest.SellerPubKey, ArbiterPubKey: localRequest.ArbiterPubKey, MinerFeeRateSatPerKB: localRequest.MinerFeeRateSatPerKB, BuyerRefundSignature: localRequest.BuyerRefundSignature, SellerRefundSignature: localResponse.SellerRefundSignature, FundingTx: localFundingTx}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify complete pool opening proof: %w", err)
	}
	publicKey, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load buyer public key: %w", err)
	}
	if !bytes.Equal(publicKey, proof.BuyerPubKey) {
		return nil, fmt.Errorf("%w: workflow signer does not match opening buyer", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.SaveOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save opening proof: %w", err)
	}
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		return nil, fmt.Errorf("assemble initial refund state: %w", err)
	}
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if initial.PaymentSequence != 2 || initial.SellerAmountSat != 0 || initial.ArbiterAmountSat != 0 {
		return nil, fmt.Errorf("%w: refund transaction is not the initial pool state", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.SaveAcceptedPayment(ctx, initial); err != nil {
		return nil, fmt.Errorf("save initial pool state: %w", err)
	}
	return &pool.Reference{SpendTxID: initial.SpendTxID, BasePaymentSequence: initial.PaymentSequence}, nil
}

// PreparePoolOpening asks the fixed MultisigPool core to build the generic 002
// refund evidence. FundingTx remains caller-owned and is not submitted here.
func (workflow *Workflow) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*pool.RefundPresignRequest, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	pub, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: pub, SellerPubKey: input.SellerPubKey, ArbiterPubKey: input.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	return pool.NewBuyerPoolAdapter(engine, workflow.signer).BuildRefundPresignRequest(ctx, pool.CloneOpeningInput(input))
}

// BuildFundingTxDelivery copies and validates fundingTx into the 002 delivery
// container. It does not submit or persist the transaction; the seller receives
// it only after AcceptRefundPresign has durably recorded the refund proof.
func (workflow *Workflow) BuildFundingTxDelivery(fundingTx []byte) (*pool.FundingTxDelivery, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	delivery := &pool.FundingTxDelivery{Version: pool.MajorVersion, FundingTx: append([]byte(nil), fundingTx...)}
	if err := pool.ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	return delivery, nil
}

// RefundAfterExpiry verifies expiry, assembles the separately stored opening
// signatures into a broadcastable refund, and submits it. If a higher
// accepted cumulative state exists, the non-final node remains authoritative
// and this method refuses to bypass it.
func (workflow *Workflow) RefundAfterExpiry(ctx context.Context, spendTxID pool.Hash32) (pool.Hash32, error) {
	if workflow == nil {
		return pool.Hash32{}, errors.New("buyer workflow is required")
	}
	if workflow.node == nil {
		return pool.Hash32{}, errors.New("buyer workflow has no final pool node")
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	now := time.Now().UTC()
	if err := engine.VerifyRefundExpired(opening, now); err != nil {
		return pool.Hash32{}, err
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	if latest != nil {
		latest = pool.ClonePaymentState(latest)
		if err := engine.VerifyAcceptedPayment(latest, opening); err != nil {
			return pool.Hash32{}, fmt.Errorf("verify stored pool state: %w", err)
		}
		if latest.PaymentSequence > 2 {
			return pool.Hash32{}, fmt.Errorf("%w: a higher cumulative payment state already exists", pool.ErrNonFinalRejected)
		}
	}
	unsignedRefund, err := engine.BuildRefundSubmission(opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	txID, err := engine.TransactionID(opening.RefundTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	if txID != spendTxID {
		return pool.Hash32{}, fmt.Errorf("%w: stored opening proof does not match requested SpendTxID", pool.ErrInvalidEvidence)
	}
	submittedTxID, err := engine.TransactionID(unsignedRefund)
	if err != nil {
		return pool.Hash32{}, err
	}
	accepted, err := workflow.node.SubmitFinal(ctx, append([]byte(nil), unsignedRefund...))
	if err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, spendTxID, submittedTxID)
		uncertain := fmt.Errorf("%w: refund backend outcome requires reconciliation: %v", pool.ErrPoolStateUncertain, err)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, markErr)
		}
		return pool.Hash32{}, uncertain
	}
	if accepted != submittedTxID {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, spendTxID, submittedTxID)
		uncertain := fmt.Errorf("%w: refund node returned inconsistent transaction ID", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, markErr)
		}
		return pool.Hash32{}, uncertain
	}
	return submittedTxID, nil
}

// BuildImmediateClose constructs the unsigned immediate-close transaction and
// buyer detached signature from the accepted pool state. The caller passes the
// result to the seller, who adds the seller signature; then the caller invokes
// SubmitImmediateClose to submit the merged transaction. That method persists
// the state only after the node accepts the final transaction.
func (workflow *Workflow) BuildImmediateClose(ctx context.Context, spendTxID pool.Hash32) (*pool.UnsignedPayment, []byte, error) {
	if workflow == nil {
		return nil, nil, errors.New("buyer workflow is required")
	}
	if err := workflow.pools.EnsurePoolOpen(ctx, spendTxID); err != nil {
		return nil, nil, err
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, nil, err
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return nil, nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, nil, err
	}
	if err := engine.VerifyRefundNotExpired(opening, time.Now().UTC()); err != nil {
		return nil, nil, err
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, nil, err
	}
	if latest == nil {
		return nil, nil, fmt.Errorf("%w: accepted payment is missing", pool.ErrInvalidEvidence)
	}
	latest = pool.ClonePaymentState(latest)
	unsigned, err := engine.BuildImmediateClose(ctx, pool.CloseInput{Opening: opening, Latest: latest, SellerAmountAfterSat: latest.SellerAmountSat})
	if err != nil {
		return nil, nil, err
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(engine, workflow.signer).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, nil, err
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, nil, fmt.Errorf("%w: immediate close is not final", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, nil, fmt.Errorf("verify immediate close: %w", err)
	}
	if err := workflow.pools.MarkPoolClosing(ctx, spendTxID); err != nil {
		return nil, nil, fmt.Errorf("mark pool closing: %w", err)
	}
	return unsigned, buyerSig, nil
}

// SubmitImmediateClose verifies a fully signed final state, submits it, and
// records the state only after the node returns the expected transaction ID.
func (workflow *Workflow) SubmitImmediateClose(ctx context.Context, close *pool.SignedPayment) (pool.Hash32, error) {
	if workflow == nil {
		return pool.Hash32{}, errors.New("buyer workflow is required")
	}
	if workflow.node == nil {
		return pool.Hash32{}, errors.New("buyer workflow has no final pool node")
	}
	localClose := pool.CloneSignedPayment(close)
	if localClose == nil || localClose.State.PaymentSequence != ^uint32(0) || len(localClose.RawTx) == 0 || !bytes.Equal(localClose.State.RawTx, localClose.RawTx) {
		return pool.Hash32{}, fmt.Errorf("%w: final signed payment is required", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.EnsurePoolHealthy(ctx, localClose.State.SpendTxID); err != nil {
		return pool.Hash32{}, err
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, localClose.State.SpendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineFor(opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	if err := engine.VerifyCompletedFinalPayment(localClose, opening); err != nil {
		return pool.Hash32{}, fmt.Errorf("verify final payment: %w", err)
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, localClose.State.SpendTxID)
	if err != nil {
		return pool.Hash32{}, fmt.Errorf("load latest accepted payment: %w", err)
	}
	txID, err := engine.TransactionID(localClose.RawTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	if latest != nil && latest.PaymentSequence == ^uint32(0) {
		latest = pool.ClonePaymentState(latest)
		latestClose := &pool.SignedPayment{State: *latest, RawTx: append([]byte(nil), latest.RawTx...)}
		if err := engine.VerifyCompletedFinalPayment(latestClose, opening); err != nil {
			return pool.Hash32{}, fmt.Errorf("verify stored final payment: %w", err)
		}
		if !sameFinalPaymentState(latest, &localClose.State) {
			return pool.Hash32{}, fmt.Errorf("%w: stored final payment differs from submitted close", pool.ErrInvalidEvidence)
		}
		if err := workflow.pools.ReconcilePoolClosing(ctx, localClose.State.SpendTxID); err != nil {
			return pool.Hash32{}, fmt.Errorf("reconcile completed close: %w", err)
		}
		return txID, nil
	}
	// Only a new external submission needs the forward expiry gate. A retry
	// that found the exact stored final above performs cleanup only, so it must
	// remain recoverable even after the refund lock has become executable.
	engine, err = workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	if err := engine.VerifyRefundNotExpired(opening, time.Now().UTC()); err != nil {
		return pool.Hash32{}, fmt.Errorf("verify final payment expiry: %w", err)
	}
	accepted, err := workflow.node.SubmitFinal(ctx, append([]byte(nil), localClose.RawTx...))
	if err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, localClose.State.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: final backend outcome requires reconciliation: %v", pool.ErrPoolStateUncertain, err)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, markErr)
		}
		return pool.Hash32{}, uncertain
	}
	if accepted != txID {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, localClose.State.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: final node returned inconsistent transaction ID", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, markErr)
		}
		return pool.Hash32{}, uncertain
	}
	if err := workflow.pools.SaveAcceptedPayment(ctx, &localClose.State); err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, localClose.State.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: local persistence failed after final node acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, err, markErr)
		}
		return pool.Hash32{}, errors.Join(uncertain, err)
	}
	if err := workflow.pools.ReconcilePoolClosing(ctx, localClose.State.SpendTxID); err != nil {
		return pool.Hash32{}, fmt.Errorf("reconcile completed close: %w", err)
	}
	return txID, nil
}

func sameFinalPaymentState(left, right *pool.PaymentState) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.SpendTxID == right.SpendTxID &&
		left.PaymentSequence == right.PaymentSequence &&
		left.BuyerAmountSat == right.BuyerAmountSat &&
		left.SellerAmountSat == right.SellerAmountSat &&
		left.ArbiterAmountSat == right.ArbiterAmountSat &&
		left.PaymentAuthorizationHash == right.PaymentAuthorizationHash &&
		left.PoolOutputSatoshis == right.PoolOutputSatoshis &&
		bytes.Equal(left.RawTx, right.RawTx) &&
		bytes.Equal(left.PoolLockingScript, right.PoolLockingScript) &&
		bytes.Equal(left.BuyerTransactionSignature, right.BuyerTransactionSignature) &&
		bytes.Equal(left.SellerTransactionSignature, right.SellerTransactionSignature) &&
		bytes.Equal(left.ArbiterTransactionSignature, right.ArbiterTransactionSignature)
}

// ContentRequestInput contains the quote, pool reference, content reference, and deadline for a request.
type ContentRequestInput struct {
	QuoteTermsHash   bitfs.Hash32
	SpendTxID        pool.Hash32
	Content          bitfs.ContentRef
	ContentSize      uint64
	DeliveryDeadline bitfs.UnixSeconds
}

// RequestContent validates the quote hash, selected arbiter, content reference,
// size, and deadline, then signs the 003 request. It does not read content or
// change pool state; the seller validates and fulfills the returned credential.
func (workflow *Workflow) RequestContent(ctx context.Context, input ContentRequestInput) (*bitfs.SignedContentRequest, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	if err := workflow.pools.EnsurePoolOpen(ctx, input.SpendTxID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	opening, err := workflow.pools.LoadOpeningProof(ctx, input.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return nil, fmt.Errorf("build pool engine: %w", err)
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := engine.VerifyRefundNotExpired(opening, now); err != nil {
		return nil, errors.Join(bitfs.ErrInvalidEvidence, fmt.Errorf("verify pool refund is still available: %w", err))
	}
	contentHash := append([]byte(nil), input.Content.Hash...)
	quote, err := workflow.quotes.LoadQuote(ctx, input.QuoteTermsHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	terms, err := bitfs.VerifySignedFileQuoteAt(quote, now, fixedQuoteVerify)
	if err != nil {
		return nil, err
	}
	publicKey, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load buyer public key: %w", err)
	}
	if !bytes.Equal(publicKey, terms.BuyerPubkey) {
		return nil, fmt.Errorf("%w: signer does not match quote buyer", bitfs.ErrInvalidEvidence)
	}
	if len(contentHash) != masterseed.DigestSize {
		return nil, fmt.Errorf("%w: content hash must be 32 bytes", bitfs.ErrInvalidEvidence)
	}
	if input.DeliveryDeadline <= bitfs.UnixSeconds(now.Unix()) {
		return nil, fmt.Errorf("%w: delivery deadline is not in the future", bitfs.ErrDeliveryDeadline)
	}
	if !bytes.Equal(opening.BuyerPubKey, terms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, quote.SellerPubkey) {
		return nil, fmt.Errorf("%w: verify pool participants", bitfs.ErrInvalidEvidence)
	}
	if !quoteAllowsArbiter(terms, opening.ArbiterPubKey) {
		return nil, fmt.Errorf("%w: opening arbiter is not allowed by quote", bitfs.ErrInvalidEvidence)
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, input.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.SpendTxID != input.SpendTxID {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.PaymentSequence >= uint32(^uint32(0)-1) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	seed, err := workflow.seedForContent(ctx, terms, bitfs.ContentRef{Type: input.Content.Type, Hash: contentHash})
	if err != nil {
		return nil, err
	}
	if err := bitfs.VerifyContentReferenceContext(ctx, terms, input.Content.Type, contentHash, seed, false); err != nil {
		return nil, err
	}
	if input.Content.Type == bitfs.ContentBlock {
		matches, err := bitfs.VerifyBlockReference(ctx, terms, contentHash, seed)
		if err != nil {
			return nil, err
		}
		if !contentSizeMatchesBlock(terms.FileSize, input.ContentSize, matches) {
			return nil, fmt.Errorf("%w: content size %d does not match any committed block position", bitfs.ErrInvalidEvidence, input.ContentSize)
		}
	}
	contentSize := input.ContentSize
	if input.Content.Type == bitfs.ContentSeed {
		contentSize = 1
	}
	price, err := bitfs.ContentPriceSat(terms, input.Content.Type, contentSize)
	if err != nil {
		return nil, err
	}
	if previous.SellerAmountSat > ^uint64(0)-price {
		return nil, bitfs.ErrInsufficientBalance
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestTerms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             input.SpendTxID[:],
		BasePaymentSequence:   uint64(previous.PaymentSequence),
		PaymentSequenceAfter:  uint64(previous.PaymentSequence + 1),
		SellerAmountAfterSat:  previous.SellerAmountSat + price,
		MinerFeeRateSatPerKB:  opening.MinerFeeRateSatPerKB,
		BuyerPubkey:           append([]byte(nil), terms.BuyerPubkey...),
		SellerPubkey:          append([]byte(nil), quote.SellerPubkey...),
		SelectedArbiterPubkey: append([]byte(nil), opening.ArbiterPubKey...),
		ContentType:           input.Content.Type,
		ContentHash:           contentHash,
		DeliveryDeadlineUnix:  int64(input.DeliveryDeadline),
	}
	raw, err := bitfs.EncodeContentRequestTerms(requestTerms)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	signature, err := workflow.signer.Sign(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign content request: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("buyer signature is required")
	}
	if err := bitfs.VerifySignature(publicKey, raw, signature); err != nil {
		return nil, fmt.Errorf("verify generated content request signature: %w", err)
	}
	return &bitfs.SignedContentRequest{TermsCBOR: raw, BuyerSignature: append([]byte(nil), signature...)}, nil
}

// contentSizeMatchesBlock checks only real match endpoints returned by
// MasterSeed. It intentionally never treats an index between FirstIndex and
// LastIndex as a match when duplicate hashes are non-contiguous.
func contentSizeMatchesBlock(fileSize, contentSize uint64, matches masterseed.BlockMatches) bool {
	if matches.MatchCount == 0 {
		return false
	}
	for _, index := range []uint64{matches.FirstIndex, matches.LastIndex} {
		expected, err := masterseed.ExpectedBlockSize(fileSize, index)
		if err == nil && expected == contentSize {
			return true
		}
	}
	return false
}

// AcceptDelivery verifies the request linkage, seller signature, content hash,
// and size in the 004 delivery. After optional ContentSink persistence succeeds,
// it builds and signs the next 005 cumulative payment update.
func (workflow *Workflow) AcceptDelivery(ctx context.Context, request *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery) (*pool.PaymentUpdate, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localRequest := bitfs.CloneSignedContentRequest(request)
	localDelivery := bitfs.CloneSignedContentDelivery(delivery)
	if localRequest == nil || localDelivery == nil {
		return nil, fmt.Errorf("%w: content request and delivery are required", bitfs.ErrInvalidEvidence)
	}
	requestTerms, err := bitfs.DecodeContentRequestTerms(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	quoteHash := hash32(requestTerms.QuoteTermsHash)
	quote, err := workflow.quotes.LoadQuote(ctx, quoteHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// Authenticate all 003/004 signatures and their quote binding before any
	// externally supplied seed is loaded. Membership/seed validation follows.
	if _, err := bitfs.VerifySignedContentDeliveryAt(localRequest, localDelivery, quote, now, fixedQuoteVerify, fixedQuoteVerify, fixedQuoteVerify); err != nil {
		return nil, err
	}
	spendTxID := poolHash32(requestTerms.SpendTxID)
	if err := workflow.pools.EnsurePoolOpen(ctx, spendTxID); err != nil {
		return nil, err
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := engine.VerifyRefundNotExpired(opening, now); err != nil {
		return nil, fmt.Errorf("verify pool refund is still available: %w", err)
	}
	if requestTerms.MinerFeeRateSatPerKB != opening.MinerFeeRateSatPerKB || !bytes.Equal(requestTerms.SpendTxID, opening.SpendTxID) {
		return nil, fmt.Errorf("%w: content request is not bound to opening proof", bitfs.ErrInvalidEvidence)
	}
	if !bytes.Equal(opening.BuyerPubKey, quoteTerms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, quote.SellerPubkey) || !bytes.Equal(opening.ArbiterPubKey, requestTerms.SelectedArbiterPubkey) {
		return nil, fmt.Errorf("%w: verify pool participants", bitfs.ErrInvalidEvidence)
	}
	seed, err := workflow.seedForContent(ctx, quoteTerms, bitfs.ContentRef{Type: requestTerms.ContentType, Hash: requestTerms.ContentHash})
	if err != nil {
		return nil, err
	}
	payload, err := bitfs.VerifySignedContentDeliveryWithSeedAtContext(ctx, localRequest, localDelivery, quote, seed, now, fixedQuoteVerify, fixedQuoteVerify, fixedQuoteVerify)
	if err != nil {
		return nil, err
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if requestTerms.PaymentSequenceAfter != uint64(previous.PaymentSequence+1) || requestTerms.PaymentSequenceAfter > uint64(^uint32(0)-1) || requestTerms.SellerAmountAfterSat < previous.SellerAmountSat {
		return nil, bitfs.ErrStalePaymentSequence
	}
	if previous.PaymentSequence >= 0xfffffffe {
		return nil, fmt.Errorf("%w: payment sequence exhausted", bitfs.ErrStalePaymentSequence)
	}
	input := pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequenceAfter: previous.PaymentSequence + 1,
		SellerAmountAfterSat: requestTerms.SellerAmountAfterSat,
	}
	if err := engine.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, requestTerms.ContentType, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	if ^uint64(0)-previous.SellerAmountSat < price || requestTerms.SellerAmountAfterSat != previous.SellerAmountSat+price {
		return nil, fmt.Errorf("%w: seller amount does not match content price", bitfs.ErrInvalidEvidence)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("build payment update: %w", err)
	}
	buyerSig, err := pool.NewBuyerPoolAdapter(engine, workflow.signer).SignBuyerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	if unsigned == nil || unsigned.SpendTxID != spendTxID || unsigned.PaymentSequence <= previous.PaymentSequence {
		return nil, fmt.Errorf("%w: signed payment state is stale", bitfs.ErrStalePaymentSequence)
	}
	if workflow.contentSink != nil {
		if err := workflow.contentSink.SaveVerifiedContent(ctx, hash32(requestTerms.ContentHash), payload); err != nil {
			return nil, fmt.Errorf("save verified content: %w", err)
		}
	}
	requestHash, err := bitfs.PaymentAuthorizationHash(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	return &pool.PaymentUpdate{
		Version:                   pool.MajorVersion,
		PaymentAuthorizationHash:  requestHash[:],
		UnsignedStateTxRaw:        append([]byte(nil), unsigned.RawTx...),
		BuyerTransactionSignature: append([]byte(nil), buyerSig...),
	}, nil
}

func hash32(raw []byte) bitfs.Hash32 {
	var result bitfs.Hash32
	copy(result[:], raw)
	return result
}

func poolHash32(raw []byte) pool.Hash32 {
	var result pool.Hash32
	copy(result[:], raw)
	return result
}

func quoteAllowsArbiter(terms *bitfs.FileQuoteTerms, wanted []byte) bool {
	pubkeys, err := bitfs.DecodeSupportedArbiterPubkeys(terms.SupportedArbiterPubkeysCBOR)
	if err != nil {
		return false
	}
	for _, pubkey := range pubkeys {
		if bytes.Equal(pubkey, wanted) {
			return true
		}
	}
	return false
}

func (workflow *Workflow) seedForContent(ctx context.Context, quoteTerms *bitfs.FileQuoteTerms, content bitfs.ContentRef) ([]byte, error) {
	if content.Type == bitfs.ContentSeed {
		return nil, nil
	}
	if workflow.seedSource == nil {
		return nil, fmt.Errorf("%w: a verified seed is required before requesting a block", bitfs.ErrContentNotInSeed)
	}
	seedHash, err := masterseed.DigestFromBytes(quoteTerms.SeedHash)
	if err != nil {
		return nil, fmt.Errorf("%w: quote seed hash: %v", bitfs.ErrInvalidEvidence, err)
	}
	seed, err := workflow.seedSource.LoadSeed(ctx, seedHash)
	if err != nil {
		return nil, fmt.Errorf("load seed: %w", err)
	}
	return append([]byte(nil), seed...), nil
}

func cloneSignedFileQuote(quote *bitfs.SignedFileQuote) *bitfs.SignedFileQuote {
	if quote == nil {
		return nil
	}
	return &bitfs.SignedFileQuote{TermsCBOR: append([]byte(nil), quote.TermsCBOR...), SellerPubkey: append([]byte(nil), quote.SellerPubkey...), TermsSignature: append([]byte(nil), quote.TermsSignature...), RecommendedFilename: bitfs.SanitizeRecommendedFilename(quote.RecommendedFilename)}
}
