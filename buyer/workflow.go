package buyer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// QuoteStore defines storage operations used by the workflow.
type QuoteStore interface {
	SaveQuote(context.Context, *bitfs.SignedFileQuote) error
	LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

// ContentSink receives verified content bytes after request and delivery validation succeeds.
type ContentSink interface {
	SaveVerifiedContent(context.Context, bitfs.Hash32, []byte) error
}

// SeedSource supplies a previously verified seed so block requests can be
// checked against the seed's committed block-hash list.
type SeedSource interface {
	LoadSeed(context.Context, bitfs.Hash32) ([]byte, error)
}

// WorkflowConfig groups the stores, signers, verifiers, and node ports required by a workflow.
type WorkflowConfig struct {
	Signer            pool.Signer
	QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
	SignatureVerifier bitfs.ContentTermsSignatureVerifier
	Clock             func() time.Time
	Quotes            QuoteStore
	Pools             pool.PoolStore
	Opening           pool.BuyerPoolOpeningHooks
	Participants      pool.ParticipantVerifier
	Node              pool.NonFinalPoolNode
	Transactions      pool.BuyerPoolPort
	ContentSink       ContentSink
	SeedSource        SeedSource
}

// Workflow coordinates role-specific protocol state transitions while keeping infrastructure in injected ports.
type Workflow struct {
	signer            pool.Signer
	quoteVerifier     bitfs.QuoteTermsSignatureVerifier
	signatureVerifier bitfs.ContentTermsSignatureVerifier
	clock             func() time.Time
	quotes            QuoteStore
	pools             pool.PoolStore
	opening           pool.BuyerPoolOpeningHooks
	participants      pool.ParticipantVerifier
	node              pool.NonFinalPoolNode
	transactions      pool.BuyerPoolPort
	contentSink       ContentSink
	seedSource        SeedSource
}

// NewWorkflow creates a buyer workflow, requires every protocol port, and
// defaults Clock to time.Now when it is omitted.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Signer == nil || config.QuoteVerifier == nil || config.SignatureVerifier == nil || config.Quotes == nil || config.Pools == nil || config.Opening == nil || config.Participants == nil || config.Transactions == nil {
		return nil, errors.New("buyer workflow requires signer, verifiers, quote, opening, participant, pool and transaction ports")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Workflow{
		signer:            config.Signer,
		quoteVerifier:     config.QuoteVerifier,
		signatureVerifier: config.SignatureVerifier,
		clock:             config.Clock,
		quotes:            config.Quotes,
		pools:             config.Pools,
		opening:           config.Opening,
		participants:      config.Participants,
		node:              config.Node,
		transactions:      config.Transactions,
		contentSink:       config.ContentSink,
		seedSource:        config.SeedSource,
	}, nil
}

// AcceptQuote verifies the seller signature, terms, and expiry before storing the quote.
func (workflow *Workflow) AcceptQuote(ctx context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	terms, err := bitfs.VerifySignedFileQuoteAt(localQuote, workflow.clock(), workflow.quoteVerifier)
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
	proof, err := pool.BuyerAcceptRefundPresign(ctx, localRequest, localResponse, localFundingTx, workflow.opening)
	if err != nil {
		return nil, err
	}
	if err := workflow.transactions.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify complete pool opening proof: %w", err)
	}
	initialRaw, err := workflow.transactions.BuildRefundSubmission(proof)
	if err != nil {
		return nil, fmt.Errorf("assemble initial refund state: %w", err)
	}
	initial, err := workflow.transactions.ParsePaymentState(ctx, initialRaw, proof)
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

// PreparePoolOpening asks the transaction engine to build the generic 002
// refund evidence. FundingTx remains caller-owned and is not submitted here.
func (workflow *Workflow) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*pool.RefundPresignRequest, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	return workflow.transactions.BuildRefundPresignRequest(ctx, pool.CloneOpeningInput(input), workflow.signer)
}

// BuildFundingTxDelivery verifies the opening proof and returns the buyer funding transaction for seller submission.
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
	if err := workflow.transactions.VerifyRefundExpired(opening, workflow.clock()); err != nil {
		return pool.Hash32{}, err
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	if latest != nil {
		latest = pool.ClonePaymentState(latest)
		if err := workflow.transactions.VerifyAcceptedPayment(latest, opening); err != nil {
			return pool.Hash32{}, fmt.Errorf("verify stored pool state: %w", err)
		}
		if latest.PaymentSequence > 2 {
			return pool.Hash32{}, fmt.Errorf("%w: a higher cumulative payment state already exists", pool.ErrNonFinalRejected)
		}
	}
	unsignedRefund, err := workflow.transactions.BuildRefundSubmission(opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	txID, err := workflow.transactions.TransactionID(opening.RefundTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	if txID != spendTxID {
		return pool.Hash32{}, fmt.Errorf("%w: stored opening proof does not match requested SpendTxID", pool.ErrInvalidEvidence)
	}
	submittedTxID, err := workflow.transactions.TransactionID(unsignedRefund)
	if err != nil {
		return pool.Hash32{}, err
	}
	accepted, err := workflow.node.SubmitFinal(ctx, append([]byte(nil), unsignedRefund...))
	if err != nil {
		return pool.Hash32{}, fmt.Errorf("%w: submit refund: %v", pool.ErrFinalRejected, err)
	}
	if accepted != submittedTxID {
		return pool.Hash32{}, fmt.Errorf("%w: refund node returned inconsistent transaction ID", pool.ErrInvalidEvidence)
	}
	return submittedTxID, nil
}

// BuildImmediateClose constructs the buyer-authorized immediate-close transaction from the accepted payment state.
func (workflow *Workflow) BuildImmediateClose(ctx context.Context, input pool.CloseInput) (*pool.UnsignedPayment, []byte, error) {
	if workflow == nil {
		return nil, nil, errors.New("buyer workflow is required")
	}
	localInput := pool.CloneCloseInput(input)
	unsigned, _, err := workflow.transactions.BuildImmediateClose(ctx, localInput)
	if err != nil {
		return nil, nil, err
	}
	buyerSig, err := workflow.transactions.SignBuyerPayment(ctx, unsigned, workflow.signer)
	if err != nil {
		return nil, nil, err
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, nil, fmt.Errorf("%w: immediate close is not final", pool.ErrInvalidEvidence)
	}
	if err := workflow.transactions.VerifyBuyerPayment(unsigned, buyerSig, localInput.Opening); err != nil {
		return nil, nil, fmt.Errorf("verify immediate close: %w", err)
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
	opening, err := workflow.pools.LoadOpeningProof(ctx, localClose.State.SpendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.transactions.VerifyCompletedFinalPayment(localClose, opening); err != nil {
		return pool.Hash32{}, fmt.Errorf("verify final payment: %w", err)
	}
	txID, err := workflow.transactions.TransactionID(localClose.RawTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	accepted, err := workflow.node.SubmitFinal(ctx, append([]byte(nil), localClose.RawTx...))
	if err != nil {
		return pool.Hash32{}, fmt.Errorf("%w: %v", pool.ErrFinalRejected, err)
	}
	if accepted != txID {
		return pool.Hash32{}, fmt.Errorf("%w: final node returned inconsistent transaction ID", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.SaveAcceptedPayment(ctx, &localClose.State); err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, localClose.State.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: local persistence failed after final node acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return pool.Hash32{}, errors.Join(uncertain, err, markErr)
		}
		return pool.Hash32{}, errors.Join(uncertain, err)
	}
	return txID, nil
}

// ContentRequestInput contains the quote, pool reference, content reference, and deadline for a request.
type ContentRequestInput struct {
	QuoteTermsHash        bitfs.Hash32
	Pool                  pool.Reference
	SelectedArbiterPubKey []byte
	Content               bitfs.ContentRef
	ContentSize           uint64
	DeliveryDeadline      bitfs.UnixSeconds
}

// RequestContent creates the signed protocol request for the selected content or workflow step.
func (workflow *Workflow) RequestContent(ctx context.Context, input ContentRequestInput) (*bitfs.SignedContentRequest, error) {
	if workflow == nil {
		return nil, errors.New("buyer workflow is required")
	}
	if err := workflow.pools.EnsurePoolHealthy(ctx, input.Pool.SpendTxID); err != nil {
		return nil, err
	}
	selectedArbiter := append([]byte(nil), input.SelectedArbiterPubKey...)
	contentHash := append([]byte(nil), input.Content.Hash...)
	quote, err := workflow.quotes.LoadQuote(ctx, input.QuoteTermsHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	terms, err := bitfs.VerifySignedFileQuoteAt(quote, workflow.clock(), workflow.quoteVerifier)
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
	if len(selectedArbiter) == 0 || !quoteAllowsArbiter(terms, selectedArbiter) {
		return nil, fmt.Errorf("%w: selected arbiter is not allowed by quote", bitfs.ErrInvalidEvidence)
	}
	if len(contentHash) != sha256.Size {
		return nil, fmt.Errorf("%w: content hash must be 32 bytes", bitfs.ErrInvalidEvidence)
	}
	if input.DeliveryDeadline <= bitfs.UnixSeconds(workflow.clock().Unix()) {
		return nil, fmt.Errorf("%w: delivery deadline is not in the future", bitfs.ErrDeliveryDeadline)
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, input.Pool.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := workflow.participants.VerifyPoolParticipants(opening, terms.BuyerPubkey, quote.SellerPubkey, selectedArbiter); err != nil {
		return nil, fmt.Errorf("verify pool participants: %w", err)
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, input.Pool.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.SpendTxID != input.Pool.SpendTxID || previous.PaymentSequence != input.Pool.BasePaymentSequence {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := workflow.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	seed, err := workflow.seedForContent(ctx, terms, bitfs.ContentRef{Type: input.Content.Type, Hash: contentHash})
	if err != nil {
		return nil, err
	}
	if err := bitfs.VerifyContentReference(terms, input.Content.Type, contentHash, seed, input.Content.Type == bitfs.ContentBlock); err != nil {
		return nil, err
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
		SpendTxID:             input.Pool.SpendTxID[:],
		BasePaymentSequence:   uint64(input.Pool.BasePaymentSequence),
		PaymentSequenceAfter:  uint64(previous.PaymentSequence + 1),
		SellerAmountAfterSat:  previous.SellerAmountSat + price,
		MinerFeeRateSatPerKB:  opening.MinerFeeRateSatPerKB,
		BuyerPubkey:           append([]byte(nil), terms.BuyerPubkey...),
		SellerPubkey:          append([]byte(nil), quote.SellerPubkey...),
		SelectedArbiterPubkey: selectedArbiter,
		ContentType:           input.Content.Type,
		ContentHash:           contentHash,
		DeliveryDeadlineUnix:  int64(input.DeliveryDeadline),
	}
	raw, err := bitfs.EncodeContentRequestTerms(requestTerms)
	if err != nil {
		return nil, err
	}
	signature, err := workflow.signer.Sign(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("sign content request: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("buyer signature is required")
	}
	return &bitfs.SignedContentRequest{TermsCBOR: raw, BuyerSignature: append([]byte(nil), signature...)}, nil
}

// AcceptDelivery verifies 004 and its content, optionally stores the payload,
// then constructs and buyer-signs the corresponding cumulative payment update.
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
	seed, err := workflow.seedForContent(ctx, quoteTerms, bitfs.ContentRef{Type: requestTerms.ContentType, Hash: requestTerms.ContentHash})
	if err != nil {
		return nil, err
	}
	payload, err := bitfs.VerifySignedContentDeliveryWithSeedAt(localRequest, localDelivery, quote, seed, workflow.clock(), workflow.quoteVerifier, workflow.signatureVerifier, workflow.signatureVerifier)
	if err != nil {
		return nil, err
	}
	spendTxID := poolHash32(requestTerms.SpendTxID)
	if err := workflow.pools.EnsurePoolHealthy(ctx, spendTxID); err != nil {
		return nil, err
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := workflow.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := workflow.participants.VerifyPoolParticipants(opening, quoteTerms.BuyerPubkey, quote.SellerPubkey, requestTerms.SelectedArbiterPubkey); err != nil {
		return nil, fmt.Errorf("verify pool participants: %w", err)
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := workflow.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if requestTerms.PaymentSequenceAfter != uint64(previous.PaymentSequence+1) || requestTerms.SellerAmountAfterSat < previous.SellerAmountSat {
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
	if err := workflow.transactions.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	unsigned, err := workflow.transactions.BuildPaymentUpdate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("build payment update: %w", err)
	}
	buyerSig, err := workflow.transactions.SignBuyerPayment(ctx, unsigned, workflow.signer)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if err := workflow.transactions.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
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
	seedHash := hash32(quoteTerms.SeedHash)
	seed, err := workflow.seedSource.LoadSeed(ctx, seedHash)
	if err != nil {
		return nil, fmt.Errorf("load verified seed: %w", err)
	}
	return append([]byte(nil), seed...), nil
}

func cloneSignedFileQuote(quote *bitfs.SignedFileQuote) *bitfs.SignedFileQuote {
	if quote == nil {
		return nil
	}
	return &bitfs.SignedFileQuote{TermsCBOR: append([]byte(nil), quote.TermsCBOR...), SellerPubkey: append([]byte(nil), quote.SellerPubkey...), TermsSignature: append([]byte(nil), quote.TermsSignature...), RecommendedFilename: bitfs.SanitizeRecommendedFilename(quote.RecommendedFilename)}
}
