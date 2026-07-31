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

type QuoteStore interface {
	SaveQuote(context.Context, *bitfs.SignedFileQuote) error
	LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

type ContentSink interface {
	SaveVerifiedContent(context.Context, bitfs.Hash32, []byte) error
}

// SeedSource supplies a previously verified seed so block requests can be
// checked against the seed's committed block-hash list.
type SeedSource interface {
	LoadSeed(context.Context, bitfs.Hash32) ([]byte, error)
}

type ClientConfig struct {
	Signer            pool.Signer
	QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
	SignatureVerifier bitfs.ContentTermsSignatureVerifier
	Clock             func() time.Time
	Quotes            QuoteStore
	Pools             pool.PoolStore
	Opening           pool.BuyerPoolOpeningHooks
	Participants      pool.ParticipantVerifier
	Node              pool.NonFinalPoolNode
	Transactions      pool.TransactionEngine
	ContentSink       ContentSink
	SeedSource        SeedSource
}

type Client struct {
	signer            pool.Signer
	quoteVerifier     bitfs.QuoteTermsSignatureVerifier
	signatureVerifier bitfs.ContentTermsSignatureVerifier
	clock             func() time.Time
	quotes            QuoteStore
	pools             pool.PoolStore
	opening           pool.BuyerPoolOpeningHooks
	participants      pool.ParticipantVerifier
	node              pool.NonFinalPoolNode
	transactions      pool.TransactionEngine
	contentSink       ContentSink
	seedSource        SeedSource
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Signer == nil || config.QuoteVerifier == nil || config.SignatureVerifier == nil || config.Quotes == nil || config.Pools == nil || config.Opening == nil || config.Participants == nil || config.Transactions == nil {
		return nil, errors.New("buyer client requires signer, verifiers, quote, opening, participant, pool and transaction ports")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Client{
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

func (client *Client) AcceptQuote(ctx context.Context, quote *bitfs.SignedFileQuote) (*bitfs.FileQuoteTerms, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
	}
	localQuote := bitfs.CloneSignedFileQuote(quote)
	terms, err := bitfs.VerifySignedFileQuoteAt(localQuote, client.clock(), client.quoteVerifier)
	if err != nil {
		return nil, err
	}
	if err := client.quotes.SaveQuote(ctx, localQuote); err != nil {
		return nil, fmt.Errorf("save quote: %w", err)
	}
	return terms, nil
}

// AcceptRefundPresign verifies and durably records the complete pool proof,
// then records RefundTx as the initial accepted payment state (sequence 1,
// seller amount 0).  The caller may reveal fundingTx only after this method
// succeeds, matching the 002 message ordering.
func (client *Client) AcceptRefundPresign(ctx context.Context, request *pool.RefundPresignRequest, response *pool.RefundPresignResponse, fundingTx []byte) (*pool.Reference, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
	}
	localRequest := pool.CloneRefundPresignRequest(request)
	localResponse := pool.CloneRefundPresignResponse(response)
	localFundingTx := append([]byte(nil), fundingTx...)
	proof, err := pool.BuyerAcceptRefundPresign(ctx, localRequest, localResponse, localFundingTx, client.opening)
	if err != nil {
		return nil, err
	}
	if err := client.transactions.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify complete pool opening proof: %w", err)
	}
	initial, err := client.transactions.ParsePaymentState(ctx, proof.RefundTx, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if initial.PaymentSequence != 1 || initial.SellerAmountSat != 0 {
		return nil, fmt.Errorf("%w: refund transaction is not the initial pool state", pool.ErrInvalidEvidence)
	}
	if err := client.pools.SaveAcceptedPayment(ctx, initial); err != nil {
		return nil, fmt.Errorf("save initial pool state: %w", err)
	}
	return &pool.Reference{SpendTxID: initial.SpendTxID, BasePaymentSequence: initial.PaymentSequence}, nil
}

// PreparePoolOpening asks the transaction engine to build the generic 002
// refund evidence. FundingTx remains caller-owned and is not submitted here.
func (client *Client) PreparePoolOpening(ctx context.Context, input pool.OpeningInput) (*pool.RefundPresignRequest, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
	}
	return client.transactions.BuildRefundPresignRequest(ctx, pool.CloneOpeningInput(input), client.signer)
}

func (client *Client) BuildFundingTxDelivery(fundingTx []byte) (*pool.FundingTxDelivery, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
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
func (client *Client) RefundAfterExpiry(ctx context.Context, spendTxID pool.Hash32) (pool.Hash32, error) {
	if client == nil {
		return pool.Hash32{}, errors.New("buyer client is required")
	}
	if client.node == nil {
		return pool.Hash32{}, errors.New("buyer client has no final pool node")
	}
	opening, err := client.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	opening = pool.CloneOpeningProof(opening)
	if err := client.transactions.VerifyRefundExpired(opening, client.clock()); err != nil {
		return pool.Hash32{}, err
	}
	latest, err := client.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	if latest != nil {
		latest = pool.ClonePaymentState(latest)
		if err := client.transactions.VerifyAcceptedPayment(latest, opening); err != nil {
			return pool.Hash32{}, fmt.Errorf("verify stored pool state: %w", err)
		}
		if latest.PaymentSequence > 1 {
			return pool.Hash32{}, fmt.Errorf("%w: a higher cumulative payment state already exists", pool.ErrNonFinalRejected)
		}
	}
	unsignedRefund, err := client.transactions.BuildRefundSubmission(opening)
	if err != nil {
		return pool.Hash32{}, err
	}
	txID, err := client.transactions.TransactionID(opening.RefundTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	if txID != spendTxID {
		return pool.Hash32{}, fmt.Errorf("%w: stored opening proof does not match requested SpendTxID", pool.ErrInvalidEvidence)
	}
	submittedTxID, err := client.transactions.TransactionID(unsignedRefund)
	if err != nil {
		return pool.Hash32{}, err
	}
	accepted, err := client.node.SubmitFinal(ctx, append([]byte(nil), unsignedRefund...))
	if err != nil {
		return pool.Hash32{}, fmt.Errorf("%w: submit refund: %v", pool.ErrFinalRejected, err)
	}
	if accepted != submittedTxID {
		return pool.Hash32{}, fmt.Errorf("%w: refund node returned inconsistent transaction ID", pool.ErrInvalidEvidence)
	}
	return submittedTxID, nil
}

func (client *Client) BuildImmediateClose(ctx context.Context, input pool.CloseInput) (*pool.PaymentState, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
	}
	localInput := pool.CloneCloseInput(input)
	unsigned, err := client.transactions.BuildImmediateClose(ctx, localInput)
	if err != nil {
		return nil, err
	}
	state, err := client.transactions.SignBuyerPayment(ctx, unsigned, client.signer)
	if err != nil {
		return nil, err
	}
	if state == nil || state.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: immediate close is not final", pool.ErrInvalidEvidence)
	}
	if err := client.transactions.VerifyFinalPayment(state, localInput.Opening); err != nil {
		return nil, fmt.Errorf("verify immediate close: %w", err)
	}
	return state, nil
}

func (client *Client) SubmitImmediateClose(ctx context.Context, close *pool.SignedPayment) (pool.Hash32, error) {
	if client == nil {
		return pool.Hash32{}, errors.New("buyer client is required")
	}
	if client.node == nil {
		return pool.Hash32{}, errors.New("buyer client has no final pool node")
	}
	localClose := pool.CloneSignedPayment(close)
	if localClose == nil || localClose.State.PaymentSequence != ^uint32(0) || len(localClose.RawTx) == 0 || !bytes.Equal(localClose.State.RawTx, localClose.RawTx) {
		return pool.Hash32{}, fmt.Errorf("%w: final signed payment is required", pool.ErrInvalidEvidence)
	}
	opening, err := client.pools.LoadOpeningProof(ctx, localClose.State.SpendTxID)
	if err != nil {
		return pool.Hash32{}, err
	}
	opening = pool.CloneOpeningProof(opening)
	if err := client.transactions.VerifyCompletedFinalPayment(localClose, opening); err != nil {
		return pool.Hash32{}, fmt.Errorf("verify final payment: %w", err)
	}
	txID, err := client.transactions.TransactionID(localClose.RawTx)
	if err != nil {
		return pool.Hash32{}, err
	}
	accepted, err := client.node.SubmitFinal(ctx, append([]byte(nil), localClose.RawTx...))
	if err != nil {
		return pool.Hash32{}, fmt.Errorf("%w: %v", pool.ErrFinalRejected, err)
	}
	if accepted != txID {
		return pool.Hash32{}, fmt.Errorf("%w: final node returned inconsistent transaction ID", pool.ErrInvalidEvidence)
	}
	if err := client.pools.SaveAcceptedPayment(ctx, &localClose.State); err != nil {
		return pool.Hash32{}, fmt.Errorf("save immediate close: %w", err)
	}
	return txID, nil
}

type ContentRequestInput struct {
	QuoteTermsHash        bitfs.Hash32
	Pool                  pool.Reference
	SelectedArbiterPubKey []byte
	Content               bitfs.ContentRef
	DeliveryDeadline      bitfs.UnixSeconds
}

func (client *Client) RequestContent(ctx context.Context, input ContentRequestInput) (*bitfs.SignedContentRequest, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
	}
	selectedArbiter := append([]byte(nil), input.SelectedArbiterPubKey...)
	contentHash := append([]byte(nil), input.Content.Hash...)
	quote, err := client.quotes.LoadQuote(ctx, input.QuoteTermsHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	terms, err := bitfs.VerifySignedFileQuoteAt(quote, client.clock(), client.quoteVerifier)
	if err != nil {
		return nil, err
	}
	publicKey, err := client.signer.PublicKey(ctx)
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
	if input.DeliveryDeadline <= bitfs.UnixSeconds(client.clock().Unix()) {
		return nil, fmt.Errorf("%w: delivery deadline is not in the future", bitfs.ErrDeliveryDeadline)
	}
	opening, err := client.pools.LoadOpeningProof(ctx, input.Pool.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := client.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := client.participants.VerifyPoolParticipants(opening, terms.BuyerPubkey, quote.SellerPubkey, selectedArbiter); err != nil {
		return nil, fmt.Errorf("verify pool participants: %w", err)
	}
	previous, err := client.pools.LoadAcceptedPayment(ctx, input.Pool.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.SpendTxID != input.Pool.SpendTxID || previous.PaymentSequence != input.Pool.BasePaymentSequence {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := client.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	seed, err := client.seedForContent(ctx, terms, bitfs.ContentRef{Type: input.Content.Type, Hash: contentHash})
	if err != nil {
		return nil, err
	}
	if err := bitfs.VerifyContentReference(terms, input.Content.Type, contentHash, seed, input.Content.Type == bitfs.ContentBlock); err != nil {
		return nil, err
	}
	quoteHash, err := bitfs.FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestTerms := &bitfs.ContentRequestTerms{
		QuoteTermsHash:        quoteHash[:],
		SpendTxID:             input.Pool.SpendTxID[:],
		BasePaymentSequence:   uint64(input.Pool.BasePaymentSequence),
		SelectedArbiterPubkey: selectedArbiter,
		ContentType:           input.Content.Type,
		ContentHash:           contentHash,
		DeliveryDeadlineUnix:  int64(input.DeliveryDeadline),
	}
	raw, err := bitfs.EncodeContentRequestTerms(requestTerms)
	if err != nil {
		return nil, err
	}
	signature, err := client.signer.Sign(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("sign content request: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("buyer signature is required")
	}
	return &bitfs.SignedContentRequest{TermsCBOR: raw, BuyerSignature: append([]byte(nil), signature...)}, nil
}

func (client *Client) AcceptDelivery(ctx context.Context, request *bitfs.SignedContentRequest, delivery *bitfs.SignedContentDelivery) (*pool.PaymentUpdate, error) {
	if client == nil {
		return nil, errors.New("buyer client is required")
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
	quote, err := client.quotes.LoadQuote(ctx, quoteHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	seed, err := client.seedForContent(ctx, quoteTerms, bitfs.ContentRef{Type: requestTerms.ContentType, Hash: requestTerms.ContentHash})
	if err != nil {
		return nil, err
	}
	payload, err := bitfs.VerifySignedContentDeliveryWithSeedAt(localRequest, localDelivery, quote, seed, client.clock(), client.quoteVerifier, client.signatureVerifier, client.signatureVerifier)
	if err != nil {
		return nil, err
	}
	spendTxID := poolHash32(requestTerms.SpendTxID)
	opening, err := client.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := client.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := client.participants.VerifyPoolParticipants(opening, quoteTerms.BuyerPubkey, quote.SellerPubkey, requestTerms.SelectedArbiterPubkey); err != nil {
		return nil, fmt.Errorf("verify pool participants: %w", err)
	}
	previous, err := client.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, bitfs.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := client.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, requestTerms.ContentType, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	if ^uint64(0)-previous.SellerAmountSat < price {
		return nil, bitfs.ErrInsufficientBalance
	}
	if previous.PaymentSequence >= 0xfffffffe {
		return nil, fmt.Errorf("%w: payment sequence exhausted", bitfs.ErrStalePaymentSequence)
	}
	input := pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequenceAfter: previous.PaymentSequence + 1,
		SellerAmountAfterSat: previous.SellerAmountSat + price,
	}
	if err := client.transactions.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	unsigned, err := client.transactions.BuildPaymentUpdate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("build payment update: %w", err)
	}
	state, err := client.transactions.SignBuyerPayment(ctx, unsigned, client.signer)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("%w: transaction engine returned empty payment state", bitfs.ErrInvalidEvidence)
	}
	if err := client.transactions.VerifyBuyerPayment(state, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	if state == nil || state.SpendTxID != spendTxID || state.PaymentSequence <= previous.PaymentSequence {
		return nil, fmt.Errorf("%w: signed payment state is stale", bitfs.ErrStalePaymentSequence)
	}
	if client.contentSink != nil {
		if err := client.contentSink.SaveVerifiedContent(ctx, hash32(requestTerms.ContentHash), payload); err != nil {
			return nil, fmt.Errorf("save verified content: %w", err)
		}
	}
	requestHash, err := bitfs.ContentRequestTermsHash(localRequest.TermsCBOR)
	if err != nil {
		return nil, err
	}
	return &pool.PaymentUpdate{
		Version:                 pool.MajorVersion,
		ContentRequestTermsHash: requestHash[:],
		PartialSpendTx:          append([]byte(nil), state.RawTx...),
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

func (client *Client) seedForContent(ctx context.Context, quoteTerms *bitfs.FileQuoteTerms, content bitfs.ContentRef) ([]byte, error) {
	if content.Type == bitfs.ContentSeed {
		return nil, nil
	}
	if client.seedSource == nil {
		return nil, fmt.Errorf("%w: a verified seed is required before requesting a block", bitfs.ErrContentNotInSeed)
	}
	seedHash := hash32(quoteTerms.SeedHash)
	seed, err := client.seedSource.LoadSeed(ctx, seedHash)
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
