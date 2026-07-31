package seller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/bsv8/go-bitfs/arbiter"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

type QuoteStore interface {
	SaveQuote(context.Context, *bitfs.SignedFileQuote) error
	LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

type ContentSource interface {
	LoadContent(context.Context, bitfs.Hash32) ([]byte, error)
}

type ServiceConfig struct {
	Signer            pool.Signer
	SignatureVerifier bitfs.ContentTermsSignatureVerifier
	QuoteVerifier     bitfs.QuoteTermsSignatureVerifier
	Clock             func() time.Time
	Quotes            QuoteStore
	Pools             pool.PoolStore
	OpeningHooks      pool.SellerPoolOpeningHooks
	Pending           pool.PendingRequestStore
	Content           ContentSource
	Transactions      pool.TransactionEngine
	Participants      pool.ParticipantVerifier
	Node              pool.NonFinalPoolNode
}

type Service struct {
	signer            pool.Signer
	signatureVerifier bitfs.ContentTermsSignatureVerifier
	quoteVerifier     bitfs.QuoteTermsSignatureVerifier
	clock             func() time.Time
	quotes            QuoteStore
	pools             pool.PoolStore
	openingHooks      pool.SellerPoolOpeningHooks
	pending           pool.PendingRequestStore
	content           ContentSource
	transactions      pool.TransactionEngine
	participants      pool.ParticipantVerifier
	node              pool.NonFinalPoolNode
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Signer == nil || config.SignatureVerifier == nil || config.QuoteVerifier == nil {
		return nil, errors.New("seller service requires signer and signature verifiers")
	}
	if config.Quotes == nil || config.Pools == nil || config.OpeningHooks == nil || config.Pending == nil || config.Content == nil || config.Transactions == nil || config.Participants == nil || config.Node == nil {
		return nil, errors.New("seller service requires quote, pool, opening, pending, content, transaction, participant and node ports")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{
		signer:            config.Signer,
		signatureVerifier: config.SignatureVerifier,
		quoteVerifier:     config.QuoteVerifier,
		clock:             config.Clock,
		quotes:            config.Quotes,
		pools:             config.Pools,
		openingHooks:      config.OpeningHooks,
		pending:           config.Pending,
		content:           config.Content,
		transactions:      config.Transactions,
		participants:      config.Participants,
		node:              config.Node,
	}, nil
}

func (service *Service) CreateQuote(ctx context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	draft = cloneFileQuoteTermsSeller(&draft)
	publicKey, err := service.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load seller public key: %w", err)
	}
	quote, err := bitfs.NewSignedFileQuote(&draft, publicKey, recommendedFilename, func(raw []byte) ([]byte, error) {
		return service.signer.Sign(ctx, raw)
	})
	if err != nil {
		return nil, err
	}
	if err := service.quotes.SaveQuote(ctx, cloneSignedFileQuoteForSeller(quote)); err != nil {
		return nil, fmt.Errorf("save quote: %w", err)
	}
	return quote, nil
}

func (service *Service) PresignPoolOpening(ctx context.Context, request *pool.RefundPresignRequest) (*pool.RefundPresignResponse, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	return pool.SellerPresignRefund(ctx, pool.CloneRefundPresignRequest(request), service.openingHooks)
}

func (service *Service) AcceptPoolFunding(ctx context.Context, delivery *pool.FundingTxDelivery) (*pool.OpeningProof, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	proof, err := pool.SellerAcceptFundingTx(ctx, pool.CloneFundingTxDelivery(delivery), service.openingHooks)
	if err != nil {
		return nil, err
	}
	initial, err := service.transactions.ParsePaymentState(ctx, proof.RefundTx, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if err := service.transactions.VerifyAcceptedPayment(initial, proof); err != nil {
		return nil, fmt.Errorf("verify initial pool state: %w", err)
	}
	if err := service.pools.SaveAcceptedPayment(ctx, initial); err != nil {
		return nil, fmt.Errorf("save initial pool state: %w", err)
	}
	return proof, nil
}

func (service *Service) DeliverRequestedContent(ctx context.Context, request *bitfs.SignedContentRequest) (delivery *bitfs.SignedContentDelivery, err error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	request = bitfs.CloneSignedContentRequest(request)
	if request == nil {
		return nil, fmt.Errorf("%w: signed content request is required", bitfs.ErrInvalidEvidence)
	}
	requestTerms, err := bitfs.DecodeContentRequestTerms(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	quoteHash := sellerHash32(requestTerms.QuoteTermsHash)
	quote, err := service.quotes.LoadQuote(ctx, quoteHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	var seed []byte
	if requestTerms.ContentType == bitfs.ContentBlock {
		seedHash := sellerHash32(quoteTerms.SeedHash)
		seed, err = service.content.LoadContent(ctx, seedHash)
		if err != nil {
			return nil, fmt.Errorf("load seed for block membership: %w", err)
		}
		seed = append([]byte(nil), seed...)
	}
	_, err = bitfs.VerifySignedContentRequestWithSeedAt(request, quote, seed, service.clock(), service.quoteVerifier, service.signatureVerifier)
	if err != nil {
		return nil, err
	}
	sellerPubkey, err := service.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load seller public key: %w", err)
	}
	if !bytes.Equal(sellerPubkey, quote.SellerPubkey) {
		return nil, fmt.Errorf("%w: service signer does not match quote seller", bitfs.ErrInvalidEvidence)
	}
	spendTxID := poolHash32Seller(requestTerms.SpendTxID)
	opening, err := service.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := service.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	if err := service.participants.VerifyPoolParticipants(opening, quoteTerms.BuyerPubkey, quote.SellerPubkey, requestTerms.SelectedArbiterPubkey); err != nil {
		return nil, fmt.Errorf("verify pool participants: %w", err)
	}
	previous, err := service.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.SpendTxID != spendTxID || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, pool.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := service.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	payload, err := service.content.LoadContent(ctx, sellerHash32(requestTerms.ContentHash))
	if err != nil {
		return nil, fmt.Errorf("load content: %w", err)
	}
	payload = append([]byte(nil), payload...)
	if err := bitfs.VerifyContentPayload(quoteTerms, requestTerms.ContentType, requestTerms.ContentHash, payload, seed, true); err != nil {
		return nil, err
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, requestTerms.ContentType, uint64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("calculate content price: %w", err)
	}
	if ^uint64(0)-previous.SellerAmountSat < price {
		return nil, pool.ErrInsufficientBalance
	}
	if previous.PaymentSequence >= 0xfffffffe {
		return nil, pool.ErrStalePaymentSequence
	}
	if err := service.transactions.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequenceAfter: previous.PaymentSequence + 1,
		SellerAmountAfterSat: previous.SellerAmountSat + price,
		// The buyer chooses the actual miner fee in 005. Zero here is the
		// conservative pre-delivery capacity check; the signed transaction is
		// checked again with its actual outputs when accepted.
		MinerFeeSat: 0,
	}); err != nil {
		return nil, fmt.Errorf("check delivery payment capacity: %w", err)
	}
	requestHash, err := bitfs.ContentRequestTermsHash(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	acquireResult, err := service.pending.TryAcquire(ctx, pool.PendingRequest{
		SpendTxID:               spendTxID,
		BasePaymentSequence:     uint32(requestTerms.BasePaymentSequence),
		ContentRequestHash:      poolHash32Seller(requestHash[:]),
		ExpectedSellerAmountSat: price,
	})
	if err != nil {
		return nil, fmt.Errorf("acquire pending request: %w", err)
	}
	if acquireResult != pool.PendingAcquired {
		return nil, pool.ErrPoolBusy
	}
	keepPending := false
	defer func() {
		if !keepPending {
			_ = service.pending.Release(ctx, spendTxID, poolHash32Seller(requestHash[:]))
		}
	}()
	delivery, err = bitfs.NewSignedContentDelivery(request, append([]byte(nil), payload...), func(raw []byte) ([]byte, error) {
		return service.signer.Sign(ctx, raw)
	})
	if err != nil {
		return nil, err
	}
	if _, err := bitfs.VerifySignedContentDeliveryWithSeedAt(request, delivery, quote, seed, service.clock(), service.quoteVerifier, service.signatureVerifier, service.signatureVerifier); err != nil {
		return nil, err
	}
	keepPending = true
	return delivery, nil
}

func (service *Service) AcceptPayment(ctx context.Context, update *pool.PaymentUpdate) (*pool.PaymentState, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	update = pool.ClonePaymentUpdate(update)
	if err := pool.ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	fundingTxID, err := service.transactions.FundingTxID(append([]byte(nil), update.PartialSpendTx...))
	if err != nil {
		return nil, fmt.Errorf("read payment funding outpoint: %w", err)
	}
	opening, err := service.pools.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	if err := service.transactions.VerifyOpening(opening); err != nil {
		return nil, fmt.Errorf("verify pool opening proof: %w", err)
	}
	spendTxID, err := service.transactions.TransactionID(opening.RefundTx)
	if err != nil {
		return nil, fmt.Errorf("calculate spend transaction ID: %w", err)
	}
	state, err := service.transactions.ParsePaymentState(ctx, append([]byte(nil), update.PartialSpendTx...), opening)
	if err != nil {
		return nil, fmt.Errorf("parse payment state: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("%w: empty payment state", pool.ErrInvalidEvidence)
	}
	if state.SpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: payment state spend transaction mismatch", pool.ErrInvalidEvidence)
	}
	if err := service.transactions.VerifyBuyerPayment(state, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	pending, err := service.pending.Load(ctx, state.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending request: %w", err)
	}
	previous, err := service.pools.LoadAcceptedPayment(ctx, state.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := service.transactions.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify previous accepted payment: %w", err)
	}
	if state.SellerAmountSat < previous.SellerAmountSat {
		return nil, fmt.Errorf("%w: seller amount cannot decrease", pool.ErrInvalidEvidence)
	}
	requestHash := poolHash32Seller(update.ContentRequestTermsHash)
	if pending == nil {
		if previous != nil && previous.PaymentSequence == state.PaymentSequence && previous.SellerAmountSat == state.SellerAmountSat && previous.ClientAmountSat == state.ClientAmountSat && previous.ContentRequestTermsHash == requestHash {
			return clonePaymentStateSeller(previous), nil
		}
		return nil, pool.ErrStalePaymentSequence
	}
	if pending.ContentRequestHash != requestHash {
		return nil, pool.ErrStalePaymentSequence
	}
	if ^uint64(0)-previous.SellerAmountSat < pending.ExpectedSellerAmountSat || state.SellerAmountSat != previous.SellerAmountSat+pending.ExpectedSellerAmountSat {
		return nil, fmt.Errorf("%w: payment seller amount does not match the verified content price", pool.ErrInvalidEvidence)
	}
	if previous != nil && previous.PaymentSequence == state.PaymentSequence && previous.SellerAmountSat == state.SellerAmountSat && previous.ClientAmountSat == state.ClientAmountSat && previous.ContentRequestTermsHash == requestHash {
		if err := service.pending.Release(ctx, state.SpendTxID, pending.ContentRequestHash); err != nil {
			return nil, fmt.Errorf("release pending request: %w", err)
		}
		return clonePaymentStateSeller(previous), nil
	}
	if state.PaymentSequence <= previous.PaymentSequence || state.PaymentSequence <= pending.BasePaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	signed, err := service.transactions.AddSellerSignature(ctx, state, service.signer)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: seller returned empty signed payment", pool.ErrInvalidEvidence)
	}
	acceptance, err := service.node.SubmitUpdate(ctx, signed.RawTx)
	if err != nil {
		return nil, fmt.Errorf("%w: submit payment update: %v", pool.ErrNonFinalRejected, err)
	}
	txID, err := service.transactions.TransactionID(signed.RawTx)
	if err != nil {
		return nil, fmt.Errorf("calculate accepted transaction ID: %w", err)
	}
	if acceptance == nil || acceptance.SpendTxID != state.SpendTxID || acceptance.PaymentSequence != signed.State.PaymentSequence || acceptance.TxID != txID {
		return nil, fmt.Errorf("%w: node returned inconsistent payment acceptance", pool.ErrInvalidEvidence)
	}
	accepted := signed.State
	accepted.RawTx = append([]byte(nil), signed.RawTx...)
	accepted.ContentRequestTermsHash = requestHash
	if err := service.pools.SaveAcceptedPayment(ctx, &accepted); err != nil {
		return nil, fmt.Errorf("save accepted payment: %w", err)
	}
	if err := service.pending.Release(ctx, state.SpendTxID, pending.ContentRequestHash); err != nil {
		return nil, fmt.Errorf("release pending request: %w", err)
	}
	return clonePaymentStateSeller(&accepted), nil
}

// SignImmediateClose complements the buyer's final close signature. It does
// not submit or alter pool state; the buyer decides when to call SubmitFinal.
func (service *Service) SignImmediateClose(ctx context.Context, state *pool.PaymentState) (*pool.SignedPayment, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	state = pool.ClonePaymentState(state)
	if state == nil || state.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: immediate close must use the final sequence", pool.ErrInvalidEvidence)
	}
	opening, err := service.pools.LoadOpeningProof(ctx, state.SpendTxID)
	if err != nil {
		return nil, err
	}
	opening = pool.CloneOpeningProof(opening)
	if err := service.transactions.VerifyOpening(opening); err != nil {
		return nil, err
	}
	fundingTxID, err := service.transactions.FundingTxID(state.RawTx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(fundingTxID[:], opening.FundingTxID) {
		return nil, fmt.Errorf("%w: close does not spend opening funding output", pool.ErrInvalidEvidence)
	}
	if err := service.transactions.VerifyFinalPayment(state, opening); err != nil {
		return nil, fmt.Errorf("verify buyer close signature: %w", err)
	}
	latest, err := service.pools.LoadAcceptedPayment(ctx, state.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load latest accepted payment: %w", err)
	}
	if latest == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	latest = pool.ClonePaymentState(latest)
	if err := service.transactions.VerifyAcceptedPayment(latest, opening); err != nil {
		return nil, fmt.Errorf("verify latest accepted payment: %w", err)
	}
	if state.SellerAmountSat < latest.SellerAmountSat {
		return nil, fmt.Errorf("%w: immediate close cannot reduce seller amount", pool.ErrInvalidEvidence)
	}
	stateCopy := *state
	stateCopy.PoolOutputSatoshis = opening.PoolOutputSatoshis
	stateCopy.PoolLockingScript = append([]byte(nil), opening.PoolLockingScript...)
	signed, err := service.transactions.AddSellerSignature(ctx, &stateCopy, service.signer)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.State.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: seller close signature did not preserve final sequence", pool.ErrInvalidEvidence)
	}
	return signed, nil
}

// BuildArbitrationRequest packages the exact opening proof and buyer-signed
// payment bytes required by 007.  It does not look up missing evidence from
// the arbiter or recalculate any content price.
func (service *Service) BuildArbitrationRequest(ctx context.Context, proof *pool.OpeningProof, update *pool.PaymentUpdate) (*arbiter.PaymentSignatureRequest, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	proof = pool.CloneOpeningProof(proof)
	update = pool.ClonePaymentUpdate(update)
	if err := pool.ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	if err := pool.ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	if err := service.transactions.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify opening proof: %w", err)
	}
	fundingTxID, err := service.transactions.FundingTxID(update.PartialSpendTx)
	if err != nil {
		return nil, fmt.Errorf("read payment funding outpoint: %w", err)
	}
	if !bytes.Equal(fundingTxID[:], proof.FundingTxID) {
		return nil, fmt.Errorf("%w: payment does not spend opening funding transaction", pool.ErrInvalidEvidence)
	}
	state, err := service.transactions.ParsePaymentState(ctx, update.PartialSpendTx, proof)
	if err != nil {
		return nil, fmt.Errorf("parse payment state: %w", err)
	}
	spendTxID, err := service.transactions.TransactionID(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	if state == nil || state.SpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: arbitration payment does not match SpendTxID", pool.ErrInvalidEvidence)
	}
	if err := service.transactions.VerifyBuyerPayment(state, proof); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	openingCBOR, err := pool.EncodeOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	updateCBOR, err := pool.EncodePaymentUpdate(update)
	if err != nil {
		return nil, err
	}
	return &arbiter.PaymentSignatureRequest{Version: arbiter.MajorVersion, PoolOpeningProofCBOR: openingCBOR, LatestPaymentStateCBOR: updateCBOR}, nil
}

// SubmitArbitratedPayment verifies the arbiter response against the exact
// evidence bytes, combines the arbiter signature, and asks the node to accept
// that non-final cumulative payment. The node response remains authoritative
// for persistence.
func (service *Service) SubmitArbitratedPayment(ctx context.Context, request *arbiter.PaymentSignatureRequest, response *arbiter.PaymentSignatureResponse) (*pool.PaymentState, error) {
	if service == nil {
		return nil, errors.New("seller service is required")
	}
	request = cloneArbitrationRequestSeller(request)
	response = cloneArbitrationResponseSeller(response)
	if request == nil || response == nil {
		return nil, fmt.Errorf("%w: arbitration request and response are required", pool.ErrInvalidEvidence)
	}
	if _, err := arbiter.MarshalRequest(request); err != nil {
		return nil, err
	}
	if _, err := arbiter.MarshalResponse(response); err != nil {
		return nil, err
	}
	expectedHash := sha256.Sum256(request.LatestPaymentStateCBOR)
	if !bytes.Equal(expectedHash[:], response.LatestPaymentStateHash) {
		return nil, fmt.Errorf("%w: arbitration response does not bind latest payment evidence", pool.ErrInvalidEvidence)
	}
	proof, err := pool.DecodeOpeningProof(request.PoolOpeningProofCBOR)
	if err != nil {
		return nil, err
	}
	if err := service.transactions.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify arbitration opening proof: %w", err)
	}
	update, err := pool.DecodePaymentUpdate(request.LatestPaymentStateCBOR)
	if err != nil {
		return nil, err
	}
	state, err := service.transactions.ParsePaymentState(ctx, update.PartialSpendTx, proof)
	if err != nil {
		return nil, err
	}
	spendTxID, err := service.transactions.TransactionID(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	if state == nil || state.SpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: arbitration payment does not match SpendTxID", pool.ErrInvalidEvidence)
	}
	if err := service.transactions.VerifyBuyerPayment(state, proof); err != nil {
		return nil, err
	}
	requestHash := poolHash32Seller(update.ContentRequestTermsHash)
	previous, err := service.pools.LoadAcceptedPayment(ctx, state.SpendTxID)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := service.transactions.VerifyAcceptedPayment(previous, proof); err != nil {
		return nil, fmt.Errorf("verify previous accepted payment: %w", err)
	}
	if previous.PaymentSequence == state.PaymentSequence && previous.SellerAmountSat == state.SellerAmountSat && previous.ClientAmountSat == state.ClientAmountSat && previous.ContentRequestTermsHash == requestHash {
		return clonePaymentStateSeller(previous), nil
	}
	if state.PaymentSequence <= previous.PaymentSequence {
		return nil, pool.ErrStalePaymentSequence
	}
	if state.SellerAmountSat < previous.SellerAmountSat {
		return nil, fmt.Errorf("%w: arbitrated seller amount cannot decrease", pool.ErrInvalidEvidence)
	}
	signed, err := service.transactions.AddArbiterSignature(ctx, state, response.ArbiterTransactionSignature)
	if err != nil {
		return nil, fmt.Errorf("combine arbiter signature: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: arbiter returned empty transaction", pool.ErrInvalidEvidence)
	}
	txID, err := service.transactions.TransactionID(signed.RawTx)
	if err != nil {
		return nil, err
	}
	acceptance, err := service.node.SubmitUpdate(ctx, signed.RawTx)
	if err != nil {
		return nil, fmt.Errorf("%w: submit arbitrated payment: %v", pool.ErrNonFinalRejected, err)
	}
	if acceptance == nil || acceptance.TxID != txID || acceptance.SpendTxID != state.SpendTxID || acceptance.PaymentSequence != state.PaymentSequence {
		return nil, fmt.Errorf("%w: non-final node returned inconsistent arbitration acceptance", pool.ErrInvalidEvidence)
	}
	accepted := signed.State
	accepted.RawTx = append([]byte(nil), signed.RawTx...)
	accepted.ContentRequestTermsHash = requestHash
	if err := service.pools.SaveAcceptedPayment(ctx, &accepted); err != nil {
		return nil, fmt.Errorf("save arbitrated payment: %w", err)
	}
	pending, err := service.pending.Load(ctx, accepted.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending arbitration request: %w", err)
	}
	if pending != nil && pending.ContentRequestHash == accepted.ContentRequestTermsHash {
		if err := service.pending.Release(ctx, accepted.SpendTxID, pending.ContentRequestHash); err != nil {
			return nil, fmt.Errorf("release pending arbitration request: %w", err)
		}
	}
	return clonePaymentStateSeller(&accepted), nil
}

func sellerHash32(raw []byte) bitfs.Hash32 {
	var result bitfs.Hash32
	copy(result[:], raw)
	return result
}

func poolHash32Seller(raw []byte) pool.Hash32 {
	var result pool.Hash32
	copy(result[:], raw)
	return result
}

func cloneFileQuoteTermsSeller(terms *bitfs.FileQuoteTerms) bitfs.FileQuoteTerms {
	if terms == nil {
		return bitfs.FileQuoteTerms{}
	}
	cloned := *terms
	cloned.SeedHash = append([]byte(nil), terms.SeedHash...)
	cloned.BuyerPubkey = append([]byte(nil), terms.BuyerPubkey...)
	cloned.SupportedArbiterPubkeysCBOR = append([]byte(nil), terms.SupportedArbiterPubkeysCBOR...)
	return cloned
}

func cloneArbitrationRequestSeller(request *arbiter.PaymentSignatureRequest) *arbiter.PaymentSignatureRequest {
	if request == nil {
		return nil
	}
	return &arbiter.PaymentSignatureRequest{
		Version:                request.Version,
		PoolOpeningProofCBOR:   append([]byte(nil), request.PoolOpeningProofCBOR...),
		LatestPaymentStateCBOR: append([]byte(nil), request.LatestPaymentStateCBOR...),
	}
}

func cloneArbitrationResponseSeller(response *arbiter.PaymentSignatureResponse) *arbiter.PaymentSignatureResponse {
	if response == nil {
		return nil
	}
	return &arbiter.PaymentSignatureResponse{
		Version:                     response.Version,
		LatestPaymentStateHash:      append([]byte(nil), response.LatestPaymentStateHash...),
		ArbiterTransactionSignature: append([]byte(nil), response.ArbiterTransactionSignature...),
	}
}

func cloneSignedFileQuoteForSeller(quote *bitfs.SignedFileQuote) *bitfs.SignedFileQuote {
	if quote == nil {
		return nil
	}
	return &bitfs.SignedFileQuote{TermsCBOR: append([]byte(nil), quote.TermsCBOR...), SellerPubkey: append([]byte(nil), quote.SellerPubkey...), TermsSignature: append([]byte(nil), quote.TermsSignature...), RecommendedFilename: bitfs.SanitizeRecommendedFilename(quote.RecommendedFilename)}
}

func clonePaymentStateSeller(state *pool.PaymentState) *pool.PaymentState {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.RawTx = append([]byte(nil), state.RawTx...)
	cloned.PoolLockingScript = append([]byte(nil), state.PoolLockingScript...)
	return &cloned
}
