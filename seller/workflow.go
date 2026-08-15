package seller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	masterseed "github.com/bsv8/MasterSeed"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
)

// QuoteStore stores seller-signed 001 quote credentials addressed by canonical
// terms hash so later 003 requests can be independently verified.
type QuoteStore interface {
	SaveQuote(context.Context, *bitfs.SignedFileQuote) error
	LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}

// ContentSource reads raw seed or block bytes selected by a validated content
// request. The workflow re-verifies every loaded result before use.
type ContentSource interface {
	LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
	LoadBlock(context.Context, masterseed.Digest) ([]byte, error)
}

// WorkflowConfig supplies every seller dependency: signer, quote/pool/pending
// stores, content source, and the raw backend used for funding, updates, and
// final settlement. The workflow constructs the verified node internally.
type WorkflowConfig struct {
	Signer  pool.Signer
	Quotes  QuoteStore
	Pools   pool.PoolStore
	Pending pool.PendingRequestStore
	Content ContentSource
	Backend pool.PoolBackend
}

// Workflow implements the seller side of 001–007. It creates quotes, completes
// pool opening, serializes content delivery, verifies buyer payments, and
// prepares or submits arbiter-authorized states through the fixed core and
// internally verified backend boundary.
type Workflow struct {
	signer  pool.Signer
	quotes  QuoteStore
	pools   pool.PoolStore
	pending pool.PendingRequestStore
	content ContentSource
	node    *pool.VerifiedNonFinalPoolNode
}

func fixedSellerVerify(pub, payload, sig []byte) error {
	return bitfs.VerifySignature(pub, payload, sig)
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
		height, err := workflow.node.BlockHeight(ctx)
		if err != nil {
			return nil, err
		}
		config.BlockHeight = func() uint32 { return height }
	}
	return pool.NewMultisigPoolEngine(config)
}

// NewWorkflow validates all mandatory seller dependencies and returns a workflow.
// Missing signing, storage, content, or node dependencies are rejected before
// any side effect.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Signer == nil || config.Quotes == nil || config.Pools == nil || config.Pending == nil || config.Content == nil || config.Backend == nil {
		return nil, errors.New("seller workflow requires signer, stores, content, and node backend")
	}
	node, err := pool.NewVerifiedNonFinalPoolNode(config.Pools, config.Backend)
	if err != nil {
		return nil, err
	}
	return &Workflow{
		signer:  config.Signer,
		quotes:  config.Quotes,
		pools:   config.Pools,
		pending: config.Pending,
		content: config.Content,
		node:    node,
	}, nil
}

// CreateQuote signs deterministic 001 quote terms with the seller key, persists
// the complete credential by its terms hash, and returns an owned copy. The
// recommended filename is display metadata and is not part of the signature.
func (workflow *Workflow) CreateQuote(ctx context.Context, draft bitfs.FileQuoteTerms, recommendedFilename string) (*bitfs.SignedFileQuote, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	draft = cloneFileQuoteTermsSeller(&draft)
	now := time.Now().UTC()
	if err := bitfs.ValidateFileQuoteTermsAt(&draft, now); err != nil {
		return nil, err
	}
	publicKey, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load seller public key: %w", err)
	}
	quote, err := bitfs.NewSignedFileQuote(&draft, publicKey, recommendedFilename, func(raw []byte) ([]byte, error) {
		digest := sha256.Sum256(raw)
		return workflow.signer.Sign(ctx, digest[:])
	})
	if err != nil {
		return nil, err
	}
	if _, err := bitfs.VerifySignedFileQuoteAt(quote, now, fixedSellerVerify); err != nil {
		return nil, fmt.Errorf("verify generated quote: %w", err)
	}
	if err := workflow.quotes.SaveQuote(ctx, cloneSignedFileQuoteForSeller(quote)); err != nil {
		return nil, fmt.Errorf("save quote: %w", err)
	}
	return quote, nil
}

// PresignPoolOpening prepares and records the presigned pool-opening evidence.
func (workflow *Workflow) PresignPoolOpening(ctx context.Context, request *pool.RefundPresignRequest) (*pool.RefundPresignResponse, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	request = pool.CloneRefundPresignRequest(request)
	if err := pool.ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey})
	if err != nil {
		return nil, err
	}
	sig, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerRefund(ctx, request)
	if err != nil {
		return nil, err
	}
	proof := &pool.OpeningProof{Version: pool.MajorVersion, MultisigProtocol: pool.MultisigProtocol, MultisigVersion: pool.MultisigVersion, RefundTx: request.RefundTx, FundingTxID: request.FundingTxID, PoolOutputIndex: request.PoolOutputIndex, PoolOutputSatoshis: request.PoolOutputSatoshis, PoolLockingScript: request.PoolLockingScript, BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey, MinerFeeRateSatPerKB: request.MinerFeeRateSatPerKB, BuyerRefundSignature: request.BuyerRefundSignature, SellerRefundSignature: sig}
	if err := engine.VerifySellerRefundSignature(ctx, request, sig); err != nil {
		return nil, err
	}
	spendTxID, err := engine.TransactionID(request.RefundTx)
	if err != nil {
		return nil, fmt.Errorf("calculate opening spend transaction ID: %w", err)
	}
	proof.SpendTxID = append([]byte(nil), spendTxID[:]...)
	if err := workflow.pools.SaveOpeningProof(ctx, proof); err != nil {
		return nil, err
	}
	return &pool.RefundPresignResponse{Version: pool.MajorVersion, SellerRefundSignature: sig}, nil
}

// AcceptPoolFunding verifies the delivered funding transaction, completes the
// opening proof, and records the initial accepted refund state.
func (workflow *Workflow) AcceptPoolFunding(ctx context.Context, delivery *pool.FundingTxDelivery) (*pool.OpeningProof, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	delivery = pool.CloneFundingTxDelivery(delivery)
	if err := pool.ValidateFundingTxDelivery(delivery); err != nil {
		return nil, err
	}
	tx, err := pool.ParseCanonicalTransaction(delivery.FundingTx)
	if err != nil {
		return nil, err
	}
	var fundingID pool.Hash32
	copy(fundingID[:], tx.TxID().CloneBytes())
	proof, err := workflow.pools.LoadOpeningProofByFundingTxID(ctx, fundingID)
	if err != nil {
		return nil, err
	}
	proof = pool.CloneOpeningProof(proof)
	engine, err := workflow.engineFor(proof)
	if err != nil {
		return nil, err
	}
	spendID, err := engine.TransactionID(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	healthErr := workflow.pools.EnsurePoolHealthy(ctx, spendID)
	uncertain := errors.Is(healthErr, pool.ErrPoolStateUncertain)
	if healthErr != nil && !uncertain {
		return nil, healthErr
	}
	if len(proof.SpendTxID) != 32 || !bytes.Equal(proof.SpendTxID, spendID[:]) {
		return nil, fmt.Errorf("%w: stored opening proof SpendTxID does not match RefundTx", pool.ErrInvalidEvidence)
	}
	publicKey, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load seller public key: %w", err)
	}
	if !bytes.Equal(publicKey, proof.SellerPubKey) {
		return nil, fmt.Errorf("%w: workflow signer does not match opening seller", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyFundingTx(ctx, delivery.FundingTx, proof); err != nil {
		return nil, err
	}
	proof.FundingTx = append([]byte(nil), delivery.FundingTx...)
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if err := workflow.pools.SaveOpeningProof(ctx, proof); err != nil {
		return nil, err
	}
	// Build and verify the exact local initial state before network submission.
	// If the backend outcome is ambiguous, this is the PaymentState/raw txid
	// that ReconcileExternalState will later receive.
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		return nil, fmt.Errorf("assemble initial refund state: %w", err)
	}
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("parse initial pool state: %w", err)
	}
	if err := engine.VerifyAcceptedPayment(initial, proof); err != nil {
		return nil, fmt.Errorf("verify initial pool state: %w", err)
	}
	initialTxID, err := engine.TransactionID(initial.RawTx)
	if err != nil {
		return nil, fmt.Errorf("calculate initial pool state ID: %w", err)
	}
	if accepted, err := workflow.node.SubmitFunding(ctx, delivery.FundingTx); err != nil || accepted != fundingID {
		if err != nil {
			markErr := workflow.pools.MarkExternalStateUncertain(ctx, spendID, initialTxID)
			uncertainErr := fmt.Errorf("%w: funding backend outcome requires reconciliation: %v", pool.ErrPoolStateUncertain, err)
			if markErr != nil {
				return nil, errors.Join(uncertainErr, markErr)
			}
			return nil, uncertainErr
		}
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, spendID, initialTxID)
		uncertainErr := fmt.Errorf("%w: funding backend returned inconsistent transaction ID", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return nil, errors.Join(uncertainErr, markErr)
		}
		return nil, uncertainErr
	}
	if uncertain {
		if err := workflow.pools.ReconcileExternalState(ctx, initial.SpendTxID, initial); err != nil {
			return nil, fmt.Errorf("reconcile recovered initial pool state: %w", err)
		}
	} else if err := workflow.pools.SaveAcceptedPayment(ctx, initial); err != nil {
		uncertain := fmt.Errorf("%w: initial pool state was accepted externally but local persistence failed", pool.ErrPoolStateUncertain)
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, initial.SpendTxID, initialTxID)
		if markErr != nil {
			return nil, errors.Join(uncertain, err, markErr)
		}
		return nil, errors.Join(uncertain, err)
	}
	return proof, nil
}

// DeliverRequestedContent verifies the buyer's 003 request and its quote, reads
// the requested seed or block from ContentSource, and signs a 004 delivery. A
// pending-request lease prevents concurrent deliveries for the same pool.
func (workflow *Workflow) DeliverRequestedContent(ctx context.Context, request *bitfs.SignedContentRequest) (delivery *bitfs.SignedContentDelivery, err error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
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
	quote, err := workflow.quotes.LoadQuote(ctx, quoteHash)
	if err != nil {
		return nil, fmt.Errorf("load quote: %w", err)
	}
	quote = bitfs.CloneSignedFileQuote(quote)
	if quote == nil {
		return nil, fmt.Errorf("%w: quote store returned no quote", bitfs.ErrInvalidEvidence)
	}
	quoteTerms, err := bitfs.DecodeFileQuoteTerms(quote.TermsCBOR)
	if err != nil {
		return nil, err
	}
	// Authenticate the signed 003 request before touching ContentSource. This
	// prevents unauthenticated requests from causing seed/block storage I/O.
	now := time.Now().UTC()
	if _, err = bitfs.VerifySignedContentRequestAt(request, quote, now, fixedSellerVerify, fixedSellerVerify); err != nil {
		return nil, err
	}
	spendTxID := poolHash32Seller(requestTerms.SpendTxID)
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
	if err := validateSellerAuthorizationPool(requestTerms, opening); err != nil {
		return nil, err
	}
	if !bytes.Equal(opening.BuyerPubKey, quoteTerms.BuyerPubkey) || !bytes.Equal(opening.SellerPubKey, quote.SellerPubkey) {
		return nil, fmt.Errorf("%w: quote participants do not match opening proof", bitfs.ErrInvalidEvidence)
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil || previous.SpendTxID != spendTxID || previous.PaymentSequence != uint32(requestTerms.BasePaymentSequence) {
		return nil, pool.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify current pool state: %w", err)
	}
	if previous.PaymentSequence >= 0xfffffffe || requestTerms.PaymentSequenceAfter != uint64(previous.PaymentSequence+1) {
		return nil, pool.ErrStalePaymentSequence
	}
	if requestTerms.SellerAmountAfterSat < previous.SellerAmountSat {
		return nil, fmt.Errorf("%w: authorization amount cannot decrease", pool.ErrInvalidEvidence)
	}
	expectedPrice := requestTerms.SellerAmountAfterSat - previous.SellerAmountSat
	if err := engine.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{Opening: opening, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: requestTerms.SellerAmountAfterSat}); err != nil {
		return nil, fmt.Errorf("check delivery payment capacity: %w", err)
	}
	requestHash, err := bitfs.PaymentAuthorizationHash(request.TermsCBOR)
	if err != nil {
		return nil, err
	}
	acquireResult, err := workflow.pending.TryAcquire(ctx, pool.PendingRequest{SpendTxID: spendTxID, BasePaymentSequence: uint32(requestTerms.BasePaymentSequence), BaseSellerAmountSat: previous.SellerAmountSat, ContentRequestHash: poolHash32Seller(requestHash[:]), ExpectedSellerAmountSat: expectedPrice})
	if err != nil {
		return nil, fmt.Errorf("acquire pending request: %w", err)
	}
	if acquireResult == pool.PendingConflict {
		return nil, pool.ErrPoolBusy
	}
	if acquireResult != pool.PendingAcquired && acquireResult != pool.PendingAlreadyHeld {
		return nil, pool.ErrPoolBusy
	}
	keepPending := false
	defer func() {
		if !keepPending {
			_ = workflow.pending.Release(ctx, spendTxID, poolHash32Seller(requestHash[:]))
		}
	}()
	var seed []byte
	var blockMatches masterseed.BlockMatches
	if requestTerms.ContentType == bitfs.ContentBlock {
		seedHash, hashErr := masterseed.DigestFromBytes(quoteTerms.SeedHash)
		if hashErr != nil {
			return nil, fmt.Errorf("%w: quote seed hash: %v", bitfs.ErrInvalidEvidence, hashErr)
		}
		seed, err = workflow.content.LoadSeed(ctx, seedHash)
		if err != nil {
			return nil, fmt.Errorf("load seed: %w", err)
		}
		seed = append([]byte(nil), seed...)
		blockMatches, err = bitfs.VerifyBlockReference(ctx, quoteTerms, requestTerms.ContentHash, seed)
		if err != nil {
			return nil, err
		}
	}
	contentHash, hashErr := masterseed.DigestFromBytes(requestTerms.ContentHash)
	if hashErr != nil {
		return nil, fmt.Errorf("%w: content hash: %v", bitfs.ErrInvalidEvidence, hashErr)
	}
	var payload []byte
	if requestTerms.ContentType == bitfs.ContentSeed {
		payload, err = workflow.content.LoadSeed(ctx, contentHash)
	} else {
		payload, err = workflow.content.LoadBlock(ctx, contentHash)
	}
	if err != nil {
		return nil, fmt.Errorf("load content: %w", err)
	}
	payload = append([]byte(nil), payload...)
	if err := bitfs.VerifyContentPayloadContext(ctx, quoteTerms, requestTerms.ContentType, requestTerms.ContentHash, payload, seed, requestTerms.ContentType == bitfs.ContentSeed); err != nil {
		return nil, err
	}
	if requestTerms.ContentType == bitfs.ContentBlock && !sellerBlockSizeMatches(quoteTerms.FileSize, uint64(len(payload)), blockMatches) {
		return nil, fmt.Errorf("%w: block payload size does not match a committed block position", bitfs.ErrInvalidEvidence)
	}
	price, err := bitfs.ContentPriceSat(quoteTerms, requestTerms.ContentType, uint64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("calculate content price: %w", err)
	}
	if ^uint64(0)-previous.SellerAmountSat < price {
		return nil, pool.ErrInsufficientBalance
	}
	if price != expectedPrice || requestTerms.PaymentSequenceAfter != uint64(previous.PaymentSequence+1) || requestTerms.SellerAmountAfterSat != previous.SellerAmountSat+price {
		return nil, fmt.Errorf("%w: authorization amount or sequence does not match verified content price", pool.ErrInvalidEvidence)
	}
	if previous.PaymentSequence >= 0xfffffffe {
		return nil, pool.ErrStalePaymentSequence
	}
	if err := engine.CheckPaymentCapacity(ctx, pool.PaymentUpdateInput{
		Opening:              opening,
		Previous:             previous,
		PaymentSequenceAfter: previous.PaymentSequence + 1,
		SellerAmountAfterSat: previous.SellerAmountSat + price,
	}); err != nil {
		return nil, fmt.Errorf("check delivery payment capacity: %w", err)
	}
	sellerPubkey, err := workflow.signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load seller public key: %w", err)
	}
	if !bytes.Equal(sellerPubkey, opening.SellerPubKey) {
		return nil, fmt.Errorf("%w: workflow signer does not match opening seller", bitfs.ErrInvalidEvidence)
	}
	delivery, err = bitfs.NewSignedContentDelivery(request, append([]byte(nil), payload...), func(raw []byte) ([]byte, error) {
		digest := sha256.Sum256(raw)
		return workflow.signer.Sign(ctx, digest[:])
	})
	if err != nil {
		return nil, err
	}
	if _, err := bitfs.VerifySignedContentDeliveryAt(request, delivery, quote, now, fixedSellerVerify, fixedSellerVerify, fixedSellerVerify); err != nil {
		return nil, err
	}
	keepPending = true
	return delivery, nil
}

// AcceptPayment verifies the buyer's 005 update against the accepted pool state,
// adds the seller signature, submits the exact transaction, and advances stored
// state only after the node confirms the expected transaction and sequence.
func (workflow *Workflow) AcceptPayment(ctx context.Context, update *pool.PaymentUpdate) (*pool.PaymentState, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	update = pool.ClonePaymentUpdate(update)
	if err := pool.ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	fundingTx, err := pool.ParseCanonicalTransaction(append([]byte(nil), update.UnsignedStateTxRaw...))
	if err != nil {
		return nil, fmt.Errorf("read payment funding outpoint: %w", err)
	}
	if len(fundingTx.Inputs) != 1 || fundingTx.Inputs[0].SourceTXID == nil {
		return nil, fmt.Errorf("%w: payment funding outpoint is missing", pool.ErrInvalidEvidence)
	}
	var fundingTxID pool.Hash32
	copy(fundingTxID[:], fundingTx.Inputs[0].SourceTXID.CloneBytes())
	opening, err := workflow.pools.LoadOpeningProofByFundingTxID(ctx, fundingTxID)
	if err != nil {
		return nil, fmt.Errorf("load pool opening proof: %w", err)
	}
	opening = pool.CloneOpeningProof(opening)
	spendTxID := poolHash32Seller(opening.SpendTxID)
	if err := workflow.pools.EnsurePoolOpen(ctx, spendTxID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
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
	refundSpendTxID, err := engine.TransactionID(opening.RefundTx)
	if err != nil {
		return nil, fmt.Errorf("calculate spend transaction ID: %w", err)
	}
	if refundSpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: opening spend transaction mismatch", pool.ErrInvalidEvidence)
	}
	unsigned, err := engine.ParseUnsignedPayment(ctx, append([]byte(nil), update.UnsignedStateTxRaw...), opening)
	if err != nil {
		return nil, fmt.Errorf("parse unsigned payment state: %w", err)
	}
	if unsigned == nil {
		return nil, fmt.Errorf("%w: empty unsigned payment state", pool.ErrInvalidEvidence)
	}
	if unsigned.SpendTxID != spendTxID {
		return nil, fmt.Errorf("%w: payment state spend transaction mismatch", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyBuyerPayment(unsigned, update.BuyerTransactionSignature, opening); err != nil {
		return nil, fmt.Errorf("verify buyer payment: %w", err)
	}
	pending, err := workflow.pending.Load(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending request: %w", err)
	}
	previous, err := workflow.pools.LoadAcceptedPayment(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load accepted payment: %w", err)
	}
	if previous == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	previous = pool.ClonePaymentState(previous)
	if err := engine.VerifyAcceptedPayment(previous, opening); err != nil {
		return nil, fmt.Errorf("verify previous accepted payment: %w", err)
	}
	if unsigned.SellerAmountSat < previous.SellerAmountSat {
		return nil, fmt.Errorf("%w: seller amount cannot decrease", pool.ErrInvalidEvidence)
	}
	requestHash := poolHash32Seller(update.PaymentAuthorizationHash)
	if pending == nil {
		if previous != nil && previous.PaymentSequence == unsigned.PaymentSequence && previous.SellerAmountSat == unsigned.SellerAmountSat && previous.BuyerAmountSat == unsigned.BuyerAmountSat && previous.PaymentAuthorizationHash == requestHash {
			if err := engine.PaymentStateMatchesUnsigned(previous, unsigned, opening); err != nil {
				return nil, err
			}
			return clonePaymentStateSeller(previous), nil
		}
		return nil, pool.ErrStalePaymentSequence
	}
	if pending.SpendTxID != unsigned.SpendTxID || pending.ContentRequestHash != requestHash {
		return nil, pool.ErrStalePaymentSequence
	}
	if previous != nil && previous.PaymentSequence == unsigned.PaymentSequence && previous.SellerAmountSat == unsigned.SellerAmountSat && previous.BuyerAmountSat == unsigned.BuyerAmountSat && previous.PaymentAuthorizationHash == requestHash {
		if err := engine.PaymentStateMatchesUnsigned(previous, unsigned, opening); err != nil {
			return nil, err
		}
		if unsigned.PaymentSequence == 0 || pending.BasePaymentSequence != unsigned.PaymentSequence-1 || pending.BaseSellerAmountSat > unsigned.SellerAmountSat || pending.ExpectedSellerAmountSat != unsigned.SellerAmountSat-pending.BaseSellerAmountSat {
			return nil, pool.ErrStalePaymentSequence
		}
		if err := workflow.pending.Release(ctx, unsigned.SpendTxID, pending.ContentRequestHash); err != nil {
			return nil, fmt.Errorf("release pending request: %w", err)
		}
		return clonePaymentStateSeller(previous), nil
	}
	if previous.PaymentSequence != pending.BasePaymentSequence || unsigned.PaymentSequence != pending.BasePaymentSequence+1 {
		return nil, pool.ErrStalePaymentSequence
	}
	if ^uint64(0)-previous.SellerAmountSat < pending.ExpectedSellerAmountSat || unsigned.SellerAmountSat != previous.SellerAmountSat+pending.ExpectedSellerAmountSat {
		return nil, fmt.Errorf("%w: payment seller amount does not match the verified content price", pool.ErrInvalidEvidence)
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, fmt.Errorf("sign payment update: %w", err)
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, update.BuyerTransactionSignature, sellerSig, opening)
	if err != nil {
		return nil, fmt.Errorf("merge buyer and seller payment signatures: %w", err)
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: seller returned empty signed payment", pool.ErrInvalidEvidence)
	}
	txID, err := engine.TransactionID(signed.RawTx)
	if err != nil {
		return nil, fmt.Errorf("calculate accepted transaction ID: %w", err)
	}
	acceptance, err := workflow.node.SubmitUpdate(ctx, signed.RawTx)
	if err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, unsigned.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: payment backend outcome requires reconciliation: %v", pool.ErrPoolStateUncertain, err)
		if markErr != nil {
			return nil, errors.Join(uncertain, markErr)
		}
		return nil, uncertain
	}
	if acceptance == nil || acceptance.SpendTxID != unsigned.SpendTxID || acceptance.PaymentSequence != signed.State.PaymentSequence || acceptance.TxID != txID {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, unsigned.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: node returned inconsistent payment acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return nil, errors.Join(uncertain, markErr)
		}
		return nil, uncertain
	}
	accepted := signed.State
	accepted.RawTx = append([]byte(nil), signed.RawTx...)
	accepted.PaymentAuthorizationHash = requestHash
	if err := workflow.pools.SaveAcceptedPayment(ctx, &accepted); err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, accepted.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: local persistence failed after non-final node acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return nil, errors.Join(uncertain, err, markErr)
		}
		return nil, errors.Join(uncertain, err)
	}
	if err := workflow.pending.Release(ctx, unsigned.SpendTxID, pending.ContentRequestHash); err != nil {
		return nil, fmt.Errorf("release pending request: %w", err)
	}
	return clonePaymentStateSeller(&accepted), nil
}

// SignImmediateClose complements the buyer's final close signature and durably
// marks the pool as closing before returning. It does not submit the final
// transaction; the buyer decides when to call SubmitFinal.
func (workflow *Workflow) SignImmediateClose(ctx context.Context, unsigned *pool.UnsignedPayment, buyerSig []byte) (*pool.SignedPayment, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if unsigned == nil || unsigned.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: immediate close must use the final sequence", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.EnsurePoolHealthy(ctx, unsigned.SpendTxID); err != nil {
		return nil, err
	}
	pending, err := workflow.pending.Load(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending request before immediate close: %w", err)
	}
	if pending != nil {
		return nil, pool.ErrPoolBusy
	}
	opening, err := workflow.pools.LoadOpeningProof(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, err
	}
	opening = pool.CloneOpeningProof(opening)
	engine, err := workflow.engineForExpiry(ctx, opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(opening); err != nil {
		return nil, err
	}
	if err := engine.VerifyRefundNotExpired(opening, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, opening); err != nil {
		return nil, fmt.Errorf("verify buyer close signature: %w", err)
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load latest accepted payment: %w", err)
	}
	if latest == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	latest = pool.ClonePaymentState(latest)
	if err := engine.VerifyAcceptedPayment(latest, opening); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(latest, opening); arbitrationErr != nil {
			return nil, fmt.Errorf("verify latest accepted payment: %w", err)
		}
	}
	if unsigned.SellerAmountSat < latest.SellerAmountSat {
		return nil, fmt.Errorf("%w: immediate close cannot reduce seller amount", pool.ErrInvalidEvidence)
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerPayment(ctx, unsigned, opening)
	if err != nil {
		return nil, err
	}
	signed, err := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, opening)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.State.PaymentSequence != ^uint32(0) {
		return nil, fmt.Errorf("%w: seller close signature did not preserve final sequence", pool.ErrInvalidEvidence)
	}
	if err := workflow.pools.MarkPoolClosing(ctx, unsigned.SpendTxID); err != nil {
		return nil, fmt.Errorf("mark pool closing: %w", err)
	}
	return signed, nil
}

func sellerHash32(raw []byte) bitfs.Hash32 {
	var result bitfs.Hash32
	copy(result[:], raw)
	return result
}

func sellerBlockSizeMatches(fileSize, contentSize uint64, matches masterseed.BlockMatches) bool {
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

// BuildArbitrationRequest is intentionally disabled: arbitration must be built
// from the signed 003 authorization, never from a buyer payment wrapper.
func (workflow *Workflow) BuildArbitrationRequest(context.Context, *pool.OpeningProof, *pool.PaymentUpdate) (*arbitration.ArbitrationRequest, error) {
	return nil, fmt.Errorf("%w: use BuildArbitrationRequestFromAuthorization", pool.ErrInvalidEvidence)
}

// BuildArbitrationRequestFromAuthorization packages the retained opening proof,
// signed 003 authorization, latest payment state, and seller signature into the
// 007 evidence request. It never constructs a replacement candidate transaction.
func (workflow *Workflow) BuildArbitrationRequestFromAuthorization(ctx context.Context, authorization *bitfs.SignedContentRequest) (*arbitration.ArbitrationRequest, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if authorization == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	terms, err := bitfs.VerifySignedContentRequestStandalone(authorization, fixedSellerVerify)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	spendTxID := poolHash32Seller(terms.SpendTxID)
	if err := workflow.pools.EnsurePoolOpen(ctx, spendTxID); err != nil {
		return nil, err
	}
	proof, err := workflow.pools.LoadOpeningProof(ctx, spendTxID)
	if err != nil {
		return nil, err
	}
	proof = pool.CloneOpeningProof(proof)
	engine, err := workflow.engineForExpiry(ctx, proof)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if err := engine.VerifyRefundNotExpired(proof, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := validateSellerAuthorizationPool(terms, proof); err != nil {
		return nil, err
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, spendTxID)
	if err != nil {
		return nil, err
	}
	latest = pool.ClonePaymentState(latest)
	if latest == nil || latest.PaymentSequence != uint32(terms.BasePaymentSequence) {
		return nil, fmt.Errorf("%w: authorization does not match latest pool state", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifyAcceptedPayment(latest, proof); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(latest, proof); arbitrationErr != nil {
			return nil, err
		}
	}
	pending, err := workflow.pending.Load(ctx, spendTxID)
	if err != nil {
		return nil, err
	}
	authHash, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if pending == nil || pending.SpendTxID != spendTxID || pending.ContentRequestHash != poolHash32Seller(authHash[:]) || pending.BasePaymentSequence != latest.PaymentSequence || pending.BaseSellerAmountSat != latest.SellerAmountSat {
		return nil, pool.ErrPoolBusy
	}
	if pending.ExpectedSellerAmountSat > ^uint64(0)-latest.SellerAmountSat || terms.SellerAmountAfterSat != latest.SellerAmountSat+pending.ExpectedSellerAmountSat {
		return nil, fmt.Errorf("%w: authorization amount does not match pending delivery", pool.ErrInvalidEvidence)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, pool.PaymentUpdateInput{Opening: proof, Previous: latest, PaymentSequenceAfter: uint32(terms.PaymentSequenceAfter), SellerAmountAfterSat: terms.SellerAmountAfterSat})
	if err != nil {
		return nil, err
	}
	sellerSig, err := pool.NewSellerPoolAdapter(engine, workflow.signer).SignSellerArbitrationCandidate(ctx, unsigned, proof)
	if err != nil {
		return nil, err
	}
	openingCBOR, err := pool.EncodeOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	authCBOR, err := bitfs.EncodeSignedContentRequest(authorization)
	if err != nil {
		return nil, err
	}
	return &arbitration.ArbitrationRequest{Version: arbitration.MajorVersion, PoolOpeningProofCBOR: openingCBOR, PaymentAuthorizationCBOR: authCBOR, UnsignedStateTxRaw: append([]byte(nil), unsigned.RawTx...), SellerTransactionSignature: sellerSig}, nil
}

// SubmitArbitratedPayment verifies the 007 response hashes and arbiter signature,
// merges the seller and arbiter signatures over the authorized unsigned state,
// submits that exact transaction, and persists it only after node acceptance.
func (workflow *Workflow) SubmitArbitratedPayment(ctx context.Context, request *arbitration.ArbitrationRequest, response *arbitration.ArbitrationResponse) (*pool.PaymentState, error) {
	if workflow == nil {
		return nil, errors.New("seller workflow is required")
	}
	if request == nil || response == nil {
		return nil, fmt.Errorf("%w: arbitration evidence is incomplete", pool.ErrInvalidEvidence)
	}
	if _, err := arbitration.MarshalRequest(request); err != nil {
		return nil, err
	}
	if _, err := arbitration.MarshalResponse(response); err != nil {
		return nil, err
	}
	authHash := sha256.Sum256(request.PaymentAuthorizationCBOR)
	txHash := sha256.Sum256(request.UnsignedStateTxRaw)
	if !bytes.Equal(authHash[:], response.PaymentAuthorizationHash) || !bytes.Equal(txHash[:], response.UnsignedStateTxHash) {
		return nil, fmt.Errorf("%w: arbiter response does not bind request evidence", pool.ErrInvalidEvidence)
	}
	proof, err := pool.DecodeOpeningProof(request.PoolOpeningProofCBOR)
	if err != nil {
		return nil, err
	}
	if err := workflow.pools.EnsurePoolOpen(ctx, poolHash32Seller(proof.SpendTxID)); err != nil {
		return nil, err
	}
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, err
	}
	_, err = bitfs.VerifySignedContentRequestStandalone(authorization, fixedSellerVerify)
	if err != nil {
		return nil, err
	}
	terms, err := bitfs.DecodeContentRequestTerms(authorization.TermsCBOR)
	if err != nil {
		return nil, err
	}
	if err := validateSellerAuthorizationPool(terms, proof); err != nil {
		return nil, err
	}
	engine, err := workflow.engineForExpiry(ctx, proof)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyRefundNotExpired(proof, time.Now().UTC()); err != nil {
		return nil, err
	}
	unsigned, err := engine.ParseUnsignedPayment(ctx, request.UnsignedStateTxRaw, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence != uint32(terms.PaymentSequenceAfter) || unsigned.SellerAmountSat != terms.SellerAmountAfterSat {
		return nil, fmt.Errorf("%w: arbitration candidate does not match payment authorization", pool.ErrInvalidEvidence)
	}
	if err := engine.VerifySellerPayment(unsigned, request.SellerTransactionSignature, proof); err != nil {
		return nil, err
	}
	latest, err := workflow.pools.LoadAcceptedPayment(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load latest accepted payment: %w", err)
	}
	if latest == nil {
		return nil, pool.ErrStalePaymentSequence
	}
	latest = pool.ClonePaymentState(latest)
	if err := engine.VerifyAcceptedPayment(latest, proof); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(latest, proof); arbitrationErr != nil {
			return nil, fmt.Errorf("verify latest accepted payment: %w", err)
		}
	}
	pending, err := workflow.pending.Load(ctx, unsigned.SpendTxID)
	if err != nil {
		return nil, fmt.Errorf("load pending request: %w", err)
	}
	authHashValue, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		return nil, err
	}
	requestHash := poolHash32Seller(authHashValue[:])
	signed, err := engine.MergeSellerArbiterPayment(unsigned, request.SellerTransactionSignature, response.ArbiterTransactionSignature, proof)
	if err != nil {
		return nil, err
	}
	if signed == nil || len(signed.RawTx) == 0 {
		return nil, fmt.Errorf("%w: arbiter returned empty transaction", pool.ErrInvalidEvidence)
	}
	signed.State.PaymentAuthorizationHash = requestHash
	if latest.PaymentSequence == signed.State.PaymentSequence &&
		latest.SellerAmountSat == signed.State.SellerAmountSat &&
		latest.BuyerAmountSat == signed.State.BuyerAmountSat &&
		latest.ArbiterAmountSat == signed.State.ArbiterAmountSat &&
		latest.PaymentAuthorizationHash == requestHash && bytes.Equal(latest.RawTx, signed.RawTx) {
		if pending != nil {
			if pending.SpendTxID != unsigned.SpendTxID || pending.ContentRequestHash != requestHash || uint64(pending.BasePaymentSequence) != terms.BasePaymentSequence || pending.BaseSellerAmountSat > terms.SellerAmountAfterSat || pending.ExpectedSellerAmountSat != terms.SellerAmountAfterSat-pending.BaseSellerAmountSat {
				return nil, pool.ErrPoolBusy
			}
			if err := workflow.pending.Release(ctx, unsigned.SpendTxID, requestHash); err != nil {
				return nil, fmt.Errorf("release pending request after idempotent arbitration: %w", err)
			}
		}
		return clonePaymentStateSeller(latest), nil
	}
	if pending == nil || pending.SpendTxID != unsigned.SpendTxID || pending.ContentRequestHash != poolHash32Seller(authHashValue[:]) ||
		latest.PaymentSequence != uint32(terms.BasePaymentSequence) ||
		pending.BasePaymentSequence != latest.PaymentSequence ||
		pending.BaseSellerAmountSat != latest.SellerAmountSat ||
		terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 ||
		terms.PaymentSequenceAfter > uint64(^uint32(0)-1) ||
		unsigned.PaymentSequence != uint32(terms.BasePaymentSequence+1) ||
		pending.ExpectedSellerAmountSat > ^uint64(0)-latest.SellerAmountSat ||
		terms.SellerAmountAfterSat != latest.SellerAmountSat+pending.ExpectedSellerAmountSat {
		return nil, pool.ErrPoolBusy
	}
	txID, err := engine.TransactionID(signed.RawTx)
	if err != nil {
		return nil, err
	}
	accepted, err := workflow.node.SubmitUpdate(ctx, signed.RawTx)
	if err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, unsigned.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: arbitration backend outcome requires reconciliation: %v", pool.ErrPoolStateUncertain, err)
		if markErr != nil {
			return nil, errors.Join(uncertain, markErr)
		}
		return nil, uncertain
	}
	if accepted == nil || accepted.TxID != txID || accepted.SpendTxID != unsigned.SpendTxID || accepted.PaymentSequence != unsigned.PaymentSequence {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, unsigned.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: inconsistent arbitration acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return nil, errors.Join(uncertain, markErr)
		}
		return nil, uncertain
	}
	if err := workflow.pools.SaveAcceptedPayment(ctx, &signed.State); err != nil {
		markErr := workflow.pools.MarkExternalStateUncertain(ctx, signed.State.SpendTxID, txID)
		uncertain := fmt.Errorf("%w: local persistence failed after arbitration node acceptance", pool.ErrPoolStateUncertain)
		if markErr != nil {
			return nil, errors.Join(uncertain, err, markErr)
		}
		return nil, errors.Join(uncertain, err)
	}
	if err := workflow.pending.Release(ctx, unsigned.SpendTxID, poolHash32Seller(requestHash[:])); err != nil {
		return nil, fmt.Errorf("release pending request after arbitration: %w", err)
	}
	return clonePaymentStateSeller(&signed.State), nil
}

func validateSellerAuthorizationPool(terms *bitfs.ContentRequestTerms, proof *pool.OpeningProof) error {
	if terms == nil || proof == nil {
		return fmt.Errorf("%w: authorization pool evidence is incomplete", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(terms.SpendTxID, proof.SpendTxID) ||
		!bytes.Equal(terms.BuyerPubkey, proof.BuyerPubKey) ||
		!bytes.Equal(terms.SellerPubkey, proof.SellerPubKey) ||
		!bytes.Equal(terms.SelectedArbiterPubkey, proof.ArbiterPubKey) {
		return fmt.Errorf("%w: authorization pool roles do not match opening proof", pool.ErrInvalidEvidence)
	}
	if terms.MinerFeeRateSatPerKB != proof.MinerFeeRateSatPerKB {
		return fmt.Errorf("%w: authorization fee rate does not match opening proof", pool.ErrInvalidEvidence)
	}
	if terms.PaymentSequenceAfter != terms.BasePaymentSequence+1 || terms.PaymentSequenceAfter > uint64(^uint32(0)-1) {
		return fmt.Errorf("%w: authorization payment sequence is invalid", pool.ErrInvalidEvidence)
	}
	return nil
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
