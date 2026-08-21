package pool

// This file is the single MultisigPool v4 boundary.  It owns no transaction
// algorithm: scripts, state construction, fees, sighash, role verification
// and signature ordering are delegated to github.com/bsv8/MultisigPool/v4.

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/protocol"
)

const finalPoolSequence = ^uint32(0)

// Bitcoin nLockTime values below this threshold are block heights; values at
// or above it are Unix timestamps. A refund must be checked against exactly
// one of those clocks, never both.
const lockTimeTimestampThreshold uint32 = 500_000_000

// MultisigPoolEngineConfig supplies compressed Buyer, Seller, and Arbiter public
// keys in role order. BlockHeight is optional and is used only for block-height
// refund expiry checks; fee and transaction rules come from MultisigPool v4.
type MultisigPoolEngineConfig struct {
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
	BlockHeight   func() uint32
}

// MultisigPoolPublicKeys identifies the three pool participants by settlement role.
// The explicit fields keep callers from relying on positional key ordering.
type MultisigPoolPublicKeys struct {
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
}

// MultisigPoolEngine is the adapter boundary to MultisigPool v4. It preserves
// Buyer/Seller/Arbiter role ordering while delegating scripts, fees, sighash,
// state construction, and signature ordering to that dependency.
type MultisigPoolEngine struct {
	buyer, seller, arbiter *ec.PublicKey
	blockHeight            func() uint32
}

// BuyerPoolAdapter adapts the pool engine to buyer workflow operations.
type BuyerPoolAdapter struct {
	*MultisigPoolEngine
	Key Signer
}

// SellerPoolAdapter adapts the pool engine to seller workflow operations.
type SellerPoolAdapter struct {
	*MultisigPoolEngine
	Key Signer
}

// ArbiterPoolAdapter adapts the pool engine to arbiter workflow operations.
type ArbiterPoolAdapter struct {
	*MultisigPoolEngine
	Key Signer
}

// NewBuyerPoolAdapter binds an engine to the buyer Signer used for
// detached payment and refund signatures. It performs no signing at construction.
func NewBuyerPoolAdapter(engine *MultisigPoolEngine, key Signer) *BuyerPoolAdapter {
	return &BuyerPoolAdapter{MultisigPoolEngine: engine, Key: key}
}

// NewSellerPoolAdapter binds an engine to the seller Signer used
// for detached payment, refund, and arbitration-candidate signatures.
func NewSellerPoolAdapter(engine *MultisigPoolEngine, key Signer) *SellerPoolAdapter {
	return &SellerPoolAdapter{MultisigPoolEngine: engine, Key: key}
}

// NewArbiterPoolAdapter binds an engine to the arbiter Signer used
// to sign the candidate state selected by the 007 workflow.
func NewArbiterPoolAdapter(engine *MultisigPoolEngine, key Signer) *ArbiterPoolAdapter {
	return &ArbiterPoolAdapter{MultisigPoolEngine: engine, Key: key}
}

// NewMultisigPoolEngine parses and validates three distinct role keys, preserving
// Buyer/Seller/Arbiter identity for every later transaction check. It returns an
// error for malformed or duplicate keys and performs no network or storage I/O.
func NewMultisigPoolEngine(config MultisigPoolEngineConfig) (*MultisigPoolEngine, error) {
	buyer, err := parsePoolKey(config.BuyerPubKey)
	if err != nil {
		return nil, fmt.Errorf("buyer public key: %w", err)
	}
	seller, err := parsePoolKey(config.SellerPubKey)
	if err != nil {
		return nil, fmt.Errorf("seller public key: %w", err)
	}
	arbiter, err := parsePoolKey(config.ArbiterPubKey)
	if err != nil {
		return nil, fmt.Errorf("arbiter public key: %w", err)
	}
	if buyer.IsEqual(seller) || buyer.IsEqual(arbiter) || seller.IsEqual(arbiter) {
		return nil, invalid("pool participants must be distinct")
	}
	return &MultisigPoolEngine{buyer: buyer, seller: seller, arbiter: arbiter, blockHeight: config.BlockHeight}, nil
}

func (engine *MultisigPoolEngine) roles() mp.ArbitratedPoolRoles {
	return mp.ArbitratedPoolRoles{Buyer: engine.buyer, Seller: engine.seller, Arbiter: engine.arbiter}
}

// Build2of3LockingScript delegates construction of the 2-of-3 MultisigPool
// locking script using the explicit Buyer, Seller, and Arbiter public keys.
func Build2of3LockingScript(keys MultisigPoolPublicKeys) ([]byte, error) {
	buyer, err := parsePoolKey(keys.BuyerPubKey)
	if err != nil {
		return nil, fmt.Errorf("buyer public key: %w", err)
	}
	seller, err := parsePoolKey(keys.SellerPubKey)
	if err != nil {
		return nil, fmt.Errorf("seller public key: %w", err)
	}
	arbiter, err := parsePoolKey(keys.ArbiterPubKey)
	if err != nil {
		return nil, fmt.Errorf("arbiter public key: %w", err)
	}
	return BuildPoolLock(mp.ArbitratedPoolRoles{Buyer: buyer, Seller: seller, Arbiter: arbiter})
}

// BuildRefundPresignRequest constructs a RefundPresignRequest from the funding
// transaction and opening input using the adapter's bound buyer signer. It
// returns an error if funding output 0 does not use the configured pool lock or
// if the buyer key does not match the engine.
func (adapter *BuyerPoolAdapter) BuildRefundPresignRequest(ctx context.Context, input OpeningInput) (*RefundPresignRequest, error) {
	if adapter == nil {
		return nil, invalid("buyer signer is required")
	}
	engine := adapter.MultisigPoolEngine
	if engine == nil || adapter.Key == nil {
		return nil, invalid("buyer signer is required")
	}
	if input.ExpiryLockTime == 0 {
		return nil, invalid("refund expiry locktime is required")
	}
	if err := engine.matchConfiguredParticipantKeys(input.SellerPubKey, input.ArbiterPubKey); err != nil {
		return nil, err
	}
	funding, err := parseCanonicalTransaction(input.FundingTx)
	if err != nil {
		return nil, err
	}
	if len(funding.Outputs) == 0 || funding.Outputs[PoolOutputIndex] == nil {
		return nil, invalid("funding transaction has no pool output at index 0")
	}
	output := funding.Outputs[PoolOutputIndex]
	lock, err := mp.BuildArbitratedPoolLock(engine.roles())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(output.LockingScript.Bytes(), lock.Bytes()) {
		return nil, invalid("funding output does not use the configured pool lock")
	}
	state, err := mp.BuildArbitratedPoolOpeningState(funding.TxID().CloneBytes(), PoolOutputIndex, output.Satoshis, engine.roles(), input.ExpiryLockTime, mp.FeeSatPerKB(input.MinerFeeRateSatPerKB))
	if err != nil {
		return nil, err
	}
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	sig, err := engine.signWithSigner(ctx, state, output.Satoshis, adapter.Key, "buyer")
	if err != nil {
		return nil, err
	}
	if ok, err := mp.VerifyArbitratedPoolBuyerSignature(state, output.Satoshis, engine.roles(), sig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("buyer refund signature is invalid")
	}
	return &RefundPresignRequest{Version: MajorVersion, RefundTx: state.Bytes(), BuyerPubKey: engine.buyer.Compressed(), SellerPubKey: engine.seller.Compressed(), ArbiterPubKey: engine.arbiter.Compressed(), MinerFeeRateSatPerKB: input.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), sig...)}, nil
}

type refundPresignTerms struct {
	state              *tx.Transaction
	fundingTxID        []byte
	poolOutputSatoshis uint64
	poolLockingScript  []byte
}

// deriveRefundPresignTerms makes RefundTx the single source of truth for its
// funding outpoint and pool amount. The locking script is fixed by the three
// role keys. The pool amount is the refund's buyer output plus the canonical
// MultisigPool fee, whose encoded size is independent of the amount value.
func (engine *MultisigPoolEngine) deriveRefundPresignTerms(request *RefundPresignRequest) (*refundPresignTerms, error) {
	if engine == nil {
		return nil, invalid("MultisigPool engine is required")
	}
	state, err := parseCanonicalTransaction(request.RefundTx)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil || state.Inputs[0].SourceTXID == nil || len(state.Outputs) != 3 || state.Outputs[0] == nil {
		return nil, invalid("opening state shape is invalid")
	}
	if state.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return nil, invalid("opening state must spend funding output index 0")
	}
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	fundingTxID := state.Inputs[0].SourceTXID.CloneBytes()
	feeTemplate, err := mp.BuildArbitratedPoolOpeningState(fundingTxID, PoolOutputIndex, math.MaxUint64, engine.roles(), state.LockTime, mp.FeeSatPerKB(request.MinerFeeRateSatPerKB))
	if err != nil {
		return nil, err
	}
	canonicalFee := uint64(math.MaxUint64) - feeTemplate.Outputs[0].Satoshis
	if state.Outputs[0].Satoshis > math.MaxUint64-canonicalFee {
		return nil, invalid("opening pool amount overflows")
	}
	poolAmount := state.Outputs[0].Satoshis + canonicalFee
	if poolAmount == 0 {
		return nil, invalid("opening pool amount is zero")
	}
	poolLock := engine.lockBytes()
	setPoolSource(state, poolAmount, poolLock)
	if err := engine.verifyOpeningState(state, fundingTxID, PoolOutputIndex, poolAmount, request.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	return &refundPresignTerms{state: state, fundingTxID: fundingTxID, poolOutputSatoshis: poolAmount, poolLockingScript: poolLock}, nil
}

// VerifySellerRefundSignature validates the 002 presigned refund state named by
// request, including its funding outpoint, role keys, buyer signature, and the
// supplied seller detached signature. It does not submit either transaction.
func (engine *MultisigPoolEngine) VerifySellerRefundSignature(_ context.Context, request *RefundPresignRequest, signature []byte) error {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return err
	}
	if err := engine.validateRequestRoles(request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey); err != nil {
		return err
	}
	terms, err := engine.deriveRefundPresignTerms(request)
	if err != nil {
		return err
	}
	ok, err := mp.VerifyArbitratedPoolBuyerSignature(terms.state, terms.poolOutputSatoshis, engine.roles(), request.BuyerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("buyer refund signature is invalid")
	}
	ok, err = mp.VerifyArbitratedPoolSellerSignature(terms.state, terms.poolOutputSatoshis, engine.roles(), signature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("seller refund signature is invalid")
	}
	return nil
}

// SignSellerRefund produces the seller's detached signature over the
// presigned refund transaction described by request.
func (adapter *SellerPoolAdapter) SignSellerRefund(ctx context.Context, request *RefundPresignRequest) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil {
		return nil, invalid("seller signer is required")
	}
	engine := adapter.MultisigPoolEngine
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	if err := engine.validateRequestRoles(request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey); err != nil {
		return nil, err
	}
	terms, err := engine.deriveRefundPresignTerms(request)
	if err != nil {
		return nil, err
	}
	sig, err := engine.signWithSigner(ctx, terms.state, terms.poolOutputSatoshis, adapter.Key, "seller")
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

// BuildOpeningProof retains only the original opening evidence. fundingTx may
// be nil while the seller stores the presigned pending proof; all transaction
// identities and pool-output terms are derived when the proof is consumed.
func (engine *MultisigPoolEngine) BuildOpeningProof(ctx context.Context, request *RefundPresignRequest, sellerSignature, fundingTx []byte) (*OpeningProof, error) {
	if err := engine.VerifySellerRefundSignature(ctx, request, sellerSignature); err != nil {
		return nil, err
	}
	proof := &OpeningProof{
		Version: MajorVersion, RefundTx: append([]byte(nil), request.RefundTx...),
		BuyerPubKey: append([]byte(nil), request.BuyerPubKey...), SellerPubKey: append([]byte(nil), request.SellerPubKey...), ArbiterPubKey: append([]byte(nil), request.ArbiterPubKey...),
		MinerFeeRateSatPerKB: request.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), request.BuyerRefundSignature...), SellerRefundSignature: append([]byte(nil), sellerSignature...),
		FundingTx: append([]byte(nil), fundingTx...),
	}
	if len(fundingTx) != 0 {
		if err := engine.VerifyOpening(proof); err != nil {
			return nil, err
		}
	}
	return proof, nil
}

// deriveOpeningDetails reconstructs every value omitted from OpeningProof.
// RefundTx is authoritative for the spend ID, funding outpoint, and amount;
// participant keys are authoritative for the locking script. When FundingTx is
// present it must independently agree with those derived terms.
func (engine *MultisigPoolEngine) deriveOpeningDetails(proof *OpeningProof) (*OpeningDetails, error) {
	if engine == nil || proof == nil {
		return nil, invalid("opening proof is required")
	}
	request := &RefundPresignRequest{
		Version: MajorVersion, RefundTx: proof.RefundTx,
		BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey,
		MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB, BuyerRefundSignature: proof.BuyerRefundSignature,
	}
	terms, err := engine.deriveRefundPresignTerms(request)
	if err != nil {
		return nil, err
	}
	details := &OpeningDetails{
		SpendTxID:          hash32FromBytes(terms.state.TxID().CloneBytes()),
		FundingTxID:        hash32FromBytes(terms.fundingTxID),
		PoolOutputSatoshis: terms.poolOutputSatoshis,
		PoolLockingScript:  append([]byte(nil), terms.poolLockingScript...),
	}
	if len(proof.FundingTx) == 0 {
		return details, nil
	}
	funding, err := parseCanonicalTransaction(proof.FundingTx)
	if err != nil {
		return nil, err
	}
	if funding.TxID() == nil || hash32FromBytes(funding.TxID().CloneBytes()) != details.FundingTxID || len(funding.Outputs) <= int(PoolOutputIndex) || funding.Outputs[PoolOutputIndex] == nil {
		return nil, invalid("funding transaction does not match refund outpoint")
	}
	output := funding.Outputs[PoolOutputIndex]
	if output.Satoshis != details.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), details.PoolLockingScript) {
		return nil, invalid("funding pool output does not match refund evidence")
	}
	return details, nil
}

// TransactionID computes the canonical transaction identifier from raw transaction bytes.
func (engine *MultisigPoolEngine) TransactionID(rawTx []byte) (Hash32, error) {
	value, err := parseCanonicalTransaction(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	return hash32FromBytes(value.TxID().CloneBytes()), nil
}

// FundingTxID returns the 32-byte funding outpoint from the first input of a raw transaction.
func (engine *MultisigPoolEngine) FundingTxID(rawTx []byte) (Hash32, error) {
	value, err := parseCanonicalTransaction(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	if len(value.Inputs) != 1 || value.Inputs[0] == nil || value.Inputs[0].SourceTXID == nil {
		return Hash32{}, invalid("transaction has no funding outpoint")
	}
	return hash32FromBytes(value.Inputs[0].SourceTXID.CloneBytes()), nil
}

// VerifyOpening validates a complete 002 OpeningProof against this engine's
// Buyer/Seller/Arbiter roles. It matches the proof to the funding output and
// unsigned refund state, then verifies the buyer and seller refund signatures;
// it performs no persistence or node submission.
func (engine *MultisigPoolEngine) VerifyOpening(proof *OpeningProof) error {
	if engine == nil {
		return invalid("MultisigPool engine is required")
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return err
	}
	if err := engine.validateRequestRoles(proof.BuyerPubKey, proof.SellerPubKey, proof.ArbiterPubKey); err != nil {
		return err
	}
	if len(proof.FundingTx) == 0 {
		return invalid("complete funding transaction is required")
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return err
	}
	refund, err := parseCanonicalTransaction(proof.RefundTx)
	if err != nil {
		return err
	}
	setPoolSource(refund, details.PoolOutputSatoshis, details.PoolLockingScript)
	if len(refund.Inputs) != 1 || refund.Inputs[0].SourceTXID == nil || hash32FromBytes(refund.Inputs[0].SourceTXID.CloneBytes()) != details.FundingTxID || refund.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return invalid("refund transaction does not spend the opening pool outpoint")
	}
	if err := requireUnsigned(refund); err != nil {
		return err
	}
	if err := engine.verifyOpeningState(refund, details.FundingTxID[:], PoolOutputIndex, details.PoolOutputSatoshis, proof.MinerFeeRateSatPerKB); err != nil {
		return err
	}
	ok, err := mp.VerifyArbitratedPoolBuyerSignature(refund, details.PoolOutputSatoshis, engine.roles(), proof.BuyerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("buyer refund signature is invalid")
	}
	ok, err = mp.VerifyArbitratedPoolSellerSignature(refund, details.PoolOutputSatoshis, engine.roles(), proof.SellerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("seller refund signature is invalid")
	}
	return nil
}

// VerifyRefundExpired checks whether the refund transaction's nLockTime has been reached.
// For block-height refunds it requires a BlockHeight provider; for timestamp refunds it compares against now.
func (engine *MultisigPoolEngine) VerifyRefundExpired(proof *OpeningProof, now time.Time) error {
	if err := engine.VerifyOpening(proof); err != nil {
		return err
	}
	refund, err := parseCanonicalTransaction(proof.RefundTx)
	if err != nil {
		return err
	}
	if refund.LockTime < lockTimeTimestampThreshold {
		if engine.blockHeight == nil {
			return invalid("block-height refund requires a block-height provider")
		}
		if refund.LockTime <= engine.blockHeight() {
			return nil
		}
		return ErrNotExpired
	}
	if now.Unix() >= int64(refund.LockTime) {
		return nil
	}
	return ErrNotExpired
}

// VerifyRefundNotExpired is the forward-operation gate. It is deliberately
// separate from VerifyRefundExpired so content and payment workflows cannot
// accidentally continue after the refund path has become executable.
func (engine *MultisigPoolEngine) VerifyRefundNotExpired(proof *OpeningProof, now time.Time) error {
	if err := engine.VerifyOpening(proof); err != nil {
		return err
	}
	if err := engine.VerifyRefundExpired(proof, now); err == nil {
		return invalid("pool refund has expired")
	} else if err != ErrNotExpired {
		return err
	}
	return nil
}

// BuildRefundSubmission merges the buyer and seller refund signatures from the opening proof into a broadcast-ready transaction.
func (engine *MultisigPoolEngine) BuildRefundSubmission(proof *OpeningProof) ([]byte, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	refund, err := parseCanonicalTransaction(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	setPoolSource(refund, details.PoolOutputSatoshis, details.PoolLockingScript)
	merged, err := mp.MergeArbitratedPoolBuyerSellerSignatures(refund, details.PoolOutputSatoshis, engine.roles(), proof.BuyerRefundSignature, proof.SellerRefundSignature)
	if err != nil {
		return nil, err
	}
	return merged.Bytes(), nil
}

// VerifyFundingTx parses the delivered 002 funding transaction and matches its txid, pool
// output index, satoshis, and role-ordered MultisigPool v4 locking script to
// proof. It is an evidence check only and does not submit the transaction.
func (engine *MultisigPoolEngine) VerifyFundingTx(_ context.Context, rawTx []byte, proof *OpeningProof) error {
	if proof == nil {
		return invalid("funding transaction and opening proof are required")
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return err
	}
	funding, err := parseCanonicalTransaction(rawTx)
	if err != nil {
		return err
	}
	if hash32FromBytes(funding.TxID().CloneBytes()) != details.FundingTxID || len(funding.Outputs) <= int(PoolOutputIndex) || funding.Outputs[PoolOutputIndex] == nil {
		return invalid("funding transaction does not match opening proof")
	}
	output := funding.Outputs[PoolOutputIndex]
	if output.Satoshis != details.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), details.PoolLockingScript) {
		return invalid("funding pool output does not match opening proof")
	}
	lock, err := mp.BuildArbitratedPoolLock(engine.roles())
	if err != nil || !bytes.Equal(lock.Bytes(), output.LockingScript.Bytes()) {
		return invalid("funding pool output role script is invalid")
	}
	return nil
}

// VerifyPoolParticipants checks that the opening proof's buyer, seller, and arbiter keys match the supplied values.
func (engine *MultisigPoolEngine) VerifyPoolParticipants(proof *OpeningProof, buyer, seller, arbiter []byte) error {
	if proof == nil || !bytes.Equal(proof.BuyerPubKey, buyer) || !bytes.Equal(proof.SellerPubKey, seller) || !bytes.Equal(proof.ArbiterPubKey, arbiter) {
		return invalid("pool participant roles do not match")
	}
	return nil
}

// ParsePaymentState parses a fully signed pool transaction into a PaymentState.
// Returns an error if the transaction has an empty unlocking script.
func (engine *MultisigPoolEngine) ParsePaymentState(_ context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	state, err := engine.parseUnsignedOrSignedState(rawTx, proof)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs[0].UnlockingScript.Bytes()) == 0 {
		return nil, invalid("payment state must be fully signed")
	}
	parsed, err := engine.stateFromTransaction(state, proof)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// ParseNonFinalPaymentState parses a fully signed pool transaction and rejects
// the reserved final-close sequence before any backend can receive it.
func (engine *MultisigPoolEngine) ParseNonFinalPaymentState(ctx context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	state, err := engine.ParsePaymentState(ctx, rawTx, proof)
	if err != nil {
		return nil, err
	}
	if state.PaymentSequence == finalPoolSequence {
		return nil, invalid("final payment cannot be submitted as a non-final update")
	}
	return state, nil
}

// ParseUnsignedPayment validates and parses an unsigned pool transaction against the opening proof's canonical state.
func (engine *MultisigPoolEngine) ParseUnsignedPayment(_ context.Context, rawTx []byte, proof *OpeningProof) (*UnsignedPayment, error) {
	if engine == nil {
		return nil, invalid("MultisigPool engine is required")
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	unsigned, err := unsignedFromRaw(rawTx, details)
	if err != nil {
		return nil, err
	}
	return unsigned, nil
}

// ParseFinalPaymentState parses a fully signed pool transaction and verifies it is the final settlement
// (sequence == finalPoolSequence).
func (engine *MultisigPoolEngine) ParseFinalPaymentState(ctx context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	state, err := engine.ParsePaymentState(ctx, rawTx, proof)
	if err != nil {
		return nil, err
	}
	if state.PaymentSequence != finalPoolSequence {
		return nil, ErrInvalidEvidence
	}
	if err := engine.VerifyFinalPayment(state, proof); err != nil {
		return nil, err
	}
	return state, nil
}

func (engine *MultisigPoolEngine) parseUnsignedOrSignedState(rawTx []byte, proof *OpeningProof) (*tx.Transaction, error) {
	if engine == nil || proof == nil {
		return nil, invalid("payment state and opening proof are required")
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	state, err := parseCanonicalTransaction(rawTx)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil || len(state.Outputs) != 3 {
		return nil, invalid("pool state must have one input and exactly three outputs")
	}
	if state.Inputs[0].SourceTXID == nil || hash32FromBytes(state.Inputs[0].SourceTXID.CloneBytes()) != details.FundingTxID || state.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return nil, invalid("pool state does not spend the opening pool outpoint")
	}
	setPoolSource(state, details.PoolOutputSatoshis, details.PoolLockingScript)
	unlocking := state.Inputs[0].UnlockingScript
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	if err := engine.verifyCanonicalState(state, proof, details, state.Outputs[1].Satoshis, state.Inputs[0].SequenceNumber, state.LockTime); err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = unlocking
	return state, nil
}

func (engine *MultisigPoolEngine) verifyOpeningState(state *tx.Transaction, fundingID []byte, outputIndex uint32, poolAmount, feeRate uint64) error {
	if len(state.Outputs) != 3 || state.Inputs[0].SequenceNumber == finalPoolSequence {
		return invalid("opening state shape is invalid")
	}
	if !bytes.Equal(state.Inputs[0].SourceTXID.CloneBytes(), fundingID) || state.Inputs[0].SourceTxOutIndex != outputIndex {
		return invalid("opening state outpoint is invalid")
	}
	expected, err := mp.BuildArbitratedPoolOpeningState(fundingID, outputIndex, poolAmount, engine.roles(), state.LockTime, mp.FeeSatPerKB(feeRate))
	if err != nil {
		return err
	}
	setPoolSource(expected, poolAmount, engine.lockBytes())
	return compareUnsignedState(state, expected)
}

func (engine *MultisigPoolEngine) verifyCanonicalState(state *tx.Transaction, proof *OpeningProof, details *OpeningDetails, sellerAmount uint64, sequence, lockTime uint32) error {
	if state.Outputs[2] == nil || state.Outputs[2].Satoshis != 0 {
		return invalid("arbiter amount must be zero")
	}
	if sequence == 0 {
		return invalid("payment sequence is invalid")
	}
	previous, err := parseCanonicalTransaction(state.Bytes())
	if err != nil {
		return err
	}
	previous.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	previous.Inputs[0].SequenceNumber = sequence - 1
	previousSource := &tx.TransactionOutput{Satoshis: details.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), details.PoolLockingScript...))}
	lock := lockTime
	expected, err := mp.BuildArbitratedPoolState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: previousSource, Sequence: sequence, LockTime: &lock, SellerAmount: sellerAmount, ArbiterAmount: 0, PoolAmount: details.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(proof.MinerFeeRateSatPerKB), PaymentProof: nil})
	if err != nil {
		return err
	}
	return compareUnsignedState(state, expected)
}

func compareUnsignedState(actual, expected *tx.Transaction) error {
	if actual == nil || expected == nil || !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		return invalid("pool state does not match canonical MultisigPool v4 state")
	}
	return nil
}

// CheckPaymentCapacity performs only deterministic arithmetic checks on a
// caller-supplied update. BuildPaymentUpdate first performs the complete
// proof-bound opening and previous-state verification, then calls this helper.
func (engine *MultisigPoolEngine) CheckPaymentCapacity(_ context.Context, input PaymentUpdateInput) error {
	if input.Opening == nil || input.Previous == nil {
		return ErrInsufficientBalance
	}
	details, err := engine.deriveOpeningDetails(input.Opening)
	if err != nil {
		return err
	}
	if input.SellerAmountAfterSat < input.Previous.SellerAmountSat || input.SellerAmountAfterSat > details.PoolOutputSatoshis {
		return ErrInsufficientBalance
	}
	if input.PaymentSequenceAfter <= input.Previous.PaymentSequence || input.PaymentSequenceAfter == finalPoolSequence {
		return ErrStalePaymentSequence
	}
	return nil
}

// BuildPaymentUpdate constructs the next unsigned pool state transaction from the previous accepted payment
// and the requested amounts.
func (engine *MultisigPoolEngine) BuildPaymentUpdate(ctx context.Context, input PaymentUpdateInput) (*UnsignedPayment, error) {
	if engine == nil || input.Opening == nil || input.Previous == nil {
		return nil, invalid("opening proof and previous payment are required")
	}
	if err := engine.VerifyOpening(input.Opening); err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(input.Opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(input.Previous, input.Opening); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(input.Previous, input.Opening); arbitrationErr != nil {
			return nil, invalid("previous payment is not a valid proof-bound accepted state")
		}
	}
	if input.Previous.PaymentSequence == finalPoolSequence || input.PaymentSequenceAfter != input.Previous.PaymentSequence+1 || input.PaymentSequenceAfter == finalPoolSequence {
		return nil, ErrStalePaymentSequence
	}
	if err := engine.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	previous, err := parseCanonicalTransaction(input.Previous.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(previous, details.PoolOutputSatoshis, details.PoolLockingScript)
	state, err := mp.BuildArbitratedPoolState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: &tx.TransactionOutput{Satoshis: details.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), details.PoolLockingScript...))}, Sequence: input.PaymentSequenceAfter, SellerAmount: input.SellerAmountAfterSat, ArbiterAmount: 0, PoolAmount: details.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB), PaymentProof: nil})
	if err != nil {
		return nil, err
	}
	return unsignedFromTx(state, details, input.PaymentSequenceAfter), nil
}

// SignBuyerPayment produces the buyer's detached signature over an unsigned pool transaction.
func (adapter *BuyerPoolAdapter) SignBuyerPayment(ctx context.Context, unsigned *UnsignedPayment, proof *OpeningProof) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("buyer signing inputs are required")
	}
	state, err := adapter.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	sig, err := adapter.signWithSigner(ctx, state, unsigned.PoolOutputSatoshis, adapter.Key, "buyer")
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

// SignSellerArbitrationCandidate produces the seller's detached signature over an arbitration candidate transaction.
func (adapter *SellerPoolAdapter) SignSellerArbitrationCandidate(ctx context.Context, unsigned *UnsignedPayment, proof *OpeningProof) ([]byte, error) {
	if unsigned == nil || unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbitration candidate cannot use final sequence")
	}
	return adapter.signSeller(ctx, unsigned, proof)
}

// SignSellerPayment produces the seller's detached signature over an unsigned pool transaction.
func (adapter *SellerPoolAdapter) SignSellerPayment(ctx context.Context, unsigned *UnsignedPayment, proof *OpeningProof) ([]byte, error) {
	return adapter.signSeller(ctx, unsigned, proof)
}

// SignImmediateClose signs the seller's portion of an immediate close and merges it with the buyer signature,
// returning the completed SignedPayment.
func (adapter *SellerPoolAdapter) SignImmediateClose(ctx context.Context, unsigned *UnsignedPayment, buyerSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	sellerSig, err := adapter.signSeller(ctx, unsigned, proof)
	if err != nil {
		return nil, err
	}
	return adapter.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
}

// SignArbiterPayment produces the arbiter's detached signature over an unsigned pool transaction.
func (adapter *ArbiterPoolAdapter) SignArbiterPayment(ctx context.Context, unsigned *UnsignedPayment, proof *OpeningProof) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("arbiter signing inputs are required")
	}
	if unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbiter payment cannot use final sequence")
	}
	state, err := adapter.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	sig, err := adapter.signWithSigner(ctx, state, unsigned.PoolOutputSatoshis, adapter.Key, "arbiter")
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (adapter *SellerPoolAdapter) signSeller(ctx context.Context, unsigned *UnsignedPayment, proof *OpeningProof) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("seller signing inputs are required")
	}
	state, err := adapter.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	sig, err := adapter.signWithSigner(ctx, state, unsigned.PoolOutputSatoshis, adapter.Key, "seller")
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

// signWithSigner computes the canonical MultisigPool sighash in the core and
// delegates only the basic signing operation. The signer boundary never receives a
// transaction or private key; it receives the exact 32-byte digest and its
// result is normalized to the protocol's required sighash byte.
func (engine *MultisigPoolEngine) signWithSigner(ctx context.Context, state *tx.Transaction, poolAmount uint64, signer Signer, role string) ([]byte, error) {
	if engine == nil || state == nil || signer == nil {
		return nil, invalid("pool signer and transaction are required")
	}
	pub, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	want := engine.buyer
	switch role {
	case "seller":
		want = engine.seller
	case "arbiter":
		want = engine.arbiter
	case "buyer":
	default:
		return nil, invalid("unsupported pool signer role")
	}
	got, err := parsePoolKey(pub)
	if err != nil || !got.IsEqual(want) {
		return nil, invalid(role + " signer does not match pool role")
	}
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	digest, err := state.CalcInputSignatureHash(0, flag)
	if err != nil {
		return nil, err
	}
	raw, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, invalid(role + " signer returned an empty signature")
	}
	if _, err := ec.ParseDERSignature(raw); err != nil {
		return nil, fmt.Errorf("%s signer returned invalid DER signature: %w", role, err)
	}
	result := append(append([]byte(nil), raw...), byte(flag))
	var valid bool
	switch role {
	case "buyer":
		valid, err = mp.VerifyArbitratedPoolBuyerSignature(state, poolAmount, engine.roles(), result)
	case "seller":
		valid, err = mp.VerifyArbitratedPoolSellerSignature(state, poolAmount, engine.roles(), result)
	case "arbiter":
		valid, err = mp.VerifyArbitratedPoolArbiterSignature(state, poolAmount, engine.roles(), result)
	}
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, invalid(role + " signer returned a signature that does not verify")
	}
	return result, nil
}

func (adapter *BuyerPoolAdapter) validateUnsignedPayment(unsigned *UnsignedPayment, proof *OpeningProof) (*tx.Transaction, error) {
	return adapter.MultisigPoolEngine.validateUnsignedPayment(unsigned, proof)
}
func (adapter *SellerPoolAdapter) validateUnsignedPayment(unsigned *UnsignedPayment, proof *OpeningProof) (*tx.Transaction, error) {
	return adapter.MultisigPoolEngine.validateUnsignedPayment(unsigned, proof)
}
func (adapter *ArbiterPoolAdapter) validateUnsignedPayment(unsigned *UnsignedPayment, proof *OpeningProof) (*tx.Transaction, error) {
	return adapter.MultisigPoolEngine.validateUnsignedPayment(unsigned, proof)
}

// VerifyBuyerPayment checks the buyer role's detached signature over the exact
// unsigned 005 payment state, after validating its canonical outputs against the
// 002 opening proof. It does not merge the seller signature or submit the state.
func (adapter *SellerPoolAdapter) VerifyBuyerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	if adapter == nil || adapter.MultisigPoolEngine == nil {
		return invalid("seller pool adapter requires an engine")
	}
	return adapter.MultisigPoolEngine.verifyDetached(unsigned, sig, proof, "buyer")
}

// VerifySellerPayment checks the seller role's detached signature over the exact
// unsigned 005 payment state and its canonical relation to the 002 opening
// proof. It does not merge the buyer signature or submit the update.
func (adapter *SellerPoolAdapter) VerifySellerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	if adapter == nil || adapter.MultisigPoolEngine == nil {
		return invalid("seller pool adapter requires an engine")
	}
	return adapter.MultisigPoolEngine.verifyDetached(unsigned, sig, proof, "seller")
}

// VerifySellerPayment checks the seller role's detached signature over the exact
// unsigned 005 payment state and its canonical relation to the 002 opening
// proof. It does not merge signatures or submit the update.
func (engine *MultisigPoolEngine) VerifySellerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	if engine == nil {
		return invalid("pool engine is required")
	}
	return engine.verifyDetached(unsigned, sig, proof, "seller")
}

// VerifyBuyerPayment checks the buyer role's detached signature over the exact
// unsigned 005 payment state and its canonical relation to the 002 opening
// proof. It does not merge signatures or submit the update.
func (engine *MultisigPoolEngine) VerifyBuyerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	if engine == nil {
		return invalid("pool engine is required")
	}
	return engine.verifyDetached(unsigned, sig, proof, "buyer")
}

// VerifyArbiterPayment validates a detached arbiter signature over an
// unsigned cumulative state before the signature can leave the SDK.
func (engine *MultisigPoolEngine) VerifyArbiterPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	if engine == nil {
		return invalid("pool engine is required")
	}
	if unsigned == nil || unsigned.PaymentSequence == finalPoolSequence {
		return invalid("arbiter payment cannot use final sequence")
	}
	return engine.verifyDetached(unsigned, sig, proof, "arbiter")
}

func (engine *MultisigPoolEngine) verifyDetached(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof, role string) error {
	if engine == nil || unsigned == nil || len(sig) == 0 || proof == nil {
		return invalid("unsigned payment and detached signature are required")
	}
	state, err := engine.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return err
	}
	var ok bool
	switch role {
	case "buyer":
		ok, err = mp.VerifyArbitratedPoolBuyerSignature(state, details.PoolOutputSatoshis, engine.roles(), sig)
	case "seller":
		ok, err = mp.VerifyArbitratedPoolSellerSignature(state, details.PoolOutputSatoshis, engine.roles(), sig)
	case "arbiter":
		ok, err = mp.VerifyArbitratedPoolArbiterSignature(state, details.PoolOutputSatoshis, engine.roles(), sig)
	default:
		return invalid("unsupported detached signature role")
	}
	if err != nil {
		return err
	}
	if !ok {
		return invalid(role + " transaction signature is invalid")
	}
	return nil
}

func (engine *MultisigPoolEngine) verifyCanonicalStateFromProof(unsigned *UnsignedPayment, proof *OpeningProof) error {
	_, err := engine.validateUnsignedPayment(unsigned, proof)
	return err
}

// validateUnsignedPayment is the single proof-bound validation path for every
// transaction-level signing and merge operation. It verifies the complete
// opening proof, raw funding outpoint, canonical state, and every public
// UnsignedPayment metadata field before a signer or merge is reached.
func (engine *MultisigPoolEngine) validateUnsignedPayment(unsigned *UnsignedPayment, proof *OpeningProof) (*tx.Transaction, error) {
	if engine == nil || unsigned == nil || proof == nil {
		return nil, invalid("unsigned payment and opening proof are required")
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	parsed, err := unsignedFromRaw(unsigned.RawTx, details)
	if err != nil {
		return nil, err
	}
	if unsigned.SpendTxID != parsed.SpendTxID || unsigned.PaymentSequence != parsed.PaymentSequence || unsigned.BuyerAmountSat != parsed.BuyerAmountSat || unsigned.SellerAmountSat != parsed.SellerAmountSat || unsigned.ArbiterAmountSat != parsed.ArbiterAmountSat || unsigned.PoolOutputSatoshis != parsed.PoolOutputSatoshis || !bytes.Equal(unsigned.PoolLockingScript, parsed.PoolLockingScript) {
		return nil, invalid("unsigned payment metadata does not match proof-bound raw transaction")
	}
	state, err := parseCanonicalTransaction(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, details.PoolOutputSatoshis, details.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	if err := engine.verifyCanonicalState(state, proof, details, state.Outputs[1].Satoshis, state.Inputs[0].SequenceNumber, state.LockTime); err != nil {
		return nil, err
	}
	return state, nil
}

// MergeBuyerSellerPayment combines detached role signatures into the required fully signed payment transaction.
func (adapter *SellerPoolAdapter) MergeBuyerSellerPayment(unsigned *UnsignedPayment, buyerSig, sellerSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil {
		return nil, invalid("seller pool adapter requires an engine")
	}
	return adapter.MultisigPoolEngine.mergeBuyerSeller(unsigned, buyerSig, sellerSig, proof)
}

func (engine *MultisigPoolEngine) MergeBuyerSellerPayment(unsigned *UnsignedPayment, buyerSig, sellerSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	if engine == nil {
		return nil, invalid("pool engine is required")
	}
	return engine.mergeBuyerSeller(unsigned, buyerSig, sellerSig, proof)
}

// MergeSellerArbiterPayment combines detached role signatures into the required fully signed payment transaction.
func (adapter *SellerPoolAdapter) MergeSellerArbiterPayment(unsigned *UnsignedPayment, sellerSig, arbiterSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil {
		return nil, invalid("seller pool adapter requires an engine")
	}
	return adapter.MultisigPoolEngine.mergeSellerArbiter(unsigned, sellerSig, arbiterSig, proof)
}

func (engine *MultisigPoolEngine) MergeSellerArbiterPayment(unsigned *UnsignedPayment, sellerSig, arbiterSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	if engine == nil {
		return nil, invalid("pool engine is required")
	}
	return engine.mergeSellerArbiter(unsigned, sellerSig, arbiterSig, proof)
}

func (engine *MultisigPoolEngine) mergeBuyerSeller(unsigned *UnsignedPayment, buyerSig, sellerSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	state, err := engine.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	if ok, err := mp.VerifyArbitratedPoolBuyerSignature(state, details.PoolOutputSatoshis, engine.roles(), buyerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("buyer transaction signature is invalid")
	}
	if ok, err := mp.VerifyArbitratedPoolSellerSignature(state, details.PoolOutputSatoshis, engine.roles(), sellerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("seller transaction signature is invalid")
	}
	merged, err := mp.MergeArbitratedPoolBuyerSellerSignatures(state, details.PoolOutputSatoshis, engine.roles(), buyerSig, sellerSig)
	if err != nil {
		return nil, err
	}
	return engine.signedFromTx(merged, unsigned, buyerSig, sellerSig, nil), nil
}

func (engine *MultisigPoolEngine) mergeSellerArbiter(unsigned *UnsignedPayment, sellerSig, arbiterSig []byte, proof *OpeningProof) (*SignedPayment, error) {
	if unsigned == nil || unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbitration payment cannot use final sequence")
	}
	state, err := engine.validateUnsignedPayment(unsigned, proof)
	if err != nil {
		return nil, err
	}
	if unsigned.PaymentSequence == finalPoolSequence {
		return nil, invalid("arbitration payment cannot use final sequence")
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	if ok, err := mp.VerifyArbitratedPoolSellerSignature(state, details.PoolOutputSatoshis, engine.roles(), sellerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("seller transaction signature is invalid")
	}
	if ok, err := mp.VerifyArbitratedPoolArbiterSignature(state, details.PoolOutputSatoshis, engine.roles(), arbiterSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("arbiter transaction signature is invalid")
	}
	merged, err := mp.MergeArbitratedPoolSellerArbiterSignatures(state, details.PoolOutputSatoshis, engine.roles(), sellerSig, arbiterSig)
	if err != nil {
		return nil, err
	}
	return engine.signedFromTx(merged, unsigned, nil, sellerSig, arbiterSig), nil
}

// BuildImmediateClose constructs the unsigned final close state from the
// accepted payment and CloseInput. The buyer obtains its detached signature
// separately through BuyerPoolAdapter before the seller adds its signature.
func (engine *MultisigPoolEngine) BuildImmediateClose(_ context.Context, input CloseInput) (*UnsignedPayment, error) {
	if engine == nil || input.Opening == nil || input.Latest == nil {
		return nil, invalid("opening proof and latest state are required")
	}
	if err := engine.VerifyOpening(input.Opening); err != nil {
		return nil, err
	}
	details, err := engine.deriveOpeningDetails(input.Opening)
	if err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(input.Latest, input.Opening); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(input.Latest, input.Opening); arbitrationErr != nil {
			return nil, invalid("latest pool state is not a valid accepted or arbitrated payment")
		}
	}
	if input.Latest.PaymentSequence >= finalPoolSequence {
		return nil, invalid("latest pool state is already final")
	}
	if input.SellerAmountAfterSat < input.Latest.SellerAmountSat || input.SellerAmountAfterSat > details.PoolOutputSatoshis {
		return nil, invalid("immediate close seller amount is outside the accepted pool state")
	}
	previous, err := parseCanonicalTransaction(input.Latest.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(previous, details.PoolOutputSatoshis, details.PoolLockingScript)
	locktime := finalPoolSequence
	state, err := mp.BuildArbitratedPoolFinalState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: &tx.TransactionOutput{Satoshis: details.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), details.PoolLockingScript...))}, Sequence: finalPoolSequence, LockTime: &locktime, SellerAmount: input.SellerAmountAfterSat, ArbiterAmount: 0, PoolAmount: details.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB), PaymentProof: nil})
	if err != nil {
		return nil, err
	}
	unsigned := unsignedFromTx(state, details, finalPoolSequence)
	return unsigned, nil
}

// VerifyFinalPayment checks a fully signed final transaction against the opening
// proof, final sequence, role signatures, outputs, and canonical transaction bytes.
func (engine *MultisigPoolEngine) VerifyFinalPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil || state.PaymentSequence != finalPoolSequence {
		return invalid("final payment state is invalid")
	}
	return engine.verifyComplete(state, proof, false)
}

// VerifyAcceptedPayment checks the initial or previously accepted non-arbitrated
// payment state against the opening proof and its complete role signatures.
func (engine *MultisigPoolEngine) VerifyAcceptedPayment(state *PaymentState, proof *OpeningProof) error {
	return engine.verifyComplete(state, proof, false)
}

// VerifyArbitratedPayment checks a final state carrying the seller and arbiter
// signatures required by the 007 arbitration path.
func (engine *MultisigPoolEngine) VerifyArbitratedPayment(state *PaymentState, proof *OpeningProof) error {
	return engine.verifyComplete(state, proof, true)
}

// VerifyCompletedFinalPayment validates the merged SignedPayment and identifies
// whether its detached signatures form a valid final settlement state.
func (engine *MultisigPoolEngine) VerifyCompletedFinalPayment(payment *SignedPayment, proof *OpeningProof) error {
	if payment == nil {
		return invalid("signed payment is required")
	}
	if len(payment.RawTx) == 0 || !bytes.Equal(payment.RawTx, payment.State.RawTx) {
		return invalid("signed payment transaction bytes do not match state")
	}
	return engine.VerifyFinalPayment(&payment.State, proof)
}

// PaymentStateMatchesUnsigned proves that a previously accepted signed state
// is the exact same unsigned candidate, including all canonical transaction
// bytes. It is used only for idempotent completion retries and never signs or
// submits anything.
func (engine *MultisigPoolEngine) PaymentStateMatchesUnsigned(state *PaymentState, unsigned *UnsignedPayment, proof *OpeningProof) error {
	if engine == nil || state == nil || unsigned == nil {
		return invalid("payment state and unsigned payment are required")
	}
	if err := engine.VerifyAcceptedPayment(state, proof); err != nil {
		if arbitrationErr := engine.VerifyArbitratedPayment(state, proof); arbitrationErr != nil {
			return err
		}
	}
	parsed, err := parseCanonicalTransaction(state.RawTx)
	if err != nil {
		return err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return err
	}
	setPoolSource(parsed, details.PoolOutputSatoshis, details.PoolLockingScript)
	cleared := clearUnlocking(parsed)
	if cleared == nil || !bytes.Equal(cleared.Bytes(), unsigned.RawTx) {
		return invalid("accepted payment does not match unsigned candidate bytes")
	}
	return nil
}

func (engine *MultisigPoolEngine) verifyComplete(state *PaymentState, proof *OpeningProof, arbitration bool) error {
	if engine == nil || state == nil || proof == nil || len(state.RawTx) == 0 {
		return invalid("complete payment state and opening proof are required")
	}
	parsed, err := engine.parseUnsignedOrSignedState(state.RawTx, proof)
	if err != nil {
		return err
	}
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return err
	}
	if state.SpendTxID != details.SpendTxID || state.PaymentSequence != parsed.Inputs[0].SequenceNumber || state.BuyerAmountSat != parsed.Outputs[0].Satoshis || state.SellerAmountSat != parsed.Outputs[1].Satoshis || state.ArbiterAmountSat != parsed.Outputs[2].Satoshis || state.ArbiterAmountSat != 0 {
		return invalid("payment state metadata does not match transaction outputs")
	}
	if len(parsed.Inputs[0].UnlockingScript.Bytes()) == 0 {
		return invalid("complete payment must contain two signatures")
	}
	sigs, err := transactionSignatures(parsed)
	if err != nil || len(sigs) != 2 {
		return invalid("complete payment must contain exactly two signatures")
	}
	unsigned := *unsignedFromTx(parsed, details, parsed.Inputs[0].SequenceNumber)
	unsigned.SpendTxID = state.SpendTxID
	var rebuilt *tx.Transaction
	if arbitration {
		rebuilt, err = mp.MergeArbitratedPoolSellerArbiterSignatures(clearUnlocking(parsed), details.PoolOutputSatoshis, engine.roles(), sigs[0], sigs[1])
	} else {
		rebuilt, err = mp.MergeArbitratedPoolBuyerSellerSignatures(clearUnlocking(parsed), details.PoolOutputSatoshis, engine.roles(), sigs[0], sigs[1])
	}
	if err != nil || !bytes.Equal(rebuilt.Bytes(), parsed.Bytes()) {
		if err != nil {
			return err
		}
		return invalid("complete payment signatures do not match canonical MultisigPool v4 merge")
	}
	return nil
}

func (engine *MultisigPoolEngine) stateFromTransaction(state *tx.Transaction, proof *OpeningProof) (*PaymentState, error) {
	details, err := engine.deriveOpeningDetails(proof)
	if err != nil {
		return nil, err
	}
	result := &PaymentState{SpendTxID: details.SpendTxID, RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: details.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), details.PoolLockingScript...)}
	sigs, err := transactionSignatures(state)
	if err != nil || len(sigs) != 2 {
		return nil, invalid("complete payment must contain exactly two signatures")
	}
	unsigned := clearUnlocking(state)
	for _, sig := range sigs {
		role, err := engine.signatureRole(unsigned, sig)
		if err != nil {
			return nil, err
		}
		switch role {
		case "buyer":
			if len(result.BuyerTransactionSignature) != 0 {
				return nil, invalid("buyer signature is duplicated")
			}
			result.BuyerTransactionSignature = append([]byte(nil), sig...)
		case "seller":
			if len(result.SellerTransactionSignature) != 0 {
				return nil, invalid("seller signature is duplicated")
			}
			result.SellerTransactionSignature = append([]byte(nil), sig...)
		case "arbiter":
			if len(result.ArbiterTransactionSignature) != 0 {
				return nil, invalid("arbiter signature is duplicated")
			}
			result.ArbiterTransactionSignature = append([]byte(nil), sig...)
		}
	}
	if len(result.SellerTransactionSignature) == 0 || (len(result.BuyerTransactionSignature) == 0 && len(result.ArbiterTransactionSignature) == 0) || (len(result.BuyerTransactionSignature) != 0 && len(result.ArbiterTransactionSignature) != 0) {
		return nil, invalid("payment signatures do not form Buyer+Seller or Seller+Arbiter")
	}
	return result, nil
}

func (engine *MultisigPoolEngine) signatureRole(unsigned *tx.Transaction, sig []byte) (string, error) {
	if unsigned == nil || len(unsigned.Inputs) != 1 || unsigned.Inputs[0] == nil || unsigned.Inputs[0].SourceTxOutput() == nil {
		return "", invalid("payment source output is required for signature identification")
	}
	roles := engine.roles()
	poolAmount := unsigned.Inputs[0].SourceTxOutput().Satoshis
	checks := []struct {
		name string
		ok   func() (bool, error)
	}{
		{name: "buyer", ok: func() (bool, error) {
			return mp.VerifyArbitratedPoolBuyerSignature(unsigned, poolAmount, roles, sig)
		}},
		{name: "seller", ok: func() (bool, error) {
			return mp.VerifyArbitratedPoolSellerSignature(unsigned, poolAmount, roles, sig)
		}},
		{name: "arbiter", ok: func() (bool, error) {
			return mp.VerifyArbitratedPoolArbiterSignature(unsigned, poolAmount, roles, sig)
		}},
	}
	var match string
	for _, check := range checks {
		ok, _ := check.ok()
		if ok {
			if match != "" {
				return "", invalid("payment signature matches multiple pool roles")
			}
			match = check.name
		}
	}
	if match == "" {
		return "", invalid("payment signature does not match a pool role")
	}
	return match, nil
}

func unsignedFromTx(state *tx.Transaction, details *OpeningDetails, sequence uint32) *UnsignedPayment {
	return &UnsignedPayment{SpendTxID: details.SpendTxID, RawTx: state.Bytes(), PaymentSequence: sequence, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: details.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), details.PoolLockingScript...)}
}
func (engine *MultisigPoolEngine) signedFromTx(state *tx.Transaction, unsigned *UnsignedPayment, buyer, seller, arbiter []byte) *SignedPayment {
	return &SignedPayment{State: PaymentState{SpendTxID: unsigned.SpendTxID, RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, BuyerTransactionSignature: append([]byte(nil), buyer...), SellerTransactionSignature: append([]byte(nil), seller...), ArbiterTransactionSignature: append([]byte(nil), arbiter...), PoolOutputSatoshis: unsigned.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), unsigned.PoolLockingScript...)}, RawTx: state.Bytes()}
}

func (engine *MultisigPoolEngine) lockBytes() []byte {
	lock, _ := mp.BuildArbitratedPoolLock(engine.roles())
	if lock == nil {
		return nil
	}
	return lock.Bytes()
}
func (engine *MultisigPoolEngine) matchConfiguredParticipantKeys(seller, arbiter []byte) error {
	sellerKey, err := parsePoolKey(seller)
	if err != nil {
		return err
	}
	arbiterKey, err := parsePoolKey(arbiter)
	if err != nil {
		return err
	}
	if !sellerKey.IsEqual(engine.seller) || !arbiterKey.IsEqual(engine.arbiter) {
		return invalid("opening participant roles do not match configured pool")
	}
	return nil
}
func (engine *MultisigPoolEngine) validateRequestRoles(buyer, seller, arbiter []byte) error {
	if engine == nil {
		return invalid("MultisigPool engine is required")
	}
	buyerKey, err := parsePoolKey(buyer)
	if err != nil {
		return err
	}
	sellerKey, err := parsePoolKey(seller)
	if err != nil {
		return err
	}
	arbiterKey, err := parsePoolKey(arbiter)
	if err != nil {
		return err
	}
	if !buyerKey.IsEqual(engine.buyer) || !sellerKey.IsEqual(engine.seller) || !arbiterKey.IsEqual(engine.arbiter) {
		return invalid("pool participant roles do not match configured pool")
	}
	return nil
}
func parsePoolKey(raw []byte) (*ec.PublicKey, error) {
	key, err := protocol.ParseCompressedPubKey(raw)
	if err != nil {
		return nil, invalid(err.Error())
	}
	return key, nil
}
func setPoolSource(state *tx.Transaction, amount uint64, lock []byte) {
	if state != nil && len(state.Inputs) == 1 {
		state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: amount, LockingScript: script.NewFromBytes(append([]byte(nil), lock...))})
	}
}
func requireUnsigned(state *tx.Transaction) error {
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return invalid("transaction must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return invalid("transaction must have an empty unlocking script")
	}
	return nil
}
func clearUnlocking(state *tx.Transaction) *tx.Transaction {
	copy, _ := parseCanonicalTransaction(state.Bytes())
	if copy != nil && len(copy.Inputs) == 1 {
		copy.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	}
	if copy != nil {
		setPoolSource(copy, state.Inputs[0].SourceTxOutput().Satoshis, state.Inputs[0].SourceTxOutput().LockingScript.Bytes())
	}
	return copy
}
func transactionSignatures(state *tx.Transaction) ([][]byte, error) {
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil || state.Inputs[0].UnlockingScript == nil {
		return nil, invalid("unlocking script is required")
	}
	chunks, err := state.Inputs[0].UnlockingScript.Chunks()
	if err != nil || len(chunks) != 3 || chunks[0].Op != script.Op0 {
		return nil, invalid("invalid multisig unlocking script")
	}
	return [][]byte{append([]byte(nil), chunks[1].Data...), append([]byte(nil), chunks[2].Data...)}, nil
}
