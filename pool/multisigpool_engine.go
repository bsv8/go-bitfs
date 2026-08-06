package pool

// This file is the single MultisigPool v4 boundary.  It owns no transaction
// algorithm: scripts, state construction, fees, sighash, role verification
// and signature ordering are delegated to github.com/bsv8/MultisigPool/v4.

import (
	"bytes"
	"context"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
)

const finalPoolSequence = ^uint32(0)

// Bitcoin nLockTime values below this threshold are block heights; values at
// or above it are Unix timestamps. A refund must be checked against exactly
// one of those clocks, never both.
const lockTimeTimestampThreshold uint32 = 500_000_000

type MultisigPoolEngineConfig struct {
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
	BlockHeight   func() uint32
}

type MultisigPoolEngine struct {
	buyer, seller, arbiter *ec.PublicKey
	blockHeight            func() uint32
}

type BuyerPoolAdapter struct {
	*MultisigPoolEngine
	Key PrivateKeyProvider
}
type SellerPoolAdapter struct {
	*MultisigPoolEngine
	Key PrivateKeyProvider
}
type ArbiterPoolAdapter struct {
	*MultisigPoolEngine
	Key PrivateKeyProvider
}

func NewBuyerPoolAdapter(engine *MultisigPoolEngine, key PrivateKeyProvider) *BuyerPoolAdapter {
	return &BuyerPoolAdapter{MultisigPoolEngine: engine, Key: key}
}
func NewSellerPoolAdapter(engine *MultisigPoolEngine, key PrivateKeyProvider) *SellerPoolAdapter {
	return &SellerPoolAdapter{MultisigPoolEngine: engine, Key: key}
}
func NewArbiterPoolAdapter(engine *MultisigPoolEngine, key PrivateKeyProvider) *ArbiterPoolAdapter {
	return &ArbiterPoolAdapter{MultisigPoolEngine: engine, Key: key}
}

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

func Build2of3LockingScript(pubkeys [][]byte) ([]byte, error) {
	if len(pubkeys) != 3 {
		return nil, invalid("exactly three pool public keys are required")
	}
	keys := make([]*ec.PublicKey, 3)
	for i, raw := range pubkeys {
		key, err := parsePoolKey(raw)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	lock, err := mp.BuildArbitratedPoolLock(mp.ArbitratedPoolRoles{Buyer: keys[0], Seller: keys[1], Arbiter: keys[2]})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

func (adapter *BuyerPoolAdapter) BuildRefundPresignRequest(ctx context.Context, input OpeningInput, _ Signer) (*RefundPresignRequest, error) {
	engine := adapter.MultisigPoolEngine
	if engine == nil || adapter.Key == nil {
		return nil, invalid("buyer private-key provider is required")
	}
	if input.ExpiryLockTime == 0 {
		return nil, invalid("refund expiry locktime is required")
	}
	if err := engine.matchConfiguredParticipantKeys(input.SellerPubKey, input.ArbiterPubKey); err != nil {
		return nil, err
	}
	funding, err := tx.NewTransactionFromBytes(input.FundingTx)
	if err != nil {
		return nil, err
	}
	if int(input.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[input.PoolOutputIndex] == nil {
		return nil, invalid("pool output index is outside funding transaction")
	}
	output := funding.Outputs[input.PoolOutputIndex]
	lock, err := mp.BuildArbitratedPoolLock(engine.roles())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(output.LockingScript.Bytes(), lock.Bytes()) {
		return nil, invalid("funding output does not use the configured pool lock")
	}
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(engine.buyer) {
		return nil, invalid("buyer private key does not match buyer role")
	}
	state, err := mp.BuildArbitratedPoolOpeningState(funding.TxID().CloneBytes(), input.PoolOutputIndex, output.Satoshis, engine.roles(), input.ExpiryLockTime, mp.FeeSatPerKB(input.MinerFeeRateSatPerKB))
	if err != nil {
		return nil, err
	}
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	sig, err := mp.SignArbitratedPoolAsBuyer(state, output.Satoshis, engine.roles(), key)
	if err != nil {
		return nil, err
	}
	return &RefundPresignRequest{Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion, RefundTx: state.Bytes(), FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: input.PoolOutputIndex, PoolOutputSatoshis: output.Satoshis, PoolLockingScript: append([]byte(nil), lock.Bytes()...), BuyerPubKey: engine.buyer.Compressed(), SellerPubKey: engine.seller.Compressed(), ArbiterPubKey: engine.arbiter.Compressed(), MinerFeeRateSatPerKB: input.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), sig...)}, nil
}

func (engine *MultisigPoolEngine) VerifySellerRefundSignature(_ context.Context, request *RefundPresignRequest, signature []byte) error {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return err
	}
	if err := engine.validateRequestRoles(request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey); err != nil {
		return err
	}
	state, err := tx.NewTransactionFromBytes(request.RefundTx)
	if err != nil {
		return err
	}
	setPoolSource(state, request.PoolOutputSatoshis, request.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return err
	}
	if err := engine.verifyOpeningState(state, request.FundingTxID, request.PoolOutputIndex, request.PoolOutputSatoshis, request.MinerFeeRateSatPerKB); err != nil {
		return err
	}
	ok, err := mp.VerifyArbitratedPoolBuyerSignature(state, request.PoolOutputSatoshis, engine.roles(), request.BuyerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("buyer refund signature is invalid")
	}
	ok, err = mp.VerifyArbitratedPoolSellerSignature(state, request.PoolOutputSatoshis, engine.roles(), signature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("seller refund signature is invalid")
	}
	return nil
}

type PoolRefundSigner struct{ Adapter *SellerPoolAdapter }

func (adapter PoolRefundSigner) SignRefundTx(ctx context.Context, request *RefundPresignRequest) ([]byte, error) {
	if adapter.Adapter == nil || adapter.Adapter.MultisigPoolEngine == nil || adapter.Adapter.Key == nil {
		return nil, invalid("seller private-key provider is required")
	}
	engine := adapter.Adapter.MultisigPoolEngine
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	if err := engine.validateRequestRoles(request.BuyerPubKey, request.SellerPubKey, request.ArbiterPubKey); err != nil {
		return nil, err
	}
	state, err := tx.NewTransactionFromBytes(request.RefundTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, request.PoolOutputSatoshis, request.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	if err := engine.verifyOpeningState(state, request.FundingTxID, request.PoolOutputIndex, request.PoolOutputSatoshis, request.MinerFeeRateSatPerKB); err != nil {
		return nil, err
	}
	key, err := adapter.Adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(engine.seller) {
		return nil, invalid("seller private key does not match seller role")
	}
	sig, err := mp.SignArbitratedPoolAsSeller(state, request.PoolOutputSatoshis, engine.roles(), key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (engine *MultisigPoolEngine) TransactionID(rawTx []byte) (Hash32, error) {
	value, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	return hash32FromBytes(value.TxID().CloneBytes()), nil
}

func (engine *MultisigPoolEngine) FundingTxID(rawTx []byte) (Hash32, error) {
	value, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	if len(value.Inputs) != 1 || value.Inputs[0] == nil || value.Inputs[0].SourceTXID == nil {
		return Hash32{}, invalid("transaction has no funding outpoint")
	}
	return hash32FromBytes(value.Inputs[0].SourceTXID.CloneBytes()), nil
}

func (engine *MultisigPoolEngine) VerifyOpening(proof *OpeningProof) error {
	if engine == nil {
		return invalid("MultisigPool engine is required")
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return err
	}
	if proof.MultisigProtocol != MultisigProtocol || proof.MultisigVersion != MultisigVersion {
		return invalid("opening proof is not bound to MultisigPool v4")
	}
	if err := engine.validateRequestRoles(proof.BuyerPubKey, proof.SellerPubKey, proof.ArbiterPubKey); err != nil {
		return err
	}
	funding, err := tx.NewTransactionFromBytes(proof.FundingTx)
	if err != nil {
		return err
	}
	if !bytes.Equal(funding.TxID().CloneBytes(), proof.FundingTxID) || int(proof.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[proof.PoolOutputIndex] == nil {
		return invalid("funding transaction does not match opening proof")
	}
	output := funding.Outputs[proof.PoolOutputIndex]
	if output.Satoshis != proof.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), proof.PoolLockingScript) {
		return invalid("funding pool output does not match opening proof")
	}
	refund, err := tx.NewTransactionFromBytes(proof.RefundTx)
	if err != nil {
		return err
	}
	setPoolSource(refund, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	if len(refund.Inputs) != 1 || refund.Inputs[0].SourceTXID == nil || !bytes.Equal(refund.Inputs[0].SourceTXID.CloneBytes(), proof.FundingTxID) || refund.Inputs[0].SourceTxOutIndex != proof.PoolOutputIndex {
		return invalid("refund transaction does not spend the opening pool outpoint")
	}
	if err := requireUnsigned(refund); err != nil {
		return err
	}
	if err := engine.verifyOpeningState(refund, proof.FundingTxID, proof.PoolOutputIndex, proof.PoolOutputSatoshis, proof.MinerFeeRateSatPerKB); err != nil {
		return err
	}
	ok, err := mp.VerifyArbitratedPoolBuyerSignature(refund, proof.PoolOutputSatoshis, engine.roles(), proof.BuyerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("buyer refund signature is invalid")
	}
	ok, err = mp.VerifyArbitratedPoolSellerSignature(refund, proof.PoolOutputSatoshis, engine.roles(), proof.SellerRefundSignature)
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("seller refund signature is invalid")
	}
	return nil
}

func (engine *MultisigPoolEngine) VerifyRefundExpired(proof *OpeningProof, now time.Time) error {
	if err := engine.VerifyOpening(proof); err != nil {
		return err
	}
	refund, err := tx.NewTransactionFromBytes(proof.RefundTx)
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

func (engine *MultisigPoolEngine) BuildRefundSubmission(proof *OpeningProof) ([]byte, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	refund, err := tx.NewTransactionFromBytes(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(refund, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	merged, err := mp.MergeArbitratedPoolBuyerSellerSignatures(refund, proof.PoolOutputSatoshis, engine.roles(), proof.BuyerRefundSignature, proof.SellerRefundSignature)
	if err != nil {
		return nil, err
	}
	return merged.Bytes(), nil
}

func (engine *MultisigPoolEngine) VerifyFundingTx(_ context.Context, rawTx []byte, proof *OpeningProof) error {
	if proof == nil {
		return invalid("funding transaction and opening proof are required")
	}
	funding, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return err
	}
	if !bytes.Equal(funding.TxID().CloneBytes(), proof.FundingTxID) || int(proof.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[proof.PoolOutputIndex] == nil {
		return invalid("funding transaction does not match opening proof")
	}
	output := funding.Outputs[proof.PoolOutputIndex]
	if output.Satoshis != proof.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), proof.PoolLockingScript) {
		return invalid("funding pool output does not match opening proof")
	}
	lock, err := mp.BuildArbitratedPoolLock(engine.roles())
	if err != nil || !bytes.Equal(lock.Bytes(), output.LockingScript.Bytes()) {
		return invalid("funding pool output role script is invalid")
	}
	return nil
}

func (engine *MultisigPoolEngine) VerifyPoolParticipants(proof *OpeningProof, buyer, seller, arbiter []byte) error {
	if proof == nil || !bytes.Equal(proof.BuyerPubKey, buyer) || !bytes.Equal(proof.SellerPubKey, seller) || !bytes.Equal(proof.ArbiterPubKey, arbiter) {
		return invalid("pool participant roles do not match")
	}
	return nil
}

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

func (engine *MultisigPoolEngine) ParseUnsignedPayment(_ context.Context, rawTx []byte, proof *OpeningProof) (*UnsignedPayment, error) {
	unsigned, err := unsignedFromRaw(rawTx, proof)
	if err != nil {
		return nil, err
	}
	if err := engine.verifyCanonicalStateFromProof(unsigned, proof); err != nil {
		return nil, err
	}
	return unsigned, nil
}

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
	state, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil || len(state.Outputs) != 3 {
		return nil, invalid("pool state must have one input and exactly three outputs")
	}
	if state.Inputs[0].SourceTXID == nil || !bytes.Equal(state.Inputs[0].SourceTXID.CloneBytes(), proof.FundingTxID) || state.Inputs[0].SourceTxOutIndex != proof.PoolOutputIndex {
		return nil, invalid("pool state does not spend the opening pool outpoint")
	}
	setPoolSource(state, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	unlocking := state.Inputs[0].UnlockingScript
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	if err := engine.verifyCanonicalState(state, proof, state.Outputs[1].Satoshis, state.Inputs[0].SequenceNumber, state.LockTime); err != nil {
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

func (engine *MultisigPoolEngine) verifyCanonicalState(state *tx.Transaction, proof *OpeningProof, sellerAmount uint64, sequence, lockTime uint32) error {
	if state.Outputs[2] == nil || state.Outputs[2].Satoshis != 0 {
		return invalid("arbiter amount must be zero")
	}
	if sequence == 0 {
		return invalid("payment sequence is invalid")
	}
	previous, err := tx.NewTransactionFromBytes(state.Bytes())
	if err != nil {
		return err
	}
	previous.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	previous.Inputs[0].SequenceNumber = sequence - 1
	previousSource := &tx.TransactionOutput{Satoshis: proof.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...))}
	lock := lockTime
	expected, err := mp.BuildArbitratedPoolState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: previousSource, Sequence: sequence, LockTime: &lock, SellerAmount: sellerAmount, ArbiterAmount: 0, PoolAmount: proof.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(proof.MinerFeeRateSatPerKB), PaymentProof: nil})
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

func (engine *MultisigPoolEngine) CheckPaymentCapacity(_ context.Context, input PaymentUpdateInput) error {
	if input.Opening == nil || input.Previous == nil {
		return ErrInsufficientBalance
	}
	if input.SellerAmountAfterSat < input.Previous.SellerAmountSat || input.SellerAmountAfterSat > input.Opening.PoolOutputSatoshis {
		return ErrInsufficientBalance
	}
	if input.PaymentSequenceAfter <= input.Previous.PaymentSequence || input.PaymentSequenceAfter == finalPoolSequence {
		return ErrStalePaymentSequence
	}
	return nil
}

func (engine *MultisigPoolEngine) BuildPaymentUpdate(ctx context.Context, input PaymentUpdateInput) (*UnsignedPayment, error) {
	if err := engine.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	previous, err := tx.NewTransactionFromBytes(input.Previous.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(previous, input.Opening.PoolOutputSatoshis, input.Opening.PoolLockingScript)
	state, err := mp.BuildArbitratedPoolState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: &tx.TransactionOutput{Satoshis: input.Opening.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), input.Opening.PoolLockingScript...))}, Sequence: input.PaymentSequenceAfter, SellerAmount: input.SellerAmountAfterSat, ArbiterAmount: 0, PoolAmount: input.Opening.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB), PaymentProof: nil})
	if err != nil {
		return nil, err
	}
	return unsignedFromTx(state, input.Opening, input.PaymentSequenceAfter), nil
}

func (adapter *BuyerPoolAdapter) SignBuyerPayment(ctx context.Context, unsigned *UnsignedPayment, _ Signer) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("buyer signing inputs are required")
	}
	state, err := adapter.unsignedTx(unsigned)
	if err != nil {
		return nil, err
	}
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(adapter.buyer) {
		return nil, invalid("buyer private key does not match buyer role")
	}
	sig, err := mp.SignArbitratedPoolAsBuyer(state, unsigned.PoolOutputSatoshis, adapter.roles(), key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (adapter *SellerPoolAdapter) SignSellerArbitrationCandidate(ctx context.Context, unsigned *UnsignedPayment, _ Signer) ([]byte, error) {
	return adapter.signSeller(ctx, unsigned)
}
func (adapter *SellerPoolAdapter) SignSellerPayment(ctx context.Context, unsigned *UnsignedPayment, _ Signer) ([]byte, error) {
	return adapter.signSeller(ctx, unsigned)
}

func (adapter *SellerPoolAdapter) SignImmediateClose(ctx context.Context, unsigned *UnsignedPayment, buyerSig []byte, _ Signer) (*SignedPayment, error) {
	sellerSig, err := adapter.signSeller(ctx, unsigned)
	if err != nil {
		return nil, err
	}
	return adapter.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig)
}

func (adapter *ArbiterPoolAdapter) SignArbiterPayment(ctx context.Context, unsigned *UnsignedPayment, _ Signer) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("arbiter signing inputs are required")
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(adapter.arbiter) {
		return nil, invalid("arbiter private key does not match arbiter role")
	}
	sig, err := mp.SignArbitratedPoolAsArbiter(state, unsigned.PoolOutputSatoshis, adapter.roles(), key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (adapter *SellerPoolAdapter) signSeller(ctx context.Context, unsigned *UnsignedPayment) ([]byte, error) {
	if adapter == nil || adapter.MultisigPoolEngine == nil || adapter.Key == nil || unsigned == nil {
		return nil, invalid("seller signing inputs are required")
	}
	state, err := adapter.unsignedTx(unsigned)
	if err != nil {
		return nil, err
	}
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(adapter.seller) {
		return nil, invalid("seller private key does not match seller role")
	}
	sig, err := mp.SignArbitratedPoolAsSeller(state, unsigned.PoolOutputSatoshis, adapter.roles(), key)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func (adapter *BuyerPoolAdapter) unsignedTx(unsigned *UnsignedPayment) (*tx.Transaction, error) {
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	return state, nil
}
func (adapter *SellerPoolAdapter) unsignedTx(unsigned *UnsignedPayment) (*tx.Transaction, error) {
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (adapter *SellerPoolAdapter) VerifyBuyerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	return adapter.MultisigPoolEngine.verifyDetached(unsigned, sig, proof, "buyer")
}
func (adapter *SellerPoolAdapter) VerifySellerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	return adapter.MultisigPoolEngine.verifyDetached(unsigned, sig, proof, "seller")
}

func (engine *MultisigPoolEngine) VerifySellerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	return engine.verifyDetached(unsigned, sig, proof, "seller")
}
func (engine *MultisigPoolEngine) VerifyBuyerPayment(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof) error {
	return engine.verifyDetached(unsigned, sig, proof, "buyer")
}

func (engine *MultisigPoolEngine) verifyDetached(unsigned *UnsignedPayment, sig []byte, proof *OpeningProof, role string) error {
	if unsigned == nil || len(sig) == 0 || proof == nil {
		return invalid("unsigned payment and detached signature are required")
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil || len(state.Outputs) != 3 {
		return invalid("unsigned payment must have one input and exactly three outputs")
	}
	setPoolSource(state, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return err
	}
	if err := engine.verifyCanonicalState(state, proof, state.Outputs[1].Satoshis, state.Inputs[0].SequenceNumber, state.LockTime); err != nil {
		return err
	}
	var ok bool
	switch role {
	case "buyer":
		ok, err = mp.VerifyArbitratedPoolBuyerSignature(state, proof.PoolOutputSatoshis, engine.roles(), sig)
	case "seller":
		ok, err = mp.VerifyArbitratedPoolSellerSignature(state, proof.PoolOutputSatoshis, engine.roles(), sig)
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
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return err
	}
	setPoolSource(state, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return err
	}
	return engine.verifyCanonicalState(state, proof, state.Outputs[1].Satoshis, state.Inputs[0].SequenceNumber, state.LockTime)
}

func (adapter *SellerPoolAdapter) MergeBuyerSellerPayment(unsigned *UnsignedPayment, buyerSig, sellerSig []byte) (*SignedPayment, error) {
	return adapter.MultisigPoolEngine.mergeBuyerSeller(unsigned, buyerSig, sellerSig)
}
func (adapter *SellerPoolAdapter) MergeSellerArbiterPayment(unsigned *UnsignedPayment, sellerSig, arbiterSig []byte) (*SignedPayment, error) {
	return adapter.MultisigPoolEngine.mergeSellerArbiter(unsigned, sellerSig, arbiterSig)
}

func (engine *MultisigPoolEngine) mergeBuyerSeller(unsigned *UnsignedPayment, buyerSig, sellerSig []byte) (*SignedPayment, error) {
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	if ok, err := mp.VerifyArbitratedPoolBuyerSignature(state, unsigned.PoolOutputSatoshis, engine.roles(), buyerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("buyer transaction signature is invalid")
	}
	if ok, err := mp.VerifyArbitratedPoolSellerSignature(state, unsigned.PoolOutputSatoshis, engine.roles(), sellerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("seller transaction signature is invalid")
	}
	merged, err := mp.MergeArbitratedPoolBuyerSellerSignatures(state, unsigned.PoolOutputSatoshis, engine.roles(), buyerSig, sellerSig)
	if err != nil {
		return nil, err
	}
	return engine.signedFromTx(merged, unsigned, buyerSig, sellerSig, nil), nil
}

func (engine *MultisigPoolEngine) mergeSellerArbiter(unsigned *UnsignedPayment, sellerSig, arbiterSig []byte) (*SignedPayment, error) {
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err := requireUnsigned(state); err != nil {
		return nil, err
	}
	if ok, err := mp.VerifyArbitratedPoolSellerSignature(state, unsigned.PoolOutputSatoshis, engine.roles(), sellerSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("seller transaction signature is invalid")
	}
	if ok, err := mp.VerifyArbitratedPoolArbiterSignature(state, unsigned.PoolOutputSatoshis, engine.roles(), arbiterSig); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return nil, invalid("arbiter transaction signature is invalid")
	}
	merged, err := mp.MergeArbitratedPoolSellerArbiterSignatures(state, unsigned.PoolOutputSatoshis, engine.roles(), sellerSig, arbiterSig)
	if err != nil {
		return nil, err
	}
	return engine.signedFromTx(merged, unsigned, nil, sellerSig, arbiterSig), nil
}

func (engine *MultisigPoolEngine) BuildImmediateClose(_ context.Context, input CloseInput) (*UnsignedPayment, []byte, error) {
	if engine == nil || input.Opening == nil || input.Latest == nil {
		return nil, nil, invalid("opening proof and latest state are required")
	}
	previous, err := tx.NewTransactionFromBytes(input.Latest.RawTx)
	if err != nil {
		return nil, nil, err
	}
	setPoolSource(previous, input.Opening.PoolOutputSatoshis, input.Opening.PoolLockingScript)
	locktime := finalPoolSequence
	state, err := mp.BuildArbitratedPoolFinalState(mp.ArbitratedPoolStateInput{Protocol: mp.Protocol, Version: mp.Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: &tx.TransactionOutput{Satoshis: input.Opening.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), input.Opening.PoolLockingScript...))}, Sequence: finalPoolSequence, LockTime: &locktime, SellerAmount: input.SellerAmountAfterSat, ArbiterAmount: 0, PoolAmount: input.Opening.PoolOutputSatoshis, Roles: engine.roles(), FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB), PaymentProof: nil})
	if err != nil {
		return nil, nil, err
	}
	unsigned := unsignedFromTx(state, input.Opening, finalPoolSequence)
	return unsigned, nil, nil
}

func (engine *MultisigPoolEngine) VerifyFinalPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil || state.PaymentSequence != finalPoolSequence {
		return invalid("final payment state is invalid")
	}
	return engine.verifyComplete(state, proof, false)
}
func (engine *MultisigPoolEngine) VerifyAcceptedPayment(state *PaymentState, proof *OpeningProof) error {
	return engine.verifyComplete(state, proof, false)
}
func (engine *MultisigPoolEngine) VerifyArbitratedPayment(state *PaymentState, proof *OpeningProof) error {
	return engine.verifyComplete(state, proof, true)
}
func (engine *MultisigPoolEngine) VerifyCompletedFinalPayment(payment *SignedPayment, proof *OpeningProof) error {
	if payment == nil {
		return invalid("signed payment is required")
	}
	if len(payment.RawTx) == 0 || !bytes.Equal(payment.RawTx, payment.State.RawTx) {
		return invalid("signed payment transaction bytes do not match state")
	}
	return engine.VerifyFinalPayment(&payment.State, proof)
}

func (engine *MultisigPoolEngine) verifyComplete(state *PaymentState, proof *OpeningProof, arbitration bool) error {
	if engine == nil || state == nil || proof == nil || len(state.RawTx) == 0 {
		return invalid("complete payment state and opening proof are required")
	}
	parsed, err := engine.parseUnsignedOrSignedState(state.RawTx, proof)
	if err != nil {
		return err
	}
	if state.SpendTxID != hash32FromBytes(proof.SpendTxID) || state.PaymentSequence != parsed.Inputs[0].SequenceNumber || state.BuyerAmountSat != parsed.Outputs[0].Satoshis || state.SellerAmountSat != parsed.Outputs[1].Satoshis || state.ArbiterAmountSat != parsed.Outputs[2].Satoshis || state.ArbiterAmountSat != 0 {
		return invalid("payment state metadata does not match transaction outputs")
	}
	if len(parsed.Inputs[0].UnlockingScript.Bytes()) == 0 {
		return invalid("complete payment must contain two signatures")
	}
	sigs, err := transactionSignatures(parsed)
	if err != nil || len(sigs) != 2 {
		return invalid("complete payment must contain exactly two signatures")
	}
	unsigned := *unsignedFromTx(parsed, proof, parsed.Inputs[0].SequenceNumber)
	unsigned.SpendTxID = state.SpendTxID
	var rebuilt *tx.Transaction
	if arbitration {
		rebuilt, err = mp.MergeArbitratedPoolSellerArbiterSignatures(clearUnlocking(parsed), proof.PoolOutputSatoshis, engine.roles(), sigs[0], sigs[1])
	} else {
		rebuilt, err = mp.MergeArbitratedPoolBuyerSellerSignatures(clearUnlocking(parsed), proof.PoolOutputSatoshis, engine.roles(), sigs[0], sigs[1])
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
	result := &PaymentState{SpendTxID: hash32FromBytes(proof.SpendTxID), RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), proof.PoolLockingScript...)}
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

func unsignedFromTx(state *tx.Transaction, proof *OpeningProof, sequence uint32) *UnsignedPayment {
	return &UnsignedPayment{SpendTxID: hash32FromBytes(proof.SpendTxID), RawTx: state.Bytes(), PaymentSequence: sequence, BuyerAmountSat: state.Outputs[0].Satoshis, SellerAmountSat: state.Outputs[1].Satoshis, ArbiterAmountSat: state.Outputs[2].Satoshis, PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), proof.PoolLockingScript...)}
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
	if len(raw) == 0 {
		return nil, invalid("public key is required")
	}
	return ec.ParsePubKey(append([]byte(nil), raw...))
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
	copy, _ := tx.NewTransactionFromBytes(state.Bytes())
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
