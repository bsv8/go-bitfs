package pool

// This file is deliberately a thin workflow adapter. Transaction templates,
// fee calculation, role signing, signature verification and signature
// ordering belong to MultisigPool; this package only converts pool evidence
// to the library's public types and rehydrates business state.

import (
	"bytes"
	"context"
	"fmt"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/pkg"
)

const finalPoolSequence = ^uint32(0)

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

// Role adapters are the only objects that hold private-key providers. The
// engine itself is a stateless verifier/template core and can safely be
// shared with nodes that must never receive a signing capability.
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
	lock, err := mp.BuildTriplePoolLock(keys[0], keys[1], keys[2])
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), lock.Bytes()...), nil
}

func (adapter *BuyerPoolAdapter) BuildRefundPresignRequest(ctx context.Context, input OpeningInput, signer Signer) (*RefundPresignRequest, error) {
	_ = signer
	engine := adapter.MultisigPoolEngine
	if engine == nil || adapter.Key == nil {
		return nil, invalid("A private-key provider is required")
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
	poolOutput := funding.Outputs[input.PoolOutputIndex]
	lock, err := mp.BuildTriplePoolLock(engine.seller, engine.buyer, engine.arbiter)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(poolOutput.LockingScript.Bytes(), lock.Bytes()) {
		return nil, invalid("funding output does not use the configured pool lock")
	}
	buyerKey, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if buyerKey == nil || !buyerKey.PubKey().IsEqual(engine.buyer) {
		return nil, invalid("A private key does not match the A slot")
	}
	state, err := mp.BuildTriplePoolOpeningState(mp.TriplePoolOpeningInput{FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: input.PoolOutputIndex, PoolAmount: poolOutput.Satoshis, LockTime: input.ExpiryLockTime, Server: engine.seller, A: engine.buyer, B: engine.arbiter, FeeRate: mp.FeeSatPerKB(input.MinerFeeRateSatPerKB)})
	if err != nil {
		return nil, err
	}
	aSig, err := mp.SignTriplePoolAsA(state, buyerKey, engine.seller, engine.arbiter)
	if err != nil {
		return nil, err
	}
	return &RefundPresignRequest{Version: MajorVersion, RefundTx: state.Bytes(), FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: input.PoolOutputIndex, PoolOutputSatoshis: poolOutput.Satoshis, PoolLockingScript: append([]byte(nil), lock.Bytes()...), ServerPubKey: engine.seller.Compressed(), BuyerPubKey: engine.buyer.Compressed(), ArbiterPubKey: engine.arbiter.Compressed(), MinerFeeRateSatPerKB: input.MinerFeeRateSatPerKB, BuyerRefundSignature: append([]byte(nil), (*aSig)...)}, nil
}

func (engine *MultisigPoolEngine) VerifySellerRefundSignature(_ context.Context, request *RefundPresignRequest, signature []byte) error {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return err
	}
	if err := engine.validateRequestRoles(request.ServerPubKey, request.BuyerPubKey, request.ArbiterPubKey); err != nil {
		return err
	}
	state, err := tx.NewTransactionFromBytes(request.RefundTx)
	if err != nil {
		return err
	}
	setPoolSource(state, request.PoolOutputSatoshis, request.PoolLockingScript)
	if len(state.Outputs) != 2 || state.Inputs[0].SequenceNumber == finalPoolSequence {
		return invalid("refund state shape is invalid")
	}
	if ok, err := mp.VerifyTriplePoolASignature(state, engine.buyer, engine.seller, engine.arbiter, &request.BuyerRefundSignature); err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("A refund signature is invalid")
	}
	if ok, err := mp.VerifyTriplePoolServerSignature(state, engine.seller, engine.buyer, engine.arbiter, &signature); err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("server refund signature is invalid")
	}
	return nil
}

type PoolRefundSigner struct{ Adapter *SellerPoolAdapter }

func (adapter PoolRefundSigner) SignRefundTx(ctx context.Context, request *RefundPresignRequest) ([]byte, error) {
	if adapter.Adapter == nil || adapter.Adapter.MultisigPoolEngine == nil || adapter.Adapter.Key == nil {
		return nil, invalid("server private-key provider is required")
	}
	engine := adapter.Adapter.MultisigPoolEngine
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	if err := engine.validateRequestRoles(request.ServerPubKey, request.BuyerPubKey, request.ArbiterPubKey); err != nil {
		return nil, err
	}
	state, err := tx.NewTransactionFromBytes(request.RefundTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, request.PoolOutputSatoshis, request.PoolLockingScript)
	key, err := adapter.Adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(engine.seller) {
		return nil, invalid("server private key does not match server slot")
	}
	sig, err := mp.SignTriplePoolAsServer(state, key, engine.buyer, engine.arbiter)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), (*sig)...), nil
}

func (engine *MultisigPoolEngine) TransactionID(rawTx []byte) (Hash32, error) {
	tx, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	return hash32FromBytes(tx.TxID().CloneBytes()), nil
}
func (engine *MultisigPoolEngine) FundingTxID(rawTx []byte) (Hash32, error) {
	tx, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	if len(tx.Inputs) != 1 || tx.Inputs[0] == nil || tx.Inputs[0].SourceTXID == nil {
		return Hash32{}, invalid("transaction has no funding outpoint")
	}
	return hash32FromBytes(tx.Inputs[0].SourceTXID.CloneBytes()), nil
}

func (engine *MultisigPoolEngine) VerifyOpening(proof *OpeningProof) error {
	if proof == nil {
		return invalid("opening proof is required")
	}
	lock, err := mp.BuildTriplePoolLock(engine.seller, engine.buyer, engine.arbiter)
	if err != nil {
		return err
	}
	if !bytes.Equal(lock.Bytes(), proof.PoolLockingScript) {
		return invalid("opening proof roles do not match canonical pool lock")
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return err
	}
	if err := engine.validateRequestRoles(proof.ServerPubKey, proof.BuyerPubKey, proof.ArbiterPubKey); err != nil {
		return err
	}
	if len(proof.FundingTx) == 0 {
		return invalid("complete funding transaction is required")
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
	if len(refund.Inputs) != 1 || refund.Inputs[0] == nil || refund.Inputs[0].SourceTXID == nil || !bytes.Equal(refund.Inputs[0].SourceTXID.CloneBytes(), proof.FundingTxID) || refund.Inputs[0].SourceTxOutIndex != proof.PoolOutputIndex {
		return invalid("refund transaction does not spend the opening pool outpoint")
	}
	setPoolSource(refund, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	refundUnlocking := refund.Inputs[0].UnlockingScript
	refund.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	stateErr := mp.VerifyTriplePoolStateWithFee(refund, engine.seller, engine.buyer, engine.arbiter, proof.PoolOutputSatoshis, 0, mp.FeeSatPerKB(proof.MinerFeeRateSatPerKB))
	refund.Inputs[0].UnlockingScript = refundUnlocking
	if stateErr != nil {
		return stateErr
	}
	if ok, err := mp.VerifyTriplePoolASignature(refund, engine.buyer, engine.seller, engine.arbiter, &proof.BuyerRefundSignature); err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("A refund signature is invalid")
	}
	if ok, err := mp.VerifyTriplePoolServerSignature(refund, engine.seller, engine.buyer, engine.arbiter, &proof.SellerRefundSignature); err != nil || !ok {
		if err != nil {
			return err
		}
		return invalid("server refund signature is invalid")
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
	if engine.blockHeight != nil && refund.LockTime <= engine.blockHeight() {
		return nil
	}
	if refund.LockTime != 0 && now.Unix() >= int64(refund.LockTime) {
		return nil
	}
	return ErrNotExpired
}
func (engine *MultisigPoolEngine) BuildRefundSubmission(proof *OpeningProof) ([]byte, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if proof == nil || len(proof.SellerRefundSignature) == 0 || len(proof.BuyerRefundSignature) == 0 {
		return nil, invalid("complete refund signatures are required")
	}
	refund, err := tx.NewTransactionFromBytes(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	merged, err := mp.MergeTriplePoolServerAWithRoles(refund.Hex(), &proof.SellerRefundSignature, &proof.BuyerRefundSignature, engine.seller, engine.buyer, engine.arbiter, proof.PoolOutputSatoshis)
	if err != nil {
		return nil, err
	}
	return merged.Bytes(), nil
}

func (engine *MultisigPoolEngine) VerifyFundingTx(_ context.Context, rawTx []byte, proof *OpeningProof) error {
	if engine == nil || proof == nil {
		return invalid("funding transaction and opening proof are required")
	}
	funding, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return err
	}
	if !bytes.Equal(funding.TxID().CloneBytes(), proof.FundingTxID) {
		return invalid("funding transaction ID does not match opening proof")
	}
	if int(proof.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[proof.PoolOutputIndex] == nil {
		return invalid("pool output index is invalid")
	}
	output := funding.Outputs[proof.PoolOutputIndex]
	if output.Satoshis != proof.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), proof.PoolLockingScript) {
		return invalid("funding pool output does not match opening proof")
	}
	lock, err := mp.BuildTriplePoolLock(engine.seller, engine.buyer, engine.arbiter)
	if err != nil || !bytes.Equal(lock.Bytes(), output.LockingScript.Bytes()) {
		return invalid("funding pool output role script is invalid")
	}
	return nil
}
func (engine *MultisigPoolEngine) VerifyPoolParticipants(proof *OpeningProof, buyer, seller, arbiter []byte) error {
	if proof == nil || !bytes.Equal(proof.BuyerPubKey, buyer) || !bytes.Equal(proof.ServerPubKey, seller) || !bytes.Equal(proof.ArbiterPubKey, arbiter) {
		return invalid("pool participant roles do not match")
	}
	return nil
}

func (engine *MultisigPoolEngine) ParsePaymentState(_ context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	return engine.parsePaymentState(rawTx, proof)
}
func (engine *MultisigPoolEngine) ParseFinalPaymentState(ctx context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	state, err := engine.parsePaymentState(rawTx, proof)
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
func (engine *MultisigPoolEngine) parsePaymentState(rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	state, err := tx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || len(state.Outputs) != 2 {
		return nil, invalid("pool state must have one input and two outputs")
	}
	if state.Inputs[0].SourceTXID == nil || !bytes.Equal(state.Inputs[0].SourceTXID.CloneBytes(), proof.FundingTxID) || state.Inputs[0].SourceTxOutIndex != proof.PoolOutputIndex {
		return nil, invalid("pool state does not spend the opening pool outpoint")
	}
	setPoolSource(state, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	unlocking := state.Inputs[0].UnlockingScript
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	if err := mp.VerifyTriplePoolStateWithFee(state, engine.seller, engine.buyer, engine.arbiter, proof.PoolOutputSatoshis, state.Outputs[0].Satoshis, mp.FeeSatPerKB(proof.MinerFeeRateSatPerKB)); err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = unlocking
	return &PaymentState{SpendTxID: hash32FromBytes(proof.SpendTxID), RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, SellerAmountSat: state.Outputs[0].Satoshis, ClientAmountSat: state.Outputs[1].Satoshis, PoolOutputSatoshis: proof.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), proof.PoolLockingScript...)}, nil
}

func (engine *MultisigPoolEngine) CheckPaymentCapacity(_ context.Context, input PaymentUpdateInput) error {
	if input.Opening == nil || input.Previous == nil || input.SellerAmountAfterSat < input.Previous.SellerAmountSat || input.SellerAmountAfterSat > input.Opening.PoolOutputSatoshis {
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
	state, err := mp.BuildTriplePoolState(mp.TriplePoolStateInput{PreviousRawTx: input.Previous.RawTx, Sequence: input.PaymentSequenceAfter, SellerAmount: input.SellerAmountAfterSat, PoolAmount: input.Opening.PoolOutputSatoshis, Server: engine.seller, A: engine.buyer, B: engine.arbiter, FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB)})
	if err != nil {
		return nil, err
	}
	return &UnsignedPayment{SpendTxID: hash32FromBytes(input.Opening.SpendTxID), RawTx: state.Bytes(), PoolOutputSatoshis: input.Opening.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), input.Opening.PoolLockingScript...)}, nil
}

func (adapter *SellerPoolAdapter) SignSellerArbitrationCandidate(ctx context.Context, unsigned *UnsignedPayment, _ Signer) ([]byte, error) {
	engine := adapter.MultisigPoolEngine
	if unsigned == nil || engine == nil || adapter.Key == nil {
		return nil, invalid("server private-key provider is required")
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(engine.seller) {
		return nil, invalid("server private key does not match server slot")
	}
	sig, err := mp.SignTriplePoolAsServer(state, key, engine.buyer, engine.arbiter)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), (*sig)...), nil
}
func (adapter *BuyerPoolAdapter) SignBuyerPayment(ctx context.Context, unsigned *UnsignedPayment, _ Signer) (*PaymentState, error) {
	engine := adapter.MultisigPoolEngine
	if unsigned == nil || engine == nil || adapter.Key == nil {
		return nil, invalid("buyer private-key provider is required")
	}
	state, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	sig, err := mp.SignTriplePoolAsA(state, key, engine.seller, engine.arbiter)
	if err != nil {
		return nil, err
	}
	signed, err := mp.AttachTriplePoolASignature(state, *sig)
	if err != nil {
		return nil, err
	}
	return stateToPayment(signed, unsigned.SpendTxID, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript), nil
}

func (engine *MultisigPoolEngine) VerifyBuyerPayment(state *PaymentState, proof *OpeningProof) error {
	if engine == nil || state == nil || proof == nil {
		return invalid("payment state and opening proof are required")
	}
	parsed, err := engine.parsePaymentState(state.RawTx, proof)
	if err != nil {
		return err
	}
	sigs, err := signatures(parsed.RawTx)
	if err != nil || len(sigs) != 1 {
		return invalid("payment must contain exactly the A signature")
	}
	ok, err := mp.VerifyTriplePoolASignature(stateTx(parsed), engine.buyer, engine.seller, engine.arbiter, &sigs[0])
	if err != nil || !ok {
		return invalid("A payment signature is invalid")
	}
	return nil
}
func (engine *MultisigPoolEngine) VerifySellerPayment(state *PaymentState, proof *OpeningProof) error {
	if engine == nil || state == nil || proof == nil {
		return invalid("payment state and opening proof are required")
	}
	parsed, err := engine.parsePaymentState(state.RawTx, proof)
	if err != nil {
		return err
	}
	sigs, err := signatures(parsed.RawTx)
	if err != nil || len(sigs) != 1 {
		return invalid("candidate must contain exactly the server signature")
	}
	ok, err := mp.VerifyTriplePoolServerSignature(stateTx(parsed), engine.seller, engine.buyer, engine.arbiter, &sigs[0])
	if err != nil || !ok {
		return invalid("server payment signature is invalid")
	}
	return nil
}
func (engine *MultisigPoolEngine) VerifySellerPaymentSignature(state *PaymentState, sig []byte, proof *OpeningProof) error {
	if engine == nil || state == nil || proof == nil {
		return invalid("payment state and opening proof are required")
	}
	tx, err := tx.NewTransactionFromBytes(state.RawTx)
	if err != nil {
		return err
	}
	setPoolSource(tx, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	ok, err := mp.VerifyTriplePoolServerSignature(tx, engine.seller, engine.buyer, engine.arbiter, &sig)
	if err != nil || !ok {
		return invalid("server signature is invalid")
	}
	return nil
}
func (engine *MultisigPoolEngine) AttachSellerArbitrationSignature(_ context.Context, state *PaymentState, sig []byte) (*PaymentState, error) {
	if state == nil || len(sig) == 0 {
		return nil, invalid("payment state and server signature are required")
	}
	tx, err := tx.NewTransactionFromBytes(state.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	signed, err := mp.AttachTriplePoolServerSignature(tx, sig)
	if err != nil {
		return nil, err
	}
	return stateToPayment(signed, state.SpendTxID, state.PoolOutputSatoshis, state.PoolLockingScript), nil
}

func (adapter *SellerPoolAdapter) AddSellerSignature(ctx context.Context, state *PaymentState, _ Signer) (*SignedPayment, error) {
	engine := adapter.MultisigPoolEngine
	if engine == nil || adapter.Key == nil {
		return nil, invalid("server private-key provider is required")
	}
	tx, err := tx.NewTransactionFromBytes(state.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	sigs, err := signatures(tx.Bytes())
	if err != nil || len(sigs) != 1 {
		return nil, invalid("A signature is required")
	}
	if ok, err := mp.VerifyTriplePoolASignature(tx, engine.buyer, engine.seller, engine.arbiter, &sigs[0]); err != nil || !ok {
		return nil, invalid("A payment signature is invalid")
	}
	tx.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	serverSig, err := mp.SignTriplePoolAsServer(tx, key, engine.buyer, engine.arbiter)
	if err != nil {
		return nil, err
	}
	tx.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	merged, err := mp.MergeTriplePoolServerAWithRoles(tx.Hex(), serverSig, &sigs[0], engine.seller, engine.buyer, engine.arbiter, state.PoolOutputSatoshis)
	if err != nil {
		return nil, err
	}
	result := stateToPayment(merged, state.SpendTxID, state.PoolOutputSatoshis, state.PoolLockingScript)
	return &SignedPayment{State: *result, RawTx: result.RawTx}, nil
}
func (adapter *ArbiterPoolAdapter) SignArbiterPayment(ctx context.Context, state *PaymentState, _ Signer) ([]byte, error) {
	engine := adapter.MultisigPoolEngine
	if engine == nil || state == nil || adapter.Key == nil {
		return nil, invalid("B private-key provider is required")
	}
	tx, err := tx.NewTransactionFromBytes(state.RawTx)
	if err != nil {
		return nil, err
	}
	setPoolSource(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	key, err := adapter.Key.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || !key.PubKey().IsEqual(engine.arbiter) {
		return nil, invalid("B private key does not match B slot")
	}
	sigs, err := signatures(tx.Bytes())
	if err != nil || len(sigs) != 1 {
		return nil, invalid("server signature is required before B signing")
	}
	if ok, err := mp.VerifyTriplePoolServerSignature(tx, engine.seller, engine.buyer, engine.arbiter, &sigs[0]); err != nil || !ok {
		return nil, invalid("server arbitration signature is invalid")
	}
	// MultisigPool signs the canonical empty-unlocking template. The existing
	// server signature is transport material and is merged only after B signs.
	tx.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	sig, err := mp.SignTriplePoolAsB(tx, key, engine.seller, engine.buyer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), (*sig)...), nil
}
func (engine *MultisigPoolEngine) AddArbitrationSignature(_ context.Context, state *PaymentState, arbiterSig []byte) (*SignedPayment, error) {
	if engine == nil || state == nil || len(arbiterSig) == 0 {
		return nil, invalid("arbitration state and B signature are required")
	}
	tx, err := tx.NewTransactionFromBytes(state.RawTx)
	if err != nil {
		return nil, err
	}
	serverSig := extractFirstSignature(tx)
	sigs, err := signatures(tx.Bytes())
	if err != nil || len(sigs) != 1 {
		return nil, invalid("server signature is required before arbitration merge")
	}
	if ok, err := mp.VerifyTriplePoolServerSignature(stateTx(state), engine.seller, engine.buyer, engine.arbiter, &serverSig); err != nil || !ok {
		return nil, invalid("server arbitration signature is invalid")
	}
	if ok, err := mp.VerifyTriplePoolBSignature(stateTx(state), engine.arbiter, engine.seller, engine.buyer, &arbiterSig); err != nil || !ok {
		return nil, invalid("B arbitration signature is invalid")
	}
	tx.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	merged, err := mp.MergeTriplePoolServerBWithRoles(tx.Hex(), &serverSig, &arbiterSig, engine.seller, engine.buyer, engine.arbiter, state.PoolOutputSatoshis)
	if err != nil {
		return nil, err
	}
	result := stateToPayment(merged, state.SpendTxID, state.PoolOutputSatoshis, state.PoolLockingScript)
	return &SignedPayment{State: *result, RawTx: result.RawTx}, nil
}

func (engine *MultisigPoolEngine) BuildImmediateClose(_ context.Context, input CloseInput) (*UnsignedPayment, error) {
	if engine == nil || input.Opening == nil || input.Latest == nil {
		return nil, invalid("opening proof and latest state are required")
	}
	locktime := finalPoolSequence
	state, err := mp.BuildTriplePoolFinalState(mp.TriplePoolStateInput{PreviousRawTx: input.Latest.RawTx, Sequence: finalPoolSequence, LockTime: &locktime, SellerAmount: input.SellerAmountAfterSat, PoolAmount: input.Opening.PoolOutputSatoshis, Server: engine.seller, A: engine.buyer, B: engine.arbiter, FeeRate: mp.FeeSatPerKB(input.Opening.MinerFeeRateSatPerKB)})
	if err != nil {
		return nil, err
	}
	return &UnsignedPayment{SpendTxID: hash32FromBytes(input.Opening.SpendTxID), RawTx: state.Bytes(), PoolOutputSatoshis: input.Opening.PoolOutputSatoshis, PoolLockingScript: append([]byte(nil), input.Opening.PoolLockingScript...)}, nil
}
func (engine *MultisigPoolEngine) VerifyFinalPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil {
		return invalid("final payment state is required")
	}
	if state.PaymentSequence != finalPoolSequence {
		return ErrInvalidEvidence
	}
	return engine.verifyServerAndAState(state, proof)
}
func (engine *MultisigPoolEngine) VerifyAcceptedPayment(state *PaymentState, proof *OpeningProof) error {
	if engine == nil || state == nil || proof == nil {
		return invalid("accepted payment state and opening proof are required")
	}
	return engine.verifyServerAndAState(state, proof)
}

func (engine *MultisigPoolEngine) verifyServerAndAState(state *PaymentState, proof *OpeningProof) error {
	parsed, err := engine.parsePaymentState(state.RawTx, proof)
	if err != nil {
		return err
	}
	sigs, err := signatures(parsed.RawTx)
	if err != nil || len(sigs) != 2 {
		return invalid("accepted state requires two signatures")
	}
	tx := stateTx(parsed)
	if ok, _ := mp.VerifyTriplePoolServerSignature(tx, engine.seller, engine.buyer, engine.arbiter, &sigs[0]); !ok {
		return invalid("accepted state server signature is invalid")
	}
	if ok, _ := mp.VerifyTriplePoolASignature(tx, engine.buyer, engine.seller, engine.arbiter, &sigs[1]); ok {
		return nil
	}
	return invalid("accepted state second signature is not A")
}

// VerifyArbitratedPayment validates the distinct server+B final signature
// arrangement used only by the seller-arbitration path.
func (engine *MultisigPoolEngine) VerifyArbitratedPayment(state *PaymentState, proof *OpeningProof) error {
	if engine == nil || state == nil || proof == nil {
		return invalid("payment state and opening proof are required")
	}
	parsed, err := engine.parsePaymentState(state.RawTx, proof)
	if err != nil {
		return err
	}
	sigs, err := signatures(parsed.RawTx)
	if err != nil || len(sigs) != 2 {
		return invalid("arbitrated state requires two signatures")
	}
	tx := stateTx(parsed)
	if ok, err := mp.VerifyTriplePoolServerSignature(tx, engine.seller, engine.buyer, engine.arbiter, &sigs[0]); err != nil || !ok {
		return invalid("arbitrated state server signature is invalid")
	}
	if ok, err := mp.VerifyTriplePoolBSignature(tx, engine.arbiter, engine.seller, engine.buyer, &sigs[1]); err != nil || !ok {
		return invalid("arbitrated state B signature is invalid")
	}
	return nil
}
func (engine *MultisigPoolEngine) VerifyCompletedFinalPayment(payment *SignedPayment, proof *OpeningProof) error {
	return engine.VerifyFinalPayment(&payment.State, proof)
}

func stateToPayment(state *tx.Transaction, spend Hash32, poolAmount uint64, lock []byte) *PaymentState {
	return &PaymentState{SpendTxID: spend, RawTx: state.Bytes(), PaymentSequence: state.Inputs[0].SequenceNumber, SellerAmountSat: state.Outputs[0].Satoshis, ClientAmountSat: state.Outputs[1].Satoshis, PoolOutputSatoshis: poolAmount, PoolLockingScript: append([]byte(nil), lock...)}
}
func parsePoolKey(raw []byte) (*ec.PublicKey, error) {
	if len(raw) == 0 {
		return nil, invalid("public key is required")
	}
	return ec.ParsePubKey(append([]byte(nil), raw...))
}
func (engine *MultisigPoolEngine) matchConfiguredParticipantKeys(server, arbiter []byte) error {
	serverKey, err := parsePoolKey(server)
	if err != nil {
		return err
	}
	arbiterKey, err := parsePoolKey(arbiter)
	if err != nil {
		return err
	}
	if !serverKey.IsEqual(engine.seller) || !arbiterKey.IsEqual(engine.arbiter) {
		return invalid("opening participant roles do not match configured pool")
	}
	return nil
}

func (engine *MultisigPoolEngine) validateRequestRoles(server, buyer, arbiter []byte) error {
	if engine == nil {
		return invalid("MultisigPool engine is required")
	}
	serverKey, err := parsePoolKey(server)
	if err != nil {
		return err
	}
	buyerKey, err := parsePoolKey(buyer)
	if err != nil {
		return err
	}
	arbiterKey, err := parsePoolKey(arbiter)
	if err != nil {
		return err
	}
	if !serverKey.IsEqual(engine.seller) || !buyerKey.IsEqual(engine.buyer) || !arbiterKey.IsEqual(engine.arbiter) {
		return invalid("pool participant roles do not match configured pool")
	}
	return nil
}
func setPoolSource(state *tx.Transaction, amount uint64, lock []byte) {
	if state != nil && len(state.Inputs) == 1 {
		state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: amount, LockingScript: script.NewFromBytes(append([]byte(nil), lock...))})
	}
}
func signatures(raw []byte) ([][]byte, error) {
	state, err := tx.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return nil, invalid("transaction must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript == nil {
		return nil, invalid("unlocking script is required")
	}
	chunks, err := state.Inputs[0].UnlockingScript.Chunks()
	if err != nil || len(chunks) < 2 || chunks[0].Op != script.Op0 {
		return nil, invalid("invalid multisig unlocking script")
	}
	result := make([][]byte, 0, len(chunks)-1)
	for _, chunk := range chunks[1:] {
		if len(chunk.Data) == 0 {
			return nil, invalid("empty signature")
		}
		result = append(result, append([]byte(nil), chunk.Data...))
	}
	return result, nil
}
func extractFirstSignature(state *tx.Transaction) []byte {
	sigs, _ := signatures(state.Bytes())
	if len(sigs) == 0 {
		return nil
	}
	return sigs[0]
}
func stateTx(state *PaymentState) *tx.Transaction {
	parsed, _ := tx.NewTransactionFromBytes(state.RawTx)
	setPoolSource(parsed, state.PoolOutputSatoshis, state.PoolLockingScript)
	return parsed
}
func hash32FromBytes(raw []byte) Hash32 { var result Hash32; copy(result[:], raw); return result }
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEvidence, fmt.Sprintf(format, args...))
}
