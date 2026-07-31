package pool

// This file contains the reference transaction engine for the protocol.  It
// deliberately keeps transaction parsing and script rules in one place: the
// buyer, seller and arbiter workflows only deal in validated states.

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	bsvtx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

const bitcoinSignatureHashType byte = byte(sighash.AllForkID)

// BSVEngineConfig fixes the participant key order used by every pool output.
// The keys are copied by NewBSVEngine and are never taken from a payment
// request, which prevents a caller from changing the beneficiary identity at
// payment time.
type BSVEngineConfig struct {
	BuyerPubKey   []byte
	SellerPubKey  []byte
	ArbiterPubKey []byte
	// BlockHeight is required only when a refund uses a height locktime.
	// The callback is supplied by the caller's chain-tip adapter.
	BlockHeight func() uint32
}

// BSVEngine implements the generic 2-of-3 transaction semantics required by
// 002, 005, 006 and 007.  It does not submit transactions or access a node.
type BSVEngine struct {
	buyer       *ec.PublicKey
	seller      *ec.PublicKey
	arbiter     *ec.PublicKey
	blockHeight func() uint32
}

func NewBSVEngine(config BSVEngineConfig) (*BSVEngine, error) {
	buyer, err := parseCompressedOrUncompressedPubKey(config.BuyerPubKey)
	if err != nil {
		return nil, fmt.Errorf("buyer public key: %w", err)
	}
	seller, err := parseCompressedOrUncompressedPubKey(config.SellerPubKey)
	if err != nil {
		return nil, fmt.Errorf("seller public key: %w", err)
	}
	arbiter, err := parseCompressedOrUncompressedPubKey(config.ArbiterPubKey)
	if err != nil {
		return nil, fmt.Errorf("arbiter public key: %w", err)
	}
	if buyer.IsEqual(seller) || buyer.IsEqual(arbiter) || seller.IsEqual(arbiter) {
		return nil, fmt.Errorf("%w: pool participants must have distinct public keys", ErrInvalidEvidence)
	}
	return &BSVEngine{buyer: buyer, seller: seller, arbiter: arbiter, blockHeight: config.BlockHeight}, nil
}

// Build2of3LockingScript is the canonical pool output script.  The input
// order is protocol data: buyer, seller, arbiter.
func Build2of3LockingScript(pubkeys [][]byte) ([]byte, error) {
	if len(pubkeys) != 3 {
		return nil, invalid("exactly three pool public keys are required")
	}
	keys := make([]*ec.PublicKey, 3)
	for index, raw := range pubkeys {
		key, err := parseCompressedOrUncompressedPubKey(raw)
		if err != nil {
			return nil, fmt.Errorf("pool public key %d: %w", index, err)
		}
		keys[index] = key
	}
	if keys[0].IsEqual(keys[1]) || keys[0].IsEqual(keys[2]) || keys[1].IsEqual(keys[2]) {
		return nil, invalid("pool participants must have distinct public keys")
	}
	result := script.NewFromBytes(nil)
	if err := result.AppendOpcodes(script.Op2); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := result.AppendPushData(key.Compressed()); err != nil {
			return nil, err
		}
	}
	if err := result.AppendOpcodes(script.Op3, script.OpCHECKMULTISIG); err != nil {
		return nil, err
	}
	return append([]byte(nil), result.Bytes()...), nil
}

func (engine *BSVEngine) BuildRefundPresignRequest(ctx context.Context, input OpeningInput, signer Signer) (*RefundPresignRequest, error) {
	if signer == nil {
		return nil, invalid("buyer signer is required")
	}
	if input.ExpiryLockTime == 0 {
		return nil, invalid("refund expiry locktime is required")
	}
	if err := engine.matchConfiguredParticipantKeys(input.SellerPubKey, input.ArbiterPubKey); err != nil {
		return nil, err
	}
	funding, err := parseTransaction(input.FundingTx)
	if err != nil {
		return nil, err
	}
	if int(input.PoolOutputIndex) >= len(funding.Outputs) || funding.Outputs[input.PoolOutputIndex] == nil {
		return nil, invalid("pool output index is outside funding transaction")
	}
	poolOutput := funding.Outputs[input.PoolOutputIndex]
	lockingScript, err := Build2of3LockingScript([][]byte{engine.buyer.Compressed(), engine.seller.Compressed(), engine.arbiter.Compressed()})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(poolOutput.LockingScript.Bytes(), lockingScript) {
		return nil, invalid("funding transaction pool output does not use the configured 2-of-3 script")
	}
	if input.RefundMinerFeeSat >= poolOutput.Satoshis {
		return nil, ErrInsufficientBalance
	}
	buyerScript, err := p2pkhScript(engine.buyer)
	if err != nil {
		return nil, err
	}
	sellerScript, err := p2pkhScript(engine.seller)
	if err != nil {
		return nil, err
	}
	refund := bsvtx.NewTransaction()
	refund.LockTime = input.ExpiryLockTime
	refund.AddInputWithOutput(&bsvtx.TransactionInput{
		SourceTXID:       funding.TxID(),
		SourceTxOutIndex: input.PoolOutputIndex,
		SequenceNumber:   1,
		UnlockingScript:  script.NewFromBytes(nil),
	}, &bsvtx.TransactionOutput{Satoshis: poolOutput.Satoshis, LockingScript: script.NewFromBytes(append([]byte(nil), lockingScript...))})
	refund.AddOutput(&bsvtx.TransactionOutput{Satoshis: 0, LockingScript: sellerScript})
	refund.AddOutput(&bsvtx.TransactionOutput{Satoshis: poolOutput.Satoshis - input.RefundMinerFeeSat, LockingScript: buyerScript})
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("buyer public key: %w", err)
	}
	if !bytes.Equal(publicKey, engine.buyer.Compressed()) {
		return nil, invalid("buyer signer does not match pool buyer")
	}
	digest, err := refund.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, fmt.Errorf("refund signature hash: %w", err)
	}
	signature, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("sign refund transaction: %w", err)
	}
	signature, err = normalizeBitcoinSignature(signature)
	if err != nil {
		return nil, err
	}
	return &RefundPresignRequest{
		Version:              MajorVersion,
		RefundTx:             refund.Bytes(),
		FundingTxID:          funding.TxID().CloneBytes(),
		PoolOutputIndex:      input.PoolOutputIndex,
		PoolOutputSatoshis:   poolOutput.Satoshis,
		PoolLockingScript:    lockingScript,
		BuyerRefundSignature: signature,
	}, nil
}

func (engine *BSVEngine) VerifySellerRefundSignature(_ context.Context, request *RefundPresignRequest, signature []byte) error {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return err
	}
	refund, err := parseTransaction(request.RefundTx)
	if err != nil {
		return err
	}
	if len(refund.Inputs) != 1 || refund.Inputs[0] == nil || refund.Inputs[0].SourceTXID == nil || !bytes.Equal(refund.Inputs[0].SourceTXID.CloneBytes(), request.FundingTxID) || refund.Inputs[0].SourceTxOutIndex != request.PoolOutputIndex || refund.Inputs[0].SequenceNumber == bsvtx.DefaultSequenceNumber || refund.LockTime == 0 {
		return invalid("refund transaction does not match the presign request")
	}
	if err := engine.verifyPoolScript(script.NewFromBytes(request.PoolLockingScript)); err != nil {
		return err
	}
	sellerScript, err := p2pkhScript(engine.seller)
	if err != nil {
		return err
	}
	buyerScript, err := p2pkhScript(engine.buyer)
	if err != nil {
		return err
	}
	if len(refund.Outputs) != 2 || refund.Outputs[0] == nil || refund.Outputs[1] == nil || refund.Outputs[0].Satoshis != 0 || refund.Outputs[1].Satoshis == 0 || refund.Outputs[1].Satoshis > request.PoolOutputSatoshis || !bytes.Equal(refund.Outputs[0].LockingScript.Bytes(), sellerScript.Bytes()) || !bytes.Equal(refund.Outputs[1].LockingScript.Bytes(), buyerScript.Bytes()) {
		return invalid("refund transaction outputs do not match the presign request")
	}
	refund.Inputs[0].SetSourceTxOutput(&bsvtx.TransactionOutput{Satoshis: request.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), request.PoolLockingScript...))})
	digest, err := refund.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return err
	}
	if err := verifyBitcoinSignature(digest, request.BuyerRefundSignature, engine.buyer); err != nil {
		return fmt.Errorf("buyer refund signature: %w", err)
	}
	if err := verifyBitcoinSignature(digest, signature, engine.seller); err != nil {
		return fmt.Errorf("seller refund signature: %w", err)
	}
	return nil
}

// BSVRefundSigner adapts a wallet Signer to the seller's 002 refund-signing
// port while leaving the private key outside the pool package.
type BSVRefundSigner struct {
	Engine *BSVEngine
	Signer Signer
}

func (adapter BSVRefundSigner) SignRefundTx(ctx context.Context, request *RefundPresignRequest) ([]byte, error) {
	if adapter.Engine == nil || adapter.Signer == nil {
		return nil, invalid("refund engine and seller signer are required")
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	refund, err := parseTransaction(request.RefundTx)
	if err != nil {
		return nil, err
	}
	if err := adapter.Engine.verifyPoolScript(script.NewFromBytes(request.PoolLockingScript)); err != nil {
		return nil, err
	}
	if len(refund.Inputs) != 1 || refund.Inputs[0] == nil || refund.Inputs[0].SourceTXID == nil || !bytes.Equal(refund.Inputs[0].SourceTXID.CloneBytes(), request.FundingTxID) || refund.Inputs[0].SourceTxOutIndex != request.PoolOutputIndex {
		return nil, invalid("refund transaction does not match presign request")
	}
	refund.Inputs[0].SetSourceTxOutput(&bsvtx.TransactionOutput{Satoshis: request.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), request.PoolLockingScript...))})
	digest, err := refund.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, err
	}
	publicKey, err := adapter.Signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, adapter.Engine.seller.Compressed()) {
		return nil, invalid("seller signer does not match pool seller")
	}
	signature, err := adapter.Signer.Sign(ctx, digest)
	if err != nil {
		return nil, err
	}
	return normalizeBitcoinSignature(signature)
}

func (engine *BSVEngine) TransactionID(rawTx []byte) (Hash32, error) {
	tx, err := parseTransaction(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	return hash32FromBytes(tx.TxID().CloneBytes()), nil
}

func (engine *BSVEngine) FundingTxID(rawTx []byte) (Hash32, error) {
	tx, err := parseTransaction(rawTx)
	if err != nil {
		return Hash32{}, err
	}
	if len(tx.Inputs) != 1 || tx.Inputs[0] == nil || tx.Inputs[0].SourceTXID == nil {
		return Hash32{}, invalid("payment must contain exactly one funding outpoint")
	}
	return hash32FromBytes(tx.Inputs[0].SourceTXID.CloneBytes()), nil
}

func (engine *BSVEngine) VerifyOpening(proof *OpeningProof) error {
	if err := ValidateOpeningProof(proof); err != nil {
		return err
	}
	if len(proof.FundingTx) == 0 {
		return invalid("complete funding transaction is required")
	}
	funding, err := parseTransaction(proof.FundingTx)
	if err != nil {
		return err
	}
	if !bytes.Equal(funding.TxID().CloneBytes(), proof.FundingTxID) {
		return invalid("funding transaction ID does not match opening proof")
	}
	if int(proof.PoolOutputIndex) >= len(funding.Outputs) {
		return invalid("pool output index is outside funding transaction")
	}
	output := funding.Outputs[proof.PoolOutputIndex]
	if output == nil || output.LockingScript == nil || output.Satoshis != proof.PoolOutputSatoshis || !bytes.Equal(output.LockingScript.Bytes(), proof.PoolLockingScript) {
		return invalid("funding pool output does not match opening proof")
	}
	if err := engine.verifyPoolScript(output.LockingScript); err != nil {
		return err
	}
	refund, err := parseTransaction(proof.RefundTx)
	if err != nil {
		return err
	}
	if len(refund.Inputs) != 1 || refund.Inputs[0] == nil || refund.Inputs[0].SourceTXID == nil {
		return invalid("refund transaction must have exactly one input")
	}
	input := refund.Inputs[0]
	if input.UnlockingScript == nil || len(input.UnlockingScript.Bytes()) != 0 {
		return invalid("opening refund evidence must not already contain an unlocking script")
	}
	if !bytes.Equal(input.SourceTXID.CloneBytes(), proof.FundingTxID) || input.SourceTxOutIndex != proof.PoolOutputIndex {
		return invalid("refund transaction does not spend the pool output")
	}
	if input.SequenceNumber == bsvtx.DefaultSequenceNumber || refund.LockTime == 0 {
		return invalid("refund transaction must be non-final and carry an expiry locktime")
	}
	if len(refund.Outputs) != 2 || refund.Outputs[0] == nil || refund.Outputs[1] == nil {
		return invalid("refund transaction must contain seller and buyer outputs")
	}
	sellerRefundScript, err := p2pkhScript(engine.seller)
	if err != nil {
		return err
	}
	buyerRefundScript, err := p2pkhScript(engine.buyer)
	if err != nil {
		return err
	}
	if refund.Outputs[0].Satoshis != 0 || !bytes.Equal(refund.Outputs[0].LockingScript.Bytes(), sellerRefundScript.Bytes()) || refund.Outputs[1].Satoshis == 0 || refund.Outputs[1].Satoshis > proof.PoolOutputSatoshis || !bytes.Equal(refund.Outputs[1].LockingScript.Bytes(), buyerRefundScript.Bytes()) {
		return invalid("refund transaction outputs do not return the pool balance to the buyer")
	}
	input.SetSourceTxOutput(&bsvtx.TransactionOutput{
		Satoshis:      proof.PoolOutputSatoshis,
		LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...)),
	})
	digest, err := refund.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return fmt.Errorf("refund signature hash: %w", err)
	}
	if err := verifyBitcoinSignature(digest, proof.BuyerRefundSignature, engine.buyer); err != nil {
		return fmt.Errorf("buyer refund signature: %w", err)
	}
	if err := verifyBitcoinSignature(digest, proof.SellerRefundSignature, engine.seller); err != nil {
		return fmt.Errorf("seller refund signature: %w", err)
	}
	return nil
}

func (engine *BSVEngine) VerifyRefundExpired(proof *OpeningProof, now time.Time) error {
	if err := engine.VerifyOpening(proof); err != nil {
		return err
	}
	refund, err := parseTransaction(proof.RefundTx)
	if err != nil {
		return err
	}
	// Bitcoin locktimes below this threshold are block heights. The generic
	// engine has no chain-tip port, so it refuses to guess their status.
	const lockTimeThreshold = uint32(500000000)
	if refund.LockTime < lockTimeThreshold {
		if engine.blockHeight == nil {
			return invalid("block-height refund expiry requires a chain height verifier")
		}
		if engine.blockHeight() < refund.LockTime {
			return ErrNotExpired
		}
		return nil
	}
	if now.Unix() < int64(refund.LockTime) {
		return ErrNotExpired
	}
	return nil
}

// BuildRefundSubmission combines the two signatures carried separately in
// OpeningProof into the unlocking script that can be broadcast after expiry.
// RefundTx itself remains the unsigned presigned evidence used as the stable
// SpendTxID anchor.
func (engine *BSVEngine) BuildRefundSubmission(proof *OpeningProof) ([]byte, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	refund, err := parseTransaction(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	unlocking := script.NewFromBytes([]byte{script.Op0})
	if err := unlocking.AppendPushData(proof.BuyerRefundSignature); err != nil {
		return nil, err
	}
	if err := unlocking.AppendPushData(proof.SellerRefundSignature); err != nil {
		return nil, err
	}
	refund.Inputs[0].UnlockingScript = unlocking
	return refund.Bytes(), nil
}

func (engine *BSVEngine) VerifyPoolParticipants(proof *OpeningProof, buyerPubkey, sellerPubkey, arbiterPubkey []byte) error {
	if err := ValidateOpeningProof(proof); err != nil {
		return err
	}
	if err := engine.verifyPoolScript(script.NewFromBytes(proof.PoolLockingScript)); err != nil {
		return err
	}
	buyer, err := parseCompressedOrUncompressedPubKey(buyerPubkey)
	if err != nil {
		return fmt.Errorf("buyer public key: %w", err)
	}
	seller, err := parseCompressedOrUncompressedPubKey(sellerPubkey)
	if err != nil {
		return fmt.Errorf("seller public key: %w", err)
	}
	arbiter, err := parseCompressedOrUncompressedPubKey(arbiterPubkey)
	if err != nil {
		return fmt.Errorf("arbiter public key: %w", err)
	}
	if !buyer.IsEqual(engine.buyer) || !seller.IsEqual(engine.seller) || !arbiter.IsEqual(engine.arbiter) {
		return invalid("content participants do not match the pool participant keys")
	}
	return nil
}

func (engine *BSVEngine) VerifyFundingTx(_ context.Context, rawTx []byte, proof *OpeningProof) error {
	if proof == nil {
		return invalid("opening proof is required")
	}
	copyProof := cloneOpeningProof(proof)
	copyProof.FundingTx = append([]byte(nil), rawTx...)
	return engine.VerifyOpening(copyProof)
}

func (engine *BSVEngine) ParsePaymentState(_ context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	return engine.parsePaymentState(rawTx, proof, false)
}

// ParseFinalPaymentState parses a transaction that is intended to close the
// pool immediately. Keeping finality in a separate entry point prevents a
// node adapter from accidentally treating a non-final update as a final
// broadcast.
func (engine *BSVEngine) ParseFinalPaymentState(_ context.Context, rawTx []byte, proof *OpeningProof) (*PaymentState, error) {
	return engine.parsePaymentState(rawTx, proof, true)
}

func (engine *BSVEngine) VerifyFinalPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil {
		return invalid("payment state is required")
	}
	parsed, err := engine.parsePaymentState(state.RawTx, proof, true)
	if err != nil {
		return err
	}
	if err := comparePaymentState(parsed, state); err != nil {
		return err
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return err
	}
	setSourceOutput(tx, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	return engine.verifyBuyerUnlockingScript(tx)
}

// VerifyAcceptedPayment validates either the opening refund (the initial
// state) or a buyer-signed non-final cumulative payment. Persisted state is
// untrusted input after a process restart, so every workflow rechecks it
// before using it as the base for another payment.
func (engine *BSVEngine) VerifyAcceptedPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil {
		return invalid("payment state is required")
	}
	if err := engine.VerifyOpening(proof); err != nil {
		return err
	}
	parsed, err := engine.ParsePaymentState(context.Background(), state.RawTx, proof)
	if err != nil {
		return err
	}
	if err := comparePaymentState(parsed, state); err != nil {
		return err
	}
	if bytes.Equal(state.RawTx, proof.RefundTx) {
		if state.PaymentSequence != 1 || state.SellerAmountSat != 0 {
			return invalid("opening refund is not the initial accepted payment state")
		}
		return nil
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return err
	}
	setSourceOutput(tx, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	return engine.verifyAcceptedUnlockingScript(tx)
}

// VerifyCompletedFinalPayment validates the final buyer+seller transaction
// received by the buyer before it is sent to the final node. Building an
// immediate close only needs VerifyFinalPayment because the buyer signs first;
// this method is for the completed two-signature transaction.
func (engine *BSVEngine) VerifyCompletedFinalPayment(payment *SignedPayment, proof *OpeningProof) error {
	if payment == nil || len(payment.RawTx) == 0 || !bytes.Equal(payment.RawTx, payment.State.RawTx) {
		return invalid("completed final payment is required")
	}
	if err := engine.VerifyFinalPayment(&payment.State, proof); err != nil {
		return err
	}
	tx, err := parseTransaction(payment.RawTx)
	if err != nil {
		return err
	}
	chunks, err := tx.Inputs[0].UnlockingScript.Chunks()
	if err != nil || len(chunks) != 3 || chunks[0].Op != script.Op0 || len(chunks[1].Data) == 0 || len(chunks[2].Data) == 0 {
		return invalid("final payment must contain buyer and seller signatures")
	}
	setSourceOutput(tx, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	if err := engine.verifySignatureOnTransaction(tx, chunks[2].Data, engine.seller); err != nil {
		return fmt.Errorf("seller final signature: %w", err)
	}
	return nil
}

func (engine *BSVEngine) parsePaymentState(rawTx []byte, proof *OpeningProof, allowFinal bool) (*PaymentState, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	tx, err := parseTransaction(rawTx)
	if err != nil {
		return nil, err
	}
	if len(tx.Inputs) != 1 || tx.Inputs[0] == nil || tx.Inputs[0].SourceTXID == nil {
		return nil, invalid("payment must have exactly one input")
	}
	input := tx.Inputs[0]
	if !bytes.Equal(input.SourceTXID.CloneBytes(), proof.FundingTxID) || input.SourceTxOutIndex != proof.PoolOutputIndex {
		return nil, invalid("payment does not spend the pool funding output")
	}
	if input.SequenceNumber == 0 || (!allowFinal && input.SequenceNumber == bsvtx.DefaultSequenceNumber) || (allowFinal && input.SequenceNumber != bsvtx.DefaultSequenceNumber) {
		return nil, invalid("payment sequence is invalid for the requested finality")
	}
	if allowFinal {
		if tx.LockTime != bsvtx.DefaultSequenceNumber {
			return nil, invalid("final payment must use the final locktime")
		}
	} else if tx.LockTime == 0 || tx.LockTime != refundLockTime(proof) {
		return nil, invalid("payment locktime does not match refund expiry")
	}
	if len(tx.Outputs) != 2 || tx.Outputs[0] == nil || tx.Outputs[1] == nil {
		return nil, invalid("payment must contain seller and buyer outputs only")
	}
	sellerScript, err := p2pkhScript(engine.seller)
	if err != nil {
		return nil, err
	}
	buyerScript, err := p2pkhScript(engine.buyer)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tx.Outputs[0].LockingScript.Bytes(), sellerScript.Bytes()) || !bytes.Equal(tx.Outputs[1].LockingScript.Bytes(), buyerScript.Bytes()) {
		return nil, invalid("payment outputs do not use the fixed seller and buyer addresses")
	}
	if tx.Outputs[1].Satoshis == 0 || tx.Outputs[0].Satoshis > proof.PoolOutputSatoshis || tx.Outputs[1].Satoshis > proof.PoolOutputSatoshis || tx.Outputs[0].Satoshis > proof.PoolOutputSatoshis-tx.Outputs[1].Satoshis {
		return nil, invalid("payment outputs exceed pool balance")
	}
	spendTxID, err := engine.TransactionID(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	return &PaymentState{
		SpendTxID:          spendTxID,
		RawTx:              append([]byte(nil), rawTx...),
		PaymentSequence:    input.SequenceNumber,
		SellerAmountSat:    tx.Outputs[0].Satoshis,
		ClientAmountSat:    tx.Outputs[1].Satoshis,
		PoolOutputSatoshis: proof.PoolOutputSatoshis,
		PoolLockingScript:  append([]byte(nil), proof.PoolLockingScript...),
	}, nil
}

func (engine *BSVEngine) InitialPaymentState(proof *OpeningProof) (*PaymentState, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	return engine.ParsePaymentState(context.Background(), proof.RefundTx, proof)
}

func (engine *BSVEngine) CheckPaymentCapacity(_ context.Context, input PaymentUpdateInput) error {
	if input.Opening == nil || input.Previous == nil {
		return invalid("opening and previous payment state are required")
	}
	if err := engine.VerifyAcceptedPayment(input.Previous, input.Opening); err != nil {
		return fmt.Errorf("verify previous payment state: %w", err)
	}
	if input.PaymentSequenceAfter == 0 || input.PaymentSequenceAfter == bsvtx.DefaultSequenceNumber || input.PaymentSequenceAfter <= input.Previous.PaymentSequence {
		return ErrStalePaymentSequence
	}
	if input.SellerAmountAfterSat < input.Previous.SellerAmountSat {
		return invalid("seller amount cannot decrease")
	}
	if input.SellerAmountAfterSat > input.Opening.PoolOutputSatoshis || input.MinerFeeSat > input.Opening.PoolOutputSatoshis-input.SellerAmountAfterSat {
		return ErrInsufficientBalance
	}
	if input.Opening.PoolOutputSatoshis-input.SellerAmountAfterSat-input.MinerFeeSat == 0 {
		return ErrInsufficientBalance
	}
	return nil
}

func (engine *BSVEngine) BuildPaymentUpdate(ctx context.Context, input PaymentUpdateInput) (*UnsignedPayment, error) {
	if err := engine.CheckPaymentCapacity(ctx, input); err != nil {
		return nil, err
	}
	tx, err := engine.buildSpendTransaction(input.Opening, input.PaymentSequenceAfter, input.SellerAmountAfterSat, input.MinerFeeSat)
	if err != nil {
		return nil, err
	}
	spendTxID, err := engine.TransactionID(input.Opening.RefundTx)
	if err != nil {
		return nil, err
	}
	return &UnsignedPayment{
		SpendTxID:          spendTxID,
		RawTx:              tx.Bytes(),
		PoolOutputSatoshis: input.Opening.PoolOutputSatoshis,
		PoolLockingScript:  append([]byte(nil), input.Opening.PoolLockingScript...),
	}, nil
}

func (engine *BSVEngine) SignBuyerPayment(ctx context.Context, unsigned *UnsignedPayment, signer Signer) (*PaymentState, error) {
	if unsigned == nil || len(unsigned.RawTx) == 0 || signer == nil {
		return nil, invalid("unsigned payment and buyer signer are required")
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("buyer public key: %w", err)
	}
	if !bytes.Equal(publicKey, engine.buyer.Compressed()) {
		return nil, invalid("buyer signer does not match pool buyer")
	}
	tx, err := parseTransaction(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	if len(tx.Inputs) != 1 {
		return nil, invalid("payment must have exactly one input")
	}
	setSourceOutput(tx, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, fmt.Errorf("payment signature hash: %w", err)
	}
	signature, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("sign buyer payment: %w", err)
	}
	signature, err = normalizeBitcoinSignature(signature)
	if err != nil {
		return nil, err
	}
	unlocking := script.NewFromBytes([]byte{script.Op0})
	if err := unlocking.AppendPushData(signature); err != nil {
		return nil, err
	}
	tx.Inputs[0].UnlockingScript = unlocking
	state, err := engine.parsePaymentTransaction(tx, unsigned.SpendTxID, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if err != nil {
		return nil, err
	}
	if err := engine.verifySignatureOnTransaction(tx, signature, engine.buyer); err != nil {
		return nil, err
	}
	return state, nil
}

func (engine *BSVEngine) VerifyBuyerPayment(state *PaymentState, proof *OpeningProof) error {
	if state == nil {
		return invalid("payment state is required")
	}
	parsed, err := engine.ParsePaymentState(context.Background(), state.RawTx, proof)
	if err != nil {
		return err
	}
	if err := comparePaymentState(parsed, state); err != nil {
		return err
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return err
	}
	setSourceOutput(tx, proof.PoolOutputSatoshis, proof.PoolLockingScript)
	return engine.verifyBuyerUnlockingScript(tx)
}

func comparePaymentState(parsed, supplied *PaymentState) error {
	if parsed == nil || supplied == nil {
		return invalid("payment state is required")
	}
	if parsed.SpendTxID != supplied.SpendTxID || parsed.PaymentSequence != supplied.PaymentSequence || parsed.SellerAmountSat != supplied.SellerAmountSat || parsed.ClientAmountSat != supplied.ClientAmountSat {
		return invalid("payment state metadata does not match transaction")
	}
	if supplied.PoolOutputSatoshis != 0 && supplied.PoolOutputSatoshis != parsed.PoolOutputSatoshis {
		return invalid("payment state source amount does not match opening")
	}
	if len(supplied.PoolLockingScript) != 0 && !bytes.Equal(supplied.PoolLockingScript, parsed.PoolLockingScript) {
		return invalid("payment state source script does not match opening")
	}
	return nil
}

func (engine *BSVEngine) AddSellerSignature(ctx context.Context, state *PaymentState, signer Signer) (*SignedPayment, error) {
	if state == nil || signer == nil {
		return nil, invalid("payment state and seller signer are required")
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return nil, err
	}
	setSourceOutput(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	if err := engine.verifyBuyerUnlockingScript(tx); err != nil {
		return nil, err
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, engine.seller.Compressed()) {
		return nil, invalid("seller signer does not match pool seller")
	}
	digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, err
	}
	signature, err = normalizeBitcoinSignature(signature)
	if err != nil {
		return nil, err
	}
	unlocking, err := multisigUnlocking(tx.Inputs[0].UnlockingScript, signature)
	if err != nil {
		return nil, err
	}
	tx.Inputs[0].UnlockingScript = unlocking
	if err := engine.verifySignatureOnTransaction(tx, signature, engine.seller); err != nil {
		return nil, err
	}
	updated, err := engine.parsePaymentTransaction(tx, state.SpendTxID, state.PoolOutputSatoshis, state.PoolLockingScript)
	if err != nil {
		return nil, err
	}
	return &SignedPayment{State: *updated, RawTx: tx.Bytes()}, nil
}

func (engine *BSVEngine) SignArbiterPayment(ctx context.Context, state *PaymentState, signer Signer) ([]byte, error) {
	if state == nil || signer == nil {
		return nil, invalid("payment state and arbiter signer are required")
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return nil, err
	}
	setSourceOutput(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	if err := engine.verifyBuyerUnlockingScript(tx); err != nil {
		return nil, err
	}
	publicKey, err := signer.PublicKey(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(publicKey, engine.arbiter.Compressed()) {
		return nil, invalid("arbiter signer does not match pool arbiter")
	}
	digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, err
	}
	return normalizeBitcoinSignature(signature)
}

func (engine *BSVEngine) AddArbiterSignature(_ context.Context, state *PaymentState, arbiterSignature []byte) (*SignedPayment, error) {
	if state == nil {
		return nil, invalid("payment state is required")
	}
	signature, err := normalizeBitcoinSignature(arbiterSignature)
	if err != nil {
		return nil, err
	}
	tx, err := parseTransaction(state.RawTx)
	if err != nil {
		return nil, err
	}
	setSourceOutput(tx, state.PoolOutputSatoshis, state.PoolLockingScript)
	if err := engine.verifyBuyerUnlockingScript(tx); err != nil {
		return nil, err
	}
	if err := engine.verifySignatureOnTransaction(tx, signature, engine.arbiter); err != nil {
		return nil, fmt.Errorf("arbiter signature: %w", err)
	}
	unlocking, err := multisigUnlocking(tx.Inputs[0].UnlockingScript, signature)
	if err != nil {
		return nil, err
	}
	tx.Inputs[0].UnlockingScript = unlocking
	updated, err := engine.parsePaymentTransaction(tx, state.SpendTxID, state.PoolOutputSatoshis, state.PoolLockingScript)
	if err != nil {
		return nil, err
	}
	return &SignedPayment{State: *updated, RawTx: tx.Bytes()}, nil
}

func (engine *BSVEngine) BuildImmediateClose(ctx context.Context, input CloseInput) (*UnsignedPayment, error) {
	if input.Opening == nil || input.Latest == nil {
		return nil, invalid("opening and latest payment state are required")
	}
	if err := engine.VerifyOpening(input.Opening); err != nil {
		return nil, err
	}
	if err := engine.VerifyAcceptedPayment(input.Latest, input.Opening); err != nil {
		return nil, fmt.Errorf("verify latest payment state: %w", err)
	}
	if input.SellerAmountAfterSat < input.Latest.SellerAmountSat || input.SellerAmountAfterSat > input.Opening.PoolOutputSatoshis {
		return nil, invalid("close seller amount is invalid")
	}
	if input.MinerFeeSat > input.Opening.PoolOutputSatoshis-input.SellerAmountAfterSat || input.Opening.PoolOutputSatoshis-input.SellerAmountAfterSat-input.MinerFeeSat == 0 {
		return nil, ErrInsufficientBalance
	}
	tx, err := engine.buildSpendTransaction(input.Opening, bsvtx.DefaultSequenceNumber, input.SellerAmountAfterSat, input.MinerFeeSat)
	if err != nil {
		return nil, err
	}
	tx.LockTime = bsvtx.DefaultSequenceNumber
	spendTxID, err := engine.TransactionID(input.Opening.RefundTx)
	if err != nil {
		return nil, err
	}
	return &UnsignedPayment{
		SpendTxID:          spendTxID,
		RawTx:              tx.Bytes(),
		PoolOutputSatoshis: input.Opening.PoolOutputSatoshis,
		PoolLockingScript:  append([]byte(nil), input.Opening.PoolLockingScript...),
	}, nil
}

func (engine *BSVEngine) buildSpendTransaction(proof *OpeningProof, sequence uint32, sellerAmount, minerFee uint64) (*bsvtx.Transaction, error) {
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, err
	}
	if sellerAmount > proof.PoolOutputSatoshis || minerFee > proof.PoolOutputSatoshis-sellerAmount {
		return nil, ErrInsufficientBalance
	}
	buyerAmount := proof.PoolOutputSatoshis - sellerAmount - minerFee
	sellerScript, err := p2pkhScript(engine.seller)
	if err != nil {
		return nil, err
	}
	buyerScript, err := p2pkhScript(engine.buyer)
	if err != nil {
		return nil, err
	}
	refund, err := parseTransaction(proof.RefundTx)
	if err != nil {
		return nil, err
	}
	tx := bsvtx.NewTransaction()
	tx.LockTime = refund.LockTime
	previousID, err := parseHash(proof.FundingTxID)
	if err != nil {
		return nil, err
	}
	tx.AddInputWithOutput(&bsvtx.TransactionInput{
		SourceTXID:       previousID,
		SourceTxOutIndex: proof.PoolOutputIndex,
		SequenceNumber:   sequence,
		UnlockingScript:  script.NewFromBytes(nil),
	}, &bsvtx.TransactionOutput{Satoshis: proof.PoolOutputSatoshis, LockingScript: script.NewFromBytes(append([]byte(nil), proof.PoolLockingScript...))})
	tx.AddOutput(&bsvtx.TransactionOutput{Satoshis: sellerAmount, LockingScript: sellerScript})
	tx.AddOutput(&bsvtx.TransactionOutput{Satoshis: buyerAmount, LockingScript: buyerScript})
	return tx, nil
}

func (engine *BSVEngine) parsePaymentTransaction(tx *bsvtx.Transaction, spendTxID Hash32, poolSatoshis uint64, poolLockingScript []byte) (*PaymentState, error) {
	if tx == nil || len(tx.Inputs) != 1 || len(tx.Outputs) != 2 || tx.Inputs[0] == nil {
		return nil, invalid("invalid payment transaction")
	}
	return &PaymentState{
		SpendTxID:          spendTxID,
		RawTx:              tx.Bytes(),
		PaymentSequence:    tx.Inputs[0].SequenceNumber,
		SellerAmountSat:    tx.Outputs[0].Satoshis,
		ClientAmountSat:    tx.Outputs[1].Satoshis,
		PoolOutputSatoshis: poolSatoshis,
		PoolLockingScript:  append([]byte(nil), poolLockingScript...),
	}, nil
}

func (engine *BSVEngine) verifyPoolScript(lockingScript *script.Script) error {
	keys, err := multisigPublicKeys(lockingScript)
	if err != nil {
		return err
	}
	expected := []*ec.PublicKey{engine.buyer, engine.seller, engine.arbiter}
	for index := range expected {
		if !keys[index].IsEqual(expected[index]) {
			return invalid("pool locking script public-key order does not match opening participants")
		}
	}
	return nil
}

func (engine *BSVEngine) matchConfiguredParticipantKeys(sellerPubkey, arbiterPubkey []byte) error {
	seller, err := parseCompressedOrUncompressedPubKey(sellerPubkey)
	if err != nil {
		return fmt.Errorf("seller public key: %w", err)
	}
	arbiter, err := parseCompressedOrUncompressedPubKey(arbiterPubkey)
	if err != nil {
		return fmt.Errorf("arbiter public key: %w", err)
	}
	if !seller.IsEqual(engine.seller) || !arbiter.IsEqual(engine.arbiter) {
		return invalid("opening participant keys do not match the transaction engine")
	}
	return nil
}

func multisigPublicKeys(lockingScript *script.Script) ([]*ec.PublicKey, error) {
	if lockingScript == nil {
		return nil, invalid("pool locking script is required")
	}
	chunks, err := lockingScript.Chunks()
	if err != nil {
		return nil, fmt.Errorf("decode pool locking script: %w", err)
	}
	if len(chunks) != 6 || chunks[0].Op != script.Op2 || chunks[4].Op != script.Op3 || chunks[5].Op != script.OpCHECKMULTISIG {
		return nil, invalid("pool locking script must be canonical 2-of-3 multisig")
	}
	keys := make([]*ec.PublicKey, 3)
	for index := 0; index < 3; index++ {
		if len(chunks[index+1].Data) == 0 {
			return nil, invalid("pool locking script contains an empty public key")
		}
		key, err := ec.ParsePubKey(chunks[index+1].Data)
		if err != nil {
			return nil, fmt.Errorf("pool public key %d: %w", index, err)
		}
		keys[index] = key
	}
	return keys, nil
}

func (engine *BSVEngine) verifyBuyerUnlockingScript(tx *bsvtx.Transaction) error {
	if tx == nil || len(tx.Inputs) != 1 || tx.Inputs[0] == nil || tx.Inputs[0].UnlockingScript == nil {
		return invalid("buyer payment signature is required")
	}
	chunks, err := tx.Inputs[0].UnlockingScript.Chunks()
	if err != nil || (len(chunks) != 2 && len(chunks) != 3) || chunks[0].Op != script.Op0 || len(chunks[1].Data) == 0 {
		return invalid("payment unlocking script does not contain a buyer signature")
	}
	return engine.verifySignatureOnTransaction(tx, chunks[1].Data, engine.buyer)
}

func (engine *BSVEngine) verifyAcceptedUnlockingScript(tx *bsvtx.Transaction) error {
	if err := engine.verifyBuyerUnlockingScript(tx); err != nil {
		return err
	}
	chunks, err := tx.Inputs[0].UnlockingScript.Chunks()
	if err != nil || len(chunks) == 2 {
		return nil
	}
	if len(chunks) != 3 || len(chunks[2].Data) == 0 {
		return invalid("accepted payment unlocking script has an invalid signature count")
	}
	if err := engine.verifySignatureOnTransaction(tx, chunks[2].Data, engine.seller); err == nil {
		return nil
	}
	if err := engine.verifySignatureOnTransaction(tx, chunks[2].Data, engine.arbiter); err == nil {
		return nil
	}
	return invalid("accepted payment second signature is neither seller nor arbiter")
}

func (engine *BSVEngine) verifySignatureOnTransaction(tx *bsvtx.Transaction, signature []byte, key *ec.PublicKey) error {
	if tx == nil || len(tx.Inputs) != 1 {
		return invalid("payment transaction input is required")
	}
	parsed, err := parseBitcoinSignature(signature)
	if err != nil {
		return err
	}
	digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return fmt.Errorf("signature hash: %w", err)
	}
	if !parsed.Verify(digest, key) {
		return invalid("transaction signature does not verify")
	}
	return nil
}

func multisigUnlocking(existing *script.Script, signature []byte) (*script.Script, error) {
	if existing == nil {
		return nil, invalid("existing payment unlocking script is required")
	}
	chunks, err := existing.Chunks()
	if err != nil || len(chunks) < 2 || chunks[0].Op != script.Op0 || len(chunks[1].Data) == 0 {
		return nil, invalid("existing buyer unlocking script is invalid")
	}
	result := script.NewFromBytes([]byte{script.Op0})
	if err := result.AppendPushData(chunks[1].Data); err != nil {
		return nil, err
	}
	if err := result.AppendPushData(signature); err != nil {
		return nil, err
	}
	return result, nil
}

func p2pkhScript(key *ec.PublicKey) (*script.Script, error) {
	if key == nil {
		return nil, invalid("public key is required")
	}
	result := script.NewFromBytes(nil)
	if err := result.AppendOpcodes(script.OpDUP, script.OpHASH160); err != nil {
		return nil, err
	}
	if err := result.AppendPushData(hash.Hash160(key.Compressed())); err != nil {
		return nil, err
	}
	if err := result.AppendOpcodes(script.OpEQUALVERIFY, script.OpCHECKSIG); err != nil {
		return nil, err
	}
	return result, nil
}

func parseTransaction(rawTx []byte) (*bsvtx.Transaction, error) {
	if len(rawTx) == 0 {
		return nil, invalid("raw transaction is required")
	}
	tx, err := bsvtx.NewTransactionFromBytes(rawTx)
	if err != nil {
		return nil, fmt.Errorf("decode raw transaction: %w", err)
	}
	return tx, nil
}

func parseHash(raw []byte) (*chainhash.Hash, error) {
	if len(raw) != 32 {
		return nil, invalid("transaction ID must be 32 bytes")
	}
	return chainhash.NewHash(append([]byte(nil), raw...))
}

func setSourceOutput(tx *bsvtx.Transaction, satoshis uint64, lockingScript []byte) {
	if tx == nil || len(tx.Inputs) == 0 || satoshis == 0 || len(lockingScript) == 0 {
		return
	}
	tx.Inputs[0].SetSourceTxOutput(&bsvtx.TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: script.NewFromBytes(append([]byte(nil), lockingScript...)),
	})
}

func refundLockTime(proof *OpeningProof) uint32 {
	if proof == nil {
		return 0
	}
	refund, err := parseTransaction(proof.RefundTx)
	if err != nil {
		return 0
	}
	return refund.LockTime
}

func parseCompressedOrUncompressedPubKey(raw []byte) (*ec.PublicKey, error) {
	if len(raw) == 0 {
		return nil, invalid("public key is required")
	}
	return ec.ParsePubKey(append([]byte(nil), raw...))
}

func normalizeBitcoinSignature(signature []byte) ([]byte, error) {
	if len(signature) == 0 {
		return nil, invalid("signature is required")
	}
	if _, err := parseExactDERSignature(signature); err == nil {
		return append(append([]byte(nil), signature...), bitcoinSignatureHashType), nil
	}
	if signature[len(signature)-1] == bitcoinSignatureHashType {
		if _, err := parseExactDERSignature(signature[:len(signature)-1]); err != nil {
			return nil, fmt.Errorf("invalid DER signature: %w", err)
		}
		return append([]byte(nil), signature...), nil
	}
	if _, err := parseExactDERSignature(signature); err != nil {
		return nil, fmt.Errorf("invalid DER signature: %w", err)
	}
	return append(append([]byte(nil), signature...), bitcoinSignatureHashType), nil
}

func parseBitcoinSignature(signature []byte) (*ec.Signature, error) {
	if len(signature) < 2 || signature[len(signature)-1] != bitcoinSignatureHashType {
		return nil, invalid("signature must use SIGHASH_ALL|FORKID")
	}
	parsed, err := parseExactDERSignature(signature[:len(signature)-1])
	if err != nil {
		return nil, fmt.Errorf("invalid DER signature: %w", err)
	}
	return parsed, nil
}

func parseExactDERSignature(raw []byte) (*ec.Signature, error) {
	if len(raw) < 2 || raw[0] != 0x30 || int(raw[1])+2 != len(raw) {
		return nil, invalid("DER signature has trailing or missing bytes")
	}
	return ec.ParseDERSignature(raw)
}

func verifyBitcoinSignature(digest, signature []byte, key *ec.PublicKey) error {
	parsed, err := parseBitcoinSignature(signature)
	if err != nil {
		return err
	}
	if !parsed.Verify(digest, key) {
		return invalid("signature does not verify")
	}
	return nil
}

func hash32FromBytes(raw []byte) Hash32 {
	var result Hash32
	copy(result[:], raw)
	return result
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEvidence, fmt.Sprintf(format, args...))
}
