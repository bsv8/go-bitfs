package pool

// This file contains the arbitration transaction boundary of the fee pool.
// Unlike the
// normal payment path, arbitration deliberately has no OpeningProof or fee
// rate input: the refund template is the canonical transaction shape and its
// retained balance is the only fee evidence available on the wire.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
	"github.com/bsv8/go-bitfs/protocol"
)

const (
	maxArbitrationRefundTemplateBytes = 16 * 1024
	maxArbitrationCandidateBytes      = 64 * 1024
)

// RefundTemplateLockTime 从退款模板原文提取强类型 nLockTime；模板字节必须
// 是 canonical 交易编码。
func RefundTemplateLockTime(refundTemplateRaw []byte) (protocol.RefundLockTime, error) {
	refund, err := parseCanonicalTransaction(refundTemplateRaw)
	if err != nil {
		return 0, err
	}
	return protocol.RefundLockTime(refund.LockTime), nil
}

// ParseArbitratedPoolLockingScript accepts only the canonical
// OP_2 <Buyer> <Seller> <Arbiter> OP_3 OP_CHECKMULTISIG script.  In
// particular, it does not normalize push encodings, sort keys, or infer
// roles from signatures.
func ParseArbitratedPoolLockingScript(raw []byte) (MultisigPoolPublicKeys, error) {
	var result MultisigPoolPublicKeys
	if len(raw) != 1+34+34+34+2 || raw[0] != byte(script.Op2) || raw[1] != 33 || raw[35] != 33 || raw[69] != 33 || raw[103] != byte(script.Op3) || raw[104] != byte(script.OpCHECKMULTISIG) {
		return result, invalid("pool locking script is not the canonical 2-of-3 P2MS form")
	}
	keys := [][]byte{raw[2:35], raw[36:69], raw[70:103]}
	parsed := make([]*ec.PublicKey, len(keys))
	for index, keyBytes := range keys {
		key, err := protocol.ParseCompressedPubKey(keyBytes)
		if err != nil {
			return result, protocol.Wrap(fmt.Errorf("pool role key #%d: %v", index+1, err), "pool.ParseArbitratedPoolLockingScript", protocol.CodeInvalidEvidence, 0, "pool_output_locking_script")
		}
		parsed[index] = key
	}
	if parsed[0].IsEqual(parsed[1]) || parsed[0].IsEqual(parsed[2]) || parsed[1].IsEqual(parsed[2]) {
		return result, invalid("pool role keys must be distinct")
	}
	canonical, err := Build2of3LockingScript(MultisigPoolPublicKeys{BuyerPublicKey: keys[0], SellerPublicKey: keys[1], ArbiterPublicKey: keys[2]})
	if err != nil {
		return result, err
	}
	if !bytes.Equal(canonical, raw) {
		return result, invalid("pool locking script is not the canonical role-ordered script")
	}
	return MultisigPoolPublicKeys{
		BuyerPublicKey:   append([]byte(nil), keys[0]...),
		SellerPublicKey:  append([]byte(nil), keys[1]...),
		ArbiterPublicKey: append([]byte(nil), keys[2]...),
	}, nil
}

// NewMultisigPoolEngineFromPoolLockingScript restores the role-aware engine
// from the exact source locking script supplied in an arbitration Claim.
func NewMultisigPoolEngineFromPoolLockingScript(raw []byte) (*MultisigPoolEngine, error) {
	keys, err := ParseArbitratedPoolLockingScript(raw)
	if err != nil {
		return nil, err
	}
	return NewMultisigPoolEngine(MultisigPoolEngineConfig{
		BuyerPublicKey: keys.BuyerPublicKey, SellerPublicKey: keys.SellerPublicKey, ArbiterPublicKey: keys.ArbiterPublicKey,
	})
}

// ValidateArbitrationClaimStructure exposes the pure Claim-structure checks of
// the 007 candidate for callers that hold evidence but not yet a decided
// arbitration fee. It performs exactly the same source, role-script, refund
// template, sequence, and Seller-balance validation as the success builder,
// minus the positive-arbiter-amount requirement, so evidence validation never
// needs a placeholder fee.
func ValidateArbitrationClaimStructure(poolOutputSatoshis uint64, poolOutputLockingScript, refundTemplateRaw []byte, paymentSequence uint32, sellerAmountAfterSatoshis uint64) error {
	return validateArbitrationClaimContext(poolOutputSatoshis, poolOutputLockingScript, refundTemplateRaw, paymentSequence, sellerAmountAfterSatoshis)
}

// validateArbitrationClaimContext performs the pure Claim-structure checks of
// the 007 candidate: source context, role scripts, canonical refund template
// with zero Seller/Arbiter initial amounts, sequence ordering, and the Seller
// balance boundary. It deliberately does not depend on any arbitration fee so
// evidence validation never needs a placeholder amount; the public success
// builder additionally requires a positive fee.
func validateArbitrationClaimContext(poolOutputSatoshis uint64, poolOutputLockingScript, refundTemplateRaw []byte, paymentSequence uint32, sellerAmountAfterSatoshis uint64) error {
	if poolOutputSatoshis == 0 || len(poolOutputLockingScript) == 0 || len(refundTemplateRaw) == 0 {
		return invalid("arbitration source context and refund template are required")
	}
	if len(refundTemplateRaw) > maxArbitrationRefundTemplateBytes {
		return invalid("arbitration refund template exceeds the protocol size limit")
	}
	keys, err := ParseArbitratedPoolLockingScript(poolOutputLockingScript)
	if err != nil {
		return err
	}
	refund, err := parseCanonicalTransaction(refundTemplateRaw)
	if err != nil {
		return err
	}
	if len(refund.Inputs) != 1 || refund.Inputs[0] == nil || refund.Inputs[0].SourceTXID == nil || len(refund.Outputs) != 3 {
		return invalid("refund template must have one input and exactly three outputs")
	}
	sourceTxID := refund.Inputs[0].SourceTXID.CloneBytes()
	if len(sourceTxID) != sha256.Size || isZeroBytes(sourceTxID) {
		return invalid("refund template funding txid must be non-zero")
	}
	if refund.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return invalid("refund template must spend funding output index 0")
	}
	if refund.Inputs[0].SequenceNumber == finalPoolSequence {
		return invalid("refund template cannot use the final sequence")
	}
	if refund.Inputs[0].UnlockingScript != nil && len(refund.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return invalid("refund template input unlocking script must be empty")
	}
	if paymentSequence == 0 || paymentSequence == finalPoolSequence || paymentSequence <= refund.Inputs[0].SequenceNumber {
		return invalid("arbitration payment sequence must extend the refund sequence")
	}

	roleScripts, err := arbitrationRoleScripts(keys)
	if err != nil {
		return err
	}
	for index, expected := range roleScripts {
		if refund.Outputs[index] == nil || refund.Outputs[index].LockingScript == nil || !bytes.Equal(refund.Outputs[index].LockingScript.Bytes(), expected) {
			return invalid(fmt.Sprintf("refund template output %d does not match its role script", index))
		}
	}
	if refund.Outputs[1].Satoshis != 0 || refund.Outputs[2].Satoshis != 0 {
		return invalid("refund template seller and arbiter outputs must be zero")
	}
	refundOutputs := refund.Outputs[0].Satoshis
	if refund.Outputs[1].Satoshis > ^uint64(0)-refundOutputs {
		return invalid("refund template output amount overflows")
	}
	refundOutputs += refund.Outputs[1].Satoshis
	if refund.Outputs[2].Satoshis > ^uint64(0)-refundOutputs {
		return invalid("refund template output amount overflows")
	}
	refundOutputs += refund.Outputs[2].Satoshis
	if refundOutputs > poolOutputSatoshis {
		return invalid("refund template outputs exceed the claimed pool output")
	}
	refundFeeSatoshis := poolOutputSatoshis - refundOutputs
	spendableSatoshis := poolOutputSatoshis - refundFeeSatoshis
	if sellerAmountAfterSatoshis > spendableSatoshis {
		return insufficientBalance()
	}
	return nil
}

// BuildArbitrationPaymentFromClaim is the sole 007 candidate builder over
// the fixed MultisigPool transaction rules.  It
// accepts only source amount, source locking script, refund template bytes,
// target sequence, the absolute seller amount, and the explicit absolute
// arbiter fee.  A successful 007 requires a positive arbiter amount; zero is
// never accepted here.  Source metadata is added to the in-memory transaction
// solely for ForkID sighash calculation and is never serialized into RawTx.
func BuildArbitrationPaymentFromClaim(poolOutputSatoshis uint64, poolOutputLockingScript, refundTemplateRaw []byte, paymentSequence uint32, sellerAmountAfterSatoshis uint64, arbiterAmountSatoshis uint64) (*UnsignedPayment, error) {
	if err := validateArbitrationClaimContext(poolOutputSatoshis, poolOutputLockingScript, refundTemplateRaw, paymentSequence, sellerAmountAfterSatoshis); err != nil {
		return nil, err
	}
	refund, err := parseCanonicalTransaction(refundTemplateRaw)
	if err != nil {
		return nil, err
	}
	refundOutputs := refund.Outputs[0].Satoshis + refund.Outputs[1].Satoshis + refund.Outputs[2].Satoshis
	refundFeeSatoshis := poolOutputSatoshis - refundOutputs
	spendableSatoshis := poolOutputSatoshis - refundFeeSatoshis
	remainingAfterSellerSatoshis := spendableSatoshis - sellerAmountAfterSatoshis
	if arbiterAmountSatoshis == 0 {
		return nil, invalid("arbitration payment requires a positive arbiter amount")
	}
	if arbiterAmountSatoshis > remainingAfterSellerSatoshis {
		return nil, insufficientBalance()
	}
	buyerAmountSatoshis := remainingAfterSellerSatoshis - arbiterAmountSatoshis

	sourceTxID := refund.Inputs[0].SourceTXID.CloneBytes()
	candidate, err := parseCanonicalTransaction(refundTemplateRaw)
	if err != nil {
		return nil, err
	}
	candidate.Inputs[0].SequenceNumber = paymentSequence
	candidate.Outputs[0].Satoshis = buyerAmountSatoshis
	candidate.Outputs[1].Satoshis = sellerAmountAfterSatoshis
	candidate.Outputs[2].Satoshis = arbiterAmountSatoshis
	setPoolSource(candidate, poolOutputSatoshis, poolOutputLockingScript)
	unsignedRaw := candidate.Bytes()
	refundID := RefundTemplateTxID(refund.TxID().CloneBytes())
	unsigned := &UnsignedPayment{
		RefundTemplateTxID:    refundID,
		RawTx:                 append([]byte(nil), unsignedRaw...),
		PaymentSequence:       paymentSequence,
		BuyerAmountSatoshis:   buyerAmountSatoshis,
		SellerAmountSatoshis:  sellerAmountAfterSatoshis,
		ArbiterAmountSatoshis: arbiterAmountSatoshis,
		PoolOutputSatoshis:    poolOutputSatoshis,
		PoolLockingScript:     append([]byte(nil), poolOutputLockingScript...),
		arbitrationSourceTxID: append([]byte(nil), sourceTxID...),
	}
	unsigned.arbitrationCandidateCommitment = arbitrationCandidateCommitment(unsigned)
	return unsigned, nil
}

func arbitrationRoleScripts(keys MultisigPoolPublicKeys) ([][]byte, error) {
	parsed := make([]*ec.PublicKey, 3)
	for index, raw := range [][]byte{keys.BuyerPublicKey, keys.SellerPublicKey, keys.ArbiterPublicKey} {
		key, err := protocol.ParseCompressedPubKey(raw)
		if err != nil {
			return nil, err
		}
		parsed[index] = key
	}
	result := make([][]byte, 3)
	for index, key := range parsed {
		address, err := libs.GetAddressFromPublicKey(key, false)
		if err != nil {
			return nil, err
		}
		locking, err := p2pkh.Lock(address)
		if err != nil {
			return nil, err
		}
		result[index] = append([]byte(nil), locking.Bytes()...)
	}
	return result, nil
}

func (engine *MultisigPoolEngine) validateArbitrationUnsignedPayment(unsigned *UnsignedPayment) (*tx.Transaction, error) {
	if engine == nil || unsigned == nil || len(unsigned.RawTx) == 0 {
		return nil, invalid("arbitration unsigned payment is required")
	}
	if len(unsigned.RawTx) > maxArbitrationCandidateBytes {
		return nil, invalid("arbitration unsigned payment exceeds the protocol size limit")
	}
	if unsigned.PaymentSequence == 0 || unsigned.PaymentSequence == finalPoolSequence || unsigned.PoolOutputSatoshis == 0 {
		return nil, invalid("arbitration unsigned payment metadata is invalid")
	}
	if err := engine.validateRequestRoles(engine.buyer.Compressed(), engine.seller.Compressed(), engine.arbiter.Compressed()); err != nil {
		return nil, err
	}
	state, err := parseCanonicalTransaction(unsigned.RawTx)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil || len(state.Outputs) != 3 {
		return nil, invalid("arbitration payment must have one input and three outputs")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, invalid("arbitration payment must be unsigned")
	}
	if state.Inputs[0].SequenceNumber != unsigned.PaymentSequence || state.Outputs[0].Satoshis != unsigned.BuyerAmountSatoshis || state.Outputs[1].Satoshis != unsigned.SellerAmountSatoshis || state.Outputs[2].Satoshis != unsigned.ArbiterAmountSatoshis {
		return nil, invalid("arbitration payment metadata does not match raw transaction")
	}
	if unsigned.ArbiterAmountSatoshis == 0 || unsigned.RefundTemplateTxID == (RefundTemplateTxID{}) {
		return nil, invalid("arbitration payment amounts or template ID are invalid")
	}
	if !bytes.Equal(unsigned.PoolLockingScript, engine.lockBytes()) {
		return nil, invalid("arbitration payment source script does not match role engine")
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	if state.Inputs[0].SourceTXID == nil || state.Inputs[0].SourceTxOutIndex != PoolOutputIndex {
		return nil, invalid("arbitration payment outpoint is invalid")
	}
	if len(unsigned.arbitrationSourceTxID) != 32 || !bytes.Equal(state.Inputs[0].SourceTXID.CloneBytes(), unsigned.arbitrationSourceTxID) {
		return nil, invalid("arbitration payment outpoint does not match the Claim refund template")
	}
	if isZeroBytes(state.Inputs[0].SourceTXID.CloneBytes()) {
		return nil, invalid("arbitration payment funding txid must be non-zero")
	}
	if state.Outputs[0].LockingScript == nil || state.Outputs[1].LockingScript == nil || state.Outputs[2].LockingScript == nil {
		return nil, invalid("arbitration payment output scripts are required")
	}
	roleScripts, err := arbitrationRoleScripts(MultisigPoolPublicKeys{
		BuyerPublicKey: engine.buyer.Compressed(), SellerPublicKey: engine.seller.Compressed(), ArbiterPublicKey: engine.arbiter.Compressed(),
	})
	if err != nil {
		return nil, err
	}
	for index, expected := range roleScripts {
		if !bytes.Equal(state.Outputs[index].LockingScript.Bytes(), expected) {
			return nil, invalid(fmt.Sprintf("arbitration payment output %d does not match its role script", index))
		}
	}
	if len(unsigned.arbitrationCandidateCommitment) != sha256.Size || !bytes.Equal(unsigned.arbitrationCandidateCommitment, arbitrationCandidateCommitment(unsigned)) {
		return nil, invalid("arbitration payment candidate was modified after construction")
	}
	return state, nil
}

func arbitrationCandidateCommitment(unsigned *UnsignedPayment) []byte {
	hash := sha256.New()
	hash.Write([]byte("bitfs.v1.arbitration.unsigned-payment\x00"))
	writeCommitmentBytes(hash, unsigned.RefundTemplateTxID[:])
	writeCommitmentBytes(hash, unsigned.RawTx)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(unsigned.PaymentSequence))
	hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], unsigned.BuyerAmountSatoshis)
	hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], unsigned.SellerAmountSatoshis)
	hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], unsigned.ArbiterAmountSatoshis)
	hash.Write(number[:])
	binary.BigEndian.PutUint64(number[:], unsigned.PoolOutputSatoshis)
	hash.Write(number[:])
	writeCommitmentBytes(hash, unsigned.PoolLockingScript)
	writeCommitmentBytes(hash, unsigned.arbitrationSourceTxID)
	return hash.Sum(nil)
}

func writeCommitmentBytes(hash hash.Hash, value []byte) {
	// This helper is never called with a nil hash; keeping the length prefix in
	// the commitment avoids ambiguous concatenations between public fields.
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

func isZeroBytes(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func (engine *MultisigPoolEngine) signArbitrationPayment(ctx context.Context, unsigned *UnsignedPayment, signer protocol.Signer, role string) ([]byte, error) {
	state, err := engine.validateArbitrationUnsignedPayment(unsigned)
	if err != nil {
		return nil, err
	}
	return engine.signDigest(ctx, signer, state, unsigned.PoolOutputSatoshis, role)
}

// SignArbitrationSellerPayment signs an independently rebuilt arbitration
// candidate with the Seller role constrained Signer.
func (engine *MultisigPoolEngine) SignArbitrationSellerPayment(ctx context.Context, unsigned *UnsignedPayment, signer protocol.Signer) ([]byte, error) {
	return engine.signArbitrationPayment(ctx, unsigned, signer, "seller")
}

// SignArbitrationArbiterPayment signs an independently rebuilt arbitration
// candidate with the Arbiter role constrained Signer.
func (engine *MultisigPoolEngine) SignArbitrationArbiterPayment(ctx context.Context, unsigned *UnsignedPayment, signer protocol.Signer) ([]byte, error) {
	return engine.signArbitrationPayment(ctx, unsigned, signer, "arbiter")
}

// VerifyArbitrationSellerPayment verifies a Seller transaction signature over
// the exact independently rebuilt candidate.
func (engine *MultisigPoolEngine) VerifyArbitrationSellerPayment(unsigned *UnsignedPayment, signature []byte) error {
	return engine.verifyArbitrationPayment(unsigned, signature, "seller")
}

// VerifyArbitrationArbiterPayment verifies an Arbiter transaction signature
// over the exact independently rebuilt candidate.
func (engine *MultisigPoolEngine) VerifyArbitrationArbiterPayment(unsigned *UnsignedPayment, signature []byte) error {
	return engine.verifyArbitrationPayment(unsigned, signature, "arbiter")
}

func (engine *MultisigPoolEngine) verifyArbitrationPayment(unsigned *UnsignedPayment, signature []byte, role string) error {
	state, err := engine.validateArbitrationUnsignedPayment(unsigned)
	if err != nil {
		return err
	}
	if len(signature) == 0 {
		return invalid(role + " transaction signature is required")
	}
	details := unsigned.PoolOutputSatoshis
	roles := engine.roles()
	var valid bool
	switch role {
	case "seller":
		valid, err = mp.VerifyArbitratedPoolSellerSignature(state, details, roles, signature)
	case "arbiter":
		valid, err = mp.VerifyArbitratedPoolArbiterSignature(state, details, roles, signature)
	default:
		return invalid("unsupported arbitration payment role")
	}
	if err != nil {
		return err
	}
	if !valid {
		return invalid(role + " transaction signature is invalid")
	}
	return nil
}

// MergeArbitratedPoolSellerArbiterSignatures is the only merge path for the
// new 007 candidate.  It verifies both detached signatures before delegating
// the canonical unlocking-script ordering to MultisigPool.
func (engine *MultisigPoolEngine) MergeArbitratedPoolSellerArbiterSignatures(unsigned *UnsignedPayment, sellerSignature, arbiterSignature []byte) (*SignedPayment, error) {
	if err := engine.VerifyArbitrationSellerPayment(unsigned, sellerSignature); err != nil {
		return nil, err
	}
	if err := engine.VerifyArbitrationArbiterPayment(unsigned, arbiterSignature); err != nil {
		return nil, err
	}
	state, err := engine.validateArbitrationUnsignedPayment(unsigned)
	if err != nil {
		return nil, err
	}
	merged, err := mp.MergeArbitratedPoolSellerArbiterSignatures(state, unsigned.PoolOutputSatoshis, engine.roles(), sellerSignature, arbiterSignature)
	if err != nil {
		return nil, err
	}
	return engine.signedFromTx(merged, unsigned, nil, sellerSignature, arbiterSignature), nil
}

// CheckArbitrationRefundNotExpired applies the local nLockTime forward gate to
// the refund template using the caller's explicit facts: 只读取锁定类型对应的
// 那一份事实。It proves only that the template is not yet mature; it does not
// prove that the source output exists, is confirmed, or remains unspent.
func CheckArbitrationRefundNotExpired(refundTemplateRaw []byte, facts protocol.Facts) error {
	const op = "pool.CheckArbitrationRefundNotExpired"
	lockTime, err := RefundTemplateLockTime(refundTemplateRaw)
	if err != nil {
		return err
	}
	if err := facts.CheckRefundNotExpired(lockTime); err != nil {
		return protocol.Wrap(err, op, protocol.CodeExpired, 8, "refund_locktime")
	}
	return nil
}
