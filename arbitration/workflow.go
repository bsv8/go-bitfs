// Package arbitration implements the v4 Kind 8/9 custody and independent
// transaction-reconstruction workflow. Kind 9 is a hard-switched four-element
// receipt response: the arbiter is paid a positive, explicitly decided fee and
// the receipt binds the Claim ID, that fee, and the arbitration transaction
// signature together under one ordinary message signature.
package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/fxamacker/cbor/v2"
)

// MajorVersion is the current v4 protocol major.
const MajorVersion uint64 = 4

const (
	kindArbitrationRequest  uint64 = 8
	kindArbitrationResponse uint64 = 9

	// These are protocol limits, applied before CBOR decoding. They bound both
	// the outer messages and the large bstr children that a decoder would
	// otherwise allocate before semantic validation. Applications may impose
	// smaller transport limits, but must not silently raise these limits.
	MaxArbitrationSignatureBytes      = 256
	MaxArbitrationRefundTemplateBytes = 16 * 1024
	MaxArbitrationTermsBytes          = 16 * 1024
	MaxArbitrationClaimBytes          = 64 * 1024

	// maxDeterministicUint64Bytes is the largest canonical CBOR encoding of a
	// uint64 (8-byte value plus its length head).
	maxDeterministicUint64Bytes = 9
	// maxClaimIDBstrBytes is the exact wire width of a 32-byte Claim ID bstr:
	// the two-byte major-type+length head (0x58 0x20) plus the fixed value.
	maxClaimIDBstrBytes = 2 + sha256.Size
	// maxSignatureBstrOverhead is the uint16 length head (0x59 + two bytes)
	// required for any bstr above 255 bytes, i.e. a full-size signature child.
	maxSignatureBstrOverhead = 3

	// MaxArbitrationReceiptBytes is derived from the Receipt child limits:
	// [claim_id(34), amount(9), transaction_signature(3+256)] plus the array
	// head = 1 + 34 + 9 + 259 = 303. It is intentionally NOT an independent
	// quota; raising it silently or shrinking it below the child limits breaks
	// interoperability.
	MaxArbitrationReceiptBytes = 1 + maxClaimIDBstrBytes + maxDeterministicUint64Bytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// MaxArbitrationResponseBytes is derived from the four-element response
	// shape [4, 9, receipt_cbor, receipt_signature]: array head, version,
	// kind, the receipt wrapped in a uint16-headed bstr, and the receipt
	// signature = 1 + 1 + 1 + (3 + 303) + (3 + 256) = 568.
	MaxArbitrationResponseBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + MaxArbitrationReceiptBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// maxArbitrationRequestEnvelopeBytes is the exact deterministic-CBOR
	// overhead of the outer five-element request [4, 8, claim, sig, payloads]:
	// the array head (1), version (1), kind (1), and the maximum bstr heads of
	// the three children — Claim at MaxArbitrationClaimBytes needs a uint32
	// length head (5), a full Seller signature needs uint16 (3), and the
	// payload bundle at bitfs.MaxContentPayloadsCBORBytes needs uint32 (5).
	maxArbitrationRequestEnvelopeBytes = 16

	// MaxArbitrationRequestBytes is derived from the protocol child limits, so
	// a request carrying the legal maximum bundle (64 payloads of one
	// MasterSeed block each) always fits. It is intentionally NOT an
	// independent quota: raising it silently or shrinking it below the sum of
	// the child limits both break interoperability.
	MaxArbitrationRequestBytes = bitfs.MaxContentPayloadsCBORBytes + MaxArbitrationClaimBytes + MaxArbitrationSignatureBytes + maxArbitrationRequestEnvelopeBytes
)

var (
	arbitrationEnc cbor.EncMode
	arbitrationDec cbor.DecMode
)

func init() {
	var err error
	arbitrationEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	arbitrationDec, err = cbor.DecOptions{
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 64,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// ArbitrationClaim is the versionless, kindless inner Kind 8 evidence.
type ArbitrationClaim struct {
	PoolOutputSatoshis      uint64
	PoolOutputLockingScript []byte
	RefundTemplateRaw       []byte
	TermsCBOR               []byte
	BuyerSignature          []byte
}

// ArbitrationRequest is the exact five-element Kind 8 message. ClaimCBOR is
// the exact deterministic ArbitrationClaim child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationRequest struct {
	Version              uint64
	ClaimCBOR            []byte
	SellerClaimSignature []byte
	ContentPayloadsCBOR  []byte
}

// ArbitrationReceipt is the versionless, kindless inner Kind 9 document. It
// binds the exact Claim ID, the absolute arbiter fee paid by output[2], and
// the ForkID|All transaction signature over the independently rebuilt
// candidate. A successful receipt always carries a positive fee.
type ArbitrationReceipt struct {
	ClaimID                     []byte
	ArbiterAmountSat            uint64
	ArbiterTransactionSignature []byte
}

// ArbitrationResponse is the exact four-element Kind 9 message. ReceiptCBOR is
// the exact deterministic ArbitrationReceipt child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationResponse struct {
	Version                 uint64
	ReceiptCBOR             []byte
	ArbiterReceiptSignature []byte
}

type WorkflowConfig struct {
	PrivateKey *ec.PrivateKey
}

// Workflow is stateless apart from the arbiter private/public key. It has no
// persistence, network, node, or clock injection hooks.
type Workflow struct {
	privateKey *ec.PrivateKey
	publicKey  []byte
}

// PreparedPayment is an opaque result of PreparePayment. All exported access
// is through deep-copy getters so applications can persist evidence without
// obtaining mutable references to the signing state.
type PreparedPayment struct {
	request            *ArbitrationRequest
	claim              *ArbitrationClaim
	unsigned           *pool.UnsignedPayment
	payloads           [][]byte
	claimID            []byte
	authorizationHash  []byte
	arbiterAmountSat   uint64
	arbiterPubKey      []byte
	evidenceCommitment []byte
	deadlineUnix       int64
	preparedAt         time.Time
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.PrivateKey == nil {
		return nil, errors.New("arbitration workflow requires an arbiter private key")
	}
	return &Workflow{privateKey: config.PrivateKey, publicKey: config.PrivateKey.PubKey().Compressed()}, nil
}

// Request returns a deep copy of the exact request prepared for signing.
func (prepared *PreparedPayment) Request() *ArbitrationRequest {
	if prepared == nil {
		return nil
	}
	return cloneRequest(prepared.request)
}

// Claim returns a deep copy of the decoded Claim evidence.
func (prepared *PreparedPayment) Claim() *ArbitrationClaim {
	if prepared == nil {
		return nil
	}
	return cloneClaim(prepared.claim)
}

// RefundTemplateTxID returns the derived fee-pool correlation ID.
func (prepared *PreparedPayment) RefundTemplateTxID() []byte {
	if prepared == nil || prepared.unsigned == nil {
		return nil
	}
	return append([]byte(nil), prepared.unsigned.RefundTemplateTxID[:]...)
}

// ClaimID returns a deep copy of the SHA-256 commitment over
// deterministic-CBOR([4, 8, exact_claim_cbor]).
func (prepared *PreparedPayment) ClaimID() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.claimID...)
}

func (prepared *PreparedPayment) PaymentAuthorizationHash() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.authorizationHash...)
}

// ArbiterAmountSat returns the frozen absolute arbitration fee this prepared
// payment will assign to output[2]. It is always positive.
func (prepared *PreparedPayment) ArbiterAmountSat() uint64 {
	if prepared == nil {
		return 0
	}
	return prepared.arbiterAmountSat
}

func (prepared *PreparedPayment) ContentPayloadsCBOR() []byte {
	if prepared == nil || prepared.request == nil {
		return nil
	}
	return append([]byte(nil), prepared.request.ContentPayloadsCBOR...)
}

func (prepared *PreparedPayment) ContentPayloads() [][]byte {
	if prepared == nil {
		return nil
	}
	return cloneByteSlices(prepared.payloads)
}

func (prepared *PreparedPayment) UnsignedPayment() *pool.UnsignedPayment {
	if prepared == nil {
		return nil
	}
	return cloneUnsigned(prepared.unsigned)
}

func (prepared *PreparedPayment) DeadlineUnix() int64 {
	if prepared == nil {
		return 0
	}
	return prepared.deadlineUnix
}

func (prepared *PreparedPayment) PreparedAt() time.Time {
	if prepared == nil {
		return time.Time{}
	}
	return prepared.preparedAt
}

// PreparePayment verifies Claim, Buyer authorization, Seller claim signature,
// exact payload custody evidence, and the independently rebuilt candidate for
// the caller-decided positive arbitration fee. It never creates a transaction
// signature. The application must persist the exact request, the Claim ID,
// the fee, and the payload bundle before calling SignPreparedPayment.
func (workflow *Workflow) PreparePayment(ctx context.Context, request *ArbitrationRequest, blockHeight uint32, arbiterAmountSat uint64) (*PreparedPayment, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if arbiterAmountSat == 0 {
		return nil, fmt.Errorf("%w: successful arbitration requires a positive arbiter amount", pool.ErrInvalidEvidence)
	}
	request = cloneRequest(request)
	at := time.Now().UTC()
	claim, terms, payloads, unsigned, claimID, authHash, keys, err := validateRequestEvidence(request, arbiterAmountSat)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPubKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	if !at.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline has passed", pool.ErrInvalidEvidence)
	}
	if err := pool.CheckArbitrationRefundNotExpired(claim.RefundTemplateRaw, blockHeight); err != nil {
		return nil, fmt.Errorf("%w: refund template is no longer available for arbitration: %v", pool.ErrInvalidEvidence, err)
	}
	exactRequest, err := MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	return &PreparedPayment{
		request: request, claim: claim, unsigned: cloneUnsigned(unsigned), payloads: cloneByteSlices(payloads),
		claimID: claimID, authorizationHash: authHash, arbiterAmountSat: arbiterAmountSat,
		arbiterPubKey:      append([]byte(nil), keys.ArbiterPubKey...),
		evidenceCommitment: preparedEvidenceCommitment(exactRequest, claimID, arbiterAmountSat, unsigned),
		deadlineUnix:       terms.DeliveryDeadlineUnix, preparedAt: at,
	}, nil
}

// SignPreparedPayment performs the post-persistence signing step. It re-runs
// full evidence validation and candidate reconstruction from the frozen exact
// request and frozen fee, compares Claim ID, amount, roles, deadline, and the
// candidate against the persisted prepared state, then signs in the fixed
// order: transaction signature first, then Receipt encoding, then the Receipt
// message signature. Both signatures are self-verified before Kind 9 is
// returned.
func (workflow *Workflow) SignPreparedPayment(ctx context.Context, prepared *PreparedPayment) (*ArbitrationResponse, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if prepared == nil || prepared.request == nil || prepared.claim == nil || prepared.unsigned == nil || len(prepared.claimID) != sha256.Size || prepared.arbiterAmountSat == 0 {
		return nil, fmt.Errorf("%w: prepared payment is required", pool.ErrInvalidEvidence)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !time.Now().UTC().Before(time.Unix(prepared.deadlineUnix, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline passed before custody signing", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(workflow.publicKey, prepared.arbiterPubKey) {
		return nil, fmt.Errorf("%w: prepared payment belongs to another arbiter", pool.ErrInvalidEvidence)
	}
	// Everything below derives from the revalidated request bytes alone; the
	// cached Claim is never trusted for signing so tampering with any cached
	// structure cannot steer transaction construction.
	frozenFee := prepared.arbiterAmountSat
	freshClaim, _, _, rebuilt, freshClaimID, freshAuthHash, keys, err := validateRequestEvidence(cloneRequest(prepared.request), frozenFee)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPubKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(freshClaimID, prepared.claimID) || !bytes.Equal(freshAuthHash, prepared.authorizationHash) {
		return nil, fmt.Errorf("%w: prepared payment evidence changed", pool.ErrInvalidEvidence)
	}
	if rebuilt.ArbiterAmountSat != prepared.arbiterAmountSat || !equalUnsigned(rebuilt, prepared.unsigned) {
		return nil, fmt.Errorf("%w: prepared candidate changed", pool.ErrInvalidEvidence)
	}
	exactRequest, err := MarshalRequest(prepared.request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(preparedEvidenceCommitment(exactRequest, prepared.claimID, prepared.arbiterAmountSat, rebuilt), prepared.evidenceCommitment) {
		return nil, fmt.Errorf("%w: prepared evidence commitment changed", pool.ErrInvalidEvidence)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(freshClaim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	// 先生成并自验仲裁交易签名，再编码回执，最后生成并自验回执普通消息签名。
	arbiterTxSig, err := engine.SignArbitrationArbiterPayment(ctx, rebuilt, workflow.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration transaction: %w", err)
	}
	if err := engine.VerifyArbitrationArbiterPayment(rebuilt, arbiterTxSig); err != nil {
		return nil, fmt.Errorf("verify arbitration transaction signature: %w", err)
	}
	receipt := &ArbitrationReceipt{ClaimID: append([]byte(nil), prepared.claimID...), ArbiterAmountSat: frozenFee, ArbiterTransactionSignature: append([]byte(nil), arbiterTxSig...)}
	receiptCBOR, err := MarshalReceipt(receipt)
	if err != nil {
		return nil, err
	}
	receiptSigning, err := ArbiterReceiptSigningCBOR(receiptCBOR)
	if err != nil {
		return nil, err
	}
	receiptSig, err := bitfs.SignMessage(workflow.privateKey, receiptSigning)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration receipt: %w", err)
	}
	if err := bitfs.VerifySignature(workflow.publicKey, receiptSigning, receiptSig); err != nil {
		return nil, fmt.Errorf("verify arbitration receipt signature: %w", err)
	}
	response := &ArbitrationResponse{Version: MajorVersion, ReceiptCBOR: receiptCBOR, ArbiterReceiptSignature: receiptSig}
	if _, err := MarshalResponse(response); err != nil {
		return nil, err
	}
	return cloneResponse(response), nil
}

// validateRequestEvidence performs the complete pre-signature evidence chain:
// strict Kind 8 decoding, Claim and terms validation, role recovery, Buyer and
// Seller signature checks, per-payload hash verification, and independent
// candidate reconstruction with the explicit arbitration fee. The zero-fee
// rejection lives in the success builder, so no caller ever passes a
// placeholder amount.
func validateRequestEvidence(request *ArbitrationRequest, arbiterAmountSat uint64) (*ArbitrationClaim, *bitfs.ContentRequestTerms, [][]byte, *pool.UnsignedPayment, []byte, []byte, pool.MultisigPoolPublicKeys, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	claim, err := UnmarshalClaim(request.ClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	terms, err := bitfs.DecodeContentRequestTerms(claim.TermsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if err := bitfs.VerifySignature(keys.BuyerPubKey, claim.TermsCBOR, claim.BuyerSignature); err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: buyer authorization signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	sellerSigning, err := SellerClaimSigningCBOR(request.ClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if err := bitfs.VerifySignature(keys.SellerPubKey, sellerSigning, request.SellerClaimSignature); err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: seller Claim signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	payloads, err := bitfs.DecodeContentPayloads(request.ContentPayloadsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	hashes, err := bitfs.DecodeContentHashes(terms.ContentHashesCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if len(payloads) != len(hashes) {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload count does not match authorized hash count", pool.ErrInvalidEvidence)
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload #%d does not match authorized hash", pool.ErrInvalidEvidence, index+1)
		}
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, terms.PaymentSequence, terms.SellerAmountAfterSat, arbiterAmountSat)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	refundID := unsigned.RefundTemplateTxID
	if !bytes.Equal(refundID[:], terms.RefundTemplateTxID) {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: refund template transaction ID does not match Buyer terms", pool.ErrInvalidEvidence)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(claim.TermsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	claimID, err := ArbitrationClaimID(request.ClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	return claim, terms, payloads, unsigned, claimID, append([]byte(nil), authHash[:]...), keys, nil
}

// BuiltClaim is the shared, time-independent result of assembling the exact
// Kind 8 Claim evidence from a complete OpeningProof and the Buyer-signed 003.
// Seller arbitration (007) and buyer content retrieval (008) both consume this
// single builder so both roles always derive byte-identical ClaimCBOR and
// ClaimID from the same opening plus authorization.
type BuiltClaim struct {
	// Claim is the decoded, deep-copied Claim evidence behind ClaimCBOR.
	Claim *ArbitrationClaim
	// ClaimCBOR is the exact canonical five-element Claim child document.
	ClaimCBOR []byte
	// ClaimID is SHA-256(deterministic-CBOR([4, 8, exact_claim_cbor])).
	ClaimID []byte
	// Terms are the decoded 003 terms carried by the authorization.
	Terms *bitfs.ContentRequestTerms
}

// BuildClaimFromAuthorization derives the pool output facts from the supplied
// OpeningProof, verifies that the signed 003 belongs to that exact opening,
// assembles and canonically encodes the Claim, and computes its Claim ID. It
// clones every input, applies no clock or block-height gate, and produces no
// signature; deadline/refund gates remain with the calling workflows.
func BuildClaimFromAuthorization(opening *pool.OpeningProof, authorization *bitfs.SignedContentRequest) (*BuiltClaim, error) {
	opening = pool.CloneOpeningProof(opening)
	authorization = bitfs.CloneSignedContentRequest(authorization)
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	terms, err := bitfs.VerifySignedContentRequestForOpening(authorization, opening)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pool.ErrInvalidEvidence, err)
	}
	claim := &ArbitrationClaim{
		PoolOutputSatoshis:      details.PoolOutputSatoshis,
		PoolOutputLockingScript: details.PoolLockingScript,
		RefundTemplateRaw:       opening.RefundTx,
		TermsCBOR:               authorization.TermsCBOR,
		BuyerSignature:          authorization.BuyerSignature,
	}
	claimCBOR, err := MarshalClaim(claim)
	if err != nil {
		return nil, err
	}
	claimID, err := ArbitrationClaimID(claimCBOR)
	if err != nil {
		return nil, err
	}
	return &BuiltClaim{Claim: cloneClaim(claim), ClaimCBOR: claimCBOR, ClaimID: claimID, Terms: terms}, nil
}

func ValidateClaim(claim *ArbitrationClaim) error {
	if claim == nil || claim.PoolOutputSatoshis == 0 || len(claim.PoolOutputLockingScript) == 0 || len(claim.RefundTemplateRaw) == 0 || len(claim.TermsCBOR) == 0 || len(claim.BuyerSignature) == 0 {
		return fmt.Errorf("%w: arbitration Claim is incomplete", pool.ErrInvalidEvidence)
	}
	if len(claim.PoolOutputLockingScript) != 105 {
		return fmt.Errorf("%w: arbitration Claim pool locking script has invalid size", pool.ErrInvalidEvidence)
	}
	if len(claim.RefundTemplateRaw) > MaxArbitrationRefundTemplateBytes {
		return fmt.Errorf("%w: arbitration Claim RefundTx exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationRefundTemplateBytes)
	}
	if len(claim.TermsCBOR) > MaxArbitrationTermsBytes {
		return fmt.Errorf("%w: arbitration Claim TermsCBOR exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationTermsBytes)
	}
	if len(claim.BuyerSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration Claim Buyer signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	terms, err := bitfs.DecodeContentRequestTerms(claim.TermsCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	// 纯结构验证：不依赖任何成功仲裁费，因此不需要占位金额。
	if err := pool.ValidateArbitrationClaimStructure(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, terms.PaymentSequence, terms.SellerAmountAfterSat); err != nil {
		return err
	}
	if err := bitfs.VerifySignature(keys.BuyerPubKey, claim.TermsCBOR, claim.BuyerSignature); err != nil {
		return fmt.Errorf("%w: buyer authorization signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	return nil
}

func MarshalClaim(claim *ArbitrationClaim) ([]byte, error) {
	if err := ValidateClaim(claim); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{claim.PoolOutputSatoshis, bstr(claim.PoolOutputLockingScript), bstr(claim.RefundTemplateRaw), bstr(claim.TermsCBOR), bstr(claim.BuyerSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationClaimBytes, "arbitration Claim"); err != nil {
		return nil, err
	}
	return raw, nil
}

func UnmarshalClaim(data []byte) (*ArbitrationClaim, error) {
	if err := requireWireSize(data, MaxArbitrationClaimBytes, "arbitration Claim"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration Claim: %v", pool.ErrInvalidEvidence, err)
	}
	claim := new(ArbitrationClaim)
	if err := arbitrationDec.Unmarshal(values[0], &claim.PoolOutputSatoshis); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &claim.PoolOutputLockingScript); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &claim.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &claim.TermsCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &claim.BuyerSignature); err != nil {
		return nil, err
	}
	if err := ValidateClaim(claim); err != nil {
		return nil, err
	}
	canonical, err := MarshalClaim(claim)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration Claim is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneClaim(claim), nil
}

func ValidateRequest(request *ArbitrationRequest) error {
	if request == nil || request.Version != MajorVersion || len(request.ClaimCBOR) == 0 || len(request.SellerClaimSignature) == 0 || len(request.ContentPayloadsCBOR) == 0 {
		return fmt.Errorf("%w: arbitration request is incomplete", pool.ErrInvalidEvidence)
	}
	if len(request.ClaimCBOR) > MaxArbitrationClaimBytes {
		return fmt.Errorf("%w: arbitration request Claim exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationClaimBytes)
	}
	if len(request.SellerClaimSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration request Seller Claim signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	if len(request.ContentPayloadsCBOR) > bitfs.MaxContentPayloadsCBORBytes {
		return fmt.Errorf("%w: arbitration request payload bundle exceeds %d bytes", pool.ErrInvalidEvidence, bitfs.MaxContentPayloadsCBORBytes)
	}
	if _, err := UnmarshalClaim(request.ClaimCBOR); err != nil {
		return err
	}
	if _, err := bitfs.DecodeContentPayloads(request.ContentPayloadsCBOR); err != nil {
		return err
	}
	return nil
}

func MarshalRequest(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationRequest, bstr(request.ClaimCBOR), bstr(request.SellerClaimSignature), bstr(request.ContentPayloadsCBOR)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationRequestBytes, "arbitration request"); err != nil {
		return nil, err
	}
	return raw, nil
}

func UnmarshalRequest(data []byte) (*ArbitrationRequest, error) {
	if err := requireWireSize(data, MaxArbitrationRequestBytes, "arbitration request"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(ArbitrationRequest)
	var kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration request version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != kindArbitrationRequest {
		return nil, fmt.Errorf("%w: arbitration request kind must be 8", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.ClaimCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.SellerClaimSignature); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &request.ContentPayloadsCBOR); err != nil {
		return nil, err
	}
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	canonical, err := MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration request is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneRequest(request), nil
}

// ArbitrationClaimID returns SHA-256(deterministic-CBOR([4, 8, exact_claim_cbor])).
// It hashes the exact Seller Claim signing domain, never a decoded Go struct
// and never the complete Kind 8 envelope.
func ArbitrationClaimID(claimCBOR []byte) ([]byte, error) {
	domain, err := SellerClaimSigningCBOR(claimCBOR)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(domain)
	return append([]byte(nil), hash[:]...), nil
}

// ValidateReceipt validates a decoded arbitration receipt: a fixed 32-byte
// Claim ID, a positive arbiter amount, and a bounded transaction signature.
func ValidateReceipt(receipt *ArbitrationReceipt) error {
	if receipt == nil || len(receipt.ClaimID) != sha256.Size {
		return fmt.Errorf("%w: arbitration receipt Claim ID must be 32 bytes", pool.ErrInvalidEvidence)
	}
	if receipt.ArbiterAmountSat == 0 {
		return fmt.Errorf("%w: arbitration receipt arbiter amount must be positive", pool.ErrInvalidEvidence)
	}
	if len(receipt.ArbiterTransactionSignature) == 0 || len(receipt.ArbiterTransactionSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration receipt transaction signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	return nil
}

// MarshalReceipt encodes the receipt as the canonical three-element
// deterministic CBOR child document.
func MarshalReceipt(receipt *ArbitrationReceipt) ([]byte, error) {
	if err := ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{bstr(receipt.ClaimID), receipt.ArbiterAmountSat, bstr(receipt.ArbiterTransactionSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationReceiptBytes, "arbitration receipt"); err != nil {
		return nil, err
	}
	return raw, nil
}

// UnmarshalReceipt strictly decodes receipt bytes: size limit first, strict
// decode, validation, then deterministic re-encode byte equality.
func UnmarshalReceipt(data []byte) (*ArbitrationReceipt, error) {
	if err := requireWireSize(data, MaxArbitrationReceiptBytes, "arbitration receipt"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration receipt: %v", pool.ErrInvalidEvidence, err)
	}
	receipt := new(ArbitrationReceipt)
	if err := arbitrationDec.Unmarshal(values[0], &receipt.ClaimID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &receipt.ArbiterAmountSat); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &receipt.ArbiterTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	canonical, err := MarshalReceipt(receipt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration receipt is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneReceipt(receipt), nil
}

func ValidateResponse(response *ArbitrationResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.ReceiptCBOR) == 0 || len(response.ArbiterReceiptSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	if len(response.ReceiptCBOR) > MaxArbitrationReceiptBytes {
		return fmt.Errorf("%w: arbitration response receipt exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationReceiptBytes)
	}
	if len(response.ArbiterReceiptSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration response signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	if _, err := UnmarshalReceipt(response.ReceiptCBOR); err != nil {
		return err
	}
	return nil
}

func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationResponse, bstr(response.ReceiptCBOR), bstr(response.ArbiterReceiptSignature)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationResponseBytes, "arbitration response"); err != nil {
		return nil, err
	}
	return raw, nil
}

func UnmarshalResponse(data []byte) (*ArbitrationResponse, error) {
	if err := requireWireSize(data, MaxArbitrationResponseBytes, "arbitration response"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration response: %v", pool.ErrInvalidEvidence, err)
	}
	response := new(ArbitrationResponse)
	var kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration response version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != kindArbitrationResponse {
		return nil, fmt.Errorf("%w: arbitration response kind must be 9", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.ReceiptCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbiterReceiptSignature); err != nil {
		return nil, err
	}
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	canonical, err := MarshalResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration response is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneResponse(response), nil
}

// SellerClaimSigningCBOR returns the exact [4,8,claim_cbor] message domain.
func SellerClaimSigningCBOR(claimCBOR []byte) ([]byte, error) {
	if _, err := UnmarshalClaim(claimCBOR); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationRequest, bstr(claimCBOR)})
}

// ArbiterReceiptSigningCBOR returns the exact [4,9,receipt_cbor] message domain.
func ArbiterReceiptSigningCBOR(receiptCBOR []byte) ([]byte, error) {
	if _, err := UnmarshalReceipt(receiptCBOR); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationResponse, bstr(receiptCBOR)})
}

// preparedEvidenceCommitment is a private anti-tamper binding only. It ties
// the exact canonical Kind 8 bytes, the Claim ID, the frozen arbitration fee,
// and the rebuilt candidate raw together so any mutation of persisted custody
// state between PreparePayment and SignPreparedPayment is detected. It is not
// a second wire truth and is never serialized into any message.
func preparedEvidenceCommitment(exactRequestRaw, claimID []byte, arbiterAmountSat uint64, unsigned *pool.UnsignedPayment) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("bitfs.v4.arbitration.prepared-payment\x00"))
	writeCommitmentPart(hash, exactRequestRaw)
	writeCommitmentPart(hash, claimID)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], arbiterAmountSat)
	_, _ = hash.Write(number[:])
	writeCommitmentPart(hash, unsigned.RawTx)
	return hash.Sum(nil)
}

func writeCommitmentPart(hash hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

func cloneRequest(request *ArbitrationRequest) *ArbitrationRequest {
	if request == nil {
		return nil
	}
	return &ArbitrationRequest{Version: request.Version, ClaimCBOR: append([]byte(nil), request.ClaimCBOR...), SellerClaimSignature: append([]byte(nil), request.SellerClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), request.ContentPayloadsCBOR...)}
}

func cloneClaim(claim *ArbitrationClaim) *ArbitrationClaim {
	if claim == nil {
		return nil
	}
	return &ArbitrationClaim{PoolOutputSatoshis: claim.PoolOutputSatoshis, PoolOutputLockingScript: append([]byte(nil), claim.PoolOutputLockingScript...), RefundTemplateRaw: append([]byte(nil), claim.RefundTemplateRaw...), TermsCBOR: append([]byte(nil), claim.TermsCBOR...), BuyerSignature: append([]byte(nil), claim.BuyerSignature...)}
}

func cloneReceipt(receipt *ArbitrationReceipt) *ArbitrationReceipt {
	if receipt == nil {
		return nil
	}
	return &ArbitrationReceipt{ClaimID: append([]byte(nil), receipt.ClaimID...), ArbiterAmountSat: receipt.ArbiterAmountSat, ArbiterTransactionSignature: append([]byte(nil), receipt.ArbiterTransactionSignature...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{Version: response.Version, ReceiptCBOR: append([]byte(nil), response.ReceiptCBOR...), ArbiterReceiptSignature: append([]byte(nil), response.ArbiterReceiptSignature...)}
}

func cloneUnsigned(unsigned *pool.UnsignedPayment) *pool.UnsignedPayment {
	if unsigned == nil {
		return nil
	}
	copy := *unsigned
	copy.RawTx = append([]byte(nil), unsigned.RawTx...)
	copy.PoolLockingScript = append([]byte(nil), unsigned.PoolLockingScript...)
	return &copy
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

func equalUnsigned(left, right *pool.UnsignedPayment) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.RefundTemplateTxID == right.RefundTemplateTxID && bytes.Equal(left.RawTx, right.RawTx) && left.PaymentSequence == right.PaymentSequence && left.BuyerAmountSat == right.BuyerAmountSat && left.SellerAmountSat == right.SellerAmountSat && left.ArbiterAmountSat == right.ArbiterAmountSat && left.PoolOutputSatoshis == right.PoolOutputSatoshis && bytes.Equal(left.PoolLockingScript, right.PoolLockingScript)
}

func decodeArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := arbitrationDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func requireWireSize(data []byte, limit int, label string) error {
	if len(data) == 0 || len(data) > limit {
		return fmt.Errorf("%w: %s exceeds %d bytes", pool.ErrInvalidEvidence, label, limit)
	}
	return nil
}

func bstr(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}
