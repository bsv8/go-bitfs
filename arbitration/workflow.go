// Package arbitration implements the Kind 8/9 custody and independent
// transaction-reconstruction workflow. Kind 9 is a hard-switched four-element
// receipt response: the arbiter is paid a positive, explicitly decided fee and
// the receipt binds the Claim ID, that fee, and the arbitration transaction
// signature together under one ordinary message signature. Both ordinary
// message signatures go through the unified protocol.SignWireDocument helper,
// and arbitration_claim_id is SHA-256 over the exact claim document itself.
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
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Kind 8/9 的统一 wire Kind 值；版本只使用 protocol.WireVersion。
const (
	wireKindArbitrationRequest  uint64 = 8
	wireKindArbitrationResponse uint64 = 9

	// These are protocol limits, applied before CBOR decoding. They bound both
	// the outer messages and the large bstr children that a decoder would
	// otherwise allocate before semantic validation. Applications may impose
	// smaller transport limits, but must not silently raise these limits.
	MaxArbitrationSignatureBytes      = 256
	MaxArbitrationRefundTemplateBytes = 16 * 1024
	MaxArbitrationAuthorizationBytes  = 16 * 1024
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
	// shape [1, 9, receipt_cbor, receipt_signature]: array head, version,
	// kind, the receipt wrapped in a uint16-headed bstr, and the receipt
	// signature = 1 + 1 + 1 + (3 + 303) + (3 + 256) = 568.
	MaxArbitrationResponseBytes = 1 + 1 + 1 + maxSignatureBstrOverhead + MaxArbitrationReceiptBytes + maxSignatureBstrOverhead + MaxArbitrationSignatureBytes

	// maxArbitrationRequestEnvelopeBytes is the exact deterministic-CBOR
	// overhead of the outer five-element request [1, 8, claim, sig, payloads]:
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

// ArbitrationClaim is the versionless, kindless inner Kind 8 authentication
// document. Its exact bytes are both the business truth and the source of the
// Claim ID: arbitration_claim_id = SHA-256(arbitration_claim_cbor).
type ArbitrationClaim struct {
	// PoolOutputSatoshis 是被托管资金池输出的聪数（uint64）；仲裁 candidate
	// 的输入金额必须与它一致。
	PoolOutputSatoshis uint64
	// PoolOutputLockingScript 是角色顺序固定 [Buyer, Seller, Arbiter] 的
	// 2-of-3 压缩公钥锁定脚本（恰好 105 字节）；三方公钥由它恢复。
	PoolOutputLockingScript []byte
	// RefundTemplateRaw 是规范未签名退款模板交易的原始字节；到期后买方凭它
	// 广播退款，仲裁方用它派生 refund_template_txid 与保留矿工费。
	RefundTemplateRaw []byte
	// PaymentAuthorizationCBOR 是买方签名的 exact Kind 5 付款授权子文档；
	// 目标序号与绝对卖方金额由此提供，绝不解码重编码。
	PaymentAuthorizationCBOR []byte
	// BuyerPaymentAuthorizationSignature 是买方对 WireSignatureInput(1, 5,
	// payment_authorization_cbor) 的统一消息签名。
	BuyerPaymentAuthorizationSignature []byte
}

// ArbitrationRequest is the exact five-element Kind 8 message. ArbitrationClaimCBOR is
// the exact deterministic ArbitrationClaim child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationRequest struct {
	// ArbitrationClaimCBOR 是 exact 确定性 Claim 子文档字节；wire 不解码重编码，
	// arbitration_claim_id = SHA-256(该字段)。
	ArbitrationClaimCBOR []byte
	// SellerArbitrationClaimSignature 是卖方对 WireSignatureInput(1, 8,
	// arbitration_claim_cbor) 的统一消息签名；payload 不直接入签。
	SellerArbitrationClaimSignature []byte
	// ContentPayloadsCBOR 是确定性 CBOR payload 批次（attachment）：顺序与
	// 授权哈希一一对应，经买方已签 content_hashes_cbor 间接绑定。
	ContentPayloadsCBOR []byte
}

// ArbitrationReceipt is the versionless, kindless inner Kind 9 document. It
// binds the exact Claim ID, the absolute arbiter fee paid by output[2], and
// the ForkID|All transaction signature over the independently rebuilt
// candidate. A successful receipt always carries a positive fee.
type ArbitrationReceipt struct {
	// ArbitrationClaimID 路由本回执对应的托管记录（SHA-256(exact claim cbor)）；
	// 必须与验证时重算的 Claim ID 一致。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// ArbiterAmountSatoshis 是分配给 output[2] 的冻结绝对仲裁费（单位
	// satoshi）；成功回执恒为正数。
	ArbiterAmountSatoshis uint64
	// ArbiterPaymentTransactionSignature 是仲裁方对独立重建付费 candidate 的
	// ForkID|All 原生交易签名；不能替代回执普通消息签名。
	ArbiterPaymentTransactionSignature []byte
}

// ArbitrationResponse is the exact four-element Kind 9 message. ArbitrationReceiptCBOR is
// the exact deterministic ArbitrationReceipt child document; it is not decoded
// and re-encoded on the wire.
type ArbitrationResponse struct {
	// ArbitrationReceiptCBOR 是 exact 确定性回执子文档字节；wire 不解码重编码。
	ArbitrationReceiptCBOR []byte
	// ArbiterArbitrationReceiptSignature 是仲裁方对 WireSignatureInput(1, 9,
	// arbitration_receipt_cbor) 的统一消息签名，把 Claim ID、费用和交易签名绑定在一起。
	ArbiterArbitrationReceiptSignature []byte
}

type WorkflowConfig struct {
	// PrivateKey 是仲裁方的官方 BSV 私钥；绝不进入任何 wire 报文、本地结果或日志。
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
	request                *ArbitrationRequest
	claim                  *ArbitrationClaim
	unsigned               *pool.UnsignedPayment
	payloads               [][]byte
	arbitrationClaimID     protocol.ArbitrationClaimID
	paymentAuthorizationID protocol.PaymentAuthorizationID
	arbiterAmountSatoshis  uint64
	arbiterPublicKey       []byte
	evidenceCommitment     []byte
	deadlineUnixSeconds    int64
	preparedAt             time.Time
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

// ArbitrationClaimID returns SHA-256(exact_claim_cbor), the typed Claim
// identity inside the Kind 8 document namespace.
func (prepared *PreparedPayment) ArbitrationClaimID() protocol.ArbitrationClaimID {
	if prepared == nil {
		return protocol.ArbitrationClaimID{}
	}
	return prepared.arbitrationClaimID
}

func (prepared *PreparedPayment) PaymentAuthorizationID() protocol.PaymentAuthorizationID {
	if prepared == nil {
		return protocol.PaymentAuthorizationID{}
	}
	return prepared.paymentAuthorizationID
}

// ArbiterAmountSatoshis returns the frozen absolute arbitration fee this
// prepared payment will assign to output[2]. It is always positive.
func (prepared *PreparedPayment) ArbiterAmountSatoshis() uint64 {
	if prepared == nil {
		return 0
	}
	return prepared.arbiterAmountSatoshis
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

func (prepared *PreparedPayment) DeadlineUnixSeconds() int64 {
	if prepared == nil {
		return 0
	}
	return prepared.deadlineUnixSeconds
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
func (workflow *Workflow) PreparePayment(ctx context.Context, request *ArbitrationRequest, blockHeight uint32, arbiterAmountSatoshis uint64) (*PreparedPayment, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if arbiterAmountSatoshis == 0 {
		return nil, fmt.Errorf("%w: successful arbitration requires a positive arbiter amount", pool.ErrInvalidEvidence)
	}
	request = cloneRequest(request)
	at := time.Now().UTC()
	claim, authorization, payloads, unsigned, claimID, authID, keys, err := validateRequestEvidence(request, arbiterAmountSatoshis)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	if !at.Before(time.Unix(authorization.DeliveryDeadlineUnixSeconds, 0)) {
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
		arbitrationClaimID: claimID, paymentAuthorizationID: authID, arbiterAmountSatoshis: arbiterAmountSatoshis,
		arbiterPublicKey:    append([]byte(nil), keys.ArbiterPublicKey...),
		evidenceCommitment:  preparedEvidenceCommitment(exactRequest, claimID[:], arbiterAmountSatoshis, unsigned),
		deadlineUnixSeconds: authorization.DeliveryDeadlineUnixSeconds, preparedAt: at,
	}, nil
}

// SignPreparedPayment performs the post-persistence signing step. It re-runs
// full evidence validation and candidate reconstruction from the frozen exact
// request and frozen fee, compares Claim ID, amount, roles, deadline, and the
// candidate against the persisted prepared state, then signs in the fixed
// order: transaction signature first, then Receipt encoding, then the unified
// SignWireDocument(1, 9, ...) receipt signature. Both signatures are
// self-verified before Kind 9 is returned.
func (workflow *Workflow) SignPreparedPayment(ctx context.Context, prepared *PreparedPayment) (*ArbitrationResponse, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if prepared == nil || prepared.request == nil || prepared.claim == nil || prepared.unsigned == nil || len(prepared.arbitrationClaimID) != sha256.Size || prepared.arbiterAmountSatoshis == 0 {
		return nil, fmt.Errorf("%w: prepared payment is required", pool.ErrInvalidEvidence)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if !time.Now().UTC().Before(time.Unix(prepared.deadlineUnixSeconds, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline passed before custody signing", pool.ErrInvalidEvidence)
	}
	if !bytes.Equal(workflow.publicKey, prepared.arbiterPublicKey) {
		return nil, fmt.Errorf("%w: prepared payment belongs to another arbiter", pool.ErrInvalidEvidence)
	}
	// Everything below derives from the revalidated request bytes alone; the
	// cached Claim is never trusted for signing so tampering with any cached
	// structure cannot steer transaction construction.
	frozenFeeSatoshis := prepared.arbiterAmountSatoshis
	freshClaim, _, _, rebuilt, freshClaimID, freshAuthID, keys, err := validateRequestEvidence(cloneRequest(prepared.request), frozenFeeSatoshis)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPublicKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	if freshClaimID != prepared.arbitrationClaimID || freshAuthID != prepared.paymentAuthorizationID {
		return nil, fmt.Errorf("%w: prepared payment evidence changed", pool.ErrInvalidEvidence)
	}
	if rebuilt.ArbiterAmountSatoshis != prepared.arbiterAmountSatoshis || !equalUnsigned(rebuilt, prepared.unsigned) {
		return nil, fmt.Errorf("%w: prepared candidate changed", pool.ErrInvalidEvidence)
	}
	exactRequest, err := MarshalRequest(prepared.request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(preparedEvidenceCommitment(exactRequest, prepared.arbitrationClaimID[:], prepared.arbiterAmountSatoshis, rebuilt), prepared.evidenceCommitment) {
		return nil, fmt.Errorf("%w: prepared evidence commitment changed", pool.ErrInvalidEvidence)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(freshClaim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	// 先生成并自验仲裁交易签名，再编码回执，最后生成并自验回执统一消息签名。
	arbiterTransactionSignature, err := engine.SignArbitrationArbiterPayment(ctx, rebuilt, workflow.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration transaction: %w", err)
	}
	if err := engine.VerifyArbitrationArbiterPayment(rebuilt, arbiterTransactionSignature); err != nil {
		return nil, fmt.Errorf("verify arbitration transaction signature: %w", err)
	}
	receipt := &ArbitrationReceipt{
		ArbitrationClaimID:                 prepared.arbitrationClaimID,
		ArbiterAmountSatoshis:              frozenFeeSatoshis,
		ArbiterPaymentTransactionSignature: append([]byte(nil), arbiterTransactionSignature...),
	}
	receiptCBOR, err := MarshalReceipt(receipt)
	if err != nil {
		return nil, err
	}
	receiptSignature, err := protocol.SignWireDocument(workflow.privateKey, protocol.WireVersion, wireKindArbitrationResponse, receiptCBOR)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration receipt: %w", err)
	}
	if err := protocol.VerifyWireDocument(workflow.publicKey, protocol.WireVersion, wireKindArbitrationResponse, receiptCBOR, receiptSignature); err != nil {
		return nil, fmt.Errorf("verify arbitration receipt signature: %w", err)
	}
	response := &ArbitrationResponse{ArbitrationReceiptCBOR: receiptCBOR, ArbiterArbitrationReceiptSignature: receiptSignature}
	if _, err := MarshalResponse(response); err != nil {
		return nil, err
	}
	return cloneResponse(response), nil
}

// validateRequestEvidence performs the complete pre-signature evidence chain:
// strict Kind 8 decoding, Claim and authorization validation, role recovery,
// Buyer and Seller signature checks, per-payload hash verification, and
// independent candidate reconstruction with the explicit arbitration fee. The
// zero-fee rejection lives in the success builder, so no caller ever passes a
// placeholder amount.
func validateRequestEvidence(request *ArbitrationRequest, arbiterAmountSatoshis uint64) (*ArbitrationClaim, *bitfs.PaymentAuthorization, [][]byte, *pool.UnsignedPayment, protocol.ArbitrationClaimID, protocol.PaymentAuthorizationID, pool.MultisigPoolPublicKeys, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	claim, err := UnmarshalClaim(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	authorization, err := bitfs.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: buyer payment authorization signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	if err := protocol.VerifyWireDocument(keys.SellerPublicKey, protocol.WireVersion, wireKindArbitrationRequest, request.ArbitrationClaimCBOR, request.SellerArbitrationClaimSignature); err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: seller Claim signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	payloads, err := bitfs.DecodeContentPayloads(request.ContentPayloadsCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	hashes, err := bitfs.DecodeContentHashes(authorization.ContentHashesCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	if len(payloads) != len(hashes) {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload count does not match authorized hash count", pool.ErrInvalidEvidence)
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload #%d does not match authorized hash", pool.ErrInvalidEvidence, index+1)
		}
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis, arbiterAmountSatoshis)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	refundID := unsigned.RefundTemplateTxID
	if !bytes.Equal(refundID[:], authorization.RefundTemplateTxID) {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: refund template transaction ID does not match Buyer terms", pool.ErrInvalidEvidence)
	}
	authID, err := bitfs.PaymentAuthorizationID(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	claimID, err := ArbitrationClaimID(request.ArbitrationClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, protocol.ArbitrationClaimID{}, protocol.PaymentAuthorizationID{}, pool.MultisigPoolPublicKeys{}, err
	}
	return claim, authorization, payloads, unsigned, claimID, authID, keys, nil
}

// BuiltClaim is the shared, time-independent result of assembling the exact
// Kind 8 Claim evidence from a complete OpeningProof and the Buyer-signed
// payment authorization. Seller arbitration (007) and buyer content retrieval
// (008) both consume this single builder so both roles always derive
// byte-identical ArbitrationClaimCBOR and ArbitrationClaimID from the same
// opening plus authorization.
type BuiltClaim struct {
	// Claim 是 ArbitrationClaimCBOR 背后的已解码、深拷贝 Claim 证据。
	Claim *ArbitrationClaim
	// ArbitrationClaimCBOR 是精确规范的五元 Claim 子文档字节。
	ArbitrationClaimCBOR []byte
	// ArbitrationClaimID = SHA-256(exact_claim_cbor)，Seller 与 Buyer 独立重建必得同一值。
	ArbitrationClaimID protocol.ArbitrationClaimID
	// Authorization 是 Claim 携带的已解码 Kind 5 付款授权（含目标序号与绝对卖方金额）。
	Authorization *bitfs.PaymentAuthorization
}

// BuildClaimFromAuthorization derives the pool output facts from the supplied
// OpeningProof, verifies that the signed payment authorization belongs to that
// exact opening, assembles and canonically encodes the Claim, and computes its
// Claim ID. It clones every input, applies no clock or block-height gate, and
// produces no signature; deadline/refund gates remain with the calling
// workflows.
func BuildClaimFromAuthorization(opening *pool.OpeningProof, signedAuthorization *bitfs.SignedContentRequest) (*BuiltClaim, error) {
	opening = pool.CloneOpeningProof(opening)
	signedAuthorization = bitfs.CloneSignedContentRequest(signedAuthorization)
	details, err := pool.DeriveOpeningDetails(opening)
	if err != nil {
		return nil, err
	}
	authorization, err := bitfs.VerifySignedContentRequestForOpening(signedAuthorization, opening)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pool.ErrInvalidEvidence, err)
	}
	claim := &ArbitrationClaim{
		PoolOutputSatoshis:                 details.PoolOutputSatoshis,
		PoolOutputLockingScript:            details.PoolLockingScript,
		RefundTemplateRaw:                  opening.RefundTemplateRaw,
		PaymentAuthorizationCBOR:           signedAuthorization.PaymentAuthorizationCBOR,
		BuyerPaymentAuthorizationSignature: signedAuthorization.BuyerPaymentAuthorizationSignature,
	}
	claimCBOR, err := MarshalClaim(claim)
	if err != nil {
		return nil, err
	}
	claimID, err := ArbitrationClaimID(claimCBOR)
	if err != nil {
		return nil, err
	}
	return &BuiltClaim{Claim: cloneClaim(claim), ArbitrationClaimCBOR: claimCBOR, ArbitrationClaimID: claimID, Authorization: authorization}, nil
}

func ValidateClaim(claim *ArbitrationClaim) error {
	if claim == nil || claim.PoolOutputSatoshis == 0 || len(claim.PoolOutputLockingScript) == 0 || len(claim.RefundTemplateRaw) == 0 || len(claim.PaymentAuthorizationCBOR) == 0 || len(claim.BuyerPaymentAuthorizationSignature) == 0 {
		return fmt.Errorf("%w: arbitration Claim is incomplete", pool.ErrInvalidEvidence)
	}
	if len(claim.PoolOutputLockingScript) != 105 {
		return fmt.Errorf("%w: arbitration Claim pool locking script has invalid size", pool.ErrInvalidEvidence)
	}
	if len(claim.RefundTemplateRaw) > MaxArbitrationRefundTemplateBytes {
		return fmt.Errorf("%w: arbitration Claim refund template exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationRefundTemplateBytes)
	}
	if len(claim.PaymentAuthorizationCBOR) > MaxArbitrationAuthorizationBytes {
		return fmt.Errorf("%w: arbitration Claim payment authorization exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationAuthorizationBytes)
	}
	if len(claim.BuyerPaymentAuthorizationSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration Claim Buyer signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	authorization, err := bitfs.DecodePaymentAuthorization(claim.PaymentAuthorizationCBOR)
	if err != nil {
		return err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return err
	}
	// 纯结构验证：不依赖任何成功仲裁费，因此不需要占位金额。
	if err := pool.ValidateArbitrationClaimStructure(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, authorization.PaymentSequence, authorization.SellerAmountAfterSatoshis); err != nil {
		return err
	}
	if err := protocol.VerifyWireDocument(keys.BuyerPublicKey, protocol.WireVersion, 5, claim.PaymentAuthorizationCBOR, claim.BuyerPaymentAuthorizationSignature); err != nil {
		return fmt.Errorf("%w: buyer payment authorization signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	return nil
}

func MarshalClaim(claim *ArbitrationClaim) ([]byte, error) {
	if err := ValidateClaim(claim); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{claim.PoolOutputSatoshis, bstr(claim.PoolOutputLockingScript), bstr(claim.RefundTemplateRaw), bstr(claim.PaymentAuthorizationCBOR), bstr(claim.BuyerPaymentAuthorizationSignature)})
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
	if err := arbitrationDec.Unmarshal(values[3], &claim.PaymentAuthorizationCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &claim.BuyerPaymentAuthorizationSignature); err != nil {
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
	if request == nil || len(request.ArbitrationClaimCBOR) == 0 || len(request.SellerArbitrationClaimSignature) == 0 || len(request.ContentPayloadsCBOR) == 0 {
		return fmt.Errorf("%w: arbitration request is incomplete", pool.ErrInvalidEvidence)
	}
	if len(request.ArbitrationClaimCBOR) > MaxArbitrationClaimBytes {
		return fmt.Errorf("%w: arbitration request Claim exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationClaimBytes)
	}
	if len(request.SellerArbitrationClaimSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration request Seller Claim signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	if len(request.ContentPayloadsCBOR) > bitfs.MaxContentPayloadsCBORBytes {
		return fmt.Errorf("%w: arbitration request payload bundle exceeds %d bytes", pool.ErrInvalidEvidence, bitfs.MaxContentPayloadsCBORBytes)
	}
	if _, err := UnmarshalClaim(request.ArbitrationClaimCBOR); err != nil {
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
	raw, err := arbitrationEnc.Marshal([]any{protocol.WireVersion, wireKindArbitrationRequest, bstr(request.ArbitrationClaimCBOR), bstr(request.SellerArbitrationClaimSignature), bstr(request.ContentPayloadsCBOR)})
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
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration request wire version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != wireKindArbitrationRequest {
		return nil, fmt.Errorf("%w: arbitration request kind must be 8", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.ArbitrationClaimCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.SellerArbitrationClaimSignature); err != nil {
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

// ArbitrationClaimID returns SHA-256(exact_claim_cbor) as the typed Kind 8
// document identity. The Claim document is the sole ID source; no
// signing-domain wrapper participates in the identity.
func ArbitrationClaimID(claimCBOR []byte) (protocol.ArbitrationClaimID, error) {
	if _, err := UnmarshalClaim(claimCBOR); err != nil {
		return protocol.ArbitrationClaimID{}, err
	}
	digest := sha256.Sum256(claimCBOR)
	return protocol.ArbitrationClaimID(digest), nil
}

// ValidateReceipt validates a decoded arbitration receipt: a fixed 32-byte
// Claim ID, a positive arbiter amount, and a bounded transaction signature.
func ValidateReceipt(receipt *ArbitrationReceipt) error {
	if receipt == nil || len(receipt.ArbitrationClaimID) != sha256.Size {
		return fmt.Errorf("%w: arbitration receipt Claim ID must be 32 bytes", pool.ErrInvalidEvidence)
	}
	if receipt.ArbiterAmountSatoshis == 0 {
		return fmt.Errorf("%w: arbitration receipt arbiter amount must be positive", pool.ErrInvalidEvidence)
	}
	if len(receipt.ArbiterPaymentTransactionSignature) == 0 || len(receipt.ArbiterPaymentTransactionSignature) > MaxArbitrationSignatureBytes {
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
	raw, err := arbitrationEnc.Marshal([]any{bstr(receipt.ArbitrationClaimID[:]), receipt.ArbiterAmountSatoshis, bstr(receipt.ArbiterPaymentTransactionSignature)})
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
	if err := arbitrationDec.Unmarshal(values[0], &receipt.ArbitrationClaimID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &receipt.ArbiterAmountSatoshis); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &receipt.ArbiterPaymentTransactionSignature); err != nil {
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
	if response == nil || len(response.ArbitrationReceiptCBOR) == 0 || len(response.ArbiterArbitrationReceiptSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	if len(response.ArbitrationReceiptCBOR) > MaxArbitrationReceiptBytes {
		return fmt.Errorf("%w: arbitration response receipt exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationReceiptBytes)
	}
	if len(response.ArbiterArbitrationReceiptSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration response signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	if _, err := UnmarshalReceipt(response.ArbitrationReceiptCBOR); err != nil {
		return err
	}
	return nil
}

func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{protocol.WireVersion, wireKindArbitrationResponse, bstr(response.ArbitrationReceiptCBOR), bstr(response.ArbiterArbitrationReceiptSignature)})
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
	var version, kind uint64
	if err := arbitrationDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration response wire version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &kind); err != nil || kind != wireKindArbitrationResponse {
		return nil, fmt.Errorf("%w: arbitration response kind must be 9", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.ArbitrationReceiptCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbiterArbitrationReceiptSignature); err != nil {
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

// preparedEvidenceCommitment is a private anti-tamper binding only. It ties
// the exact canonical Kind 8 bytes, the Claim ID, the frozen arbitration fee,
// and the rebuilt candidate raw together so any mutation of persisted custody
// state between PreparePayment and SignPreparedPayment is detected. It is not
// a second wire truth and is never serialized into any message.
func preparedEvidenceCommitment(exactRequestRaw, claimID []byte, arbiterAmountSatoshis uint64, unsigned *pool.UnsignedPayment) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("bitfs.v1.arbitration.prepared-payment\x00"))
	writeCommitmentPart(hash, exactRequestRaw)
	writeCommitmentPart(hash, claimID)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], arbiterAmountSatoshis)
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
	return &ArbitrationRequest{ArbitrationClaimCBOR: append([]byte(nil), request.ArbitrationClaimCBOR...), SellerArbitrationClaimSignature: append([]byte(nil), request.SellerArbitrationClaimSignature...), ContentPayloadsCBOR: append([]byte(nil), request.ContentPayloadsCBOR...)}
}

func cloneClaim(claim *ArbitrationClaim) *ArbitrationClaim {
	if claim == nil {
		return nil
	}
	return &ArbitrationClaim{PoolOutputSatoshis: claim.PoolOutputSatoshis, PoolOutputLockingScript: append([]byte(nil), claim.PoolOutputLockingScript...), RefundTemplateRaw: append([]byte(nil), claim.RefundTemplateRaw...), PaymentAuthorizationCBOR: append([]byte(nil), claim.PaymentAuthorizationCBOR...), BuyerPaymentAuthorizationSignature: append([]byte(nil), claim.BuyerPaymentAuthorizationSignature...)}
}

func cloneReceipt(receipt *ArbitrationReceipt) *ArbitrationReceipt {
	if receipt == nil {
		return nil
	}
	return &ArbitrationReceipt{ArbitrationClaimID: receipt.ArbitrationClaimID, ArbiterAmountSatoshis: receipt.ArbiterAmountSatoshis, ArbiterPaymentTransactionSignature: append([]byte(nil), receipt.ArbiterPaymentTransactionSignature...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{ArbitrationReceiptCBOR: append([]byte(nil), response.ArbitrationReceiptCBOR...), ArbiterArbitrationReceiptSignature: append([]byte(nil), response.ArbiterArbitrationReceiptSignature...)}
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
	return left.RefundTemplateTxID == right.RefundTemplateTxID && bytes.Equal(left.RawTx, right.RawTx) && left.PaymentSequence == right.PaymentSequence && left.BuyerAmountSatoshis == right.BuyerAmountSatoshis && left.SellerAmountSatoshis == right.SellerAmountSatoshis && left.ArbiterAmountSatoshis == right.ArbiterAmountSatoshis && left.PoolOutputSatoshis == right.PoolOutputSatoshis && bytes.Equal(left.PoolLockingScript, right.PoolLockingScript)
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
