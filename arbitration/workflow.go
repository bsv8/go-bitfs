// Package arbitration implements the v4 Kind 8/9 custody and independent
// transaction-reconstruction workflow.
package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	MaxArbitrationResultBytes         = 256
	MaxArbitrationResponseBytes       = 16 * 1024

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

// ArbitrationResult is the versionless, kindless inner Kind 9 result.
type ArbitrationResult struct {
	RequestCommitment   []byte
	ContentPayloadsHash []byte
	UnsignedStateTxHash []byte
}

// ArbitrationResponse is the exact five-element Kind 9 message.
type ArbitrationResponse struct {
	Version                     uint64
	ResultCBOR                  []byte
	ArbiterResultSignature      []byte
	ArbiterTransactionSignature []byte
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
	request           *ArbitrationRequest
	claim             *ArbitrationClaim
	unsigned          *pool.UnsignedPayment
	payloads          [][]byte
	requestCommitment []byte
	authorizationHash []byte
	payloadsHash      []byte
	unsignedTxHash    []byte
	arbiterPubKey     []byte
	deadlineUnix      int64
	preparedAt        time.Time
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

func (prepared *PreparedPayment) RequestCommitment() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.requestCommitment...)
}

func (prepared *PreparedPayment) PaymentAuthorizationHash() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.authorizationHash...)
}

func (prepared *PreparedPayment) ContentPayloadsHash() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.payloadsHash...)
}

func (prepared *PreparedPayment) UnsignedStateTxHash() []byte {
	if prepared == nil {
		return nil
	}
	return append([]byte(nil), prepared.unsignedTxHash...)
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
// exact payload custody evidence, and the independently rebuilt candidate. It
// never creates a transaction signature. The application must persist the
// exact request and payload bundle before calling SignPreparedPayment.
func (workflow *Workflow) PreparePayment(ctx context.Context, request *ArbitrationRequest, blockHeight uint32) (*PreparedPayment, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	request = cloneRequest(request)
	claim, terms, payloads, unsigned, commitment, authHash, payloadHash, txHash, keys, err := validateRequestEvidence(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPubKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	at := time.Now().UTC()
	if !at.Before(time.Unix(terms.DeliveryDeadlineUnix, 0)) {
		return nil, fmt.Errorf("%w: delivery deadline has passed", pool.ErrInvalidEvidence)
	}
	if err := pool.CheckArbitrationRefundNotExpired(claim.RefundTemplateRaw, blockHeight); err != nil {
		return nil, fmt.Errorf("%w: refund template is no longer available for arbitration: %v", pool.ErrInvalidEvidence, err)
	}
	return &PreparedPayment{
		request: request, claim: claim, unsigned: cloneUnsigned(unsigned), payloads: cloneByteSlices(payloads),
		requestCommitment: commitment, authorizationHash: authHash, payloadsHash: payloadHash,
		unsignedTxHash: txHash, arbiterPubKey: append([]byte(nil), keys.ArbiterPubKey...),
		deadlineUnix: terms.DeliveryDeadlineUnix, preparedAt: at,
	}, nil
}

// SignPreparedPayment performs the post-persistence signing step. It rebuilds
// the candidate and all three hashes from the opaque evidence, then produces
// and self-verifies both the Result message signature and the transaction
// signature before returning Kind 9.
func (workflow *Workflow) SignPreparedPayment(ctx context.Context, prepared *PreparedPayment) (*ArbitrationResponse, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	if prepared == nil || prepared.request == nil || prepared.claim == nil || prepared.unsigned == nil {
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
	freshClaim, _, _, rebuilt, commitment, authHash, payloadHash, txHash, keys, err := validateRequestEvidence(cloneRequest(prepared.request))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(commitment, prepared.requestCommitment) || !bytes.Equal(authHash, prepared.authorizationHash) || !bytes.Equal(payloadHash, prepared.payloadsHash) || !bytes.Equal(txHash, prepared.unsignedTxHash) {
		return nil, fmt.Errorf("%w: prepared payment evidence changed", pool.ErrInvalidEvidence)
	}
	if !equalUnsigned(rebuilt, prepared.unsigned) {
		return nil, fmt.Errorf("%w: prepared candidate changed", pool.ErrInvalidEvidence)
	}
	engine, err := pool.NewMultisigPoolEngineFromPoolLockingScript(freshClaim.PoolOutputLockingScript)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(keys.ArbiterPubKey, workflow.publicKey) {
		return nil, fmt.Errorf("%w: Claim arbiter key does not match workflow key", pool.ErrInvalidEvidence)
	}
	arbiterTxSig, err := engine.SignArbitrationArbiterPayment(ctx, rebuilt, workflow.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration transaction: %w", err)
	}
	if err := engine.VerifyArbitrationArbiterPayment(rebuilt, arbiterTxSig); err != nil {
		return nil, fmt.Errorf("verify arbitration transaction signature: %w", err)
	}
	result := &ArbitrationResult{RequestCommitment: commitment, ContentPayloadsHash: payloadHash, UnsignedStateTxHash: txHash}
	resultCBOR, err := MarshalResult(result)
	if err != nil {
		return nil, err
	}
	resultSigning, err := ArbiterResultSigningCBOR(resultCBOR)
	if err != nil {
		return nil, err
	}
	resultSig, err := bitfs.SignMessage(workflow.privateKey, resultSigning)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration result: %w", err)
	}
	if err := bitfs.VerifySignature(workflow.publicKey, resultSigning, resultSig); err != nil {
		return nil, fmt.Errorf("verify arbitration result signature: %w", err)
	}
	response := &ArbitrationResponse{Version: MajorVersion, ResultCBOR: resultCBOR, ArbiterResultSignature: resultSig, ArbiterTransactionSignature: arbiterTxSig}
	if _, err := MarshalResponse(response); err != nil {
		return nil, err
	}
	return cloneResponse(response), nil
}

func validateRequestEvidence(request *ArbitrationRequest) (*ArbitrationClaim, *bitfs.ContentRequestTerms, [][]byte, *pool.UnsignedPayment, []byte, []byte, []byte, []byte, pool.MultisigPoolPublicKeys, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	claim, err := UnmarshalClaim(request.ClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	terms, err := bitfs.DecodeContentRequestTerms(claim.TermsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	keys, err := pool.ParseArbitratedPoolLockingScript(claim.PoolOutputLockingScript)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if err := bitfs.VerifySignature(keys.BuyerPubKey, claim.TermsCBOR, claim.BuyerSignature); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: buyer authorization signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	sellerSigning, err := SellerClaimSigningCBOR(request.ClaimCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if err := bitfs.VerifySignature(keys.SellerPubKey, sellerSigning, request.SellerClaimSignature); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: seller Claim signature invalid: %v", pool.ErrInvalidEvidence, err)
	}
	payloads, err := bitfs.DecodeContentPayloads(request.ContentPayloadsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	hashes, err := bitfs.DecodeContentHashes(terms.ContentHashesCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	if len(payloads) != len(hashes) {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload count does not match authorized hash count", pool.ErrInvalidEvidence)
	}
	for index := range payloads {
		digest := sha256.Sum256(payloads[index])
		if !bytes.Equal(digest[:], hashes[index]) {
			return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: payload #%d does not match authorized hash", pool.ErrInvalidEvidence, index+1)
		}
	}
	unsigned, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, terms.PaymentSequence, terms.SellerAmountAfterSat)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	refundID := unsigned.RefundTemplateTxID
	if !bytes.Equal(refundID[:], terms.RefundTemplateTxID) {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, fmt.Errorf("%w: refund template transaction ID does not match Buyer terms", pool.ErrInvalidEvidence)
	}
	authHash, err := bitfs.PaymentAuthorizationHash(claim.TermsCBOR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	commitment, err := RequestCommitment(request)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, pool.MultisigPoolPublicKeys{}, err
	}
	payloadHash := sha256.Sum256(request.ContentPayloadsCBOR)
	txHash := sha256.Sum256(unsigned.RawTx)
	return claim, terms, payloads, unsigned, commitment, append([]byte(nil), authHash[:]...), append([]byte(nil), payloadHash[:]...), append([]byte(nil), txHash[:]...), keys, nil
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
	if _, err := pool.BuildArbitrationPaymentFromClaim(claim.PoolOutputSatoshis, claim.PoolOutputLockingScript, claim.RefundTemplateRaw, terms.PaymentSequence, terms.SellerAmountAfterSat); err != nil {
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

func ValidateResult(result *ArbitrationResult) error {
	if result == nil || len(result.RequestCommitment) != sha256.Size || len(result.ContentPayloadsHash) != sha256.Size || len(result.UnsignedStateTxHash) != sha256.Size {
		return fmt.Errorf("%w: arbitration result hashes must be 32 bytes", pool.ErrInvalidEvidence)
	}
	return nil
}

func MarshalResult(result *ArbitrationResult) ([]byte, error) {
	if err := ValidateResult(result); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{bstr(result.RequestCommitment), bstr(result.ContentPayloadsHash), bstr(result.UnsignedStateTxHash)})
	if err != nil {
		return nil, err
	}
	if err := requireWireSize(raw, MaxArbitrationResultBytes, "arbitration Result"); err != nil {
		return nil, err
	}
	return raw, nil
}

func UnmarshalResult(data []byte) (*ArbitrationResult, error) {
	if err := requireWireSize(data, MaxArbitrationResultBytes, "arbitration Result"); err != nil {
		return nil, err
	}
	values, err := decodeArray(data, 3)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration result: %v", pool.ErrInvalidEvidence, err)
	}
	result := new(ArbitrationResult)
	if err := arbitrationDec.Unmarshal(values[0], &result.RequestCommitment); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[1], &result.ContentPayloadsHash); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &result.UnsignedStateTxHash); err != nil {
		return nil, err
	}
	if err := ValidateResult(result); err != nil {
		return nil, err
	}
	canonical, err := MarshalResult(result)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("%w: arbitration result is not deterministically encoded", pool.ErrInvalidEvidence)
	}
	return cloneResult(result), nil
}

func ValidateResponse(response *ArbitrationResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.ResultCBOR) == 0 || len(response.ArbiterResultSignature) == 0 || len(response.ArbiterTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	if len(response.ResultCBOR) > MaxArbitrationResultBytes {
		return fmt.Errorf("%w: arbitration response Result exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationResultBytes)
	}
	if len(response.ArbiterResultSignature) > MaxArbitrationSignatureBytes || len(response.ArbiterTransactionSignature) > MaxArbitrationSignatureBytes {
		return fmt.Errorf("%w: arbitration response signature exceeds %d bytes", pool.ErrInvalidEvidence, MaxArbitrationSignatureBytes)
	}
	if _, err := UnmarshalResult(response.ResultCBOR); err != nil {
		return err
	}
	return nil
}

func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	raw, err := arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationResponse, bstr(response.ResultCBOR), bstr(response.ArbiterResultSignature), bstr(response.ArbiterTransactionSignature)})
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
	values, err := decodeArray(data, 5)
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
	if err := arbitrationDec.Unmarshal(values[2], &response.ResultCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbiterResultSignature); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &response.ArbiterTransactionSignature); err != nil {
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

// ArbiterResultSigningCBOR returns the exact [4,9,result_cbor] message domain.
func ArbiterResultSigningCBOR(resultCBOR []byte) ([]byte, error) {
	if _, err := UnmarshalResult(resultCBOR); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, kindArbitrationResponse, bstr(resultCBOR)})
}

func RequestCommitment(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	domain, err := SellerClaimSigningCBOR(request.ClaimCBOR)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(domain)
	return append([]byte(nil), hash[:]...), nil
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

func cloneResult(result *ArbitrationResult) *ArbitrationResult {
	if result == nil {
		return nil
	}
	return &ArbitrationResult{RequestCommitment: append([]byte(nil), result.RequestCommitment...), ContentPayloadsHash: append([]byte(nil), result.ContentPayloadsHash...), UnsignedStateTxHash: append([]byte(nil), result.UnsignedStateTxHash...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{Version: response.Version, ResultCBOR: append([]byte(nil), response.ResultCBOR...), ArbiterResultSignature: append([]byte(nil), response.ArbiterResultSignature...), ArbiterTransactionSignature: append([]byte(nil), response.ArbiterTransactionSignature...)}
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
