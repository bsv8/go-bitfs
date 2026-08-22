// Package arbitration implements the BitFS v4 seller-arbitration signing workflow.
// It verifies the buyer authorization and seller candidate transaction, then
// adds only the arbiter signature. It does not price content, construct
// transactions, or receive the 005 buyer signature.
package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/fxamacker/cbor/v2"
)

// MajorVersion is the current major version of the pool workflow protocol.
const MajorVersion uint64 = 4

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
		MaxArrayElements: 16,
		MaxMapPairs:      16,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// ArbitrationRequest is the complete v4 wire request. RefundTemplateTxID is the
// pool correlation ID that lets the request route independently of any
// connection or session. All transaction bytes are unsigned-template bytes;
// the seller signature is deliberately separate.
type ArbitrationRequest struct {
	Version                    uint64
	RefundTemplateTxID         pool.RefundTemplateTxID
	PoolOpeningProofCBOR       []byte
	PaymentAuthorizationCBOR   []byte
	UnsignedStateTxRaw         []byte
	SellerTransactionSignature []byte
}

// ArbitrationResponse contains the verified pool correlation ID, the hashes of
// the authorized bytes, and the arbiter decision signature.
type ArbitrationResponse struct {
	Version                     uint64
	RefundTemplateTxID          pool.RefundTemplateTxID
	PaymentAuthorizationHash    []byte
	UnsignedStateTxHash         []byte
	ArbiterTransactionSignature []byte
}

type WorkflowConfig struct {
	// PrivateKey 是仲裁方官方 BSV Go SDK 私钥。它是唯一的运行时配置：
	// 不存在 Signer、Verifier、Clock、Store 或 Node hook，私钥也绝不进入
	// 任何报文、返回值、日志或持久化结构。
	PrivateKey *ec.PrivateKey
}

// Workflow verifies 007 evidence and adds only the arbiter signature. It never
// prices content, replaces the seller candidate transaction, or submits a node
// transaction on the arbiter's behalf. The workflow is stateless apart from
// the arbiter private key and the compressed public key derived from it.
type Workflow struct {
	privateKey *ec.PrivateKey
	publicKey  []byte
}

// NewWorkflow requires only a non-nil official BSV private key. It returns an
// arbiter workflow with no storage or network side effects.
func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.PrivateKey == nil {
		return nil, errors.New("arbitration workflow requires an arbiter private key")
	}
	return &Workflow{privateKey: config.PrivateKey, publicKey: config.PrivateKey.PubKey().Compressed()}, nil
}

// SignPayment decodes and verifies the opening proof, standalone 003 buyer
// authorization, seller candidate transaction, and seller signature. On success
// it returns a 007 response containing hashes of the authorized bytes and the
// detached arbiter signature; it does not broadcast or mutate the candidate.
func (workflow *Workflow) SignPayment(ctx context.Context, request *ArbitrationRequest) (*ArbitrationResponse, error) {
	if workflow == nil {
		return nil, errors.New("arbitration workflow is required")
	}
	request = cloneRequest(request)
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	proof, err := pool.DecodeOpeningProof(request.PoolOpeningProofCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode opening proof: %w", err)
	}
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
	if err != nil {
		return nil, fmt.Errorf("build pool engine: %w", err)
	}
	poolAdapter := &pool.MultisigPoolAdapter{Engine: engine, ArbiterKey: workflow.privateKey}
	if err := engine.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify opening proof: %w", err)
	}
	derivedRefundTemplateTxID, err := pool.DeriveRefundTemplateTxID(ctx, proof)
	if err != nil {
		return nil, fmt.Errorf("derive refund template transaction ID: %w", err)
	}
	if derivedRefundTemplateTxID != request.RefundTemplateTxID {
		return nil, fmt.Errorf("%w: arbitration request correlation ID does not match opening evidence", pool.ErrInvalidEvidence)
	}
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode payment authorization: %w", err)
	}
	// 007 携带 OpeningProof：身份、费率与池绑定全部从证据恢复，003 只需
	// 通过池绑定与买方签名验证；仲裁不读取 004 或 payload。
	terms, err := bitfs.VerifySignedContentRequestForOpening(authorization, proof)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	if _, err := poolAdapter.VerifyArbitrationCandidate(ctx, request.UnsignedStateTxRaw, proof, terms, request.SellerTransactionSignature); err != nil {
		return nil, fmt.Errorf("verify arbitration candidate: %w", err)
	}
	arbiterSig, err := poolAdapter.SignArbitrationCandidate(ctx, request.UnsignedStateTxRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration candidate: %w", err)
	}
	unsigned, err := engine.ParseUnsignedPayment(ctx, request.UnsignedStateTxRaw, proof)
	if err != nil {
		return nil, fmt.Errorf("reparse arbitration candidate: %w", err)
	}
	if err := engine.VerifyArbiterPayment(unsigned, arbiterSig, proof); err != nil {
		return nil, fmt.Errorf("verify arbiter signature: %w", err)
	}
	if len(arbiterSig) == 0 {
		return nil, fmt.Errorf("%w: arbiter signature is empty", pool.ErrInvalidEvidence)
	}
	// 唯一真值：PaymentAuthorizationHash = SHA-256(003 TermsCBOR)，
	// 与 004/005 携带的授权哈希完全一致；绝不对完整 003 外壳取哈希。
	authHash, err := bitfs.PaymentAuthorizationHash(authorization.TermsCBOR)
	if err != nil {
		return nil, fmt.Errorf("compute payment authorization hash: %w", err)
	}
	txHash := sha256.Sum256(request.UnsignedStateTxRaw)
	return &ArbitrationResponse{Version: MajorVersion, RefundTemplateTxID: derivedRefundTemplateTxID, PaymentAuthorizationHash: append([]byte(nil), authHash[:]...), UnsignedStateTxHash: txHash[:], ArbiterTransactionSignature: append([]byte(nil), arbiterSig...)}, nil
}

// MarshalRequest validates and encodes a six-field 007 arbitration request led
// by its RefundTemplateTxID correlation ID.
func MarshalRequest(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, request.RefundTemplateTxID[:], request.PoolOpeningProofCBOR, request.PaymentAuthorizationCBOR, request.UnsignedStateTxRaw, request.SellerTransactionSignature})
}

// UnmarshalRequest strictly decodes and canonicalizes a 007 arbitration request.
func UnmarshalRequest(data []byte) (*ArbitrationRequest, error) {
	values, err := decodeArray(data, 6)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(ArbitrationRequest)
	if err := arbitrationDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration request version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &request.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.PoolOpeningProofCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.PaymentAuthorizationCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &request.UnsignedStateTxRaw); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[5], &request.SellerTransactionSignature); err != nil {
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

// MarshalResponse validates and encodes a five-field 007 arbitration response
// carrying the verified RefundTemplateTxID correlation ID.
func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, response.RefundTemplateTxID[:], response.PaymentAuthorizationHash, response.UnsignedStateTxHash, response.ArbiterTransactionSignature})
}

// UnmarshalResponse strictly decodes and canonicalizes a 007 arbitration response.
func UnmarshalResponse(data []byte) (*ArbitrationResponse, error) {
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration response: %v", pool.ErrInvalidEvidence, err)
	}
	response := new(ArbitrationResponse)
	if err := arbitrationDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration response version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &response.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.PaymentAuthorizationHash); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.UnsignedStateTxHash); err != nil {
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

// ValidateRequest checks the 007 version, required CBOR/transaction byte fields,
// SHA-256 hash lengths, and detached seller signature before decoding evidence.
func ValidateRequest(request *ArbitrationRequest) error {
	if request == nil || request.Version != MajorVersion || len(request.PoolOpeningProofCBOR) == 0 || len(request.PaymentAuthorizationCBOR) == 0 || len(request.UnsignedStateTxRaw) == 0 || len(request.SellerTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration request is incomplete", pool.ErrInvalidEvidence)
	}
	for _, b := range request.RefundTemplateTxID {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: arbitration refund_template_txid must not be all zero", pool.ErrInvalidEvidence)
}

// ValidateResponse checks the 007 response version, authorization/state hashes,
// and detached arbiter signature lengths before a caller accepts the response.
func ValidateResponse(response *ArbitrationResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.PaymentAuthorizationHash) != sha256.Size || len(response.UnsignedStateTxHash) != sha256.Size || len(response.ArbiterTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	for _, b := range response.RefundTemplateTxID {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: arbitration refund_template_txid must not be all zero", pool.ErrInvalidEvidence)
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

func cloneRequest(request *ArbitrationRequest) *ArbitrationRequest {
	if request == nil {
		return nil
	}
	return &ArbitrationRequest{Version: request.Version, RefundTemplateTxID: request.RefundTemplateTxID, PoolOpeningProofCBOR: append([]byte(nil), request.PoolOpeningProofCBOR...), PaymentAuthorizationCBOR: append([]byte(nil), request.PaymentAuthorizationCBOR...), UnsignedStateTxRaw: append([]byte(nil), request.UnsignedStateTxRaw...), SellerTransactionSignature: append([]byte(nil), request.SellerTransactionSignature...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{Version: response.Version, RefundTemplateTxID: response.RefundTemplateTxID, PaymentAuthorizationHash: append([]byte(nil), response.PaymentAuthorizationHash...), UnsignedStateTxHash: append([]byte(nil), response.UnsignedStateTxHash...), ArbiterTransactionSignature: append([]byte(nil), response.ArbiterTransactionSignature...)}
}
