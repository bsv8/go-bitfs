// Package arbitration 实现 v3 卖方仲裁签名工作流。
// 仲裁工作流验证买方的最终授权和卖方候选交易，然后仅添加 Arbiter 签名；
// 不负责内容定价、交易构造或接收 005 买方签名。
package arbitration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/pool"
	"github.com/fxamacker/cbor/v2"
)

const MajorVersion uint64 = 3

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

// ArbitrationRequest is the complete v3 wire request. All transaction bytes
// are unsigned-template bytes; the seller signature is deliberately separate.
type ArbitrationRequest struct {
	Version                    uint64
	PoolOpeningProofCBOR       []byte
	PaymentAuthorizationCBOR   []byte
	UnsignedStateTxRaw         []byte
	SellerTransactionSignature []byte
}

type ArbitrationResponse struct {
	Version                     uint64
	PaymentAuthorizationHash    []byte
	UnsignedStateTxHash         []byte
	ArbiterTransactionSignature []byte
}

// PoolPort 是仲裁工作流所需的唯一交易能力端口。
// 实现必须使用 MultisigPool 验证交易，不得修改候选交易或构造替代交易；
// Seller 验证通过后，由 Arbiter 提供 Arbiter 角色签名。
type PoolPort interface {
	VerifyOpening(*pool.OpeningProof) error
	VerifyArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, *bitfs.ContentRequestTerms, []byte) (*pool.UnsignedPayment, error)
	SignArbitrationCandidate(context.Context, []byte, *pool.OpeningProof, pool.Signer) ([]byte, error)
}

type WorkflowConfig struct {
	Signer                pool.Signer
	Pool                  PoolPort
	AuthorizationVerifier bitfs.ContentTermsSignatureVerifier
}

type Workflow struct {
	signer                pool.Signer
	pool                  PoolPort
	authorizationVerifier bitfs.ContentTermsSignatureVerifier
}

func NewWorkflow(config WorkflowConfig) (*Workflow, error) {
	if config.Signer == nil || config.Pool == nil || config.AuthorizationVerifier == nil {
		return nil, errors.New("arbitration workflow requires an arbiter signer, an authorization verifier, and a pool verification and signing port")
	}
	return &Workflow{signer: config.Signer, pool: config.Pool, authorizationVerifier: config.AuthorizationVerifier}, nil
}

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
	if err := workflow.pool.VerifyOpening(proof); err != nil {
		return nil, fmt.Errorf("verify opening proof: %w", err)
	}
	authorization, err := bitfs.DecodeSignedContentRequest(request.PaymentAuthorizationCBOR)
	if err != nil {
		return nil, fmt.Errorf("decode payment authorization: %w", err)
	}
	terms, err := bitfs.VerifySignedContentRequestStandalone(authorization, workflow.authorizationVerifier)
	if err != nil {
		return nil, fmt.Errorf("verify payment authorization: %w", err)
	}
	if err := ensureAuthorizationPool(terms, proof); err != nil {
		return nil, err
	}
	if _, err := workflow.pool.VerifyArbitrationCandidate(ctx, request.UnsignedStateTxRaw, proof, terms, request.SellerTransactionSignature); err != nil {
		return nil, fmt.Errorf("verify arbitration candidate: %w", err)
	}
	arbiterSig, err := workflow.pool.SignArbitrationCandidate(ctx, request.UnsignedStateTxRaw, proof, workflow.signer)
	if err != nil {
		return nil, fmt.Errorf("sign arbitration candidate: %w", err)
	}
	if len(arbiterSig) == 0 {
		return nil, fmt.Errorf("%w: arbiter signature is empty", pool.ErrInvalidEvidence)
	}
	authHash := sha256.Sum256(request.PaymentAuthorizationCBOR)
	txHash := sha256.Sum256(request.UnsignedStateTxRaw)
	return &ArbitrationResponse{Version: MajorVersion, PaymentAuthorizationHash: authHash[:], UnsignedStateTxHash: txHash[:], ArbiterTransactionSignature: append([]byte(nil), arbiterSig...)}, nil
}

func MarshalRequest(request *ArbitrationRequest) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, request.PoolOpeningProofCBOR, request.PaymentAuthorizationCBOR, request.UnsignedStateTxRaw, request.SellerTransactionSignature})
}

func UnmarshalRequest(data []byte) (*ArbitrationRequest, error) {
	values, err := decodeArray(data, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration request: %v", pool.ErrInvalidEvidence, err)
	}
	request := new(ArbitrationRequest)
	if err := arbitrationDec.Unmarshal(values[0], &request.Version); err != nil || request.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration request version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &request.PoolOpeningProofCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &request.PaymentAuthorizationCBOR); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &request.UnsignedStateTxRaw); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[4], &request.SellerTransactionSignature); err != nil {
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

func MarshalResponse(response *ArbitrationResponse) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	return arbitrationEnc.Marshal([]any{MajorVersion, response.PaymentAuthorizationHash, response.UnsignedStateTxHash, response.ArbiterTransactionSignature})
}

func UnmarshalResponse(data []byte) (*ArbitrationResponse, error) {
	values, err := decodeArray(data, 4)
	if err != nil {
		return nil, fmt.Errorf("%w: decode arbitration response: %v", pool.ErrInvalidEvidence, err)
	}
	response := new(ArbitrationResponse)
	if err := arbitrationDec.Unmarshal(values[0], &response.Version); err != nil || response.Version != MajorVersion {
		return nil, fmt.Errorf("%w: unsupported arbitration response version", pool.ErrInvalidEvidence)
	}
	if err := arbitrationDec.Unmarshal(values[1], &response.PaymentAuthorizationHash); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[2], &response.UnsignedStateTxHash); err != nil {
		return nil, err
	}
	if err := arbitrationDec.Unmarshal(values[3], &response.ArbiterTransactionSignature); err != nil {
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

func ValidateRequest(request *ArbitrationRequest) error {
	if request == nil || request.Version != MajorVersion || len(request.PoolOpeningProofCBOR) == 0 || len(request.PaymentAuthorizationCBOR) == 0 || len(request.UnsignedStateTxRaw) == 0 || len(request.SellerTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration request is incomplete", pool.ErrInvalidEvidence)
	}
	return nil
}

func ValidateResponse(response *ArbitrationResponse) error {
	if response == nil || response.Version != MajorVersion || len(response.PaymentAuthorizationHash) != sha256.Size || len(response.UnsignedStateTxHash) != sha256.Size || len(response.ArbiterTransactionSignature) == 0 {
		return fmt.Errorf("%w: arbitration response is incomplete", pool.ErrInvalidEvidence)
	}
	return nil
}

func ensureAuthorizationPool(terms *bitfs.ContentRequestTerms, proof *pool.OpeningProof) error {
	if terms == nil || proof == nil || !bytes.Equal(terms.SpendTxID, proof.SpendTxID) {
		return fmt.Errorf("%w: authorization pool anchor is missing", pool.ErrInvalidEvidence)
	}
	if len(proof.BuyerPubKey) != 0 && !bytes.Equal(terms.BuyerPubkey, proof.BuyerPubKey) {
		return fmt.Errorf("%w: buyer role mismatch", pool.ErrInvalidEvidence)
	}
	if len(proof.SellerPubKey) != 0 && !bytes.Equal(terms.SellerPubkey, proof.SellerPubKey) {
		return fmt.Errorf("%w: seller role mismatch", pool.ErrInvalidEvidence)
	}
	if len(proof.ArbiterPubKey) != 0 && !bytes.Equal(terms.SelectedArbiterPubkey, proof.ArbiterPubKey) {
		return fmt.Errorf("%w: arbiter role mismatch", pool.ErrInvalidEvidence)
	}
	if proof.MinerFeeRateSatPerKB != 0 && terms.MinerFeeRateSatPerKB != proof.MinerFeeRateSatPerKB {
		return fmt.Errorf("%w: fee rate mismatch", pool.ErrInvalidEvidence)
	}
	return nil
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
	return &ArbitrationRequest{Version: request.Version, PoolOpeningProofCBOR: append([]byte(nil), request.PoolOpeningProofCBOR...), PaymentAuthorizationCBOR: append([]byte(nil), request.PaymentAuthorizationCBOR...), UnsignedStateTxRaw: append([]byte(nil), request.UnsignedStateTxRaw...), SellerTransactionSignature: append([]byte(nil), request.SellerTransactionSignature...)}
}

func cloneResponse(response *ArbitrationResponse) *ArbitrationResponse {
	if response == nil {
		return nil
	}
	return &ArbitrationResponse{Version: response.Version, PaymentAuthorizationHash: append([]byte(nil), response.PaymentAuthorizationHash...), UnsignedStateTxHash: append([]byte(nil), response.UnsignedStateTxHash...), ArbiterTransactionSignature: append([]byte(nil), response.ArbiterTransactionSignature...)}
}
