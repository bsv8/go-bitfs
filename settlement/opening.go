package settlement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
)

const poolOpeningProofVersion uint64 = 1

// PoolOpeningProof is the portable, self-verifying material retained during a
// pool opening. Before FundingTx is revealed it is a pending proof; after
// FundingTx is stored it is complete. It is evidence data, not a database
// entity, and the caller chooses how to store or index it.
type PoolOpeningProof struct {
	_                     struct{} `cbor:",toarray"`
	Version               uint64
	RefundTx              []byte
	FundingTxID           []byte
	PoolOutputIndex       uint32
	PoolOutputSatoshis    uint64
	PoolLockingScript     []byte
	BuyerRefundSignature  []byte
	SellerRefundSignature []byte
	FundingTx             []byte
}

// PoolOpeningProofStore is the storage port used by the opening flow. It must
// preserve the exact proof bytes and make repeated saves of identical proof
// data safe.
type PoolOpeningProofStore interface {
	SavePoolOpeningProof(ctx context.Context, proof *PoolOpeningProof) error
	LoadPoolOpeningProofByFundingTxID(ctx context.Context, fundingTxID []byte) (*PoolOpeningProof, error)
}

// RefundTxSigner is the seller-side signing port. SellerPresignRefund invokes
// it without pre-validating the buyer's economics or transaction: FundingTx
// has not been revealed or funded at this point.
type RefundTxSigner interface {
	SignRefundTx(ctx context.Context, request *PoolRefundPresignRequest) ([]byte, error)
}

// RefundTxSignatureVerifier verifies the seller's refund signature against
// all source-output material contained in the presign request.
type RefundTxSignatureVerifier interface {
	VerifySellerRefundSignature(ctx context.Context, request *PoolRefundPresignRequest, signature []byte) error
}

// TransactionIDCalculator returns the canonical 32-byte transaction ID for
// one raw BSV transaction.
type TransactionIDCalculator interface {
	TransactionID(ctx context.Context, rawTx []byte) ([]byte, error)
}

// FundingTxVerifier performs the seller's step-7 verification. It must verify
// the pool output, amount, locking script, refund input, and both refund
// signatures against the supplied FundingTx.
type FundingTxVerifier interface {
	VerifyFundingTx(ctx context.Context, fundingTx []byte, proof *PoolOpeningProof) error
}

// TransactionSubmitter submits a raw transaction through the caller's chosen
// chain node, wallet, or broadcaster. Success must return the transaction ID.
type TransactionSubmitter interface {
	SubmitTransaction(ctx context.Context, rawTx []byte) ([]byte, error)
}

// BuyerPoolOpeningHooks contains precisely the external capabilities used on
// the buyer side after a seller refund pre-signature arrives.
type BuyerPoolOpeningHooks interface {
	PoolOpeningProofStore
	RefundTxSignatureVerifier
	TransactionIDCalculator
}

// SellerPoolOpeningHooks contains precisely the external capabilities used on
// the seller side. It intentionally has no chain-observation method: opening
// succeeds when SubmitTransaction accepts FundingTx and returns its txid.
type SellerPoolOpeningHooks interface {
	PoolOpeningProofStore
	RefundTxSigner
	TransactionIDCalculator
	FundingTxVerifier
	TransactionSubmitter
}

// SellerPresignRefund implements opening step 4. It signs and persists the
// refund transaction before returning the signature. It intentionally does not
// perform business or FundingTx validation before signing.
func SellerPresignRefund(ctx context.Context, request *PoolRefundPresignRequest, hooks SellerPoolOpeningHooks) (*PoolRefundPresignResponse, error) {
	if hooks == nil {
		return nil, errors.New("seller pool opening hooks are required")
	}
	if err := validate(request); err != nil {
		return nil, err
	}
	signature, err := hooks.SignRefundTx(ctx, clonePoolRefundPresignRequest(request))
	if err != nil {
		return nil, fmt.Errorf("sign refund transaction: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("seller refund signature is empty")
	}
	proof := proofFromRefundPresignRequest(request)
	proof.SellerRefundSignature = append([]byte(nil), signature...)
	if err := hooks.SavePoolOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save seller pending opening proof: %w", err)
	}
	return NewPoolRefundPresignResponse(signature), nil
}

// BuyerAcceptRefundPresign implements opening step 5. It verifies the seller
// signature and persists complete buyer proof before the caller is allowed to
// send PoolFundingTxDelivery.
func BuyerAcceptRefundPresign(ctx context.Context, request *PoolRefundPresignRequest, response *PoolRefundPresignResponse, fundingTx []byte, hooks BuyerPoolOpeningHooks) (*PoolOpeningProof, error) {
	if hooks == nil {
		return nil, errors.New("buyer pool opening hooks are required")
	}
	if err := validate(request); err != nil {
		return nil, err
	}
	if err := validate(response); err != nil {
		return nil, err
	}
	if len(fundingTx) == 0 {
		return nil, errors.New("funding_tx is required")
	}
	if err := hooks.VerifySellerRefundSignature(ctx, clonePoolRefundPresignRequest(request), append([]byte(nil), response.SellerRefundSignature...)); err != nil {
		return nil, fmt.Errorf("verify seller refund signature: %w", err)
	}
	fundingTxID, err := hooks.TransactionID(ctx, append([]byte(nil), fundingTx...))
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction ID: %w", err)
	}
	if !bytes.Equal(fundingTxID, request.FundingTxID) {
		return nil, errors.New("funding_tx ID does not match funding_txid")
	}
	proof := proofFromRefundPresignRequest(request)
	proof.SellerRefundSignature = append([]byte(nil), response.SellerRefundSignature...)
	proof.FundingTx = append([]byte(nil), fundingTx...)
	if err := hooks.SavePoolOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save buyer opening proof: %w", err)
	}
	return clonePoolOpeningProof(proof), nil
}

// SellerAcceptFundingTx implements steps 7 and 8. It derives the association
// from FundingTx content, loads the seller's retained proof, verifies the full
// relationship, persists FundingTx, submits it, verifies the submitter's txid,
// and persists the complete proof. No confirmation wait is performed.
func SellerAcceptFundingTx(ctx context.Context, delivery *PoolFundingTxDelivery, hooks SellerPoolOpeningHooks) (*PoolOpeningProof, error) {
	if hooks == nil {
		return nil, errors.New("seller pool opening hooks are required")
	}
	if err := validate(delivery); err != nil {
		return nil, err
	}
	fundingTx := append([]byte(nil), delivery.FundingTx...)
	fundingTxID, err := hooks.TransactionID(ctx, fundingTx)
	if err != nil {
		return nil, fmt.Errorf("calculate funding transaction ID: %w", err)
	}
	if len(fundingTxID) != sha256.Size {
		return nil, errors.New("calculated funding transaction ID must be 32 bytes")
	}
	proof, err := hooks.LoadPoolOpeningProofByFundingTxID(ctx, append([]byte(nil), fundingTxID...))
	if err != nil {
		return nil, fmt.Errorf("load seller pending opening proof: %w", err)
	}
	if err := validatePoolOpeningProof(proof); err != nil {
		return nil, fmt.Errorf("loaded opening proof: %w", err)
	}
	if !bytes.Equal(proof.FundingTxID, fundingTxID) {
		return nil, errors.New("loaded opening proof funding_txid does not match funding_tx")
	}
	if err := hooks.VerifyFundingTx(ctx, fundingTx, clonePoolOpeningProof(proof)); err != nil {
		return nil, fmt.Errorf("verify funding transaction against refund transaction: %w", err)
	}
	proof = clonePoolOpeningProof(proof)
	proof.FundingTx = fundingTx
	if err := hooks.SavePoolOpeningProof(ctx, proof); err != nil {
		return nil, fmt.Errorf("save seller complete opening proof: %w", err)
	}
	submittedTxID, err := hooks.SubmitTransaction(ctx, append([]byte(nil), fundingTx...))
	if err != nil {
		return nil, fmt.Errorf("submit funding transaction: %w", err)
	}
	if !bytes.Equal(submittedTxID, fundingTxID) {
		return nil, errors.New("submitted transaction ID does not match funding_tx ID")
	}
	return clonePoolOpeningProof(proof), nil
}

// EncodePoolOpeningProof returns the deterministic CBOR representation of an
// opening proof. It is separate from a wire message, so callers can persist it
// without introducing a database ID.
func EncodePoolOpeningProof(proof *PoolOpeningProof) ([]byte, error) {
	if err := validatePoolOpeningProof(proof); err != nil {
		return nil, err
	}
	return enc.Marshal(proof)
}

// DecodePoolOpeningProof decodes one deterministic opening proof.
func DecodePoolOpeningProof(data []byte) (*PoolOpeningProof, error) {
	proof := new(PoolOpeningProof)
	if err := dec.Unmarshal(data, proof); err != nil {
		return nil, fmt.Errorf("decode pool opening proof: %w", err)
	}
	if err := validatePoolOpeningProof(proof); err != nil {
		return nil, err
	}
	canonical, err := EncodePoolOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("pool opening proof is not deterministically encoded")
	}
	return clonePoolOpeningProof(proof), nil
}

// PoolOpeningProofHash returns the content hash of canonical opening proof.
func PoolOpeningProofHash(proof *PoolOpeningProof) ([sha256.Size]byte, error) {
	encoded, err := EncodePoolOpeningProof(proof)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func proofFromRefundPresignRequest(request *PoolRefundPresignRequest) *PoolOpeningProof {
	return &PoolOpeningProof{
		Version:              poolOpeningProofVersion,
		RefundTx:             append([]byte(nil), request.RefundTx...),
		FundingTxID:          append([]byte(nil), request.FundingTxID...),
		PoolOutputIndex:      request.PoolOutputIndex,
		PoolOutputSatoshis:   request.PoolOutputSatoshis,
		PoolLockingScript:    append([]byte(nil), request.PoolLockingScript...),
		BuyerRefundSignature: append([]byte(nil), request.BuyerRefundSignature...),
	}
}

func validatePoolRefundPresignRequest(request *PoolRefundPresignRequest) error {
	if request == nil {
		return errors.New("refund presign request is required")
	}
	if len(request.RefundTx) == 0 {
		return errors.New("refund_tx is required")
	}
	if err := requireID("funding_txid", request.FundingTxID); err != nil {
		return err
	}
	if request.PoolOutputSatoshis == 0 {
		return errors.New("pool_output_satoshis is required")
	}
	if len(request.PoolLockingScript) == 0 {
		return errors.New("pool_locking_script is required")
	}
	if len(request.BuyerRefundSignature) == 0 {
		return errors.New("buyer_refund_signature is required")
	}
	return nil
}

func validatePoolOpeningProof(proof *PoolOpeningProof) error {
	if proof == nil {
		return errors.New("pool opening proof is required")
	}
	if proof.Version != poolOpeningProofVersion {
		return fmt.Errorf("unsupported pool opening proof version %d", proof.Version)
	}
	if err := validatePoolRefundPresignRequest(&PoolRefundPresignRequest{
		RefundTx:             proof.RefundTx,
		FundingTxID:          proof.FundingTxID,
		PoolOutputIndex:      proof.PoolOutputIndex,
		PoolOutputSatoshis:   proof.PoolOutputSatoshis,
		PoolLockingScript:    proof.PoolLockingScript,
		BuyerRefundSignature: proof.BuyerRefundSignature,
	}); err != nil {
		return err
	}
	if len(proof.SellerRefundSignature) == 0 {
		return errors.New("seller_refund_signature is required")
	}
	return nil
}

func clonePoolRefundPresignRequest(request *PoolRefundPresignRequest) *PoolRefundPresignRequest {
	if request == nil {
		return nil
	}
	return NewPoolRefundPresignRequest(request.RefundTx, request.FundingTxID, request.PoolOutputIndex, request.PoolOutputSatoshis, request.PoolLockingScript, request.BuyerRefundSignature)
}

func clonePoolOpeningProof(proof *PoolOpeningProof) *PoolOpeningProof {
	if proof == nil {
		return nil
	}
	return &PoolOpeningProof{
		Version:               proof.Version,
		RefundTx:              append([]byte(nil), proof.RefundTx...),
		FundingTxID:           append([]byte(nil), proof.FundingTxID...),
		PoolOutputIndex:       proof.PoolOutputIndex,
		PoolOutputSatoshis:    proof.PoolOutputSatoshis,
		PoolLockingScript:     append([]byte(nil), proof.PoolLockingScript...),
		BuyerRefundSignature:  append([]byte(nil), proof.BuyerRefundSignature...),
		SellerRefundSignature: append([]byte(nil), proof.SellerRefundSignature...),
		FundingTx:             append([]byte(nil), proof.FundingTx...),
	}
}
