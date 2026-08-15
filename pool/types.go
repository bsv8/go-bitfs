package pool

import (
	"context"
	"crypto/sha256"
)

// ProtocolFamily is the go-bitfs pool workflow protocol.  It is deliberately
// separate from the MultisigPool library protocol embedded in OpeningProof.
const ProtocolFamily = "bitfs.pool.workflow.v3"

// MajorVersion is the current major version of the pool workflow protocol.
const MajorVersion uint64 = 3

// MultisigProtocol identifies the embedded MultisigPool transaction protocol.
const MultisigProtocol = "bitfs.pool.v4"

// MultisigVersion is the version of the embedded MultisigPool protocol.
const MultisigVersion uint64 = 4

// Hash32 stores a fixed-width 32-byte hash used for protocol identities and transaction IDs.
type Hash32 [sha256.Size]byte

// Reference identifies the settlement pool and payment sequence used by a content request.
type Reference struct {
	SpendTxID           Hash32
	BasePaymentSequence uint32
}

// OpeningProof records the mutually verified refund and funding transactions that open a pool.
type OpeningProof struct {
	Version               uint64
	MultisigProtocol      string
	MultisigVersion       uint64
	RefundTx              []byte
	SpendTxID             []byte
	FundingTxID           []byte
	PoolOutputIndex       uint32
	PoolOutputSatoshis    uint64
	PoolLockingScript     []byte
	BuyerPubKey           []byte
	SellerPubKey          []byte
	ArbiterPubKey         []byte
	MinerFeeRateSatPerKB  uint64
	BuyerRefundSignature  []byte
	SellerRefundSignature []byte
	FundingTx             []byte
}

// RefundPresignRequest contains the buyer-seller terms for a presigned refund transaction.
type RefundPresignRequest struct {
	Version              uint64
	MultisigProtocol     string
	MultisigVersion      uint64
	RefundTx             []byte
	FundingTxID          []byte
	PoolOutputIndex      uint32
	PoolOutputSatoshis   uint64
	PoolLockingScript    []byte
	BuyerPubKey          []byte
	SellerPubKey         []byte
	ArbiterPubKey        []byte
	MinerFeeRateSatPerKB uint64
	BuyerRefundSignature []byte
}

// RefundPresignResponse carries the seller signature over the presigned refund transaction.
type RefundPresignResponse struct {
	Version               uint64
	SellerRefundSignature []byte
}

// FundingTxDelivery carries the buyer-signed funding transaction revealed after refund verification.
type FundingTxDelivery struct {
	Version   uint64
	FundingTx []byte
}

// PaymentUpdate is the v3 005 transport container.  It carries an unsigned
// state transaction and a detached Buyer signature; it never carries a
// partially unlocked transaction.
type PaymentUpdate struct {
	Version                   uint64
	PaymentAuthorizationHash  []byte
	UnsignedStateTxRaw        []byte
	BuyerTransactionSignature []byte
}

// PaymentState only represents a fully merged transaction accepted by a
// node. Detached signatures are kept explicitly when a workflow needs to
// carry them across an API boundary, but RawTx is never a single-signature
// or unsigned transaction.
type PaymentState struct {
	SpendTxID                   Hash32
	RawTx                       []byte
	PaymentSequence             uint32
	BuyerAmountSat              uint64
	SellerAmountSat             uint64
	ArbiterAmountSat            uint64
	PaymentAuthorizationHash    Hash32
	BuyerTransactionSignature   []byte
	SellerTransactionSignature  []byte
	ArbiterTransactionSignature []byte
	PoolOutputSatoshis          uint64
	PoolLockingScript           []byte
}

// SignedPayment contains one detached role signature over an unsigned payment transaction.
type SignedPayment struct {
	State PaymentState
	RawTx []byte
}

// UnsignedPayment is the only transaction object accepted by single-sign
// methods. It contains no unlocking script and no embedded signature.
type UnsignedPayment struct {
	SpendTxID          Hash32
	RawTx              []byte
	PaymentSequence    uint32
	BuyerAmountSat     uint64
	SellerAmountSat    uint64
	ArbiterAmountSat   uint64
	PoolOutputSatoshis uint64
	PoolLockingScript  []byte
}

// PaymentUpdateInput supplies the next cumulative payment state and its transaction bytes.
type PaymentUpdateInput struct {
	Opening              *OpeningProof
	Previous             *PaymentState
	PaymentSequenceAfter uint32
	SellerAmountAfterSat uint64
}

// CloseInput supplies the signatures and transaction data required for an immediate close.
type CloseInput struct {
	Opening              *OpeningProof
	Latest               *PaymentState
	SellerAmountAfterSat uint64
}

// UpdateAcceptance describes the node acceptance result for a non-final payment update.
type UpdateAcceptance struct {
	TxID            Hash32
	SpendTxID       Hash32
	PaymentSequence uint32
}

// OpeningProofStore persists and retrieves the verified 002 opening proof keyed
// by SpendTxID, the canonical ID of the presigned refund evidence.
type OpeningProofStore interface {
	SaveOpeningProof(context.Context, *OpeningProof) error
	LoadOpeningProof(context.Context, Hash32) (*OpeningProof, error)
}

// PendingOpeningProofStore persists an opening proof before funding is accepted
// and retrieves it by the revealed funding transaction ID.
type PendingOpeningProofStore interface {
	SaveOpeningProof(context.Context, *OpeningProof) error
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
}

// PoolStore combines opening-proof and accepted-payment persistence with health
// and closing reconciliation. Delivery leases are supplied separately through
// PendingRequestStore.
type PoolStore interface {
	OpeningProofStore
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
	SaveAcceptedPayment(context.Context, *PaymentState) error
	LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
	EnsurePoolHealthy(context.Context, Hash32) error
	EnsurePoolOpen(context.Context, Hash32) error
	MarkPoolClosing(context.Context, Hash32) error
	ReconcilePoolClosing(context.Context, Hash32) error
	MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
	ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

// PendingRequest records the request hash and ownership lease used to serialize delivery.
type PendingRequest struct {
	SpendTxID               Hash32 // The pool spend anchor this lease protects.
	BasePaymentSequence     uint32 // The accepted state sequence before delivery.
	BaseSellerAmountSat     uint64 // The accepted seller amount before delivery.
	ContentRequestHash      Hash32 // The canonical hash of the signed 003 request.
	ExpectedSellerAmountSat uint64 // The exact seller amount delta promised by delivery.
}

// PendingAcquireResult reports whether a delivery lease was acquired, held, or conflicted.
type PendingAcquireResult uint8

const (
	// PendingAcquired indicates the delivery lease was successfully acquired.
	PendingAcquired PendingAcquireResult = 1
	// PendingAlreadyHeld indicates that this exact request lease is already held.
	PendingAlreadyHeld PendingAcquireResult = 2
	// PendingConflict indicates that the request hash conflicts with the owner.
	PendingConflict PendingAcquireResult = 3
)

// PendingRequestStore manages content-request delivery leases keyed by spend transaction ID.
type PendingRequestStore interface {
	TryAcquire(context.Context, PendingRequest) (PendingAcquireResult, error)
	Load(context.Context, Hash32) (*PendingRequest, error)
	Release(context.Context, Hash32, Hash32) error
}

// Signer exposes the canonical compressed public key and basic DER-only
// signing operation used by credentials and pool transactions. PublicKey
// must return a valid 33-byte compressed secp256k1 public key. Role workflows
// always pass a 32-byte digest computed by the SDK: canonical CBOR bytes for 001/003/004 are
// hashed once with SHA-256, while pool transactions use the fixed sighash
// digest. Implementations return DER-only signatures and retain private-key
// custody outside the SDK.
type Signer interface {
	PublicKey(context.Context) ([]byte, error)
	Sign(context.Context, []byte) ([]byte, error)
}

// OpeningInput contains generic pool construction data only.
type OpeningInput struct {
	FundingTx            []byte
	PoolOutputIndex      uint32
	ExpiryLockTime       uint32
	MinerFeeRateSatPerKB uint64
	SellerPubKey         []byte
	ArbiterPubKey        []byte
}
