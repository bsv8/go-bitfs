package pool

import (
	"context"
	"crypto/sha256"
	"time"
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

// TransactionIDCalculator computes a canonical 32-byte transaction identifier from raw transaction bytes.
type TransactionIDCalculator interface {
	TransactionID(context.Context, []byte) (Hash32, error)
}

// RefundTxSigner produces the seller's detached signature over a presigned refund transaction.
type RefundTxSigner interface {
	SignRefundTx(context.Context, *RefundPresignRequest) ([]byte, error)
}

// RefundTxSignatureVerifier validates the seller's detached refund signature against the presign request.
type RefundTxSignatureVerifier interface {
	VerifySellerRefundSignature(context.Context, *RefundPresignRequest, []byte) error
}

// FundingTxVerifier validates that a raw funding transaction matches its opening proof.
type FundingTxVerifier interface {
	VerifyFundingTx(context.Context, []byte, *OpeningProof) error
}

// TransactionSubmitter broadcasts a raw transaction to the network and returns its canonical transaction ID.
type TransactionSubmitter interface {
	SubmitTransaction(context.Context, []byte) (Hash32, error)
}

// BuyerPoolOpeningHooks supplies persistence and verification capabilities for buyer-side pool opening.
type BuyerPoolOpeningHooks interface {
	OpeningProofStore
	RefundTxSignatureVerifier
	TransactionIDCalculator
}

// SellerPoolOpeningHooks supplies signing, verification, persistence, and submission for seller-side opening.
type SellerPoolOpeningHooks interface {
	PendingOpeningProofStore
	RefundTxSigner
	TransactionIDCalculator
	FundingTxVerifier
	TransactionSubmitter
}

// PoolStore combines opening-proof and accepted-payment persistence with health
// reconciliation and the seller delivery lease used by the role workflows.
type PoolStore interface {
	OpeningProofStore
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
	SaveAcceptedPayment(context.Context, *PaymentState) error
	LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
	EnsurePoolHealthy(context.Context, Hash32) error
	MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
	ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

// PendingRequest records the request hash and ownership lease used to serialize delivery.
type PendingRequest struct {
	SpendTxID               Hash32
	BasePaymentSequence     uint32
	ContentRequestHash      Hash32
	ExpectedSellerAmountSat uint64
}

// PendingAcquireResult reports whether a delivery lease was acquired, held, or conflicted.
type PendingAcquireResult uint8

const (
	// PendingAcquired indicates the delivery lease was successfully acquired.
	PendingAcquired PendingAcquireResult = 1
	// PendingAlreadyHeld indicates that another request currently owns the lock.
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

// Signer exposes the public key and detached signatures used by credentials and
// pool transactions. Implementations retain private-key custody outside the SDK.
type Signer interface {
	PublicKey(context.Context) ([]byte, error)
	Sign(context.Context, []byte) ([]byte, error)
}

// SignatureVerifier validates a detached signature over the exact supplied bytes
// and public key; it must not normalize or re-encode the payload.
type SignatureVerifier interface {
	Verify(pubkey, payload, signature []byte) error
}

// PoolNodeVerifierPort verifies pool transactions before they reach a concrete node adapter.
type PoolNodeVerifierPort interface {
	FundingTxID([]byte) (Hash32, error)
	TransactionID([]byte) (Hash32, error)
	BuildRefundSubmission(*OpeningProof) ([]byte, error)
	VerifyRefundExpired(*OpeningProof, time.Time) error
	ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
	ParseFinalPaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
	VerifyArbitratedPayment(*PaymentState, *OpeningProof) error
	VerifyCompletedFinalPayment(*SignedPayment, *OpeningProof) error
}

// BuyerPoolPort exposes buyer-side pool construction, signing, and payment validation operations.
type BuyerPoolPort interface {
	TransactionID([]byte) (Hash32, error)
	BuildRefundPresignRequest(context.Context, OpeningInput, Signer) (*RefundPresignRequest, error)
	BuildRefundSubmission(*OpeningProof) ([]byte, error)
	VerifyRefundExpired(*OpeningProof, time.Time) error
	VerifyOpening(*OpeningProof) error
	ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
	VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
	VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
	VerifyCompletedFinalPayment(*SignedPayment, *OpeningProof) error
	CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
	BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
	SignBuyerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
	BuildImmediateClose(context.Context, CloseInput) (*UnsignedPayment, []byte, error)
}

// SellerPoolPort exposes seller-side pool validation, signing, and payment merge operations.
type SellerPoolPort interface {
	TransactionID([]byte) (Hash32, error)
	FundingTxID([]byte) (Hash32, error)
	BuildRefundSubmission(*OpeningProof) ([]byte, error)
	VerifyOpening(*OpeningProof) error
	ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	ParseUnsignedPayment(context.Context, []byte, *OpeningProof) (*UnsignedPayment, error)
	VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
	VerifyArbitratedPayment(*PaymentState, *OpeningProof) error
	VerifyBuyerPayment(*UnsignedPayment, []byte, *OpeningProof) error
	VerifySellerPayment(*UnsignedPayment, []byte, *OpeningProof) error
	CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
	BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
	SignSellerArbitrationCandidate(context.Context, *UnsignedPayment, Signer) ([]byte, error)
	SignSellerPayment(context.Context, *UnsignedPayment, Signer) ([]byte, error)
	MergeBuyerSellerPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
	MergeSellerArbiterPayment(*UnsignedPayment, []byte, []byte) (*SignedPayment, error)
	SignImmediateClose(context.Context, *UnsignedPayment, []byte, Signer) (*SignedPayment, error)
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

// ParticipantVerifier checks that an opening proof's buyer, seller, and arbiter keys match the expected values.
type ParticipantVerifier interface {
	VerifyPoolParticipants(*OpeningProof, []byte, []byte, []byte) error
}

// NonFinalPoolNode submits verified cumulative updates and final settlement transactions to a node.
type NonFinalPoolNode interface {
	SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
	SubmitFinal(context.Context, []byte) (Hash32, error)
}
