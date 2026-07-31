package pool

import (
	"context"
	"crypto/sha256"
	"time"
)

// ProtocolFamily is a package boundary identifier. MajorVersion is scoped to
// this family and must not be compared with settlement.MajorVersion.
const ProtocolFamily = "bitfs.pool.v2"

const MajorVersion uint64 = 2

// Hash32 is a fixed-size transaction or evidence reference.
type Hash32 [sha256.Size]byte

// Reference is the stable pool reference used by 003. It never contains a
// per-payment transaction ID.
type Reference struct {
	SpendTxID           Hash32
	BasePaymentSequence uint32
}

// OpeningProof is the portable evidence retained for a generic 2-of-3 pool.
// FundingTx is empty while the seller's refund pre-signature is pending.
type OpeningProof struct {
	Version               uint64
	RefundTx              []byte
	SpendTxID             []byte
	FundingTxID           []byte
	PoolOutputIndex       uint32
	PoolOutputSatoshis    uint64
	PoolLockingScript     []byte
	ServerPubKey          []byte
	BuyerPubKey           []byte
	ArbiterPubKey         []byte
	MinerFeeRateSatPerKB  uint64
	BuyerRefundSignature  []byte
	SellerRefundSignature []byte
	FundingTx             []byte
}

type RefundPresignRequest struct {
	Version              uint64
	RefundTx             []byte
	FundingTxID          []byte
	PoolOutputIndex      uint32
	PoolOutputSatoshis   uint64
	PoolLockingScript    []byte
	ServerPubKey         []byte
	BuyerPubKey          []byte
	ArbiterPubKey        []byte
	MinerFeeRateSatPerKB uint64
	BuyerRefundSignature []byte
}

type RefundPresignResponse struct {
	Version               uint64
	SellerRefundSignature []byte
}

type FundingTxDelivery struct {
	Version   uint64
	FundingTx []byte
}

// OpeningInput contains only generic pool construction data. It has no quote,
// content or price fields, keeping 002 independent from BitFS business data.
type OpeningInput struct {
	FundingTx            []byte
	PoolOutputIndex      uint32
	ExpiryLockTime       uint32
	MinerFeeRateSatPerKB uint64
	SellerPubKey         []byte
	ArbiterPubKey        []byte
}

// PendingRequest is seller-side delivery protection plus the price commitment
// calculated from the already verified request and delivery. The pool layer
// stores only the satoshi delta; it does not know BitFS quote semantics.
type PendingRequest struct {
	SpendTxID               Hash32
	BasePaymentSequence     uint32
	ContentRequestHash      Hash32
	ExpectedSellerAmountSat uint64
}

// PendingAcquireResult makes the atomic latch outcome explicit. A retry of
// the same request is not a fresh acquisition and must never re-enter the
// delivery side effect.
type PendingAcquireResult uint8

const (
	PendingAcquired    PendingAcquireResult = 1
	PendingAlreadyHeld PendingAcquireResult = 2
	PendingConflict    PendingAcquireResult = 3
)

// PaymentUpdate is the 005 transport container. ContentRequestTermsHash is
// the hash of the final 003 payment authorization (the historical field name
// is retained); amounts and sequence are derived from PartialSpendTx by
// MultisigPoolPort, never from this wrapper.
type PaymentUpdate struct {
	Version                 uint64
	ContentRequestTermsHash []byte
	PartialSpendTx          []byte
}

// PaymentState is the last transaction state accepted by the pool node.
type PaymentState struct {
	SpendTxID               Hash32
	RawTx                   []byte
	PaymentSequence         uint32
	SellerAmountSat         uint64
	ClientAmountSat         uint64
	ContentRequestTermsHash Hash32
	// SourceOutput fields are derived from the opening proof and are never
	// serialized in 005. They are retained in-process so a signer can recreate
	// the BSV sighash after the raw transaction crosses a process boundary.
	PoolOutputSatoshis uint64
	PoolLockingScript  []byte
}

// SignedPayment is a fully assembled transaction ready for final or
// non-final submission.
type SignedPayment struct {
	State PaymentState
	RawTx []byte
}

type UnsignedPayment struct {
	SpendTxID          Hash32
	RawTx              []byte
	PoolOutputSatoshis uint64
	PoolLockingScript  []byte
}

type PaymentUpdateInput struct {
	Opening              *OpeningProof
	Previous             *PaymentState
	PaymentSequenceAfter uint32
	SellerAmountAfterSat uint64
}

type CloseInput struct {
	Opening              *OpeningProof
	Latest               *PaymentState
	SellerAmountAfterSat uint64
}

type UpdateAcceptance struct {
	TxID            Hash32
	SpendTxID       Hash32
	PaymentSequence uint32
}

// OpeningProofStore persists raw proof material and makes identical retries
// idempotent.
type OpeningProofStore interface {
	SaveOpeningProof(context.Context, *OpeningProof) error
	LoadOpeningProof(context.Context, Hash32) (*OpeningProof, error)
}

type PendingOpeningProofStore interface {
	SaveOpeningProof(context.Context, *OpeningProof) error
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
}

type TransactionIDCalculator interface {
	TransactionID(context.Context, []byte) (Hash32, error)
}

type RefundTxSigner interface {
	SignRefundTx(context.Context, *RefundPresignRequest) ([]byte, error)
}

type RefundTxSignatureVerifier interface {
	VerifySellerRefundSignature(context.Context, *RefundPresignRequest, []byte) error
}

type FundingTxVerifier interface {
	VerifyFundingTx(context.Context, []byte, *OpeningProof) error
}

type TransactionSubmitter interface {
	SubmitTransaction(context.Context, []byte) (Hash32, error)
}

type BuyerPoolOpeningHooks interface {
	OpeningProofStore
	RefundTxSignatureVerifier
	TransactionIDCalculator
}

type SellerPoolOpeningHooks interface {
	PendingOpeningProofStore
	RefundTxSigner
	TransactionIDCalculator
	FundingTxVerifier
	TransactionSubmitter
}

type PoolStore interface {
	OpeningProofStore
	LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
	SaveAcceptedPayment(context.Context, *PaymentState) error
	LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
}

// PendingRequestStore must implement TryAcquire atomically with respect to
// the same SpendTxID. Release must be conditional on request hash.
type PendingRequestStore interface {
	TryAcquire(context.Context, PendingRequest) (PendingAcquireResult, error)
	Load(context.Context, Hash32) (*PendingRequest, error)
	Release(context.Context, Hash32, Hash32) error
}

type Signer interface {
	PublicKey(context.Context) ([]byte, error)
	Sign(context.Context, []byte) ([]byte, error)
}

type SignatureVerifier interface {
	Verify(pubkey, payload, signature []byte) error
}

// MultisigPoolPort owns all transaction parsing, signature, input/output and
// amount rules. Workflow layers must not reconstruct these rules themselves.
type MultisigPoolPort interface {
	BuildRefundPresignRequest(context.Context, OpeningInput, Signer) (*RefundPresignRequest, error)
	TransactionID(rawTx []byte) (Hash32, error)
	VerifyRefundExpired(*OpeningProof, time.Time) error
	BuildRefundSubmission(*OpeningProof) ([]byte, error)
	FundingTxID(rawTx []byte) (Hash32, error)
	VerifyOpening(*OpeningProof) error
	ParsePaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	ParseFinalPaymentState(context.Context, []byte, *OpeningProof) (*PaymentState, error)
	VerifyAcceptedPayment(*PaymentState, *OpeningProof) error
	VerifyArbitratedPayment(*PaymentState, *OpeningProof) error
	VerifyFinalPayment(*PaymentState, *OpeningProof) error
	VerifyCompletedFinalPayment(*SignedPayment, *OpeningProof) error
	CheckPaymentCapacity(context.Context, PaymentUpdateInput) error
	BuildPaymentUpdate(context.Context, PaymentUpdateInput) (*UnsignedPayment, error)
	SignSellerArbitrationCandidate(context.Context, *UnsignedPayment, Signer) ([]byte, error)
	SignBuyerPayment(context.Context, *UnsignedPayment, Signer) (*PaymentState, error)
	VerifyBuyerPayment(*PaymentState, *OpeningProof) error
	VerifySellerPayment(*PaymentState, *OpeningProof) error
	VerifySellerPaymentSignature(*PaymentState, []byte, *OpeningProof) error
	AttachSellerArbitrationSignature(context.Context, *PaymentState, []byte) (*PaymentState, error)
	AddSellerSignature(context.Context, *PaymentState, Signer) (*SignedPayment, error)
	SignArbiterPayment(context.Context, *PaymentState, Signer) ([]byte, error)
	AddArbitrationSignature(context.Context, *PaymentState, []byte) (*SignedPayment, error)
	BuildImmediateClose(context.Context, CloseInput) (*UnsignedPayment, error)
}

// NonFinalPoolNode must return only after the node accepted the update as the
// current higher-sequence spend of the pool output.
type NonFinalPoolNode interface {
	SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
	SubmitFinal(context.Context, []byte) (Hash32, error)
}

type ParticipantVerifier interface {
	VerifyPoolParticipants(proof *OpeningProof, buyerPubkey, sellerPubkey, arbiterPubkey []byte) error
}
