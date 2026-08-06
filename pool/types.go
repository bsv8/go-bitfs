package pool

import (
	"context"
	"crypto/sha256"
	"time"
)

// ProtocolFamily is the go-bitfs pool workflow protocol.  It is deliberately
// separate from the MultisigPool library protocol embedded in OpeningProof.
const ProtocolFamily = "bitfs.pool.workflow.v3"

const MajorVersion uint64 = 3

const MultisigProtocol = "bitfs.pool.v4"

const MultisigVersion uint64 = 4

type Hash32 [sha256.Size]byte

type Reference struct {
	SpendTxID           Hash32
	BasePaymentSequence uint32
}

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

type RefundPresignResponse struct {
	Version               uint64
	SellerRefundSignature []byte
}

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
	EnsurePoolHealthy(context.Context, Hash32) error
	MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
	ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}

type PendingRequest struct {
	SpendTxID               Hash32
	BasePaymentSequence     uint32
	ContentRequestHash      Hash32
	ExpectedSellerAmountSat uint64
}

type PendingAcquireResult uint8

const (
	PendingAcquired    PendingAcquireResult = 1
	PendingAlreadyHeld PendingAcquireResult = 2
	PendingConflict    PendingAcquireResult = 3
)

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

type ParticipantVerifier interface {
	VerifyPoolParticipants(*OpeningProof, []byte, []byte, []byte) error
}

type NonFinalPoolNode interface {
	SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
	SubmitFinal(context.Context, []byte) (Hash32, error)
}
