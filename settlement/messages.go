// Package settlement defines the transport-neutral settlement protocol.
package settlement

const MajorVersion uint64 = 1

type Kind uint64

const (
	KindPaymentPrepare Kind = iota + 1
	KindPaymentPrepared
	KindPaymentCommit
	KindPaymentCommitted
	KindPaymentAbort
	KindPaymentAborted
	KindPaymentRejected
	KindArbitrationRequest
	KindCloseSignatureRequest
	KindCloseSignature
	KindPoolArbitrated
	KindPoolRefundPresignRequest
	KindPoolRefundPresignResponse
	KindPoolFundingTxDelivery
)

type State uint8

const (
	StateOpening    State = 1
	StateActive     State = 2
	StateUpdating   State = 3
	StateDisputed   State = 4
	StateClosed     State = 5
	StateArbitrated State = 6
)

// TicketRef is the payment layer's idempotent reference to a BitFS ticket.
type TicketRef struct {
	_           struct{} `cbor:",toarray"`
	SpendTxID   []byte
	Sequence    uint64
	ContentHash []byte
	PriceSat    uint64
	TicketID    []byte
}

type PaymentPrepare struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	Ticket      TicketRef
}
type PaymentPrepared struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	TicketID    []byte
	ProposalID  []byte
}
type PaymentCommit struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	Ticket      TicketRef
	ProposalID  []byte
}
type PaymentCommitted struct {
	_                 struct{} `cbor:",toarray"`
	Version           uint64
	MessageKind       Kind
	TicketID          []byte
	SequenceAfter     uint64
	ServerAmountAfter uint64
	ClientAmountAfter uint64
}
type PaymentAbort struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	Ticket      TicketRef
	ProposalID  []byte
	ReasonCode  string
}
type PaymentAborted struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	TicketID    []byte
	ReasonCode  string
}
type PaymentRejected struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	TicketID    []byte
	Stage       Kind
	ReasonCode  string
}

// ArbitrationRequest starts the pool's terminal settlement state machine.
type ArbitrationRequest struct {
	_                struct{} `cbor:",toarray"`
	Version          uint64
	MessageKind      Kind
	SpendTxID        []byte
	Approved         bool
	ReasonCode       string
	ArbiterSignature []byte
	FinalPayoutSat   uint64
}
type CloseSignatureRequest struct {
	_                        struct{} `cbor:",toarray"`
	Version                  uint64
	MessageKind              Kind
	SpendTxID                []byte
	ArbitrationID            []byte
	UnsignedCloseTransaction []byte
	CloseSighash             []byte
}
type CloseSignature struct {
	_                                  struct{} `cbor:",toarray"`
	Version                            uint64
	MessageKind                        Kind
	SpendTxID                          []byte
	ArbitrationID                      []byte
	ArbiterSignatureOnCloseTransaction []byte
}
type PoolArbitrated struct {
	_                    struct{} `cbor:",toarray"`
	Version              uint64
	MessageKind          Kind
	SpendTxID            []byte
	ArbitrationID        []byte
	ClosingTransactionID []byte
	ClosingTransaction   []byte
}

// PoolRefundPresignRequest asks the seller to pre-sign the timelocked refund
// transaction before the buyer reveals the funding transaction. FundingTx is
// deliberately absent: the seller receives it only after returning the
// pre-signature.
type PoolRefundPresignRequest struct {
	_                    struct{} `cbor:",toarray"`
	Version              uint64
	MessageKind          Kind
	RefundTx             []byte
	FundingTxID          []byte
	PoolOutputIndex      uint32
	PoolOutputSatoshis   uint64
	PoolLockingScript    []byte
	BuyerRefundSignature []byte
}

// PoolRefundPresignResponse contains only the seller's signature. The
// signature itself binds it to the exact request transaction and source output.
type PoolRefundPresignResponse struct {
	_                     struct{} `cbor:",toarray"`
	Version               uint64
	MessageKind           Kind
	SellerRefundSignature []byte
}

// PoolFundingTxDelivery reveals the buyer-signed funding transaction after
// the buyer has already verified and persisted the seller's pre-signature.
type PoolFundingTxDelivery struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	MessageKind Kind
	FundingTx   []byte
}

func NewPaymentPrepare(ticket TicketRef) *PaymentPrepare {
	return &PaymentPrepare{Version: MajorVersion, MessageKind: KindPaymentPrepare, Ticket: ticket}
}
func NewPaymentCommit(ticket TicketRef, proposalID []byte) *PaymentCommit {
	return &PaymentCommit{Version: MajorVersion, MessageKind: KindPaymentCommit, Ticket: ticket, ProposalID: proposalID}
}
func NewArbitrationRequest(spendTxID []byte, approved bool, reasonCode string, signature []byte, payout uint64) *ArbitrationRequest {
	return &ArbitrationRequest{Version: MajorVersion, MessageKind: KindArbitrationRequest, SpendTxID: spendTxID, Approved: approved, ReasonCode: reasonCode, ArbiterSignature: signature, FinalPayoutSat: payout}
}

func NewPoolRefundPresignRequest(refundTx, fundingTxID []byte, poolOutputIndex uint32, poolOutputSatoshis uint64, poolLockingScript, buyerRefundSignature []byte) *PoolRefundPresignRequest {
	return &PoolRefundPresignRequest{
		Version:              MajorVersion,
		MessageKind:          KindPoolRefundPresignRequest,
		RefundTx:             append([]byte(nil), refundTx...),
		FundingTxID:          append([]byte(nil), fundingTxID...),
		PoolOutputIndex:      poolOutputIndex,
		PoolOutputSatoshis:   poolOutputSatoshis,
		PoolLockingScript:    append([]byte(nil), poolLockingScript...),
		BuyerRefundSignature: append([]byte(nil), buyerRefundSignature...),
	}
}

func NewPoolRefundPresignResponse(sellerRefundSignature []byte) *PoolRefundPresignResponse {
	return &PoolRefundPresignResponse{
		Version:               MajorVersion,
		MessageKind:           KindPoolRefundPresignResponse,
		SellerRefundSignature: append([]byte(nil), sellerRefundSignature...),
	}
}

func NewPoolFundingTxDelivery(fundingTx []byte) *PoolFundingTxDelivery {
	return &PoolFundingTxDelivery{
		Version:     MajorVersion,
		MessageKind: KindPoolFundingTxDelivery,
		FundingTx:   append([]byte(nil), fundingTx...),
	}
}
