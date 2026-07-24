package bitfs

// FileQuote is a seller's price for a complete file identified by SeedHash.
// It is an asynchronous BitFS business message, not an RPC request.
type FileQuote struct {
	SeedHash                []byte
	SeedPriceSat            uint64
	BlockPriceSat           uint64
	EndblockPriceSat        uint64
	FileSize                uint64
	RecommendedFilename     string
	QuoteExpiresAtUnix      int64
	BlockCount              uint32
	SellerPubkey            []byte
	SupportedArbiterPubkeys [][]byte
}

// HashGetTicket is a buyer-signed authorization to deliver exactly one hash.
type HashGetTicket struct {
	SessionID      string
	Sequence       uint64
	RootSeedHash   []byte
	ContentHash    []byte
	ContentIndex   int64
	ExpectedSize   uint64
	PriceSat       uint64
	BuyerPubkey    []byte
	SellerPubkey   []byte
	ExpiresAtUnix  int64
	BuyerSignature []byte
}

// HashDelivery is the asynchronous seller-to-buyer delivery for one ticket.
type HashDelivery struct {
	SessionID   string
	Sequence    uint64
	ContentHash []byte
	Payload     []byte
}

// ArbitrationClaimantRole identifies the party submitting an arbitration claim.
type ArbitrationClaimantRole uint8

const (
	ArbitrationClaimantRoleBuyer  ArbitrationClaimantRole = 1
	ArbitrationClaimantRoleSeller ArbitrationClaimantRole = 2
)

// ArbitrationState is the durable state of an arbitration record.
type ArbitrationState uint8

const (
	ArbitrationStatePending   ArbitrationState = 1
	ArbitrationStateApproved  ArbitrationState = 2
	ArbitrationStateRejected  ArbitrationState = 3
	ArbitrationStateDelivered ArbitrationState = 4
	ArbitrationStateClosed    ArbitrationState = 5
)

// ArbitrationClaim is the evidence submitted by a buyer or seller.
type ArbitrationClaim struct {
	Ticket       *HashGetTicket
	Payload      []byte
	ClaimantRole ArbitrationClaimantRole
}

// ArbitrationDecision is the arbiter's business decision for a ticket.
type ArbitrationDecision struct {
	SessionID        string
	Sequence         uint64
	TicketID         []byte
	Approved         bool
	ReasonCode       string
	FinalPayoutSat   uint64
	SellerPubkey     []byte
	RecoveredPayload []byte
}

// ArbitrationRecord is a durable snapshot of an arbitration state machine.
type ArbitrationRecord struct {
	SessionID        string
	Sequence         uint64
	State            ArbitrationState
	Claim            *ArbitrationClaim
	Decision         *ArbitrationDecision
	CreatedAtUnix    int64
	UpdatedAtUnix    int64
	RejectReasonCode string
}
