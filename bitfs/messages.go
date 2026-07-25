package bitfs

// FileQuote is the legacy unsigned V1 seller price message. New integrations
// should use SignedFileQuote, whose signed FileQuoteTerms are self-verifying.
// It is retained for V1 wire compatibility.
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

// FileQuoteTerms is the seller-signed commercial commitment for one buyer and
// one file. It deliberately contains no display metadata: metadata such as a
// suggested filename is not part of the economic truth of a quote.
//
// The wire representation is obtained with EncodeFileQuoteTerms. Its exact
// canonical CBOR bytes are the input to TermsSignature.
type FileQuoteTerms struct {
	SeedHash                    []byte
	BuyerPubkey                 []byte
	SeedPriceSat                uint64
	FullBlockPriceSat           uint64
	FileSize                    uint64
	QuoteExpiresAtUnix          int64
	SupportedArbiterPubkeysCBOR []byte
}

// SignedFileQuote is a portable, self-verifying seller quote credential.
// TermsSignature is a seller signature over TermsCBOR. RecommendedFilename is
// deliberately unsigned display metadata and must not be used for any payment,
// identity, path, or content decision.
type SignedFileQuote struct {
	TermsCBOR           []byte
	SellerPubkey        []byte
	TermsSignature      []byte
	RecommendedFilename string
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
