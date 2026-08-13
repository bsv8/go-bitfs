package bitfs

// FileQuoteTerms is the seller's signed pricing and expiry commitment to one buyer.
type FileQuoteTerms struct {
	SeedHash                    []byte
	BuyerPubkey                 []byte
	SeedPriceSat                uint64
	FullBlockPriceSat           uint64
	FileSize                    uint64
	QuoteExpiresAtUnix          int64
	SupportedArbiterPubkeysCBOR []byte
}

// SignedFileQuote carries canonical quote terms, the seller identity and
// signature, and a display-only recommended filename.
type SignedFileQuote struct {
	TermsCBOR           []byte
	SellerPubkey        []byte
	TermsSignature      []byte
	RecommendedFilename string
}
