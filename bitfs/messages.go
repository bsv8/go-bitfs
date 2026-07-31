package bitfs

type FileQuoteTerms struct {
	SeedHash                    []byte
	BuyerPubkey                 []byte
	SeedPriceSat                uint64
	FullBlockPriceSat           uint64
	FileSize                    uint64
	QuoteExpiresAtUnix          int64
	SupportedArbiterPubkeysCBOR []byte
}

type SignedFileQuote struct {
	TermsCBOR           []byte
	SellerPubkey        []byte
	TermsSignature      []byte
	RecommendedFilename string
}
