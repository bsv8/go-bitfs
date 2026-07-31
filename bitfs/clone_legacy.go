package bitfs

func CloneFileQuote(quote *FileQuote) *FileQuote {
	if quote == nil {
		return nil
	}
	cloned := *quote
	cloned.SeedHash = append([]byte(nil), quote.SeedHash...)
	cloned.SellerPubkey = append([]byte(nil), quote.SellerPubkey...)
	cloned.SupportedArbiterPubkeys = cloneByteSlices(quote.SupportedArbiterPubkeys)
	return &cloned
}

func CloneHashGetTicket(ticket *HashGetTicket) *HashGetTicket {
	if ticket == nil {
		return nil
	}
	cloned := *ticket
	cloned.RootSeedHash = append([]byte(nil), ticket.RootSeedHash...)
	cloned.ContentHash = append([]byte(nil), ticket.ContentHash...)
	cloned.BuyerPubkey = append([]byte(nil), ticket.BuyerPubkey...)
	cloned.SellerPubkey = append([]byte(nil), ticket.SellerPubkey...)
	cloned.BuyerSignature = append([]byte(nil), ticket.BuyerSignature...)
	return &cloned
}

func CloneHashDelivery(delivery *HashDelivery) *HashDelivery {
	if delivery == nil {
		return nil
	}
	cloned := *delivery
	cloned.ContentHash = append([]byte(nil), delivery.ContentHash...)
	cloned.Payload = append([]byte(nil), delivery.Payload...)
	return &cloned
}

// CloneSignedFileQuote returns an independent copy suitable for an API
// boundary or storage adapter.
func CloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	return cloneSignedFileQuote(quote)
}

// CloneSignedContentRequest returns an independent copy suitable for a
// workflow entry point.
func CloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	return cloneSignedContentRequest(request)
}

// CloneSignedContentDelivery returns an independent copy suitable for a
// workflow entry point.
func CloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	return cloneSignedContentDelivery(delivery)
}
