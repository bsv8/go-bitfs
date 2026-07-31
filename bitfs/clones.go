package bitfs

// CloneSignedFileQuote returns an independent copy for API and storage
// boundaries.
func CloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	return cloneSignedFileQuote(quote)
}

func CloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	return cloneSignedContentRequest(request)
}

func CloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	return cloneSignedContentDelivery(delivery)
}
