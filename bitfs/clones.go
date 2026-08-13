package bitfs

// CloneSignedFileQuote returns an independent copy for API and storage
// boundaries.
func CloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	return cloneSignedFileQuote(quote)
}

// CloneSignedContentRequest returns an independent copy of SignedContentRequest, including copies of mutable byte slices.
func CloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	return cloneSignedContentRequest(request)
}

// CloneSignedContentDelivery returns an independent copy of SignedContentDelivery, including copies of mutable byte slices.
func CloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	return cloneSignedContentDelivery(delivery)
}
