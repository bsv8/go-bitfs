package bitfs

// CloneSignedFileQuote returns an independent copy for API and storage
// boundaries.
func CloneSignedFileQuote(quote *SignedFileQuote) *SignedFileQuote {
	return cloneSignedFileQuote(quote)
}

// CloneSignedContentRequest returns a deep copy of a 003 credential, including
// independent terms, public-key, and signature byte slices.
func CloneSignedContentRequest(request *SignedContentRequest) *SignedContentRequest {
	return cloneSignedContentRequest(request)
}

// CloneSignedContentDelivery returns a deep copy of a 004 credential, including
// independent terms, public-key, payload, and signature byte slices.
func CloneSignedContentDelivery(delivery *SignedContentDelivery) *SignedContentDelivery {
	return cloneSignedContentDelivery(delivery)
}
