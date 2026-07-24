package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

var ticketSigningDomain = []byte("bitfs.ticket.v1")

const ticketSigningVersion byte = 1

// TicketSignatureVerifier verifies a buyer signature without binding BitFS to a wallet implementation.
type TicketSignatureVerifier func(pubKey []byte, digest [sha256.Size]byte, signature []byte) error

// ValidateHashGetTicket validates ticket structure independently of time and signature algorithm.
func ValidateHashGetTicket(ticket *HashGetTicket) error {
	if ticket == nil {
		return errors.New("ticket is required")
	}
	if ticket.SessionID == "" {
		return errors.New("ticket session_id is required")
	}
	if len(ticket.RootSeedHash) != sha256.Size {
		return fmt.Errorf("ticket root_seed_hash length must be %d", sha256.Size)
	}
	if len(ticket.ContentHash) != sha256.Size {
		return fmt.Errorf("ticket content_hash length must be %d", sha256.Size)
	}
	if len(ticket.BuyerPubkey) == 0 {
		return errors.New("ticket buyer_pubkey is required")
	}
	if len(ticket.SellerPubkey) == 0 {
		return errors.New("ticket seller_pubkey is required")
	}
	if ticket.ExpiresAtUnix <= 0 {
		return errors.New("ticket expires_at_unix is required")
	}
	if ticket.ContentIndex == SeedContentIndex {
		if ticket.ExpectedSize%sha256.Size != 0 {
			return fmt.Errorf("seed ticket expected_size must be a multiple of %d", sha256.Size)
		}
		if !bytes.Equal(ticket.RootSeedHash, ticket.ContentHash) {
			return errors.New("seed ticket content_hash must equal root_seed_hash")
		}
		return nil
	}
	if ticket.ContentIndex < 0 {
		return fmt.Errorf("invalid ticket content_index %d", ticket.ContentIndex)
	}
	if ticket.ExpectedSize == 0 || ticket.ExpectedSize > BlockSize {
		return fmt.Errorf("invalid block ticket expected_size %d", ticket.ExpectedSize)
	}
	return nil
}

// ValidateHashGetTicketAt additionally verifies a ticket has not expired.
func ValidateHashGetTicketAt(ticket *HashGetTicket, now time.Time) error {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return err
	}
	if !now.Before(time.Unix(ticket.ExpiresAtUnix, 0)) {
		return errors.New("ticket is expired")
	}
	return nil
}

// HashGetTicketSigningPayload is the domain-separated canonical CBOR ticket preimage.
// BuyerSignature is deliberately omitted.
func HashGetTicketSigningPayload(ticket *HashGetTicket) ([]byte, error) {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return nil, err
	}
	return encodeArray(string(ticketSigningDomain), uint64(ticketSigningVersion), protocolMajorVersion, messageKindHashGetTicket, ticket.SessionID, ticket.Sequence, bstr(ticket.RootSeedHash), bstr(ticket.ContentHash), ticket.ContentIndex, ticket.ExpectedSize, ticket.PriceSat, bstr(ticket.BuyerPubkey), bstr(ticket.SellerPubkey), ticket.ExpiresAtUnix)
}

// HashGetTicketSigningDigest calculates the stable ticket identifier and signing digest.
func HashGetTicketSigningDigest(ticket *HashGetTicket) ([sha256.Size]byte, error) {
	payload, err := HashGetTicketSigningPayload(ticket)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

// TicketID returns the stable business identity of a ticket, excluding its signature bytes.
func TicketID(ticket *HashGetTicket) ([sha256.Size]byte, error) {
	return HashGetTicketSigningDigest(ticket)
}

// VerifyHashGetTicket validates ticket structure and its buyer signature.
func VerifyHashGetTicket(ticket *HashGetTicket, verifier TicketSignatureVerifier) error {
	if verifier == nil {
		return errors.New("ticket signature verifier is required")
	}
	if len(ticket.BuyerSignature) == 0 {
		return errors.New("ticket buyer_signature is required")
	}
	digest, err := HashGetTicketSigningDigest(ticket)
	if err != nil {
		return err
	}
	if err := verifier(ticket.BuyerPubkey, digest, ticket.BuyerSignature); err != nil {
		return fmt.Errorf("buyer signature invalid: %w", err)
	}
	return nil
}

// ValidateFileQuote validates quote structure and its final-block price constraint.
func ValidateFileQuote(quote *FileQuote) error {
	if quote == nil {
		return errors.New("file quote is required")
	}
	if len(quote.SeedHash) != sha256.Size {
		return fmt.Errorf("quote seed_hash length must be %d", sha256.Size)
	}
	if quote.RecommendedFilename == "" {
		return errors.New("quote recommended_filename is required")
	}
	if quote.QuoteExpiresAtUnix <= 0 {
		return errors.New("quote quote_expires_at_unix is required")
	}
	if len(quote.SellerPubkey) == 0 {
		return errors.New("quote seller_pubkey is required")
	}
	if quote.FileSize > 0 && quote.FileSize%BlockSize == 0 && quote.EndblockPriceSat != quote.BlockPriceSat {
		return errors.New("endblock_price_sat must equal block_price_sat for a full final block")
	}
	if quote.BlockCount != 0 && quote.BlockCount != blockCountForSize(quote.FileSize) {
		return fmt.Errorf("quote block_count %d does not match file_size", quote.BlockCount)
	}
	return nil
}

// ValidateFileQuoteAt additionally verifies a quote has not expired.
func ValidateFileQuoteAt(quote *FileQuote, now time.Time) error {
	if err := ValidateFileQuote(quote); err != nil {
		return err
	}
	if !now.Before(time.Unix(quote.QuoteExpiresAtUnix, 0)) {
		return errors.New("file quote is expired")
	}
	return nil
}

// ValidateDelivery validates delivery correlation and the raw content hash.
func ValidateDelivery(ticket *HashGetTicket, delivery *HashDelivery) error {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return err
	}
	if delivery == nil {
		return errors.New("delivery is required")
	}
	if delivery.SessionID != ticket.SessionID {
		return errors.New("delivery session_id does not match ticket")
	}
	if delivery.Sequence != ticket.Sequence {
		return errors.New("delivery sequence does not match ticket")
	}
	if !bytes.Equal(delivery.ContentHash, ticket.ContentHash) {
		return errors.New("delivery content_hash does not match ticket")
	}
	digest, err := ContentHash(ticket.ContentIndex, ticket.ExpectedSize, delivery.Payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest[:], ticket.ContentHash) {
		return errors.New("delivery payload hash does not match ticket")
	}
	return nil
}

// IsSeedTicket reports whether a ticket purchases a seed rather than a block.
func IsSeedTicket(ticket *HashGetTicket) bool {
	return ticket != nil && ticket.ContentIndex == SeedContentIndex
}

func blockCountForSize(fileSize uint64) uint32 {
	if fileSize == 0 {
		return 0
	}
	return uint32((fileSize + BlockSize - 1) / BlockSize)
}
