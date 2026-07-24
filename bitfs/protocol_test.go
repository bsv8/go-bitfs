package bitfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// TestSeedBytesAreOnlyConcatenatedHashes 验证 seed 不含 BSE1 头或任何元数据。
func TestSeedBytesAreOnlyConcatenatedHashes(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, sha256.Size)
	second := bytes.Repeat([]byte{0x22}, sha256.Size)

	seed, err := BuildSeedBytes([][]byte{first, second})
	if err != nil {
		t.Fatalf("BuildSeedBytes() error = %v", err)
	}
	if len(seed) != 2*sha256.Size {
		t.Fatalf("seed length = %d, want %d", len(seed), 2*sha256.Size)
	}
	if !bytes.Equal(seed, append(append([]byte(nil), first...), second...)) {
		t.Fatal("seed bytes contain data other than ordered block hashes")
	}
	parsed, err := ParseSeedBytes(seed)
	if err != nil {
		t.Fatalf("ParseSeedBytes() error = %v", err)
	}
	if len(parsed) != 2 || !bytes.Equal(parsed[0], first) || !bytes.Equal(parsed[1], second) {
		t.Fatal("parsed seed hashes do not match")
	}
}

// TestContentHashDoesNotPadFinalBlock 验证最后一个残块按原始字节哈希。
func TestContentHashDoesNotPadFinalBlock(t *testing.T) {
	payload := []byte("final-block")
	got, err := ContentHash(3, uint64(len(payload)), payload)
	if err != nil {
		t.Fatalf("ContentHash() error = %v", err)
	}
	want := sha256.Sum256(payload)
	if got != want {
		t.Fatalf("content hash = %x, want raw payload hash %x", got, want)
	}
	padded := make([]byte, BlockSize)
	copy(padded, payload)
	if got == sha256.Sum256(padded) {
		t.Fatal("content hash unexpectedly used zero-padded payload")
	}
}

// TestValidateDeliveryUsesRawFinalBlockHash 验证交付校验沿用残块原始哈希规则。
func TestValidateDeliveryUsesRawFinalBlockHash(t *testing.T) {
	payload := []byte("tail")
	contentHash := sha256.Sum256(payload)
	ticket := testTicket(contentHash[:], 0, uint64(len(payload)))
	delivery := &HashDelivery{
		SessionID:   ticket.SessionID,
		Sequence:    ticket.Sequence,
		ContentHash: contentHash[:],
		Payload:     payload,
	}
	if err := ValidateDelivery(ticket, delivery); err != nil {
		t.Fatalf("ValidateDelivery() error = %v", err)
	}
}

// TestValidateArbitrationClaimRequiresSellerPayload 验证卖方仲裁必须提交可验证二进制。
func TestValidateArbitrationClaimRequiresSellerPayload(t *testing.T) {
	contentHash := sha256.Sum256([]byte("block"))
	ticket := testTicket(contentHash[:], 0, 5)
	ticket.BuyerSignature = []byte{0x01}
	claim := &ArbitrationClaim{
		Ticket:       ticket,
		ClaimantRole: ArbitrationClaimantRoleSeller,
	}
	_, err := ValidateArbitrationClaim(claim, time.Unix(100, 0), testVerifier)
	if err == nil || err.Error() != "seller arbitration claim payload is required" {
		t.Fatalf("ValidateArbitrationClaim() error = %v, want missing payload error", err)
	}
}

// TestValidateArbitrationClaimAcceptsVerifiedSellerEvidence 验证票据和原始二进制能构成卖方证据。
func TestValidateArbitrationClaimAcceptsVerifiedSellerEvidence(t *testing.T) {
	payload := []byte("block")
	contentHash := sha256.Sum256(payload)
	ticket := testTicket(contentHash[:], 0, uint64(len(payload)))
	ticket.BuyerSignature = []byte{0x01}
	claim := &ArbitrationClaim{
		Ticket:       ticket,
		Payload:      payload,
		ClaimantRole: ArbitrationClaimantRoleSeller,
	}
	evidence, err := ValidateArbitrationClaim(claim, time.Unix(100, 0), testVerifier)
	if err != nil {
		t.Fatalf("ValidateArbitrationClaim() error = %v", err)
	}
	if !evidence.PayloadVerified || len(evidence.TicketID) != sha256.Size {
		t.Fatal("arbitration evidence was not verified")
	}
}

// testTicket 构造满足基础结构约束的 block 票据。
func testTicket(contentHash []byte, contentIndex int64, expectedSize uint64) *HashGetTicket {
	rootHash := bytes.Repeat([]byte{0x44}, sha256.Size)
	return &HashGetTicket{
		SessionID:     "session-1",
		Sequence:      1,
		RootSeedHash:  rootHash,
		ContentHash:   contentHash,
		ContentIndex:  contentIndex,
		ExpectedSize:  expectedSize,
		PriceSat:      1,
		BuyerPubkey:   []byte{0x02, 0x01},
		SellerPubkey:  []byte{0x03, 0x02},
		ExpiresAtUnix: 200,
	}
}

// testVerifier 提供稳定的测试验签实现。
func testVerifier(_ []byte, _ [sha256.Size]byte, signature []byte) error {
	if len(signature) == 1 && signature[0] == 0x01 {
		return nil
	}
	return errors.New("invalid test signature")
}
