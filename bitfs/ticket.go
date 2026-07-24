package bitfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bitfspb "github.com/bsv8/go-bitfs/proto/bitfspb"
)

var ticketSigningDomain = []byte("bitfs.ticket.v1")

const ticketSigningVersion byte = 1

// TicketSignatureVerifier 验证买方对票据摘要做出的签名。
// 调用方负责选用自己的 secp256k1 实现，本库不绑定钱包或密钥库。
type TicketSignatureVerifier func(pubKey []byte, digest [sha256.Size]byte, signature []byte) error

// ValidateHashGetTicket 校验不依赖当前时间和签名算法的票据结构约束。
func ValidateHashGetTicket(ticket *bitfspb.HashGetTicketV1) error {
	if ticket == nil {
		return errors.New("ticket is required")
	}
	if ticket.GetSessionId() == "" {
		return errors.New("ticket session_id is required")
	}
	if len(ticket.GetRootSeedHash()) != sha256.Size {
		return fmt.Errorf("ticket root_seed_hash length must be %d", sha256.Size)
	}
	if len(ticket.GetContentHash()) != sha256.Size {
		return fmt.Errorf("ticket content_hash length must be %d", sha256.Size)
	}
	if len(ticket.GetBuyerPubkey()) == 0 {
		return errors.New("ticket buyer_pubkey is required")
	}
	if len(ticket.GetSellerPubkey()) == 0 {
		return errors.New("ticket seller_pubkey is required")
	}
	if ticket.GetExpiresAtUnix() <= 0 {
		return errors.New("ticket expires_at_unix is required")
	}
	if ticket.GetContentIndex() == SeedContentIndex {
		if ticket.GetExpectedSize()%sha256.Size != 0 {
			return fmt.Errorf("seed ticket expected_size must be a multiple of %d", sha256.Size)
		}
		if !bytes.Equal(ticket.GetRootSeedHash(), ticket.GetContentHash()) {
			return errors.New("seed ticket content_hash must equal root_seed_hash")
		}
		return nil
	}
	if ticket.GetContentIndex() < 0 {
		return fmt.Errorf("invalid ticket content_index %d", ticket.GetContentIndex())
	}
	if ticket.GetExpectedSize() == 0 || ticket.GetExpectedSize() > BlockSize {
		return fmt.Errorf("invalid block ticket expected_size %d", ticket.GetExpectedSize())
	}
	return nil
}

// ValidateHashGetTicketAt 额外校验票据在给定时间仍可使用。
func ValidateHashGetTicketAt(ticket *bitfspb.HashGetTicketV1, now time.Time) error {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return err
	}
	if !now.Before(time.Unix(ticket.GetExpiresAtUnix(), 0)) {
		return errors.New("ticket is expired")
	}
	return nil
}

// HashGetTicketSigningPayload 以固定的非 Protobuf 编码序列化票据待签字段。
func HashGetTicketSigningPayload(ticket *bitfspb.HashGetTicketV1) ([]byte, error) {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return nil, err
	}
	buffer := make([]byte, 0, len(ticketSigningDomain)+1+128+
		len(ticket.GetSessionId())+len(ticket.GetRootSeedHash())+len(ticket.GetContentHash())+
		len(ticket.GetBuyerPubkey())+len(ticket.GetSellerPubkey()))
	buffer = append(buffer, ticketSigningDomain...)
	buffer = append(buffer, ticketSigningVersion)
	buffer = appendTicketString(buffer, ticket.GetSessionId())
	buffer = appendTicketUint64(buffer, ticket.GetSequence())
	buffer = appendTicketBytes(buffer, ticket.GetRootSeedHash())
	buffer = appendTicketBytes(buffer, ticket.GetContentHash())
	buffer = appendTicketInt64(buffer, ticket.GetContentIndex())
	buffer = appendTicketUint64(buffer, ticket.GetExpectedSize())
	buffer = appendTicketUint64(buffer, ticket.GetPriceSat())
	buffer = appendTicketBytes(buffer, ticket.GetBuyerPubkey())
	buffer = appendTicketBytes(buffer, ticket.GetSellerPubkey())
	buffer = appendTicketInt64(buffer, ticket.GetExpiresAtUnix())
	return buffer, nil
}

// HashGetTicketSigningDigest 计算票据待签字段的 sha256 摘要。
func HashGetTicketSigningDigest(ticket *bitfspb.HashGetTicketV1) ([sha256.Size]byte, error) {
	payload, err := HashGetTicketSigningPayload(ticket)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

// TicketID 返回票据稳定身份。它与待签字段摘要相同，且不包含签名字节。
func TicketID(ticket *bitfspb.HashGetTicketV1) ([sha256.Size]byte, error) {
	return HashGetTicketSigningDigest(ticket)
}

// VerifyHashGetTicket 验证票据结构和买方签名。
func VerifyHashGetTicket(ticket *bitfspb.HashGetTicketV1, verifier TicketSignatureVerifier) error {
	if verifier == nil {
		return errors.New("ticket signature verifier is required")
	}
	if len(ticket.GetBuyerSignature()) == 0 {
		return errors.New("ticket buyer_signature is required")
	}
	digest, err := HashGetTicketSigningDigest(ticket)
	if err != nil {
		return err
	}
	if err := verifier(ticket.GetBuyerPubkey(), digest, ticket.GetBuyerSignature()); err != nil {
		return fmt.Errorf("buyer signature invalid: %w", err)
	}
	return nil
}

// ValidateFileQuote 校验报价的结构和最后一块价格约束。
func ValidateFileQuote(quote *bitfspb.FileQuoteV1) error {
	if quote == nil {
		return errors.New("file quote is required")
	}
	if len(quote.GetSeedHash()) != sha256.Size {
		return fmt.Errorf("quote seed_hash length must be %d", sha256.Size)
	}
	if quote.GetRecommendedFilename() == "" {
		return errors.New("quote recommended_filename is required")
	}
	if quote.GetQuoteExpiresAtUnix() <= 0 {
		return errors.New("quote quote_expires_at_unix is required")
	}
	if len(quote.GetSellerPubkey()) == 0 {
		return errors.New("quote seller_pubkey is required")
	}
	if quote.GetFileSize() > 0 && quote.GetFileSize()%BlockSize == 0 && quote.GetEndblockPriceSat() != quote.GetBlockPriceSat() {
		return errors.New("endblock_price_sat must equal block_price_sat for a full final block")
	}
	if quote.GetBlockCount() != 0 && quote.GetBlockCount() != blockCountForSize(quote.GetFileSize()) {
		return fmt.Errorf("quote block_count %d does not match file_size", quote.GetBlockCount())
	}
	return nil
}

// ValidateFileQuoteAt 额外校验报价在给定时间仍然有效。
func ValidateFileQuoteAt(quote *bitfspb.FileQuoteV1, now time.Time) error {
	if err := ValidateFileQuote(quote); err != nil {
		return err
	}
	if !now.Before(time.Unix(quote.GetQuoteExpiresAtUnix(), 0)) {
		return errors.New("file quote is expired")
	}
	return nil
}

// ValidateDelivery 校验交付与票据的会话、顺序、内容哈希和原始 payload 哈希。
func ValidateDelivery(ticket *bitfspb.HashGetTicketV1, delivery *bitfspb.HashDeliveryV1) error {
	if err := ValidateHashGetTicket(ticket); err != nil {
		return err
	}
	if delivery == nil {
		return errors.New("delivery is required")
	}
	if delivery.GetSessionId() != ticket.GetSessionId() {
		return errors.New("delivery session_id does not match ticket")
	}
	if delivery.GetSequence() != ticket.GetSequence() {
		return errors.New("delivery sequence does not match ticket")
	}
	if !bytes.Equal(delivery.GetContentHash(), ticket.GetContentHash()) {
		return errors.New("delivery content_hash does not match ticket")
	}
	digest, err := ContentHash(ticket.GetContentIndex(), ticket.GetExpectedSize(), delivery.GetPayload())
	if err != nil {
		return err
	}
	if !bytes.Equal(digest[:], ticket.GetContentHash()) {
		return errors.New("delivery payload hash does not match ticket")
	}
	return nil
}

// IsSeedTicket 报告票据是否购买 seed。
func IsSeedTicket(ticket *bitfspb.HashGetTicketV1) bool {
	return ticket != nil && ticket.GetContentIndex() == SeedContentIndex
}

// appendTicketString 追加四字节大端长度和字符串字节。
func appendTicketString(buffer []byte, value string) []byte {
	return appendTicketBytes(buffer, []byte(value))
}

// appendTicketBytes 追加四字节大端长度和原始字节。
func appendTicketBytes(buffer []byte, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer = append(buffer, length[:]...)
	return append(buffer, value...)
}

// appendTicketUint64 追加八字节大端无符号整数。
func appendTicketUint64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}

// appendTicketInt64 追加八字节大端有符号整数的位表示。
func appendTicketInt64(buffer []byte, value int64) []byte {
	return appendTicketUint64(buffer, uint64(value))
}

// blockCountForSize 返回文件大小对应的 block 数量。
func blockCountForSize(fileSize uint64) uint32 {
	if fileSize == 0 {
		return 0
	}
	return uint32((fileSize + BlockSize - 1) / BlockSize)
}
