package content

import (
	"bytes"
	"time"

	"github.com/bsv8/go-bitfs/protocol"
)

// VerifiedQuote 是字段私有、访问器防御性复制的已验证报价：它证明卖方签名、
// 条款结构与其绑定关系全部正确（Verified），并携带买方做后续时间判断所需的
// 最终规范化 terms。它不拥有存储或网络行为；应用自行保存 exact Kind 1 bytes。
type VerifiedQuote struct {
	// quote 是深拷贝的完整已签报价凭证；外部无法修改内部字节。
	quote *SignedFileQuote
	// terms 是从 exact file_quote_terms_cbor 严格解码的最终条款。
	terms *FileQuoteTerms
	// id = SHA-256(exact file_quote_terms_cbor)。
	id protocol.FileQuoteTermsID
}

// newVerifiedQuote 是包内唯一构造入口：只能在完整证据验证成功后调用；
// 外部包无法把伪造 DTO 包装成 VerifiedQuote。
func newVerifiedQuote(quote *SignedFileQuote, terms *FileQuoteTerms, id protocol.FileQuoteTermsID) *VerifiedQuote {
	return &VerifiedQuote{quote: cloneSignedFileQuote(quote), terms: cloneFileQuoteTerms(terms), id: id}
}

// VerifyQuoteEvidence 是时间无关的 VerifiedQuote 构造路径：验证结构与卖方
// 统一签名并计算 typed ID，不读取任何时间事实。需要过期判断的调用方应在拿到
// 结果后用显式 Facts 自行比较 QuoteExpiresAtUnixSeconds。
func VerifyQuoteEvidence(quote *SignedFileQuote) (*VerifiedQuote, error) {
	terms, err := VerifyFileQuoteEvidence(quote)
	if err != nil {
		return nil, err
	}
	id, err := FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		return nil, err
	}
	return newVerifiedQuote(quote, terms, id), nil
}

// VerifyQuote 执行时间无关证据验证（结构与卖方统一签名）与显式时间过期判断，
// 不绑定调用方身份；买方应用自行比较返回 terms 的 BuyerPublicKey 与本地身份。
// 时间事实经 protocol.Facts.RequireNow 获取：零值时间直接拒绝，绝不回退
// 系统时钟，也绝不可能用零值绕过过期门禁。
func VerifyQuote(quote *SignedFileQuote, facts protocol.Facts) (*VerifiedQuote, error) {
	const op = "content.VerifyQuote"
	at, err := facts.RequireNow()
	if err != nil {
		return nil, protocol.Wrap(err, op, protocol.CodeInvalidEvidence, 1, "facts.now")
	}
	verified, err := VerifyQuoteEvidence(quote)
	if err != nil {
		return nil, err
	}
	if !at.Before(time.Unix(verified.terms.QuoteExpiresAtUnixSeconds, 0)) {
		return nil, protocol.Errorf(op, protocol.CodeExpired, 1, "quote_expires_at_unix_seconds", "file quote is expired")
	}
	return verified, nil
}

// VerifyQuoteForBuyer 在 VerifyQuote 的基础上再绑定买方归属：报价必须命名
// 指定压缩公钥，否则返回 unauthorized。伪造、他人报价或已过期报价都会被拒绝。
func VerifyQuoteForBuyer(quote *SignedFileQuote, facts protocol.Facts, buyerPublicKey []byte) (*VerifiedQuote, error) {
	const op = "content.VerifyQuoteForBuyer"
	if len(buyerPublicKey) != 32+1 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 1, "buyer_public_key", "buyer public key must be a compressed key")
	}
	verified, err := VerifyQuote(quote, facts)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(verified.terms.BuyerPublicKey, buyerPublicKey) {
		return nil, protocol.Errorf(op, protocol.CodeUnauthorized, 1, "buyer_public_key", "this quote names another buyer")
	}
	return verified, nil
}

// Quote 返回深拷贝的完整已签报价凭证（含 exact terms CBOR 与卖方签名）。
func (v *VerifiedQuote) Quote() *SignedFileQuote {
	if v == nil || v.quote == nil {
		return nil
	}
	return cloneSignedFileQuote(v.quote)
}

// Terms 返回深拷贝的已解码条款；RecommendedFilename 是实际签署的单一来源值。
func (v *VerifiedQuote) Terms() *FileQuoteTerms {
	if v == nil || v.terms == nil {
		return nil
	}
	return cloneFileQuoteTerms(v.terms)
}

// ID 返回 file_quote_terms_id = SHA-256(exact file_quote_terms_cbor)。
func (v *VerifiedQuote) ID() protocol.FileQuoteTermsID {
	if v == nil {
		return protocol.FileQuoteTermsID{}
	}
	return v.id
}

// ExpiresAt 返回报价失效时间（UTC Unix 秒）；过期判断由调用方用自己的显式
// 时间事实完成，SDK 不读钟。
func (v *VerifiedQuote) ExpiresAt() time.Time {
	if v == nil || v.terms == nil {
		return time.Time{}
	}
	return time.Unix(v.terms.QuoteExpiresAtUnixSeconds, 0)
}

// SeedHash 返回报价种子摘要的副本。
func (v *VerifiedQuote) SeedHash() []byte {
	if v == nil || v.terms == nil {
		return nil
	}
	return append([]byte(nil), v.terms.SeedHash...)
}

// BuyerPublicKey 返回唯一被授权买方的压缩公钥副本。
func (v *VerifiedQuote) BuyerPublicKey() []byte {
	if v == nil || v.terms == nil {
		return nil
	}
	return append([]byte(nil), v.terms.BuyerPublicKey...)
}

// SellerPublicKey 返回卖方压缩公钥副本。
func (v *VerifiedQuote) SellerPublicKey() []byte {
	if v == nil || v.quote == nil {
		return nil
	}
	return append([]byte(nil), v.quote.SellerPublicKey...)
}

// SupportedArbiterPublicKeys 解码并返回受支持仲裁公钥的深拷贝列表。
func (v *VerifiedQuote) SupportedArbiterPublicKeys() [][]byte {
	if v == nil || v.terms == nil {
		return nil
	}
	keys, err := DecodeSupportedArbiterPublicKeys(v.terms.SupportedArbiterPublicKeysCBOR)
	if err != nil {
		return nil
	}
	return keys
}

// AllowsArbiter 报告指定仲裁公钥是否在报价允许列表内。
func (v *VerifiedQuote) AllowsArbiter(publicKey []byte) bool {
	if v == nil || v.terms == nil {
		return false
	}
	return containsArbiterPublicKey(v.terms.SupportedArbiterPublicKeysCBOR, publicKey)
}

// EqualTermsID 比较给定 ID 是否等于本报价的 typed ID。
func (v *VerifiedQuote) EqualTermsID(other protocol.FileQuoteTermsID) bool {
	if v == nil {
		return false
	}
	return v.id == other && !bytes.Equal(idZeroSentinel(), v.id[:])
}

func idZeroSentinel() []byte { return make([]byte, 32) }
