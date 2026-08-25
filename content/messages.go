package content

// FileQuoteTerms is the seller's signed pricing and expiry commitment to one
// buyer. It is the authenticated Kind 1 document: business fields only, no
// version and no kind. RecommendedFilename is a sanitized display fact
// supplied by the seller, so it is signed together with the economic terms;
// different filenames therefore produce different file_quote_terms_id values.
type FileQuoteTerms struct {
	// SeedHash 是内容仓库的种子摘要（SHA-256，32 字节）：买方据此识别要购买
	// 的 seed；等于该值的哈希按 seed 计价，其余哈希必须能在该 seed 中找到。
	SeedHash []byte
	// BuyerPublicKey 是唯一被允许接受并签署后续 003 请求的买方压缩公钥
	// （33 字节）；报价只面向这一个买方。
	BuyerPublicKey []byte
	// SeedPriceSatoshis 是整个 MasterSeed 的绝对单价，单位 satoshi。
	SeedPriceSatoshis uint64
	// FullBlockPriceSatoshis 是一个完整块（256 KiB）的绝对单价，单位
	// satoshi；尾块按实际长度比例计算并享受 10% 卖方让利。
	FullBlockPriceSatoshis uint64
	// FileSizeBytes 是文件总字节数；块数由它派生：0 -> 0 块，正数 ->
	// ceil(file_size_bytes / 262144)。
	FileSizeBytes uint64
	// QuoteExpiresAtUnixSeconds 是报价失效时间（UTC Unix 秒，int64）；
	// 到期判断由调用方用自己读取的一次系统时间完成。
	QuoteExpiresAtUnixSeconds int64
	// SupportedArbiterPublicKeysCBOR 是仲裁公钥数组的独立确定性 CBOR 子文档；
	// 可为空数组，但内部公钥不得为空或重复。开池时 Arbiter 公钥必须在其中。
	SupportedArbiterPublicKeysCBOR []byte
	// RecommendedFilename 是经 sanitize 的展示文件名建议：先 sanitize 再编码，
	// 与经济条款一起进入卖方统一签名；不同文件名产生不同 file_quote_terms_id。
	// 它只是展示事实，不是内容/价格/身份的真值。
	RecommendedFilename string
}

// SignedFileQuote is the complete Kind 1 FileQuote wire message payload:
// canonical quote terms, the seller identity key, and the seller signature
// over WireSignatureInput(1, 1, terms_cbor).
type SignedFileQuote struct {
	// FileQuoteTermsCBOR 是 exact 规范条款字节（确定性 CBOR），也是
	// file_quote_terms_id = SHA-256(...) 的计算来源；验证后绝不重编码。
	FileQuoteTermsCBOR []byte
	// SellerPublicKey 是卖方压缩公钥（33 字节），用于恢复并验证条款统一签名。
	SellerPublicKey []byte
	// SellerFileQuoteTermsSignature 是卖方对 WireSignatureInput(1, 1,
	// file_quote_terms_cbor) 的 low-S DER 统一消息签名。
	SellerFileQuoteTermsSignature []byte
}
