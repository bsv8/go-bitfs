package protocol

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/fxamacker/cbor/v2"
)

// WireVersion 是 BitFS 对外暴露的唯一协议版本。所有完整 wire 报文都以
// [WireVersion, wire_kind, ...] 开头；认证子文档不再重复携带版本与 Kind。
// 任何改变 wire shape、签名对象、ID 算法、交易重建或验收语义的修改都必须
// 提升该值；依赖库修复且协议可观察结果完全不变时不提升。
const WireVersion uint64 = 1

// WireSignatureDomain 是统一普通消息签名上下文的固定域分隔字符串。
const WireSignatureDomain = "bitfs/wire-signature"

var wireSignatureEnc cbor.EncMode

func init() {
	var err error
	wireSignatureEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}

// WireSignatureInput 把外层版本、wire Kind 与 exact 认证文档打包成唯一的
// 普通消息签名预映像：
//
//	deterministic-CBOR(["bitfs/wire-signature", wire_version, wire_kind, document_cbor])
//
// 结果不是 wire 字段，也不持久化为第二份业务文档；它只把外层上下文和
// exact document_cbor 作为一个整体纳入签名输入，绝不解码并重新编码业务字段。
// documentCBOR 必须是已经过对应 Kind 严格 decoder 验证的 exact 字节。
func WireSignatureInput(wireVersion, wireKind uint64, documentCBOR []byte) ([]byte, error) {
	if len(documentCBOR) == 0 {
		return nil, errors.New("document CBOR is required")
	}
	return wireSignatureEnc.Marshal([]any{
		WireSignatureDomain,
		wireVersion,
		wireKind,
		documentCBOR,
	})
}

// SignWireDocument 用固定单次 SHA-256 + low-S DER 路径签署
// WireSignatureInput(wireVersion, wireKind, documentCBOR)。它是所有普通消息
// 签名的唯一入口，禁止跨协议、跨版本、跨 Kind 解释签名。私钥只进入运行时
// 参数，绝不进入 CBOR、报文、日志或持久化结构。
func SignWireDocument(privateKey *ec.PrivateKey, wireVersion, wireKind uint64, documentCBOR []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	input, err := WireSignatureInput(wireVersion, wireKind, documentCBOR)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(input)
	signature, err := privateKey.Sign(digest[:])
	if err != nil {
		return nil, err
	}
	return signature.ToDER()
}

// ErrHighSSignature 标记一个 S > N/2 的可延展（high-S）签名。协议只接受
// low-S DER：同一认证文档因此只存在一份有效 wire 签名，杜绝 exact-wire
// 双真值与不必要的重复证据冲突。
var ErrHighSSignature = errors.New("high-S signature is rejected; only low-S DER is canonical")

// verifyLowS enforces the protocol-wide low-S rule over any parsed ECDSA
// signature. It is the single gate for every ordinary message signature.
func verifyLowS(signature *ec.Signature) error {
	if signature == nil || signature.R == nil || signature.S == nil {
		return errors.New("signature R/S are required")
	}
	if signature.S.Sign() != 1 {
		return errors.New("signature S must be positive")
	}
	halfOrder := new(big.Int).Rsh(ec.S256().Params().N, 1)
	if signature.S.Cmp(halfOrder) > 0 {
		return ErrHighSSignature
	}
	return nil
}

// VerifyMessageSignature 是协议固定的普通消息签名验证入口：对 payload 做一次
// SHA-256，解析 DER，强制 low-S，再做 ECDSA 验证。所有跨包验证路径都必须经
// 过本函数或 VerifyWireDocument，禁止绕过 low-S 检查。
func VerifyMessageSignature(publicKey, payload, signature []byte) error {
	key, err := ParseCompressedPubKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return err
	}
	if err := verifyLowS(sig); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !sig.Verify(digest[:], key) {
		return errors.New("signature mismatch")
	}
	return nil
}

// VerifyWireDocument 验证 SignWireDocument 生成的签名：先用相同外层版本、
// Kind 与 exact 认证文档重建唯一 WireSignatureInput，再走统一的
// VerifyMessageSignature 路径（含强制 low-S）。
func VerifyWireDocument(publicKey []byte, wireVersion, wireKind uint64, documentCBOR, signature []byte) error {
	input, err := WireSignatureInput(wireVersion, wireKind, documentCBOR)
	if err != nil {
		return fmt.Errorf("verify wire document: %w", err)
	}
	if err := VerifyMessageSignature(publicKey, input, signature); err != nil {
		return fmt.Errorf("verify wire document: %w", err)
	}
	return nil
}
