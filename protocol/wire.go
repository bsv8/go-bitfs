package protocol

import (
	"context"
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

// WireSignatureDigest 构造普通消息签名的唯一 32 字节摘要：
// SHA-256(WireSignatureInput(wireVersion, wireKind, documentCBOR))。
// SDK 是 digest 的唯一构造者；Signer 只接触本返回值。
func WireSignatureDigest(wireVersion, wireKind uint64, documentCBOR []byte) (Digest32, error) {
	input, err := WireSignatureInput(wireVersion, wireKind, documentCBOR)
	if err != nil {
		return Digest32{}, fmt.Errorf("wire signature input: %w", err)
	}
	return Digest32(sha256.Sum256(input)), nil
}

// SignWireDocument 用受约束 Signer 签署普通 wire 报文：SDK 固定构造
// WireSignatureDigest(1, kind, exact document)，Signer 只对该摘要执行密钥
// 操作；签名返回后 SDK 用 Signer 固定公钥立即自验（DER、low-S、验签），
// 失败即拒绝。ctx 只用于取消远程签名；私钥/托管细节绝不进入 CBOR、报文、
// 日志或持久化结构。
func SignWireDocument(ctx context.Context, signer Signer, wireVersion, wireKind uint64, documentCBOR []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: protocol.SignWireDocument requires a non-nil context", ErrNilInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, Wrap(err, "protocol.SignWireDocument", CodeCanceled, uint16(wireKind), "")
	}
	if signer == nil {
		return nil, Errorf("protocol.SignWireDocument", CodeSignerUnavailable, uint16(wireKind), "signer", "signer is required")
	}
	digest, err := WireSignatureDigest(wireVersion, wireKind, documentCBOR)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, SigningRequest{
		Purpose:  PurposeWireMessage,
		WireKind: uint16(wireKind),
		Digest:   digest,
	})
	if err != nil {
		// 取消语义优先：调用方取消/超时永远是 canceled，绝不归类为
		// signer_unavailable（那意味着托管故障，语义完全不同）。
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, Wrap(err, "protocol.SignWireDocument", CodeCanceled, uint16(wireKind), "")
		}
		if !errors.Is(err, ErrSignerUnavailable) {
			err = fmt.Errorf("sign wire document (kind %d): %v", wireKind, err)
		}
		return nil, Wrap(err, "protocol.SignWireDocument", CodeSignerUnavailable, uint16(wireKind), "signature")
	}
	if len(signature) == 0 {
		return nil, Errorf("protocol.SignWireDocument", CodeInvalidSignature, uint16(wireKind), "signature", "signer returned an empty signature")
	}
	publicKey := signer.PublicKey()
	if err := VerifyDigestSignature(publicKey, digest, signature); err != nil {
		return nil, Wrap(fmt.Errorf("self-verify wire signature: %v", err), "protocol.SignWireDocument", CodeInvalidSignature, uint16(wireKind), "signature")
	}
	return append([]byte(nil), signature...), nil
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

// VerifyDigestSignature 是协议固定的摘要级验证入口：直接对 SDK 已构造的
// 32 字节摘要解析 DER、强制 low-S 并做 ECDSA 验证。交易签名自验与 Signer
// 返回值检查都使用它；调用方不能替换验证器。
func VerifyDigestSignature(publicKey PublicKey, digest Digest32, signature []byte) error {
	key, err := ParseCompressedPubKey(publicKey[:])
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
	if !sig.Verify(digest[:], key) {
		return errors.New("signature mismatch")
	}
	return nil
}

// VerifyWireDocument 验证普通 wire 报文签名：用相同外层版本、Kind 与 exact
// 认证文档重建唯一 WireSignatureInput，做一次 SHA-256 后走统一 low-S 验签。
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
