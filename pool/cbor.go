package pool

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bsv8/go-bitfs/protocol"
	"github.com/fxamacker/cbor/v2"
)

// Kind 2/3/4/7/12/13 的统一 wire Kind 值。完整报文外壳固定为
// [protocol.WireVersion, wireKind, ...]；认证内容不再携带任何内层版本或 Kind。
const (
	wireKindRefundPresignRequest  uint64 = 2
	wireKindRefundPresignResponse uint64 = 3
	wireKindFundingDelivery       uint64 = 4
	wireKindPaymentUpdate         uint64 = 7
	wireKindPoolCloseRequest      uint64 = 12
	wireKindPoolCloseResponse     uint64 = 13
	maxPoolCloseTransactionBytes         = 64 * 1024
)

// decodePoolByteString 禁止 CBOR array 到 Go 字节数组的隐式转换。
func decodePoolByteString(raw cbor.RawMessage, target any, kind uint16, field string) error {
	if len(raw) == 0 || raw[0]>>5 != 2 {
		return protocol.Errorf("pool.decodePoolByteString", protocol.CodeMalformedWire, kind, field, "field must be a CBOR byte string")
	}
	if err := poolDec.Unmarshal(raw, target); err != nil {
		return protocol.Wrap(err, "pool.decodePoolByteString", protocol.CodeMalformedWire, kind, field)
	}
	return nil
}

var poolEnc cbor.EncMode
var poolDec cbor.DecMode

func init() {
	var err error
	poolEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	poolDec, err = cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden, MaxNestedLevels: 16, MaxArrayElements: 32,
		MaxMapPairs: 16, UTF8: cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// validatePoolHash32 checks that a decoded hash field is exactly 32 bytes and
// not the all-zero "unset" sentinel.
func validatePoolHash32(raw []byte, name string) error {
	if len(raw) != sha256.Size {
		return protocol.Errorf("pool", protocol.CodeMalformedWire, 0, name, "must be 32 bytes")
	}
	for _, b := range raw {
		if b != 0 {
			return nil
		}
	}
	return protocol.Errorf("pool", protocol.CodeInvalidEvidence, 0, name, "must not be all zero")
}

func validatePoolHash32Value(value [sha256.Size]byte, name string) error {
	return validatePoolHash32(value[:], name)
}

// encodeWireEnvelope prepends the fixed [wire_version, wire_kind] outer pair.
// The encoder owns both values; callers never supply them.
func encodeWireEnvelope(wireKind uint64, fields ...any) ([]byte, error) {
	return poolEnc.Marshal(append([]any{protocol.WireVersion, wireKind}, fields...))
}

// decodeWireEnvelope strictly decodes the [wire_version, wire_kind, ...] outer
// pair and returns the remaining elements.
func decodeWireEnvelope(data []byte, wantKind uint64, totalLength int) ([]cbor.RawMessage, error) {
	values, err := decodePoolArray(data, totalLength)
	if err != nil {
		return nil, err
	}
	var version, kind uint64
	if err := poolDec.Unmarshal(values[0], &version); err != nil || version != protocol.WireVersion {
		return nil, protocol.Errorf("pool", protocol.CodeUnsupportedVersion, 0, "wire_version", "unsupported wire version")
	}
	if err := poolDec.Unmarshal(values[1], &kind); err != nil || kind != wantKind {
		return nil, protocol.Errorf("pool", protocol.CodeUnsupportedKind, 0, "wire_kind", "unexpected wire kind %d", kind)
	}
	return values[2:], nil
}

// EncodePaymentUpdate validates and encodes the minimal Kind 7 payment
// authorization ID plus detached buyer payment transaction signature as its
// four-field deterministic CBOR container. The pool correlation ID and the
// unsigned state transaction are not transmitted: both sides rebuild the exact
// transaction locally from the opening proof, previous payment state, and the
// signed payment authorization referenced by the ID. It performs structural
// validation, not node acceptance or signature verification.
func EncodePaymentUpdate(update *PaymentUpdate) ([]byte, error) {
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindPaymentUpdate, update.PaymentAuthorizationID, update.BuyerPaymentTransactionSignature)
}

// DecodePaymentUpdate decodes and canonicality-checks the Kind 7 four-element
// minimal container, then validates its field shape. Any other shape is
// rejected outright; it does not prove pool ownership or verify the buyer
// signature against a rebuilt transaction.
func DecodePaymentUpdate(data []byte) (*PaymentUpdate, error) {
	fields, err := decodeWireEnvelope(data, wireKindPaymentUpdate, 4)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	update := new(PaymentUpdate)
	if err := poolDec.Unmarshal(fields[0], &update.PaymentAuthorizationID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &update.BuyerPaymentTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidatePaymentUpdate(update); err != nil {
		return nil, err
	}
	canonical, err := EncodePaymentUpdate(update)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("payment update_cbor", "payment update is not deterministically encoded")
	}
	return clonePaymentUpdate(update), nil
}

// EncodeRefundPresignRequest validates and encodes the Kind 2 buyer
// refund-presign request: the canonical unsigned refund template raw bytes,
// role keys, fee rate, and detached buyer transaction signature. The funding
// outpoint, pool amount, and pool lock are derived canonically from
// refund_template_raw and the participant keys. The request does not duplicate
// the derived RefundTemplateTxID.
func EncodeRefundPresignRequest(request *RefundPresignRequest) ([]byte, error) {
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindRefundPresignRequest,
		request.RefundTemplateRaw,
		request.BuyerPublicKey, request.SellerPublicKey, request.ArbiterPublicKey,
		request.MinerFeeRateSatoshisPerKilobyte, request.BuyerRefundTransactionSignature,
	)
}

// DecodeRefundPresignRequest decodes and canonicality-checks the Kind 2
// request; cryptographic and funding-transaction acceptance remains the
// opening workflow's job.
func DecodeRefundPresignRequest(data []byte) (*RefundPresignRequest, error) {
	fields, err := decodeWireEnvelope(data, wireKindRefundPresignRequest, 8)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	request := new(RefundPresignRequest)
	if err := poolDec.Unmarshal(fields[0], &request.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &request.BuyerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[2], &request.SellerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[3], &request.ArbiterPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[4], &request.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[5], &request.BuyerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateRefundPresignRequest(request); err != nil {
		return nil, err
	}
	canonical, err := EncodeRefundPresignRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("refund presign request_cbor", "refund presign request is not deterministically encoded")
	}
	return cloneRefundPresignRequest(request), nil
}

// EncodeRefundPresignResponse validates and encodes the seller's Kind 3 refund
// signature response with the pool's RefundTemplateTxID correlation ID
// re-derived by the seller from the request.
func EncodeRefundPresignResponse(response *RefundPresignResponse) ([]byte, error) {
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindRefundPresignResponse, response.RefundTemplateTxID[:], response.SellerRefundTransactionSignature)
}

// DecodeRefundPresignResponse decodes and canonicality-checks the Kind 3
// seller response without deciding whether the signature matches a particular
// request.
func DecodeRefundPresignResponse(data []byte) (*RefundPresignResponse, error) {
	fields, err := decodeWireEnvelope(data, wireKindRefundPresignResponse, 4)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	response := new(RefundPresignResponse)
	if err := poolDec.Unmarshal(fields[0], &response.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &response.SellerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := ValidateRefundPresignResponse(response); err != nil {
		return nil, err
	}
	canonical, err := EncodeRefundPresignResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("refund presign response_cbor", "refund presign response is not deterministically encoded")
	}
	return cloneRefundPresignResponse(response), nil
}

// EncodeFundingTransactionDelivery validates and encodes the Kind 4
// funding-transaction delivery container with its RefundTemplateTxID
// correlation ID. It does not verify that the funding transaction spends the
// retained opening proof.
func EncodeFundingTransactionDelivery(delivery *FundingTransactionDelivery) ([]byte, error) {
	if err := ValidateFundingTransactionDelivery(delivery); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindFundingDelivery, delivery.RefundTemplateTxID[:], delivery.FundingTransactionRaw)
}

// DecodeFundingTransactionDelivery decodes and canonicality-checks the Kind 4
// funding delivery; SellerAcceptFundingTx performs the proof and node checks.
func DecodeFundingTransactionDelivery(data []byte) (*FundingTransactionDelivery, error) {
	fields, err := decodeWireEnvelope(data, wireKindFundingDelivery, 4)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	delivery := new(FundingTransactionDelivery)
	if err := poolDec.Unmarshal(fields[0], &delivery.RefundTemplateTxID); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(fields[1], &delivery.FundingTransactionRaw); err != nil {
		return nil, err
	}
	if err := ValidateFundingTransactionDelivery(delivery); err != nil {
		return nil, err
	}
	canonical, err := EncodeFundingTransactionDelivery(delivery)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("funding transaction delivery_cbor", "funding transaction delivery is not deterministically encoded")
	}
	return cloneFundingTransactionDelivery(delivery), nil
}

// EncodePoolCloseRequest 校验并编码 Kind 12 买方请求。字段顺序固定为费用池
// 关联 ID、未签名关闭交易和买方分离式交易签名；关联 ID 必须是首个业务字段。
func EncodePoolCloseRequest(request *PoolCloseRequest) ([]byte, error) {
	if err := ValidatePoolCloseRequest(request); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindPoolCloseRequest,
		request.RefundTemplateTxID[:],
		request.UnsignedCloseTransactionRaw,
		request.BuyerCloseTransactionSignature,
	)
}

// DecodePoolCloseRequest 严格解码固定五元 Kind 12 请求并复核确定性 CBOR。
// 关闭交易与买方签名的密码学验证仍由卖方角色工作流负责。
func DecodePoolCloseRequest(data []byte) (*PoolCloseRequest, error) {
	fields, err := decodeWireEnvelope(data, wireKindPoolCloseRequest, 5)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	request := new(PoolCloseRequest)
	if err := decodePoolByteString(fields[0], &request.RefundTemplateTxID, 12, "refund_template_txid"); err != nil {
		return nil, protocol.Wrap(err, "pool.DecodePoolCloseRequest", protocol.CodeMalformedWire, 12, "refund_template_txid")
	}
	if err := decodePoolByteString(fields[1], &request.UnsignedCloseTransactionRaw, 12, "unsigned_close_transaction_raw"); err != nil {
		return nil, protocol.Wrap(err, "pool.DecodePoolCloseRequest", protocol.CodeMalformedWire, 12, "unsigned_close_transaction_raw")
	}
	if err := decodePoolByteString(fields[2], &request.BuyerCloseTransactionSignature, 12, "buyer_close_transaction_signature"); err != nil {
		return nil, protocol.Wrap(err, "pool.DecodePoolCloseRequest", protocol.CodeMalformedWire, 12, "buyer_close_transaction_signature")
	}
	if err := ValidatePoolCloseRequest(request); err != nil {
		return nil, err
	}
	canonical, err := EncodePoolCloseRequest(request)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("pool close request_cbor", "pool close request is not deterministically encoded")
	}
	return clonePoolCloseRequest(request), nil
}

// EncodePoolCloseResponse 校验并编码 Kind 13 卖方响应。完整交易的解锁脚本
// 携带双方签名；接收方仍须结合自己的开池证据验证交易。
func EncodePoolCloseResponse(response *PoolCloseResponse) ([]byte, error) {
	if err := ValidatePoolCloseResponse(response); err != nil {
		return nil, err
	}
	return encodeWireEnvelope(wireKindPoolCloseResponse,
		response.RefundTemplateTxID[:], response.CompleteCloseTransactionRaw)
}

// DecodePoolCloseResponse 严格解码固定四元 Kind 13 响应并复核确定性 CBOR。
func DecodePoolCloseResponse(data []byte) (*PoolCloseResponse, error) {
	fields, err := decodeWireEnvelope(data, wireKindPoolCloseResponse, 4)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	response := new(PoolCloseResponse)
	if err := decodePoolByteString(fields[0], &response.RefundTemplateTxID, 13, "refund_template_txid"); err != nil {
		return nil, protocol.Wrap(err, "pool.DecodePoolCloseResponse", protocol.CodeMalformedWire, 13, "refund_template_txid")
	}
	if err := decodePoolByteString(fields[1], &response.CompleteCloseTransactionRaw, 13, "complete_close_transaction_raw"); err != nil {
		return nil, protocol.Wrap(err, "pool.DecodePoolCloseResponse", protocol.CodeMalformedWire, 13, "complete_close_transaction_raw")
	}
	if err := ValidatePoolCloseResponse(response); err != nil {
		return nil, err
	}
	canonical, err := EncodePoolCloseResponse(response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("pool close response_cbor", "pool close response is not deterministically encoded")
	}
	return clonePoolCloseResponse(response), nil
}

// EncodeOpeningProof validates and encodes the complete opening proof. IDs,
// the fixed output index, amount, and locking script are deliberately omitted
// because they are derived from the transaction evidence and participant keys.
// The opening proof is application-local evidence, not one of the thirteen wire
// kinds; its encoding carries no version or kind of its own.
func EncodeOpeningProof(proof *OpeningProof) ([]byte, error) {
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	if len(proof.FundingTransactionRaw) == 0 {
		return nil, invalid("complete funding transaction is required")
	}
	return poolEnc.Marshal([]any{
		proof.RefundTemplateRaw, proof.BuyerPublicKey, proof.SellerPublicKey,
		proof.ArbiterPublicKey, proof.MinerFeeRateSatoshisPerKilobyte,
		proof.BuyerRefundTransactionSignature, proof.SellerRefundTransactionSignature, proof.FundingTransactionRaw,
	})
}

// DecodeOpeningProof decodes and canonicality-checks an opening proof, then
// performs field validation; VerifyOpening is still required for signatures
// and transaction relationships.
func DecodeOpeningProof(data []byte) (*OpeningProof, error) {
	values, err := decodePoolArray(data, 8)
	if err != nil {
		return nil, malformedWire("decode", err)
	}
	proof := new(OpeningProof)
	if err := poolDec.Unmarshal(values[0], &proof.RefundTemplateRaw); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[1], &proof.BuyerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[2], &proof.SellerPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[3], &proof.ArbiterPublicKey); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[4], &proof.MinerFeeRateSatoshisPerKilobyte); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[5], &proof.BuyerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[6], &proof.SellerRefundTransactionSignature); err != nil {
		return nil, err
	}
	if err := poolDec.Unmarshal(values[7], &proof.FundingTransactionRaw); err != nil {
		return nil, err
	}
	if err := ValidateOpeningProof(proof); err != nil {
		return nil, err
	}
	canonical, err := EncodeOpeningProof(proof)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, nonCanonical("opening proof_cbor", "opening proof is not deterministically encoded")
	}
	return cloneOpeningProof(proof), nil
}

// ValidatePaymentUpdate checks the Kind 7 minimal envelope, 32-byte non-zero
// authorization ID, and presence of the detached buyer payment transaction
// signature. It does not parse transactions or establish that a node accepted
// anything; the referenced signed payment authorization and the rebuilt
// unsigned state transaction are verified by the receiving workflow.
func ValidatePaymentUpdate(update *PaymentUpdate) error {
	if update == nil {
		return invalid("payment update is required")
	}
	if update.PaymentAuthorizationID.IsZero() {
		return protocol.Errorf("pool.ValidatePaymentUpdate", protocol.CodeInvalidEvidence, 7, "payment_authorization_id", "%w", protocol.ErrZeroIdentifier)
	}
	if len(update.BuyerPaymentTransactionSignature) == 0 {
		return invalid("buyer payment transaction signature is required")
	}
	return nil
}

// ValidateRefundPresignRequest checks the Kind 2 request required refund
// evidence, role keys, fee rate, and buyer transaction signature presence.
// It does not verify the refund transaction or either signature cryptographically.
func ValidateRefundPresignRequest(request *RefundPresignRequest) error {
	if request == nil {
		return invalid("invalid refund presign request")
	}
	if len(request.RefundTemplateRaw) == 0 || len(request.BuyerRefundTransactionSignature) == 0 {
		return invalid("incomplete refund presign request")
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", request.BuyerPublicKey}, {"seller", request.SellerPublicKey}, {"arbiter", request.ArbiterPublicKey}}
	for _, role := range roles {
		if err := protocol.ValidateCompressedPubKey(role.key); err != nil {
			return protocol.Wrap(fmt.Errorf("%s public key: %v", role.name, err), "pool", protocol.CodeInvalidEvidence, 0, role.name+"_public_key")
		}
	}
	return nil
}

// ValidateRefundPresignResponse requires a non-zero 32-byte RefundTemplateTxID
// and a seller refund transaction signature; matching them to a request is a
// workflow operation.
func ValidateRefundPresignResponse(response *RefundPresignResponse) error {
	if response == nil || len(response.SellerRefundTransactionSignature) == 0 {
		return invalid("invalid refund presign response")
	}
	if err := validatePoolHash32Value(response.RefundTemplateTxID, "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidateFundingTransactionDelivery requires a non-zero 32-byte
// RefundTemplateTxID and raw funding transaction bytes; it does not prove the
// bytes spend the opening.
func ValidateFundingTransactionDelivery(delivery *FundingTransactionDelivery) error {
	if delivery == nil || len(delivery.FundingTransactionRaw) == 0 {
		return invalid("invalid funding transaction delivery")
	}
	if err := validatePoolHash32Value(delivery.RefundTemplateTxID, "refund_template_txid"); err != nil {
		return err
	}
	return nil
}

// ValidatePoolCloseRequest 校验 Kind 12 的字段长度和必填字节串；不验证候选
// 交易或买方签名的密码学正确性。
func ValidatePoolCloseRequest(request *PoolCloseRequest) error {
	if request == nil {
		return protocol.Errorf("pool.ValidatePoolCloseRequest", protocol.CodeMalformedWire, 12, "pool_close_request", "close request is required")
	}
	if len(request.UnsignedCloseTransactionRaw) == 0 || len(request.UnsignedCloseTransactionRaw) > maxPoolCloseTransactionBytes {
		return protocol.Errorf("pool.ValidatePoolCloseRequest", protocol.CodeMalformedWire, 12, "unsigned_close_transaction_raw", "unsigned close transaction is required")
	}
	if len(request.BuyerCloseTransactionSignature) == 0 {
		return protocol.Errorf("pool.ValidatePoolCloseRequest", protocol.CodeMalformedWire, 12, "buyer_close_transaction_signature", "buyer close transaction signature is required")
	}
	if len(request.BuyerCloseTransactionSignature) > 256 {
		return protocol.Errorf("pool.ValidatePoolCloseRequest", protocol.CodeMalformedWire, 12, "buyer_close_transaction_signature", "signature exceeds 256 bytes")
	}
	if request.RefundTemplateTxID == (RefundTemplateTxID{}) {
		return protocol.Errorf("pool.ValidatePoolCloseRequest", protocol.CodeInvalidEvidence, 12, "refund_template_txid", "must not be all zero")
	}
	return nil
}

// ValidatePoolCloseResponse 校验 Kind 13 的字段长度和必填交易原文；不验证
// 交易签名或费用池归属。
func ValidatePoolCloseResponse(response *PoolCloseResponse) error {
	if response == nil {
		return protocol.Errorf("pool.ValidatePoolCloseResponse", protocol.CodeMalformedWire, 13, "pool_close_response", "close response is required")
	}
	if len(response.CompleteCloseTransactionRaw) == 0 || len(response.CompleteCloseTransactionRaw) > maxPoolCloseTransactionBytes {
		return protocol.Errorf("pool.ValidatePoolCloseResponse", protocol.CodeMalformedWire, 13, "complete_close_transaction_raw", "complete close transaction is required")
	}
	if response.RefundTemplateTxID == (RefundTemplateTxID{}) {
		return protocol.Errorf("pool.ValidatePoolCloseResponse", protocol.CodeInvalidEvidence, 13, "refund_template_txid", "must not be all zero")
	}
	return nil
}

// ValidateOpeningProof checks role keys and raw refund evidence. It is
// structural; VerifyOpening performs transaction and signature relationship
// checks.
func ValidateOpeningProof(proof *OpeningProof) error {
	if proof == nil {
		return invalid("opening proof is required")
	}
	if len(proof.RefundTemplateRaw) == 0 || len(proof.BuyerRefundTransactionSignature) == 0 || len(proof.SellerRefundTransactionSignature) == 0 {
		return invalid("opening proof contains incomplete evidence")
	}
	roles := []struct {
		name string
		key  []byte
	}{{"buyer", proof.BuyerPublicKey}, {"seller", proof.SellerPublicKey}, {"arbiter", proof.ArbiterPublicKey}}
	for _, role := range roles {
		if err := protocol.ValidateCompressedPubKey(role.key); err != nil {
			return protocol.Wrap(fmt.Errorf("%s public key: %v", role.name, err), "pool", protocol.CodeInvalidEvidence, 0, role.name+"_public_key")
		}
	}
	return nil
}

func decodePoolArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := poolDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func clonePaymentUpdate(update *PaymentUpdate) *PaymentUpdate {
	if update == nil {
		return nil
	}
	return &PaymentUpdate{PaymentAuthorizationID: update.PaymentAuthorizationID, BuyerPaymentTransactionSignature: append([]byte(nil), update.BuyerPaymentTransactionSignature...)}
}

func cloneRefundPresignRequest(request *RefundPresignRequest) *RefundPresignRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.RefundTemplateRaw = append([]byte(nil), request.RefundTemplateRaw...)
	cloned.BuyerPublicKey = append([]byte(nil), request.BuyerPublicKey...)
	cloned.SellerPublicKey = append([]byte(nil), request.SellerPublicKey...)
	cloned.ArbiterPublicKey = append([]byte(nil), request.ArbiterPublicKey...)
	cloned.BuyerRefundTransactionSignature = append([]byte(nil), request.BuyerRefundTransactionSignature...)
	return &cloned
}

func cloneRefundPresignResponse(response *RefundPresignResponse) *RefundPresignResponse {
	if response == nil {
		return nil
	}
	return &RefundPresignResponse{RefundTemplateTxID: response.RefundTemplateTxID, SellerRefundTransactionSignature: append([]byte(nil), response.SellerRefundTransactionSignature...)}
}
func cloneFundingTransactionDelivery(delivery *FundingTransactionDelivery) *FundingTransactionDelivery {
	if delivery == nil {
		return nil
	}
	return &FundingTransactionDelivery{RefundTemplateTxID: delivery.RefundTemplateTxID, FundingTransactionRaw: append([]byte(nil), delivery.FundingTransactionRaw...)}
}

func clonePoolCloseRequest(request *PoolCloseRequest) *PoolCloseRequest {
	if request == nil {
		return nil
	}
	return &PoolCloseRequest{
		RefundTemplateTxID:             request.RefundTemplateTxID,
		UnsignedCloseTransactionRaw:    append([]byte(nil), request.UnsignedCloseTransactionRaw...),
		BuyerCloseTransactionSignature: append([]byte(nil), request.BuyerCloseTransactionSignature...),
	}
}

func clonePoolCloseResponse(response *PoolCloseResponse) *PoolCloseResponse {
	if response == nil {
		return nil
	}
	return &PoolCloseResponse{
		RefundTemplateTxID:          response.RefundTemplateTxID,
		CompleteCloseTransactionRaw: append([]byte(nil), response.CompleteCloseTransactionRaw...),
	}
}

func cloneOpeningProof(proof *OpeningProof) *OpeningProof {
	if proof == nil {
		return nil
	}
	cloned := *proof
	cloned.RefundTemplateRaw = append([]byte(nil), proof.RefundTemplateRaw...)
	cloned.BuyerPublicKey = append([]byte(nil), proof.BuyerPublicKey...)
	cloned.SellerPublicKey = append([]byte(nil), proof.SellerPublicKey...)
	cloned.ArbiterPublicKey = append([]byte(nil), proof.ArbiterPublicKey...)
	cloned.BuyerRefundTransactionSignature = append([]byte(nil), proof.BuyerRefundTransactionSignature...)
	cloned.SellerRefundTransactionSignature = append([]byte(nil), proof.SellerRefundTransactionSignature...)
	cloned.FundingTransactionRaw = append([]byte(nil), proof.FundingTransactionRaw...)
	return &cloned
}

func clonePaymentState(state *PaymentState) *PaymentState {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.RawTx = append([]byte(nil), state.RawTx...)
	cloned.BuyerTransactionSignature = append([]byte(nil), state.BuyerTransactionSignature...)
	cloned.SellerTransactionSignature = append([]byte(nil), state.SellerTransactionSignature...)
	cloned.ArbiterTransactionSignature = append([]byte(nil), state.ArbiterTransactionSignature...)
	cloned.PoolLockingScript = append([]byte(nil), state.PoolLockingScript...)
	return &cloned
}
