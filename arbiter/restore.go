package arbiter

import (
	"bytes"

	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/protocol"
)

// RestorePreparedArbitration 从应用持久化的 exact 托管证据（exact Kind 8
// bytes + 冻结仲裁费）恢复 PreparedArbitration：重新执行完整时间无关证据链
// （Claim 结构、买卖双方签名、逐 payload 哈希、按冻结费用独立重建 candidate、
// Claim ID/授权 ID/证据承诺全部重算），绝不信任任何持久化派生字段。
//
// 与 PrepareArbitration 的差别只有两点：本入口不读取任何事实——deadline 与
// refund 门禁在 Prepare 时已执行，SignPreparedArbitration 会用新 Facts 再查
// deadline；恢复后的值与 Prepare 产物在相同输入下逐字段一致。
func RestorePreparedArbitration(rawKind8 []byte, fee protocol.Satoshis) (*PreparedArbitration, error) {
	const op = "arbiter.RestorePreparedArbitration"
	if fee == 0 {
		return nil, protocol.Errorf(op, protocol.CodeInvalidEvidence, 8, "fee_satoshis", "frozen arbitration fee must be positive")
	}
	request, err := arbitration.UnmarshalRequest(rawKind8)
	if err != nil {
		return nil, err
	}
	claim, authorization, payloads, unsigned, claimID, authID, keys, err := arbitration.ValidateRequestEvidence(request, uint64(fee))
	if err != nil {
		return nil, err
	}
	exactRequest, err := arbitration.MarshalRequest(request)
	if err != nil {
		return nil, err
	}
	return &PreparedArbitration{
		request: request, claim: claim, unsigned: cloneUnsigned(unsigned), payloads: cloneByteSlices(payloads),
		arbitrationClaimID: claimID, paymentAuthorizationID: authID, arbiterAmountSatoshis: fee,
		arbiterPublicKey:    append([]byte(nil), keys.ArbiterPublicKey...),
		evidenceCommitment:  preparedEvidenceCommitment(exactRequest, claimID[:], uint64(fee), unsigned),
		deadlineUnixSeconds: authorization.DeliveryDeadlineUnixSeconds,
	}, nil
}

// PreparedBelongsTo 报告 prepared 托管记录是否归属指定仲裁方压缩公钥。
func (prepared *PreparedArbitration) PreparedBelongsTo(arbiterPublicKey []byte) bool {
	if prepared == nil {
		return false
	}
	return bytes.Equal(prepared.arbiterPublicKey, arbiterPublicKey)
}
