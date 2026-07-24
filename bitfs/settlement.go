package bitfs

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	pool2of3pb "github.com/bsv8/go-bitfs/proto/pool2of3pb"
)

var poolArbitrationSigningDomain = []byte("pool2of3.arbitrate.v1")

const poolArbitrationSigningVersion byte = 1

// PoolArbitrationSigningPayload 以固定编码序列化费用池仲裁签名字段。
func PoolArbitrationSigningPayload(spendTxID string, approved bool, reason string, finalPayoutSat uint64) []byte {
	buffer := make([]byte, 0, len(poolArbitrationSigningDomain)+1+4+len(spendTxID)+1+4+len(reason)+8)
	buffer = append(buffer, poolArbitrationSigningDomain...)
	buffer = append(buffer, poolArbitrationSigningVersion)
	buffer = appendPoolString(buffer, spendTxID)
	if approved {
		buffer = append(buffer, 1)
	} else {
		buffer = append(buffer, 0)
	}
	buffer = appendPoolString(buffer, reason)
	return appendPoolUint64(buffer, finalPayoutSat)
}

// PoolArbitrationSigningDigest 计算费用池仲裁签名的 sha256 摘要。
func PoolArbitrationSigningDigest(spendTxID string, approved bool, reason string, finalPayoutSat uint64) [sha256.Size]byte {
	return sha256.Sum256(PoolArbitrationSigningPayload(spendTxID, approved, reason, finalPayoutSat))
}

// ValidatePoolArbitrationRequest 校验费用池仲裁请求的基本金额与两阶段字段约束。
func ValidatePoolArbitrationRequest(request *pool2of3pb.ArbitrateSessionPoolRequestV1) error {
	if request == nil {
		return errors.New("pool arbitration request is required")
	}
	if request.GetSpendTxid() == "" {
		return errors.New("pool arbitration spend_txid is required")
	}
	if request.GetReason() == "" {
		return errors.New("pool arbitration reason is required")
	}
	if len(request.GetArbiterSignature()) == 0 {
		return errors.New("pool arbitration arbiter_signature is required")
	}
	if request.GetApproved() && request.GetFinalPayoutSat() == 0 {
		return errors.New("approved pool arbitration final_payout_sat must be positive")
	}
	if !request.GetApproved() && request.GetFinalPayoutSat() != 0 {
		return fmt.Errorf("rejected pool arbitration final_payout_sat must be zero, got %d", request.GetFinalPayoutSat())
	}
	return nil
}

// appendPoolString 追加四字节大端长度和字符串字节。
func appendPoolString(buffer []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer = append(buffer, length[:]...)
	return append(buffer, value...)
}

// appendPoolUint64 追加八字节大端无符号整数。
func appendPoolUint64(buffer []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(buffer, encoded[:]...)
}
