package protocol

import (
	"errors"
	"fmt"
	"time"

	"github.com/bsv8/go-bitfs/internal/refundlock"
)

// Facts 是调用方作为显式外部事实传入的观测值：影响协议过期、deadline 与
// refund lock 判断的时间，以及区块高度。SDK 不读取系统时钟，也不查询节点；
// 应用负责同时读取并记录 Now/BlockHeight 的来源与观测时刻。
//
// SDK 只校验当前操作实际需要的字段：仅验证 Quote 的操作不应强迫应用查询
// 区块高度；height 锁定的退款判断只要求 BlockHeight，timestamp 锁定只要求
// Now。需要哪个事实由当前操作的协议分支决定。
type Facts struct {
	// Now 是本操作唯一使用的时间事实（UTC）；时间无关操作不读取它。
	Now time.Time
	// BlockHeight 是本操作唯一使用的高度事实；仅当退款锁定为区块高时读取。
	BlockHeight BlockHeight
}

// ErrFactsMissing 标记当前操作所需的显式事实缺失（零值时间或零高度）。
var ErrFactsMissing = errors.New("required explicit facts are missing or zero")

// RequireNow 返回规范化为 UTC 的时间事实；零值直接拒绝，绝不回退系统时钟。
// 返回结构化 invalid_evidence 错误（Cause 保留 ErrFactsMissing 供 errors.Is）。
func (f Facts) RequireNow() (time.Time, error) {
	if f.Now.IsZero() {
		return time.Time{}, &Error{
			Op: "protocol.Facts.RequireNow", Code: CodeInvalidEvidence,
			Field: "facts.now",
			Cause: fmt.Errorf("%w: facts.now is required for this time-sensitive operation", ErrFactsMissing),
		}
	}
	return f.Now.UTC(), nil
}

// RequireBlockHeight 返回高度事实；零值直接拒绝，绝不猜测高度。
func (f Facts) RequireBlockHeight() (BlockHeight, error) {
	if f.BlockHeight == 0 {
		return 0, &Error{
			Op: "protocol.Facts.RequireBlockHeight", Code: CodeInvalidEvidence,
			Field: "facts.block_height",
			Cause: fmt.Errorf("%w: facts.block_height is required for this height-sensitive operation", ErrFactsMissing),
		}
	}
	return f.BlockHeight, nil
}

// RefundMatured 按锁定的实际类型只读取需要的那一份事实：height 锁定与
// f.BlockHeight 比较，timestamp 锁定与 f.Now 比较。matured 为 true 表示
// 锁定已到期可执行退款。
func (f Facts) RefundMatured(lockTime RefundLockTime) (bool, error) {
	if lockTime.UsesBlockHeight() {
		height, err := f.RequireBlockHeight()
		if err != nil {
			return false, err
		}
		return refundlock.CheckExpired(uint32(lockTime), time.Time{}, uint32(height)) == nil, nil
	}
	now, err := f.RequireNow()
	if err != nil {
		return false, err
	}
	return refundlock.CheckExpired(uint32(lockTime), now, 0) == nil, nil
}

// CheckRefundNotExpired 是正向操作门禁：refund 已到期时返回 CodeExpired，
// 未到期返回 nil。只读取锁定类型对应的那一份事实。
func (f Facts) CheckRefundNotExpired(lockTime RefundLockTime) error {
	matured, err := f.RefundMatured(lockTime)
	if err != nil {
		return err
	}
	if matured {
		return Errorf("protocol.CheckRefundNotExpired", CodeExpired, 0, "refund_locktime", "pool refund has expired")
	}
	return nil
}

// CheckRefundMatured 是成熟门禁：refund 尚未到期时返回 CodeNotMatured；
// 已到期返回 nil（可执行退款）。
func (f Facts) CheckRefundMatured(lockTime RefundLockTime) error {
	matured, err := f.RefundMatured(lockTime)
	if err != nil {
		return err
	}
	if !matured {
		return Errorf("protocol.CheckRefundMatured", CodeNotMatured, 0, "refund_locktime", "refund locktime has not been reached")
	}
	return nil
}
