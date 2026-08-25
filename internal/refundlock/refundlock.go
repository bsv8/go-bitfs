// Package refundlock holds the pure nLockTime comparison rules for MultisigPool
// refund templates. It lives under internal so it can never become part of the
// public SDK surface: callers pass explicit time/height facts into the SDK and
// the SDK never reads wall-clock or node state here.
package refundlock

import (
	"errors"
	"time"
)

var (
	// ErrNotMatured reports that the refund lock has not matured yet.
	ErrNotMatured = errors.New("refund locktime not reached")
	// ErrMatured reports that the refund lock has already matured.
	ErrMatured = errors.New("pool refund has expired")
)

// TimestampThreshold 是 nLockTime 的解释分界：低于它为区块高，否则为
// UTC Unix 时间戳。它是仓库唯一的阈值真值。
const TimestampThreshold = 500000000

const timestampThreshold = TimestampThreshold

// UsesBlockHeight classifies the raw nLockTime value: values below the
// timestamp threshold are block heights, everything else is a Unix timestamp.
func UsesBlockHeight(lockTime uint32) bool {
	return lockTime < timestampThreshold
}

// CheckExpired reports whether the refund is executable at "at" (timestamp
// locks) or at blockHeight (height locks). It returns nil when matured and
// ErrNotMatured otherwise. It is pure: no clock read, no node query.
func CheckExpired(lockTime uint32, at time.Time, blockHeight uint32) error {
	if UsesBlockHeight(lockTime) {
		if lockTime <= blockHeight {
			return nil
		}
		return ErrNotMatured
	}
	if at.Unix() >= int64(lockTime) {
		return nil
	}
	return ErrNotMatured
}

// CheckNotExpired is the forward-operation gate: refund 仍被锁定时返回 nil；
// 已经到期时返回 ErrMatured。
func CheckNotExpired(lockTime uint32, at time.Time, blockHeight uint32) error {
	if err := CheckExpired(lockTime, at, blockHeight); err == nil {
		return ErrMatured
	} else if !errors.Is(err, ErrNotMatured) {
		return err
	}
	return nil
}
