// Package refundlock holds the pure nLockTime comparison rules for MultisigPool
// refund templates. It lives under internal so it can never become part of the
// public SDK surface: callers never pass wall-clock times into the SDK.
package refundlock

import (
	"errors"
	"time"
)

var (
	// ErrNotExpired reports that the refund lock has not matured yet.
	ErrNotExpired = errors.New("refund locktime not reached")
	// ErrExpired reports that the refund lock has already matured.
	ErrExpired = errors.New("pool refund has expired")
)

const timestampThreshold = 500000000

// UsesBlockHeight classifies the raw nLockTime value: values below the
// timestamp threshold are block heights, everything else is a Unix timestamp.
func UsesBlockHeight(lockTime uint32) bool {
	return lockTime < timestampThreshold
}

// CheckExpired reports whether the refund is executable at "at" (timestamp
// locks) or at blockHeight (height locks). It returns nil when matured and
// ErrNotExpired otherwise. It is pure: no clock read, no node query.
func CheckExpired(lockTime uint32, at time.Time, blockHeight uint32) error {
	if UsesBlockHeight(lockTime) {
		if lockTime <= blockHeight {
			return nil
		}
		return ErrNotExpired
	}
	if at.Unix() >= int64(lockTime) {
		return nil
	}
	return ErrNotExpired
}

// CheckNotExpired is the forward-operation gate: refund 仍被锁定时返回 nil；
// 已经到期时返回 ErrExpired。
func CheckNotExpired(lockTime uint32, at time.Time, blockHeight uint32) error {
	if err := CheckExpired(lockTime, at, blockHeight); err == nil {
		return ErrExpired
	} else if !errors.Is(err, ErrNotExpired) {
		return err
	}
	return nil
}
