package protocol

import (
	"errors"
	"testing"
	"time"
)

// 本文件锁定退款门禁的稳定分类矩阵与 WrapClassified 的"保分类"契约：
//   - 事实缺失（ErrFactsMissing）→ invalid_evidence，属于输入问题；
//   - 正向门禁撞上已成熟锁 → expired；成熟判定未到 → not_matured；
//   - WrapClassified 绝不覆盖链上已有分类，无分类时才落 invalid_evidence。
//
// 应用只依据 Code/CodeOf 做分支：任何调用层包装把 invalid_evidence 报成
// expired/not_matured 都会让应用得到错误的协议状态结论，在此直接失败。

// requireGateCode 断言 err 非空、CodeOf 精确等于 want，且可选地穿透到哨兵。
func requireGateCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", want)
	}
	code, ok := CodeOf(err)
	if !ok || code != want {
		t.Fatalf("error code = %v (err=%v), want exactly %s", code, err, want)
	}
}

func TestRefundGateClassificationMatrix(t *testing.T) {
	tsLock := RefundLockTime(RefundTimestampThreshold) // 时间戳锁定（阈值即时间戳语义）
	heightLock := RefundLockTime(400_000)              // 区块高锁定
	maturedAt := time.Unix(int64(tsLock), 0)
	before := maturedAt.Add(-time.Second)

	t.Run("timestamp lock missing Now → invalid_evidence", func(t *testing.T) {
		requireGateCode(t, Facts{}.CheckRefundNotExpired(tsLock), CodeInvalidEvidence)
		requireGateCode(t, Facts{}.CheckRefundMatured(tsLock), CodeInvalidEvidence)
	})
	t.Run("height lock missing BlockHeight → invalid_evidence", func(t *testing.T) {
		facts := Facts{Now: before} // 只有时间：height 门禁绝不猜测高度
		requireGateCode(t, facts.CheckRefundNotExpired(heightLock), CodeInvalidEvidence)
		requireGateCode(t, facts.CheckRefundMatured(heightLock), CodeInvalidEvidence)
	})
	t.Run("facts missing keeps ErrFactsMissing reachable", func(t *testing.T) {
		err := Facts{}.CheckRefundNotExpired(tsLock)
		if !errors.Is(err, ErrFactsMissing) {
			t.Fatalf("error = %v, want errors.Is(ErrFactsMissing)", err)
		}
	})
	t.Run("forward gate truly matured → expired", func(t *testing.T) {
		requireGateCode(t, Facts{Now: maturedAt}.CheckRefundNotExpired(tsLock), CodeExpired)
		requireGateCode(t, Facts{BlockHeight: 400_000}.CheckRefundNotExpired(heightLock), CodeExpired)
	})
	t.Run("matured gate truly immature → not_matured", func(t *testing.T) {
		requireGateCode(t, Facts{Now: before}.CheckRefundMatured(tsLock), CodeNotMatured)
		requireGateCode(t, Facts{BlockHeight: 399_999}.CheckRefundMatured(heightLock), CodeNotMatured)
	})
	t.Run("gate successes are nil", func(t *testing.T) {
		if err := (Facts{Now: before}).CheckRefundNotExpired(tsLock); err != nil {
			t.Fatalf("locked forward op rejected: %v", err)
		}
		if err := (Facts{Now: maturedAt}).CheckRefundMatured(tsLock); err != nil {
			t.Fatalf("matured refund rejected: %v", err)
		}
	})
}

func TestWrapClassifiedPreservesExistingClassification(t *testing.T) {
	gateErr := Errorf("protocol.CheckRefundNotExpired", CodeExpired, 0, "refund_locktime", "pool refund has expired")
	wrapped := WrapClassified(gateErr, "buyer.RequestContent", 5, "refund_locktime")
	code, ok := CodeOf(wrapped)
	if !ok || code != CodeExpired {
		t.Fatalf("code = %v (ok=%v), want preserved expired", code, ok)
	}
	if !errors.Is(wrapped, gateErr) {
		t.Fatal("wrap lost the cause chain")
	}
	var typed *Error
	if !errors.As(wrapped, &typed) || typed.Field != "refund_locktime" {
		t.Fatalf("field/context lost: %+v", typed)
	}
}

func TestWrapClassifiedDefaultsToInvalidEvidenceForUnclassified(t *testing.T) {
	wrapped := WrapClassified(errors.New("boom"), "entry", 0, "refund_locktime")
	requireGateCode(t, wrapped, CodeInvalidEvidence)
}

func TestWrapClassifiedNilPassesThrough(t *testing.T) {
	if err := WrapClassified(nil, "entry", 0, ""); err != nil {
		t.Fatalf("nil input produced %v", err)
	}
}
