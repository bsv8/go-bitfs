package libs

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
)

// BuildOptionalOpReturnScript 为费用池付款证明构造可选 OP_RETURN 锁定脚本。
// 设计说明：
// - proof 按原始字节处理，库层不猜测文本编码，避免二进制 proof 被误改；
// - 空 proof 直接返回 nil，调用方据此维持旧交易结构，不生成额外输出；
// - 使用 OP_FALSE OP_RETURN，保持数据输出的标准表达。
func BuildOptionalOpReturnScript(proof []byte) (*script.Script, error) {
	if len(proof) == 0 {
		return nil, nil
	}

	lockingScript := &script.Script{}
	if err := lockingScript.AppendOpcodes(script.OpFALSE, script.OpRETURN); err != nil {
		return nil, fmt.Errorf("build op_return prefix: %w", err)
	}
	if err := lockingScript.AppendPushData(proof); err != nil {
		return nil, fmt.Errorf("build op_return payload: %w", err)
	}
	return lockingScript, nil
}
