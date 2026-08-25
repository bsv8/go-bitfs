package protocol

import (
	"crypto/rand"
	"encoding/hex"
)

// cryptorandRead 是 crypto/rand 的包内唯一入口，便于测试与审计。
func cryptorandRead(target []byte) (int, error) { return rand.Read(target) }

// hexString 返回小写 hex；仅用于诊断字符串，不进入 wire。
func hexString(raw []byte) string { return hex.EncodeToString(raw) }
