package arbitration

import "github.com/fxamacker/cbor/v2"

// 本文件是外部测试包 arbitration_test 的内部桥（_test.go 不参与生产构建）：
// 仅导出安全矩阵构造敌意报文所需的私有常量、确定性 encoder 与派生上限，
// 不改变任何生产行为。

// DeterministicEncForTest 返回包内确定性 CBOR encoder，供外部测试包手工编码
// 敌意/非规范报文。
func DeterministicEncForTest() cbor.EncMode { return arbitrationEnc }

// BstrForTest 导出 nil→空字节串 的规范化 helper。
func BstrForTest(value []byte) []byte { return bstr(value) }

// 与生产派生公式共享同一常量来源的上限值；外部测试包用它复核派生关系。
const (
	// MaxSignatureBstrOverheadForTest 是超过 255 字节的 bstr 所需的 uint16
	// 长度头开销（0x59 + 两字节）。
	MaxSignatureBstrOverheadForTest = maxSignatureBstrOverhead
	// MaxArbitrationRequestEnvelopeBytesForTest 是 Kind 8 五元外壳的精确
	// 确定性 CBOR 开销。
	MaxArbitrationRequestEnvelopeBytesForTest = maxArbitrationRequestEnvelopeBytes
	// MaxContentRetrievalRequestDocBytesForTest 是 Kind 10 内层请求子文档的
	// 字节上限。
	MaxContentRetrievalRequestDocBytesForTest = maxContentRetrievalRequestDocBytes
)
