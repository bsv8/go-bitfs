package buyer

// 本文件只在测试二进制内恢复旧内部符号的可见名字，让既有测试继续通过新的
// 纯函数实现驱动同一套内部证据逻辑。它不是公开 API：公开面只有 api.go 中的
// 包级纯函数与普通证据包。

import "github.com/bsv8/go-bitfs/protocol"

// Workflow 是测试内可见的内部工作区别名（非公开 API）。
type Workflow = workflow

// OpeningCheckpoint 是测试内可见的内部开池 checkpoint 别名（非公开 API）。
type OpeningCheckpoint = openingCheckpoint

// PoolCheckpoint 是测试内可见的内部池 checkpoint 别名（非公开 API）。
type PoolCheckpoint = poolCheckpoint

// AuthorizationCheckpoint 是测试内可见的内部授权 checkpoint 别名（非公开 API）。
type AuthorizationCheckpoint = authorizationCheckpoint

// PrepareOpeningCommand 是测试内可见的内部开池命令别名（非公开 API）。
type PrepareOpeningCommand = prepareOpeningCommand

// PreparePoolOpeningResult 是测试内可见的内部开池结果别名（非公开 API）。
type PreparePoolOpeningResult = preparePoolOpeningResult

// CompleteOpeningResult 是测试内可见的内部完成开池结果别名（非公开 API）。
type CompleteOpeningResult = completeOpeningResult

// RequestContentCommand 是测试内可见的内部内容请求命令别名（非公开 API）。
type RequestContentCommand = requestContentCommand

// RequestContentResult 是测试内可见的内部内容请求结果别名（非公开 API）。
type RequestContentResult = requestContentResult

// VerifyDeliveryCommand 是测试内可见的内部交付验收命令别名（非公开 API）。
type VerifyDeliveryCommand = verifyDeliveryCommand

// PaymentPreparationResult 是测试内可见的内部付款准备结果别名（非公开 API）。
type PaymentPreparationResult = paymentPreparationResult

// PrepareCloseCommand 是测试内可见的内部关池准备命令别名（非公开 API）。
type PrepareCloseCommand = prepareCloseCommand

// ClosePreparationResult 是测试内可见的内部关池准备结果别名（非公开 API）。
type ClosePreparationResult = closePreparationResult

// VerifyCloseCommand 是测试内可见的内部关池验收命令别名（非公开 API）。
type VerifyCloseCommand = verifyCloseCommand

// ArbitrationRetrievalCommand 是测试内可见的内部取回命令别名（非公开 API）。
type ArbitrationRetrievalCommand = arbitrationRetrievalCommand

// ArbitratedContentCommand 是测试内可见的内部取回验收命令别名（非公开 API）。
type ArbitratedContentCommand = arbitratedContentCommand

// NewWorkflow 仅在测试内构造内部工作区。
func NewWorkflow(signer protocol.Signer) (*Workflow, error) { return newWorkflow(signer) }

// RestoreOpeningCheckpoint 仅在测试内从 exact evidence 恢复开池 checkpoint。
func RestoreOpeningCheckpoint(rawKind2 []byte, fundingTransactionRaw []byte) (*OpeningCheckpoint, error) {
	return restoreOpeningCheckpoint(rawKind2, fundingTransactionRaw)
}

// RestorePoolCheckpoint 仅在测试内从 exact evidence 恢复池 checkpoint。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	return restorePoolCheckpoint(openingProofCBOR, paymentRawTx)
}

// RestoreAuthorizationCheckpoint 仅在测试内从完整本地证据恢复授权 checkpoint。
func RestoreAuthorizationCheckpoint(rawKind1 []byte, rawKind5 []byte, openingProofCBOR []byte) (*AuthorizationCheckpoint, error) {
	return restoreAuthorizationCheckpoint(rawKind1, rawKind5, openingProofCBOR)
}
