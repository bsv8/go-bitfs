package seller

// 本文件只在测试二进制内恢复旧内部符号的可见名字，让既有测试继续通过新的
// 纯函数实现驱动同一套内部证据逻辑。它不是公开 API：公开面只有 api.go 中的
// 包级纯函数与普通证据包。

import "github.com/bsv8/go-bitfs/protocol"

// Workflow 是测试内可见的内部工作区别名（非公开 API）。
type Workflow = workflow

// OpeningCheckpoint 是测试内可见的内部预签 checkpoint 别名（非公开 API）。
type OpeningCheckpoint = openingCheckpoint

// PoolCheckpoint 是测试内可见的内部池 checkpoint 别名（非公开 API）。
type PoolCheckpoint = poolCheckpoint

// QuoteResult 是测试内可见的内部报价结果别名（非公开 API）。
type QuoteResult = quoteResult

// PreparePoolOpeningResult 是测试内可见的内部预签结果别名（非公开 API）。
type PreparePoolOpeningResult = preparePoolOpeningResult

// FundingVerificationResult 是测试内可见的内部验资结果别名（非公开 API）。
type FundingVerificationResult = fundingVerificationResult

// DeliveryCommand 是测试内可见的内部交付命令别名（非公开 API）。
type DeliveryCommand = deliveryCommand

// DeliveryResult 是测试内可见的内部交付结果别名（非公开 API）。
type DeliveryResult = deliveryResult

// DeliveryCheckpoint 是测试内可见的内部交付 checkpoint 别名（非公开 API）。
type DeliveryCheckpoint = deliveryCheckpoint

// PaymentCommand 是测试内可见的内部收款命令别名（非公开 API）。
type PaymentCommand = paymentCommand

// CloseCommand 是测试内可见的内部关池命令别名（非公开 API）。
type CloseCommand = closeCommand

// ArbitrationCommand 是测试内可见的内部仲裁命令别名（非公开 API）。
type ArbitrationCommand = arbitrationCommand

// ArbitratedPaymentCommand 是测试内可见的内部仲裁收款命令别名（非公开 API）。
type ArbitratedPaymentCommand = arbitratedPaymentCommand

// CompletePaymentResult 是测试内可见的内部收款结果别名（非公开 API）。
type CompletePaymentResult = completePaymentResult

// NewWorkflow 仅在测试内构造内部工作区。
func NewWorkflow(signer protocol.Signer) (*Workflow, error) { return newWorkflow(signer) }

// RestoreOpeningCheckpoint 仅在测试内从 exact evidence 恢复预签 checkpoint。
func RestoreOpeningCheckpoint(rawKind2 []byte, rawKind3 []byte) (*OpeningCheckpoint, error) {
	return restoreOpeningCheckpoint(rawKind2, rawKind3)
}

// RestorePoolCheckpoint 仅在测试内从 exact evidence 恢复池 checkpoint。
func RestorePoolCheckpoint(openingProofCBOR []byte, paymentRawTx []byte) (*PoolCheckpoint, error) {
	return restorePoolCheckpoint(openingProofCBOR, paymentRawTx)
}

// RestoreDeliveryCheckpoint 仅在测试内从 exact evidence 恢复交付 checkpoint。
func RestoreDeliveryCheckpoint(rawKind1, openingProofCBOR, rawKind5, rawKind6 []byte) (*DeliveryCheckpoint, error) {
	return restoreDeliveryCheckpoint(rawKind1, openingProofCBOR, rawKind5, rawKind6)
}
