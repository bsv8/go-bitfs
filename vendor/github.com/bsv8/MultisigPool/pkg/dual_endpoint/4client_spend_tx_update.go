package chain_utils

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"

	// primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// 最终 locaktime
const FINAL_LOCKTIME uint32 = 0xffffffff

// 合成两个签名
func LoadTx(
	txHex string,
	locktime *uint32,
	sequenceNumber uint32,
	serverAmount uint64,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	targetAmount uint64,
	// serverSignByte *[]byte,
	// clientSignByte *[]byte,
) (*transaction.Transaction, error) {
	return LoadTxWithProof(txHex, locktime, sequenceNumber, serverAmount, serverPublicKey, clientPublicKey, targetAmount, nil)
}

// LoadTxWithProof 在旧更新逻辑上追加“同步可选 proof OP_RETURN”的能力。
// 设计说明：
// - paymentProof=nil 时，沿用旧交易里的数据输出，不改动现有 proof；
// - paymentProof 非 nil 时，会把当前状态 proof 同步到交易最后一个 OP_RETURN 输出；
// - 这样 BFTP 可以把 proof state 作为共享库挂在状态交易上，而 MultisigPool 仍然保持通用。
func LoadTxWithProof(
	txHex string,
	locktime *uint32,
	sequenceNumber uint32,
	serverAmount uint64,
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
	targetAmount uint64,
	paymentProof []byte,
) (*transaction.Transaction, error) {
	// 恢复 bTx
	bTx, err := transaction.NewTransactionFromHex(txHex)
	if err != nil {
		return nil, err
	}

	if locktime != nil {
		bTx.LockTime = *locktime
	}

	// 创建优先级脚本
	priorityScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return nil, fmt.Errorf("创建优先级脚本失败: %v", err)
	}

	bTx.Inputs[0].SetSourceTxOutput(
		&tx.TransactionOutput{
			Satoshis:      targetAmount,
			LockingScript: priorityScript,
		},
	)

	// signs := [][]byte{*serverSignByte, *clientSignByte}
	// unScript, err := multisig.BuildSignScript(&signs)
	// if err != nil {
	// 	return nil, fmt.Errorf("BuildSignScript error: %v", err)
	// }

	// 更新输入
	// bTx.Inputs[0].UnlockingScript = unScript
	bTx.Inputs[0].SequenceNumber = sequenceNumber

	// 更新输出金额
	allAmount := bTx.Outputs[0].Satoshis + bTx.Outputs[1].Satoshis
	bTx.Outputs[0].Satoshis = serverAmount
	bTx.Outputs[1].Satoshis = allAmount - serverAmount

	if paymentProof != nil {
		if err := syncOptionalProofOutput(bTx, paymentProof); err != nil {
			return nil, err
		}
	}

	// fmt.Printf("bTx 2: %s\n", bTx.Hex())

	return bTx, nil
}

func syncOptionalProofOutput(bTx *transaction.Transaction, paymentProof []byte) error {
	if bTx == nil {
		return fmt.Errorf("transaction is nil")
	}
	lockingScript, err := multisig.BuildOptionalOpReturnScript(paymentProof)
	if err != nil {
		return fmt.Errorf("failed to build optional proof output: %w", err)
	}
	dataIdx := -1
	for idx, out := range bTx.Outputs {
		if out == nil || out.LockingScript == nil {
			continue
		}
		if out.LockingScript.IsData() {
			dataIdx = idx
			break
		}
	}
	if lockingScript == nil {
		if dataIdx >= 0 {
			bTx.Outputs = append(bTx.Outputs[:dataIdx], bTx.Outputs[dataIdx+1:]...)
		}
		return nil
	}
	dataOut := &tx.TransactionOutput{
		Satoshis:      0,
		LockingScript: lockingScript,
	}
	if dataIdx >= 0 {
		bTx.Outputs[dataIdx] = dataOut
		return nil
	}
	// 数据输出固定追加到尾部，避免打乱前两个金额输出语义。
	bTx.Outputs = append(bTx.Outputs, dataOut)
	return nil
}

// 双端费用池，分配资金, 客户端签名
// client -> server 修改金额和版本号
func ClientDualFeePoolSpendTXUpdateSign(
	tx *tx.Transaction,
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
) (*[]byte, error) {
	// if locktime != nil {
	// 	tx.LockTime = *locktime
	// }

	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{}, []*ec.PublicKey{serverPublicKey, clientPrivateKey.PubKey()}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 重新签名所有输入
	clientSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(tx, 0, clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("c 重新签名输入 %d 失败: %v", 1, err)
	}

	return clientSignByte, nil
}
