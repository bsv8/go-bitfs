package triple_endpoint

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
// const FINAL_LOCKTIME uint32 = 0xffffffff

// 合成两个签名
func TripleFeePoolLoadTx(
	txHex string,
	locktime *uint32,
	sequenceNumber uint32,
	serverAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	bPublicKey *ec.PublicKey,
	targetAmount uint64, // input 的金额
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
	priorityScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, bPublicKey}, 2)
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
	bTx.Inputs[0].UnlockingScript = nil

	// 更新输出金额
	if len(bTx.Outputs) != 2 || bTx.Outputs[0] == nil || bTx.Outputs[1] == nil {
		return nil, fmt.Errorf("triple pool state requires exactly two outputs")
	}
	allAmount := bTx.Outputs[0].Satoshis + bTx.Outputs[1].Satoshis
	// fmt.Printf("++++++++++++++++++++++++++++++++++++++++++ allAmount: %d\n", allAmount)
	bTx.Outputs[0].Satoshis = serverAmount
	if serverAmount > allAmount {
		return nil, fmt.Errorf("pool_insufficient")
	}
	bTx.Outputs[1].Satoshis = allAmount - serverAmount
	bTx.Inputs[0].UnlockingScript = nil

	// fmt.Printf("allamount: %d, ssatoshis 1: %d, satoshis 2: %d\n", allAmount, bTx.Outputs[0].Satoshis, bTx.Outputs[1].Satoshis)

	// fmt.Printf("bTx 2: %s\n", bTx.Hex())

	return bTx, nil
}

// 双端费用池，分配资金, 客户端签名
// client -> server 修改金额和版本号
func ClientATripleFeePoolSpendTXUpdateSign(
	tx *tx.Transaction,
	serverPublicKey *ec.PublicKey,
	aPrivateKey *ec.PrivateKey,
	bPublicKey *ec.PublicKey,
) (*[]byte, error) {
	// if locktime != nil {
	// 	tx.LockTime = *locktime
	// }

	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{aPrivateKey}, []*ec.PublicKey{serverPublicKey, aPrivateKey.PubKey(), bPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 重新签名所有输入
	clientSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(tx, 0, aPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("c 重新签名输入 %d 失败: %v", 1, err)
	}

	return clientSignByte, nil
}

// ClientTripleFeePoolSpendTXUpdateSign 三方费用池，客户端签名
// 用于 GetLatestTripleCostPoolHistory 函数中，由客户端对三方费用池进行签名
func ClientTripleFeePoolSpendTXUpdateSign(
	tx *tx.Transaction,
	clientPrivateKey *ec.PrivateKey,
	serverPublicKey *ec.PublicKey,
	receiverPublicKey *ec.PublicKey,
) (*[]byte, error) {
	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	// 这里客户端作为 A 方签名，服务器和接收方作为其他两方
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{clientPrivateKey}, []*ec.PublicKey{serverPublicKey, clientPrivateKey.PubKey(), receiverPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 客户端签名
	clientSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(tx, 0, clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("client 重新签名输入 %d 失败: %v", 1, err)
	}

	return clientSignByte, nil
}
