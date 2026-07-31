package chain_utils

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	// primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// 服务器 回签
func SpendTXServerSign(
	transactionObject *tx.Transaction,
	targetAmount uint64,
	serverPrivateKey *ec.PrivateKey,
	clientPublicKey *ec.PublicKey,
) (*[]byte, error) {
	serverPublicKey := serverPrivateKey.PubKey()

	// 创建优先级脚本
	priorityScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return nil, fmt.Errorf("创建优先级脚本失败: %v", err)
	}

	// 设置输入的锁定脚本
	transactionObject.Inputs[0].SetSourceTxOutput(
		&tx.TransactionOutput{
			Satoshis:      targetAmount,
			LockingScript: priorityScript,
		},
	)

	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{}, []*ec.PublicKey{serverPublicKey, clientPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 重新签名所有输入
	serverSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(transactionObject, 0, serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("b 重新签名输入 %d 失败: %v", 1, err)
	}

	return serverSignByte, nil
}
