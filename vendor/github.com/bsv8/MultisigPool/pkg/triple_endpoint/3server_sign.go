package triple_endpoint

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	// primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// 服务器 回签
func SpendTXTripleFeePoolBSign(
	transactionObject *tx.Transaction,
	targetAmount uint64,
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	bPrivateKey *ec.PrivateKey,
) (*[]byte, error) {
	// 创建优先级脚本
	priorityScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, bPrivateKey.PubKey()}, 2)
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
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{bPrivateKey}, []*ec.PublicKey{serverPublicKey, aPublicKey, bPrivateKey.PubKey()}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 重新签名所有输入
	bSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(transactionObject, 0, bPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("b 重新签名输入 %d 失败: %v", 1, err)
	}

	return bSignByte, nil
}
