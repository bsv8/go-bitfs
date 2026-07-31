package chain_utils

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	// primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// 双端费用池，分配资金, server 签名
// client -> server 修改金额和版本号
func ServerDualFeePoolSpendTXUpdateSign(
	tx *tx.Transaction,
	serverPrivateKey *ec.PrivateKey,
	clientPublicKey *ec.PublicKey,
) (*[]byte, error) {
	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aMultisigUnlockingScriptTemplate, err := multisig.Unlock([]*ec.PrivateKey{}, []*ec.PublicKey{serverPrivateKey.PubKey(), clientPublicKey}, 2, &sigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create unlocking script template: %w", err)
	}

	// 重新签名所有输入
	serverSignByte, err := aMultisigUnlockingScriptTemplate.SignOne(tx, 0, serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("d 重新签名输入 %d 失败: %v", 1, err)
	}

	return serverSignByte, nil
}
