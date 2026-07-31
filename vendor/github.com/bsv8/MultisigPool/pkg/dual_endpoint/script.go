package chain_utils

import (
	"fmt"

	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
)

// 构建双端费用池的花费脚本
func DualPoolSpentScript(
	serverPublicKey *ec.PublicKey,
	clientPublicKey *ec.PublicKey,
) (*script.Script, error) {
	prevMultisigScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, clientPublicKey}, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to create server locking script: %w", err)
	}

	return prevMultisigScript, nil
}

// 从创建花费脚本,客户端签名
func MergeDualPoolSigForSpendTx(
	txHex string,
	serverSignByte *[]byte,
	clientSignByte *[]byte,
) (*tx.Transaction, error) {
	// 恢复 bTx
	bTx, err := tx.NewTransactionFromHex(txHex)
	if err != nil {
		return nil, err
	}

	signs := [][]byte{*serverSignByte, *clientSignByte}
	unScript, err := multisig.BuildSignScript(&signs)
	if err != nil {
		return nil, fmt.Errorf("BuildSignScript error: %v", err)
	}

	bTx.Inputs[0].UnlockingScript = unScript

	return bTx, nil
}
