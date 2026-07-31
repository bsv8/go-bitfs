//go:build chainutils
// +build chainutils

package libs

import (
	"b/chain"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// 把这些未花费，通过一个交易，整理成标准未花费
func (c *ChainUtils) OrganizeUnspent(
	priv *ec.PrivateKey,
	unspents *[]chain.UTXO,
	standardSatoshi uint64,
	standardlimit int,
) (*[]chain.UTXO, uint64, error) {
	tempTx := tx.NewTransaction()

	// 创建解锁脚本模板
	sigHash := sighash.Flag(sighash.ForkID | sighash.All)
	aUnlockingScriptTemplate, err := p2pkh.Unlock(priv, &sigHash)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create one unlocking script template: %w", err)
	}

	// 前序交易锁定脚本
	clientAddress, err := c.GetAddressFromPubKey(priv.PubKey())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get address: %w", err)
	}
	prevScript, err := p2pkh.Lock(clientAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create locking script: %w", err)
	}
	prevTxLockingScript := hex.EncodeToString(prevScript.Bytes())

	// add input
	var totalValue uint64 = 0
	for _, utxo := range *unspents {
		err := tempTx.AddInputFrom(
			utxo.TxID,
			utxo.Vout,
			prevTxLockingScript,
			utxo.Value,
			aUnlockingScriptTemplate,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to add input: %w", err)
		}
		totalValue += utxo.Value
		// fmt.Printf("add input: %s, %d, %d\n", utxo.TxID, utxo.Vout, utxo.Value)
	}

	// 计算可以生产多少个标准未花费，如果超过 standardlimit，那就只生产 standardlimit 个
	var count int = 0
	count = int(totalValue / standardSatoshi)
	if count > standardlimit {
		count = standardlimit
	}

	if count == 0 {
		return &[]chain.UTXO{}, 0, nil
	}

	// add output
	for i := 0; i < count; i++ {
		tempTx.AddOutput(&tx.TransactionOutput{
			Satoshis:      standardSatoshi,
			LockingScript: prevScript,
		})
	}

	// add change
	// if totalValue > 0 {
	tempTx.AddOutput(&tx.TransactionOutput{
		Satoshis:      totalValue - uint64(count)*standardSatoshi,
		LockingScript: prevScript,
	})
	// }``

	// 为每个输入签名，以便正确估计交易大小
	for i := range tempTx.Inputs {
		unlockingScript, err := aUnlockingScriptTemplate.Sign(tempTx, uint32(i))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to sign input %d: %w", i, err)
		}
		tempTx.Inputs[i].UnlockingScript = unlockingScript
	}

	// 计算交易大小（字节）
	txSize := tempTx.Size()
	fee := uint64(float64(txSize) / 1000.0 * float64(c.feeRate))

	if totalValue-fee < standardSatoshi {
		return nil, 0, fmt.Errorf("not enough balance, need %d, have %d", standardSatoshi, totalValue-fee)
	}

	// 正式做 tx
	thisTx := tx.NewTransaction()

	// 添加 input
	for _, utxo := range *unspents {
		err := thisTx.AddInputFrom(
			utxo.TxID,
			utxo.Vout,
			prevTxLockingScript,
			utxo.Value,
			aUnlockingScriptTemplate,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to add input: %w", err)
		}
	}

	outputCount := int((totalValue - fee) / standardSatoshi)
	if outputCount > standardlimit {
		outputCount = standardlimit
	}
	for i := 0; i < outputCount; i++ {
		thisTx.AddOutput(&tx.TransactionOutput{
			Satoshis:      standardSatoshi,
			LockingScript: prevScript,
		})
	}

	// add change
	if totalValue-fee > uint64(outputCount)*standardSatoshi {
		thisTx.AddOutput(&tx.TransactionOutput{
			Satoshis:      totalValue - fee - uint64(outputCount)*standardSatoshi,
			LockingScript: prevScript,
		})
	}

	// 为每个输入签名，以便正确估计交易大小
	// 重新签名
	for i := range thisTx.Inputs {
		unlockingScript, err := aUnlockingScriptTemplate.Sign(thisTx, uint32(i))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to sign input %d: %w", i, err)
		}
		thisTx.Inputs[i].UnlockingScript = unlockingScript
	}

	// broadcast
	txHex, err := c.Chain.BroadcastTx(thisTx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	if txHex != thisTx.TxID().String() {
		return nil, 0, fmt.Errorf("failed to broadcast transaction, txHex: %s, txId: %s", txHex, thisTx.TxID().String())
	}

	retUtxo := &[]chain.UTXO{}
	var amount uint64 = 0
	for i := 0; i < outputCount; i++ {
		r := chain.UTXO{
			TxID:  txHex,
			Vout:  uint32(i),
			Value: standardSatoshi,
		}
		*retUtxo = append(*retUtxo, r)
		amount += standardSatoshi
	}

	return retUtxo, amount, nil
}
