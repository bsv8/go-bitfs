package arbitrated_pool

import (
	"encoding/hex"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

type FundingTxResult struct {
	Tx              *tx.Transaction
	PoolAmount      uint64
	PoolOutputIndex uint32
	Fee             uint64
}

// BuildArbitratedPoolFundingTx 使用 Buyer UTXO 创建 2-of-3 仲裁池。
func BuildArbitratedPoolFundingTx(utxos []libs.UTXO, poolAmount uint64, buyerPrivateKey *ec.PrivateKey, roles ArbitratedPoolRoles, isMain bool, feeRate FeeSatPerKB) (*FundingTxResult, error) {
	if len(utxos) == 0 {
		return nil, fmt.Errorf("buyer UTXOs are required")
	}
	if poolAmount == 0 {
		return nil, fmt.Errorf("pool amount must be positive")
	}
	if err := validateRoles(roles); err != nil {
		return nil, err
	}
	if err := validatePrivateKey(buyerPrivateKey, roles.Buyer, "buyer"); err != nil {
		return nil, err
	}
	lock, err := BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, err
	}
	address, err := libs.GetAddressFromPublicKey(roles.Buyer, isMain)
	if err != nil {
		return nil, fmt.Errorf("failed to get buyer address: %w", err)
	}
	previous, err := p2pkh.Lock(address)
	if err != nil {
		return nil, fmt.Errorf("failed to build buyer source script: %w", err)
	}
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	unlock, err := p2pkh.Unlock(buyerPrivateKey, &flag)
	if err != nil {
		return nil, fmt.Errorf("failed to build buyer unlocking template: %w", err)
	}
	result := tx.NewTransaction()
	var total uint64
	for _, utxo := range utxos {
		if ^uint64(0)-total < utxo.Value {
			return nil, fmt.Errorf("buyer UTXO total overflows")
		}
		total += utxo.Value
		if err := result.AddInputFrom(utxo.TxID, utxo.Vout, hex.EncodeToString(previous.Bytes()), utxo.Value, unlock); err != nil {
			return nil, fmt.Errorf("failed to add buyer UTXO: %w", err)
		}
	}
	if total < poolAmount {
		return nil, fmt.Errorf("buyer balance is insufficient for pool amount")
	}
	result.AddOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	result.AddOutput(&tx.TransactionOutput{Satoshis: total - poolAmount, LockingScript: previous})
	for i := range result.Inputs {
		s, err := unlock.Sign(result, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to sign buyer input %d: %w", i, err)
		}
		result.Inputs[i].UnlockingScript = s
	}
	fee, err := feeSat(result.Size(), feeRate)
	if err != nil {
		return nil, err
	}
	if fee > ^uint64(0)-poolAmount || total < poolAmount+fee {
		return nil, fmt.Errorf("buyer balance is insufficient for pool amount and fee")
	}
	result.Outputs[1].Satoshis = total - poolAmount - fee
	for i := range result.Inputs {
		s, err := unlock.Sign(result, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to sign buyer input %d: %w", i, err)
		}
		result.Inputs[i].UnlockingScript = s
	}
	return &FundingTxResult{Tx: result, PoolAmount: poolAmount, PoolOutputIndex: 0, Fee: fee}, nil
}
