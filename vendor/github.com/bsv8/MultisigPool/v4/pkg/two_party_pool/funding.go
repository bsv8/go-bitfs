package two_party_pool

import (
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

// FundingTxResult 是建池交易及其资金池输出的显式结果。
type FundingTxResult struct {
	Tx              *tx.Transaction
	PoolAmount      uint64
	PoolOutputIndex uint32
	Fee             uint64
}

// BuildTwoPartyPoolFundingTx 只接受 Buyer 所有的 UTXO，并创建 [Buyer, Seller] 池。
func BuildTwoPartyPoolFundingTx(
	utxos []libs.UTXO,
	poolAmount uint64,
	buyerPrivateKey *ec.PrivateKey,
	roles TwoPartyPoolRoles,
	isMain bool,
	feeRate float64,
) (*FundingTxResult, error) {
	if len(utxos) == 0 {
		return nil, fmt.Errorf("buyer UTXOs are required")
	}
	if poolAmount == 0 {
		return nil, fmt.Errorf("pool amount must be positive")
	}
	if feeRate < 0 {
		return nil, fmt.Errorf("fee rate must not be negative")
	}
	if err := validateBuyerKey(roles, buyerPrivateKey); err != nil {
		return nil, err
	}
	lock, err := BuildTwoPartyPoolLock(roles)
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
	unlockTemplate, err := p2pkh.Unlock(buyerPrivateKey, func() *sighash.Flag { f := sighash.Flag(sighash.ForkID | sighash.All); return &f }())
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
		if err := result.AddInputFrom(utxo.TxID, utxo.Vout, hex.EncodeToString(previous.Bytes()), utxo.Value, unlockTemplate); err != nil {
			return nil, fmt.Errorf("failed to add buyer UTXO: %w", err)
		}
	}
	if total < poolAmount {
		return nil, fmt.Errorf("buyer balance is insufficient for pool amount")
	}
	result.AddOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	result.AddOutput(&tx.TransactionOutput{Satoshis: total - poolAmount, LockingScript: previous})
	for i := range result.Inputs {
		signed, err := unlockTemplate.Sign(result, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to sign buyer input %d: %w", i, err)
		}
		result.Inputs[i].UnlockingScript = signed
	}
	fee := uint64(float64(result.Size()) / 1000 * feeRate)
	if fee == 0 {
		fee = 1
	}
	if fee > ^uint64(0)-poolAmount || total < poolAmount+fee {
		return nil, fmt.Errorf("buyer balance is insufficient for pool amount and fee")
	}
	result.Outputs[1].Satoshis = total - poolAmount - fee
	for i := range result.Inputs {
		signed, err := unlockTemplate.Sign(result, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("failed to sign buyer input %d: %w", i, err)
		}
		result.Inputs[i].UnlockingScript = signed
	}
	return &FundingTxResult{Tx: result, PoolAmount: poolAmount, PoolOutputIndex: 0, Fee: fee}, nil
}
