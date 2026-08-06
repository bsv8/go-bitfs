package two_party_pool

import (
	"bytes"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

type FeeSatPerKB uint64

type StateInput struct {
	Protocol      string
	Version       uint32
	PreviousRawTx []byte
	// PreviousSourceOutput 在标准 raw transaction 不包含源输出元数据时显式提供源输出。
	PreviousSourceOutput *tx.TransactionOutput
	Sequence             uint32
	LockTime             *uint32
	BuyerAmount          uint64
	SellerAmount         uint64
	PoolAmount           uint64
	Roles                TwoPartyPoolRoles
	FeeRate              FeeSatPerKB
	PaymentProof         []byte
}

func transactionFee(size int, rate FeeSatPerKB) (uint64, error) {
	if size < 0 {
		return 0, fmt.Errorf("negative transaction size")
	}
	if size == 0 || rate == 0 {
		return 0, nil
	}
	if uint64(size) > ^uint64(0)/uint64(rate) {
		return 0, fmt.Errorf("transaction fee overflow")
	}
	value := uint64(size) * uint64(rate)
	if value > ^uint64(0)-999 {
		return 0, fmt.Errorf("transaction fee overflow")
	}
	return (value + 999) / 1000, nil
}

func cloneTransaction(value *tx.Transaction) (*tx.Transaction, error) {
	if value == nil {
		return nil, fmt.Errorf("transaction is required")
	}
	copy, err := tx.NewTransactionFromBytes(value.Bytes())
	if err != nil {
		return nil, fmt.Errorf("copy transaction: %w", err)
	}
	return copy, nil
}

func stateScripts(roles TwoPartyPoolRoles, isMain bool) (*script.Script, *script.Script, error) {
	if err := validateRoles(roles); err != nil {
		return nil, nil, err
	}
	lock, err := BuildTwoPartyPoolLock(roles)
	if err != nil {
		return nil, nil, err
	}
	buyerAddress, err := libs.GetAddressFromPublicKey(roles.Buyer, isMain)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build buyer address: %w", err)
	}
	sellerAddress, err := libs.GetAddressFromPublicKey(roles.Seller, isMain)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build seller address: %w", err)
	}
	buyerScript, err := p2pkh.Lock(buyerAddress)
	if err != nil {
		return nil, nil, err
	}
	sellerScript, err := p2pkh.Lock(sellerAddress)
	if err != nil {
		return nil, nil, err
	}
	_ = buyerScript
	return lock, sellerScript, nil
}

// BuildTwoPartyPoolState 构建 output[0]=Buyer、output[1]=Seller 的状态交易。
func BuildTwoPartyPoolState(input StateInput) (*tx.Transaction, error) {
	if input.Protocol != Protocol || input.Version != Version {
		return nil, fmt.Errorf("unsupported pool protocol: expected %s v%d", Protocol, Version)
	}
	if len(input.PreviousRawTx) == 0 || input.PoolAmount == 0 {
		return nil, fmt.Errorf("previous state and pool amount are required")
	}
	if err := validateRoles(input.Roles); err != nil {
		return nil, err
	}
	state, err := tx.NewTransactionFromBytes(input.PreviousRawTx)
	if err != nil {
		return nil, fmt.Errorf("decode previous state: %w", err)
	}
	if len(state.Inputs) != 1 || (len(state.Outputs) != 2 && len(state.Outputs) != 3) || state.Inputs[0] == nil {
		return nil, fmt.Errorf("two-party pool state must have one input and two value outputs")
	}
	if input.Sequence <= state.Inputs[0].SequenceNumber {
		return nil, fmt.Errorf("payment sequence must increase")
	}
	lock, sellerScript, err := stateScripts(input.Roles, false)
	if err != nil {
		return nil, err
	}
	buyerAddress, err := libs.GetAddressFromPublicKey(input.Roles.Buyer, false)
	if err != nil {
		return nil, err
	}
	buyerScript, err := p2pkh.Lock(buyerAddress)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(state.Outputs[0].LockingScript.Bytes(), buyerScript.Bytes()) || !bytes.Equal(state.Outputs[1].LockingScript.Bytes(), sellerScript.Bytes()) {
		return nil, fmt.Errorf("previous state outputs do not match buyer and seller roles")
	}
	source := state.Inputs[0].SourceTxOutput()
	if input.PreviousSourceOutput != nil {
		if source != nil && (source.Satoshis != input.PreviousSourceOutput.Satoshis || !bytes.Equal(source.LockingScript.Bytes(), input.PreviousSourceOutput.LockingScript.Bytes())) {
			return nil, fmt.Errorf("previous state source output does not match configured pool")
		}
		if source == nil {
			source = input.PreviousSourceOutput
		}
	}
	if source == nil {
		return nil, fmt.Errorf("previous state source output is required")
	}
	if source == nil || source.Satoshis != input.PoolAmount || !bytes.Equal(source.LockingScript.Bytes(), lock.Bytes()) {
		return nil, fmt.Errorf("previous state source output does not match configured pool")
	}
	if state.Inputs[0].SourceTxOutput() == nil {
		state.Inputs[0].SetSourceTxOutput(source)
	}
	if input.SellerAmount > input.PoolAmount {
		return nil, fmt.Errorf("seller amount exceeds pool amount")
	}
	state.Outputs[0].Satoshis = input.PoolAmount - input.SellerAmount
	state.Outputs[1].Satoshis = input.SellerAmount
	state.Outputs[0].LockingScript = buyerScript
	state.Outputs[1].LockingScript = sellerScript
	state.Inputs[0].SequenceNumber = input.Sequence
	if input.LockTime != nil {
		state.LockTime = *input.LockTime
	}
	if len(input.PaymentProof) > 0 {
		proof, err := libs.BuildOptionalOpReturnScript(input.PaymentProof)
		if err != nil {
			return nil, err
		}
		if len(state.Outputs) == 3 {
			state.Outputs[2] = &tx.TransactionOutput{Satoshis: 0, LockingScript: proof}
		} else {
			state.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: proof})
		}
	}
	fake, err := libs.FakeSign(2)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = fake
	fee, err := transactionFee(state.Size(), input.FeeRate)
	if err != nil {
		return nil, err
	}
	if fee > state.Outputs[0].Satoshis {
		return nil, fmt.Errorf("buyer balance is insufficient for fee")
	}
	state.Outputs[0].Satoshis -= fee
	if input.BuyerAmount != 0 && input.BuyerAmount != state.Outputs[0].Satoshis {
		return nil, fmt.Errorf("buyer amount does not match canonical fee")
	}
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	return state, nil
}

// BuildTwoPartyPoolOpeningState creates the first state with zero Seller amount.
func BuildTwoPartyPoolOpeningState(fundingTxID []byte, poolOutputIndex uint32, poolAmount uint64, roles TwoPartyPoolRoles, lockTime uint32, feeRate FeeSatPerKB) (*tx.Transaction, error) {
	if len(fundingTxID) != 32 {
		return nil, fmt.Errorf("funding transaction ID must contain 32 bytes")
	}
	lock, sellerScript, err := stateScripts(roles, false)
	if err != nil {
		return nil, err
	}
	buyerAddress, err := libs.GetAddressFromPublicKey(roles.Buyer, false)
	if err != nil {
		return nil, err
	}
	buyerScript, err := p2pkh.Lock(buyerAddress)
	if err != nil {
		return nil, err
	}
	state := tx.NewTransaction()
	id, err := chainhash.NewHash(fundingTxID)
	if err != nil {
		return nil, err
	}
	state.AddInputWithOutput(&tx.TransactionInput{SourceTXID: id, SourceTxOutIndex: poolOutputIndex, SequenceNumber: 2, UnlockingScript: script.NewFromBytes(nil)}, &tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	state.AddOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: buyerScript})
	state.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: sellerScript})
	state.LockTime = lockTime
	fake, err := libs.FakeSign(2)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = fake
	fee, err := transactionFee(state.Size(), feeRate)
	if err != nil {
		return nil, err
	}
	if fee > poolAmount {
		return nil, fmt.Errorf("buyer balance is insufficient for fee")
	}
	state.Outputs[0].Satoshis -= fee
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	return state, nil
}
