package arbitrated_pool

import (
	"bytes"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	libs "github.com/bsv8/MultisigPool/v4/pkg/libs"
)

type StateInput struct {
	Protocol             string
	Version              uint32
	PreviousRawTx        []byte
	PreviousSourceOutput *tx.TransactionOutput
	Sequence             uint32
	LockTime             *uint32
	BuyerAmount          *uint64
	SellerAmount         uint64
	ArbiterAmount        uint64
	PoolAmount           uint64
	Roles                ArbitratedPoolRoles
	FeeRate              FeeSatPerKB
	PaymentProof         []byte
}

func clone(value *tx.Transaction) (*tx.Transaction, error) {
	if value == nil {
		return nil, fmt.Errorf("transaction is required")
	}
	copy, err := tx.NewTransactionFromBytes(value.Bytes())
	if err != nil {
		return nil, fmt.Errorf("copy transaction: %w", err)
	}
	return copy, nil
}

func scripts(roles ArbitratedPoolRoles) (*script.Script, *script.Script, *script.Script, *script.Script, error) {
	if err := validateRoles(roles); err != nil {
		return nil, nil, nil, nil, err
	}
	lock, err := BuildArbitratedPoolLock(roles)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	buyerAddress, err := libs.GetAddressFromPublicKey(roles.Buyer, false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sellerAddress, err := libs.GetAddressFromPublicKey(roles.Seller, false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	arbiterAddress, err := libs.GetAddressFromPublicKey(roles.Arbiter, false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	buyer, err := p2pkh.Lock(buyerAddress)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	seller, err := p2pkh.Lock(sellerAddress)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	arbiter, err := p2pkh.Lock(arbiterAddress)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return lock, buyer, seller, arbiter, nil
}

func checkedAllocation(seller, arbiter, pool uint64) (uint64, error) {
	if seller > ^uint64(0)-arbiter {
		return 0, fmt.Errorf("allocated amount overflow")
	}
	allocated := seller + arbiter
	if allocated > pool {
		return 0, fmt.Errorf("allocated amount exceeds pool amount")
	}
	return allocated, nil
}

func BuildArbitratedPoolState(input StateInput) (*tx.Transaction, error) {
	if input.Protocol != Protocol || input.Version != Version {
		return nil, fmt.Errorf("unsupported pool protocol: expected %s v%d", Protocol, Version)
	}
	if len(input.PreviousRawTx) == 0 || input.PoolAmount == 0 {
		return nil, fmt.Errorf("previous state and pool amount are required")
	}
	state, err := tx.NewTransactionFromBytes(input.PreviousRawTx)
	if err != nil {
		return nil, fmt.Errorf("decode previous state: %w", err)
	}
	if len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return nil, fmt.Errorf("arbitrated pool state must have exactly one input")
	}
	if input.Sequence <= state.Inputs[0].SequenceNumber {
		return nil, fmt.Errorf("payment sequence must increase")
	}
	lock, buyer, seller, arbiter, err := scripts(input.Roles)
	if err != nil {
		return nil, err
	}
	if err := validateStateOutputs(state, input.Roles, buyer, seller, arbiter); err != nil {
		return nil, err
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
	if source.Satoshis != input.PoolAmount || !bytes.Equal(source.LockingScript.Bytes(), lock.Bytes()) {
		return nil, fmt.Errorf("previous state source output does not match configured pool")
	}
	state.Inputs[0].SetSourceTxOutput(source)
	allocated, err := checkedAllocation(input.SellerAmount, input.ArbiterAmount, input.PoolAmount)
	if err != nil {
		return nil, err
	}
	state.Outputs[0].LockingScript = buyer
	state.Outputs[1].LockingScript = seller
	state.Outputs[2].LockingScript = arbiter
	state.Outputs[0].Satoshis = input.PoolAmount - allocated
	state.Outputs[1].Satoshis = input.SellerAmount
	state.Outputs[2].Satoshis = input.ArbiterAmount
	state.Inputs[0].SequenceNumber = input.Sequence
	if input.LockTime != nil {
		state.LockTime = *input.LockTime
	}
	if len(input.PaymentProof) > 0 {
		proof, err := libs.BuildOptionalOpReturnScript(input.PaymentProof)
		if err != nil {
			return nil, err
		}
		if len(state.Outputs) == 4 {
			state.Outputs[3] = &tx.TransactionOutput{Satoshis: 0, LockingScript: proof}
		} else {
			state.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: proof})
		}
	}
	fake, err := libs.FakeSign(2)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = fake
	fee, err := feeSat(state.Size(), input.FeeRate)
	if err != nil {
		return nil, err
	}
	if fee > state.Outputs[0].Satoshis {
		return nil, fmt.Errorf("buyer balance is insufficient for fee")
	}
	state.Outputs[0].Satoshis -= fee
	if input.BuyerAmount != nil && *input.BuyerAmount != state.Outputs[0].Satoshis {
		return nil, fmt.Errorf("buyer amount does not match canonical fee")
	}
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	return state, nil
}

func BuildArbitratedPoolOpeningState(fundingTxID []byte, poolOutputIndex uint32, poolAmount uint64, roles ArbitratedPoolRoles, lockTime uint32, rate FeeSatPerKB) (*tx.Transaction, error) {
	if len(fundingTxID) != 32 || poolAmount == 0 {
		return nil, fmt.Errorf("funding outpoint and pool amount are required")
	}
	lock, buyer, seller, arbiter, err := scripts(roles)
	if err != nil {
		return nil, err
	}
	id, err := chainhash.NewHash(fundingTxID)
	if err != nil {
		return nil, err
	}
	previous := tx.NewTransaction()
	source := &tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock}
	previous.AddInputWithOutput(&tx.TransactionInput{SourceTXID: id, SourceTxOutIndex: poolOutputIndex, SequenceNumber: 1, UnlockingScript: script.NewFromBytes(nil)}, source)
	previous.AddOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: buyer})
	previous.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: seller})
	previous.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: arbiter})
	previous.LockTime = lockTime
	return BuildArbitratedPoolState(StateInput{Protocol: Protocol, Version: Version, PreviousRawTx: previous.Bytes(), PreviousSourceOutput: source, Sequence: 2, SellerAmount: 0, ArbiterAmount: 0, PoolAmount: poolAmount, Roles: roles, FeeRate: rate})
}

func BuildArbitratedPoolFinalState(input StateInput) (*tx.Transaction, error) {
	return BuildArbitratedPoolState(input)
}
