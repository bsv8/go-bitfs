package triple_endpoint

// This file is the role-explicit protocol-major-2 boundary. The older endpoint
// names remain deprecated for source compatibility; new integrations must use
// these functions so slot order cannot be inferred from a runtime scenario.

import (
	"bytes"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	libs "github.com/bsv8/MultisigPool/pkg/libs"
)

// TriplePoolOpeningInput describes the one pool output that funds the first
// state. It keeps funding-transaction parsing and the initial two-output
// state template inside MultisigPool.
type TriplePoolOpeningInput struct {
	FundingTxID     []byte
	PoolOutputIndex uint32
	PoolAmount      uint64
	LockTime        uint32
	Server          *ec.PublicKey
	A               *ec.PublicKey
	B               *ec.PublicKey
	FeeRate         FeeSatPerKB
}

type TriplePoolStateInput struct {
	PreviousRawTx []byte
	Sequence      uint32
	LockTime      *uint32
	SellerAmount  uint64
	PoolAmount    uint64
	Server        *ec.PublicKey
	A             *ec.PublicKey
	B             *ec.PublicKey
	FeeRate       FeeSatPerKB
}

func BuildTriplePoolLock(server, a, b *ec.PublicKey) (*script.Script, error) {
	if server == nil || a == nil || b == nil {
		return nil, fmt.Errorf("server, A and B public keys are required")
	}
	return TripleFeePoolSpentScript(server, a, b)
}

func BuildTriplePoolState(input TriplePoolStateInput) (*tx.Transaction, error) {
	if len(input.PreviousRawTx) == 0 || input.Server == nil || input.A == nil || input.B == nil {
		return nil, fmt.Errorf("previous state and server/A/B keys are required")
	}
	state, err := tx.NewTransactionFromBytes(input.PreviousRawTx)
	if err != nil {
		return nil, fmt.Errorf("decode previous state: %w", err)
	}
	if len(state.Inputs) != 1 || len(state.Outputs) != 2 {
		return nil, fmt.Errorf("triple pool state must have one input and two outputs")
	}
	if input.Sequence <= state.Inputs[0].SequenceNumber {
		return nil, fmt.Errorf("triple pool payment sequence must increase")
	}
	lock, err := BuildTriplePoolLock(input.Server, input.A, input.B)
	if err != nil {
		return nil, err
	}
	serverAddr, err := libs.GetAddressFromPublicKey(input.Server, false)
	if err != nil {
		return nil, err
	}
	aAddr, err := libs.GetAddressFromPublicKey(input.A, false)
	if err != nil {
		return nil, err
	}
	serverScript, err := p2pkh.Lock(serverAddr)
	if err != nil {
		return nil, err
	}
	aScript, err := p2pkh.Lock(aAddr)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(state.Outputs[0].LockingScript.Bytes(), serverScript.Bytes()) || !bytes.Equal(state.Outputs[1].LockingScript.Bytes(), aScript.Bytes()) {
		return nil, fmt.Errorf("previous state outputs do not match server and A roles")
	}
	if state.Outputs[0].Satoshis > ^uint64(0)-state.Outputs[1].Satoshis {
		return nil, fmt.Errorf("previous state output amount overflows")
	}
	total := state.Outputs[0].Satoshis + state.Outputs[1].Satoshis
	if input.PoolAmount == 0 {
		input.PoolAmount = total
	}
	if total > input.PoolAmount {
		return nil, fmt.Errorf("previous state value exceeds pool amount")
	}
	if source := state.Inputs[0].SourceTxOutput(); source != nil && (source.Satoshis != input.PoolAmount || !bytes.Equal(source.LockingScript.Bytes(), lock.Bytes())) {
		return nil, fmt.Errorf("previous state source output does not match configured pool")
	}
	if input.SellerAmount > total {
		if input.SellerAmount > input.PoolAmount {
			return nil, fmt.Errorf("seller amount exceeds pool value")
		}
	}
	state.Outputs[0].LockingScript = serverScript
	state.Outputs[1].LockingScript = aScript
	state.Outputs[0].Satoshis = input.SellerAmount
	state.Outputs[1].Satoshis = input.PoolAmount - input.SellerAmount
	state.Inputs[0].SequenceNumber = input.Sequence
	if input.LockTime != nil {
		state.LockTime = *input.LockTime
	}
	state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: input.PoolAmount, LockingScript: lock})
	fake, err := libs.FakeSign(2)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = fake
	fee, err := TriplePoolFeeSat(state.Size(), input.FeeRate)
	if err != nil {
		return nil, err
	}
	if input.SellerAmount+fee > input.PoolAmount {
		return nil, fmt.Errorf("pool balance is insufficient for seller amount and fee")
	}
	state.Outputs[1].Satoshis = input.PoolAmount - input.SellerAmount - fee
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	return state, nil
}

// BuildTriplePoolOpeningState constructs the initial, empty-unlocking state
// directly from the funding outpoint. The returned transaction has exactly
// two value outputs and no unlocking script.
func BuildTriplePoolOpeningState(input TriplePoolOpeningInput) (*tx.Transaction, error) {
	if len(input.FundingTxID) != 32 || input.Server == nil || input.A == nil || input.B == nil || input.PoolAmount == 0 {
		return nil, fmt.Errorf("funding outpoint, pool amount and server/A/B keys are required")
	}
	lock, err := BuildTriplePoolLock(input.Server, input.A, input.B)
	if err != nil {
		return nil, err
	}
	serverAddress, err := libs.GetAddressFromPublicKey(input.Server, false)
	if err != nil {
		return nil, err
	}
	aAddress, err := libs.GetAddressFromPublicKey(input.A, false)
	if err != nil {
		return nil, err
	}
	serverScript, err := p2pkh.Lock(serverAddress)
	if err != nil {
		return nil, err
	}
	aScript, err := p2pkh.Lock(aAddress)
	if err != nil {
		return nil, err
	}
	state := tx.NewTransaction()
	txid, err := chainhash.NewHash(input.FundingTxID)
	if err != nil {
		return nil, err
	}
	state.AddInputWithOutput(&tx.TransactionInput{
		SourceTXID: txid, SourceTxOutIndex: input.PoolOutputIndex,
		SequenceNumber: 1, UnlockingScript: script.NewFromBytes(nil),
	}, &tx.TransactionOutput{Satoshis: input.PoolAmount, LockingScript: lock})
	state.AddOutput(&tx.TransactionOutput{Satoshis: 0, LockingScript: serverScript})
	state.AddOutput(&tx.TransactionOutput{Satoshis: input.PoolAmount, LockingScript: aScript})
	state.LockTime = input.LockTime
	return applyTriplePoolFee(state, input.PoolAmount, input.FeeRate)
}

func applyTriplePoolFee(state *tx.Transaction, poolAmount uint64, rate FeeSatPerKB) (*tx.Transaction, error) {
	if state == nil || len(state.Outputs) != 2 {
		return nil, fmt.Errorf("triple pool state requires two outputs")
	}
	fake, err := libs.FakeSign(2)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = fake
	fee, err := TriplePoolFeeSat(state.Size(), rate)
	state.Inputs[0].UnlockingScript = script.NewFromBytes(nil)
	if err != nil {
		return nil, err
	}
	if fee >= poolAmount {
		return nil, fmt.Errorf("pool balance is insufficient for fee")
	}
	state.Outputs[1].Satoshis = poolAmount - fee
	return state, nil
}

func SignTriplePoolAsServer(state *tx.Transaction, server *ec.PrivateKey, a, b *ec.PublicKey) (*[]byte, error) {
	if err := validateTriplePoolSigningState(state, server, a, b); err != nil {
		return nil, err
	}
	if server == nil || a == nil || b == nil || server.PubKey().IsEqual(a) || server.PubKey().IsEqual(b) {
		return nil, fmt.Errorf("server key does not match the server slot")
	}
	lock, err := BuildTriplePoolLock(server.PubKey(), a, b)
	if err != nil || !sourceMatchesPool(state, lock) {
		return nil, fmt.Errorf("state source output does not match server/A/B roles")
	}
	return ServerTripleFeePoolSpendTXUpdateSign(state, server, a, b)
}

func SignTriplePoolAsA(state *tx.Transaction, a *ec.PrivateKey, server, b *ec.PublicKey) (*[]byte, error) {
	if err := validateTriplePoolSigningState(state, a, server, b); err != nil {
		return nil, err
	}
	if a == nil || server == nil || b == nil || a.PubKey().IsEqual(server) || a.PubKey().IsEqual(b) {
		return nil, fmt.Errorf("A key does not match the A slot")
	}
	lock, err := BuildTriplePoolLock(server, a.PubKey(), b)
	if err != nil || !sourceMatchesPool(state, lock) {
		return nil, fmt.Errorf("state source output does not match server/A/B roles")
	}
	return ClientATripleFeePoolSpendTXUpdateSign(state, server, a, b)
}

func SignTriplePoolAsB(state *tx.Transaction, b *ec.PrivateKey, server, a *ec.PublicKey) (*[]byte, error) {
	if err := validateTriplePoolSigningState(state, b, server, a); err != nil {
		return nil, err
	}
	if b == nil || server == nil || a == nil || b.PubKey().IsEqual(server) || b.PubKey().IsEqual(a) {
		return nil, fmt.Errorf("B key does not match the B slot")
	}
	lock, err := BuildTriplePoolLock(server, a, b.PubKey())
	if err != nil || !sourceMatchesPool(state, lock) {
		return nil, fmt.Errorf("state source output does not match server/A/B roles")
	}
	source := state.Inputs[0].SourceTxOutput()
	return SpendTXTripleFeePoolBSign(state, source.Satoshis, server, a, b)
}

// AttachTriplePoolASignature returns the candidate with only A's signature
// attached. It is the 005 transport form and never claims to be final.
func AttachTriplePoolASignature(state *tx.Transaction, signature []byte) (*tx.Transaction, error) {
	return attachTriplePoolSignature(state, signature)
}

// AttachTriplePoolServerSignature returns the candidate with only server's
// signature attached for the 007 transport form.
func AttachTriplePoolServerSignature(state *tx.Transaction, signature []byte) (*tx.Transaction, error) {
	return attachTriplePoolSignature(state, signature)
}

func attachTriplePoolSignature(state *tx.Transaction, signature []byte) (*tx.Transaction, error) {
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil || len(signature) == 0 {
		return nil, fmt.Errorf("state and one non-empty signature are required")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return nil, fmt.Errorf("state must have an empty unlocking script")
	}
	unlocking, err := libs.BuildSignScript(&[][]byte{signature})
	if err != nil {
		return nil, err
	}
	state.Inputs[0].UnlockingScript = unlocking
	return state, nil
}

// VerifyTriplePoolServerSignature verifies the server signature against the
// same unsigned state and configured server slot.
func VerifyTriplePoolServerSignature(state *tx.Transaction, server *ec.PublicKey, a, b *ec.PublicKey, signature *[]byte) (bool, error) {
	if state == nil || server == nil || a == nil || b == nil {
		return false, fmt.Errorf("state and server/A/B keys are required")
	}
	if server.IsEqual(a) || server.IsEqual(b) {
		return false, fmt.Errorf("server key does not match the server slot")
	}
	return VerifySignature(state, 0, server, signature)
}

// VerifyTriplePoolASignature verifies an A/buyer signature.
func VerifyTriplePoolASignature(state *tx.Transaction, a *ec.PublicKey, server, b *ec.PublicKey, signature *[]byte) (bool, error) {
	if state == nil || a == nil || server == nil || b == nil {
		return false, fmt.Errorf("state and server/A/B keys are required")
	}
	if a.IsEqual(server) || a.IsEqual(b) {
		return false, fmt.Errorf("A key does not match the A slot")
	}
	return VerifySignature(state, 0, a, signature)
}

// VerifyTriplePoolBSignature verifies a B/arbiter signature.
func VerifyTriplePoolBSignature(state *tx.Transaction, b *ec.PublicKey, server, a *ec.PublicKey, signature *[]byte) (bool, error) {
	if state == nil || b == nil || server == nil || a == nil {
		return false, fmt.Errorf("state and server/A/B keys are required")
	}
	if b.IsEqual(server) || b.IsEqual(a) {
		return false, fmt.Errorf("B key does not match the B slot")
	}
	return VerifySignature(state, 0, b, signature)
}

// VerifyTriplePoolState checks the fixed role mapping, two-value-output
// layout, empty unlocking script, and non-negative value conservation.
func VerifyTriplePoolState(state *tx.Transaction, server, a, b *ec.PublicKey, poolAmount, sellerAmount uint64) error {
	if state == nil || len(state.Inputs) != 1 || len(state.Outputs) != 2 || state.Inputs[0] == nil {
		return fmt.Errorf("triple pool state must have one input and two outputs")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return fmt.Errorf("triple pool state must have an empty unlocking script")
	}
	lock, err := BuildTriplePoolLock(server, a, b)
	if err != nil {
		return err
	}
	source := state.Inputs[0].SourceTxOutput()
	if source == nil || source.Satoshis != poolAmount || string(source.LockingScript.Bytes()) != string(lock.Bytes()) {
		return fmt.Errorf("triple pool source output does not match the configured pool")
	}
	serverAddr, err := libs.GetAddressFromPublicKey(server, false)
	if err != nil {
		return err
	}
	aAddr, err := libs.GetAddressFromPublicKey(a, false)
	if err != nil {
		return err
	}
	serverScript, err := p2pkh.Lock(serverAddr)
	if err != nil {
		return err
	}
	aScript, err := p2pkh.Lock(aAddr)
	if err != nil {
		return err
	}
	if string(state.Outputs[0].LockingScript.Bytes()) != string(serverScript.Bytes()) || string(state.Outputs[1].LockingScript.Bytes()) != string(aScript.Bytes()) {
		return fmt.Errorf("triple pool outputs do not match server and A roles")
	}
	if state.Outputs[0].Satoshis != sellerAmount || sellerAmount > poolAmount || state.Outputs[1].Satoshis > poolAmount-sellerAmount {
		return fmt.Errorf("triple pool output amounts are invalid")
	}
	return nil
}

// VerifyTriplePoolStateWithFee additionally proves that the buyer output was
// derived from the canonical integer fee policy for this exact state shape.
// The fee probe uses the same deterministic fake unlocking script as the
// builders, while the caller's transaction remains untouched.
func VerifyTriplePoolStateWithFee(state *tx.Transaction, server, a, b *ec.PublicKey, poolAmount, sellerAmount uint64, rate FeeSatPerKB) error {
	if err := VerifyTriplePoolState(state, server, a, b, poolAmount, sellerAmount); err != nil {
		return err
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil || len(state.Outputs) != 2 {
		return fmt.Errorf("triple pool state must have one input and two outputs")
	}
	probe, err := tx.NewTransactionFromBytes(state.Bytes())
	if err != nil {
		return fmt.Errorf("copy triple pool state for fee verification: %w", err)
	}
	source := state.Inputs[0].SourceTxOutput()
	if source == nil {
		return fmt.Errorf("triple pool source output is required")
	}
	probe.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: source.Satoshis, LockingScript: script.NewFromBytes(append([]byte(nil), source.LockingScript.Bytes()...))})
	fake, err := libs.FakeSign(2)
	if err != nil {
		return err
	}
	probe.Inputs[0].UnlockingScript = fake
	fee, err := TriplePoolFeeSat(probe.Size(), rate)
	if err != nil {
		return err
	}
	if sellerAmount > poolAmount || fee > poolAmount-sellerAmount || state.Outputs[1].Satoshis != poolAmount-sellerAmount-fee {
		return fmt.Errorf("triple pool output amount does not match canonical fee")
	}
	return nil
}

func validateTriplePoolSigningState(state *tx.Transaction, signer *ec.PrivateKey, first, second *ec.PublicKey) error {
	if signer == nil || first == nil || second == nil {
		return fmt.Errorf("signer and pool public keys are required")
	}
	if signer.PubKey().IsEqual(first) || signer.PubKey().IsEqual(second) {
		return fmt.Errorf("signer key does not match the requested role")
	}
	if state == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return fmt.Errorf("state must have exactly one input")
	}
	if state.Inputs[0].UnlockingScript != nil && len(state.Inputs[0].UnlockingScript.Bytes()) != 0 {
		return fmt.Errorf("state must have an empty unlocking script")
	}
	return nil
}

func sourceMatchesPool(state *tx.Transaction, lock *script.Script) bool {
	if state == nil || lock == nil || len(state.Inputs) != 1 || state.Inputs[0] == nil {
		return false
	}
	source := state.Inputs[0].SourceTxOutput()
	return source != nil && bytes.Equal(source.LockingScript.Bytes(), lock.Bytes())
}

func BuildTriplePoolInitialState(input TriplePoolStateInput) (*tx.Transaction, error) {
	input.SellerAmount = 0
	return BuildTriplePoolState(input)
}

func BuildTriplePoolFinalState(input TriplePoolStateInput) (*tx.Transaction, error) {
	if input.LockTime == nil {
		zero := uint32(0)
		input.LockTime = &zero
	}
	return BuildTriplePoolState(input)
}
