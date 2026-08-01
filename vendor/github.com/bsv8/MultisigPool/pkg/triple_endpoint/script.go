package triple_endpoint

import (
	"bytes"
	"fmt"

	multisig "github.com/bsv8/MultisigPool/pkg/libs"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ecdsa "github.com/bsv-blockchain/go-sdk/primitives/ecdsa"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// 构建双端费用池的花费脚本
func TripleFeePoolSpentScript(
	serverPublicKey *ec.PublicKey,
	aPublicKey *ec.PublicKey,
	bPublicKey *ec.PublicKey,
) (*script.Script, error) {
	prevMultisigScript, err := multisig.Lock([]*ec.PublicKey{serverPublicKey, aPublicKey, bPublicKey}, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to create server locking script: %w", err)
	}

	return prevMultisigScript, nil
}

// 从创建花费脚本,客户端签名
// Deprecated: use MergeTriplePoolServerA or MergeTriplePoolServerB so the
// CHECKMULTISIG role order is explicit.
func MergeTripleFeePoolSigForSpendTx(
	txHex string,
	aSignByte *[]byte,
	bSignByte *[]byte,
) (*tx.Transaction, error) {
	// 恢复 bTx
	bTx, err := tx.NewTransactionFromHex(txHex)
	if err != nil {
		return nil, err
	}

	signs := [][]byte{*aSignByte, *bSignByte}
	unScript, err := multisig.BuildSignScript(&signs)
	if err != nil {
		return nil, fmt.Errorf("BuildSignScript error: %v", err)
	}

	bTx.Inputs[0].UnlockingScript = unScript

	return bTx, nil
}

// MergeTriplePoolServerA fixes the CHECKMULTISIG order to server then A.
//
// Deprecated: use MergeTriplePoolServerAWithRoles. Without the role keys and
// source amount this compatibility helper can only enforce signature shape,
// not which pool slot produced each signature.
func MergeTriplePoolServerA(txHex string, serverSig, aSig *[]byte) (*tx.Transaction, error) {
	return mergeTripleRoleSigs(txHex, serverSig, aSig)
}

// MergeTriplePoolServerB fixes the CHECKMULTISIG order to server then B.
//
// Deprecated: use MergeTriplePoolServerBWithRoles. Without the role keys and
// source amount this compatibility helper can only enforce signature shape,
// not which pool slot produced each signature.
func MergeTriplePoolServerB(txHex string, serverSig, bSig *[]byte) (*tx.Transaction, error) {
	return mergeTripleRoleSigs(txHex, serverSig, bSig)
}

// MergeTriplePoolServerAWithRoles verifies both signatures against the same
// unsigned transaction before assembling the canonical server+A unlocking
// script. The source output is restored from the explicit pool description so
// a raw transaction cannot silently validate against a different pool.
func MergeTriplePoolServerAWithRoles(txHex string, serverSig, aSig *[]byte, server, a, b *ec.PublicKey, poolAmount uint64) (*tx.Transaction, error) {
	state, err := roleMergeState(txHex, server, a, b, poolAmount)
	if err != nil {
		return nil, err
	}
	if ok, err := VerifyTriplePoolServerSignature(state, server, a, b, serverSig); err != nil || !ok {
		if err != nil {
			return nil, fmt.Errorf("server signature does not match server slot: %w", err)
		}
		return nil, fmt.Errorf("server signature does not match server slot")
	}
	if ok, err := VerifyTriplePoolASignature(state, a, server, b, aSig); err != nil || !ok {
		if err != nil {
			return nil, fmt.Errorf("A signature does not match A slot: %w", err)
		}
		return nil, fmt.Errorf("A signature does not match A slot")
	}
	return mergeTripleRoleSigs(state.Hex(), serverSig, aSig)
}

// MergeTriplePoolServerBWithRoles is the role-checked server+B counterpart
// used by arbitration submissions.
func MergeTriplePoolServerBWithRoles(txHex string, serverSig, bSig *[]byte, server, a, b *ec.PublicKey, poolAmount uint64) (*tx.Transaction, error) {
	state, err := roleMergeState(txHex, server, a, b, poolAmount)
	if err != nil {
		return nil, err
	}
	if ok, err := VerifyTriplePoolServerSignature(state, server, a, b, serverSig); err != nil || !ok {
		if err != nil {
			return nil, fmt.Errorf("server signature does not match server slot: %w", err)
		}
		return nil, fmt.Errorf("server signature does not match server slot")
	}
	if ok, err := VerifyTriplePoolBSignature(state, b, server, a, bSig); err != nil || !ok {
		if err != nil {
			return nil, fmt.Errorf("B signature does not match B slot: %w", err)
		}
		return nil, fmt.Errorf("B signature does not match B slot")
	}
	return mergeTripleRoleSigs(state.Hex(), serverSig, bSig)
}

func roleMergeState(txHex string, server, a, b *ec.PublicKey, poolAmount uint64) (*tx.Transaction, error) {
	if poolAmount == 0 {
		return nil, fmt.Errorf("pool amount is required for role-checked merge")
	}
	state, err := tx.NewTransactionFromHex(txHex)
	if err != nil {
		return nil, err
	}
	if len(state.Inputs) != 1 || len(state.Outputs) != 2 || state.Inputs[0] == nil {
		return nil, fmt.Errorf("triple pool state must have one input and two outputs")
	}
	lock, err := BuildTriplePoolLock(server, a, b)
	if err != nil {
		return nil, err
	}
	state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: poolAmount, LockingScript: lock})
	if err := VerifyTriplePoolState(state, server, a, b, poolAmount, state.Outputs[0].Satoshis); err != nil {
		return nil, fmt.Errorf("unsigned triple pool state is invalid: %w", err)
	}
	return state, nil
}

func mergeTripleRoleSigs(txHex string, first, second *[]byte) (*tx.Transaction, error) {
	if first == nil || second == nil || len(*first) == 0 || len(*second) == 0 {
		return nil, fmt.Errorf("two non-empty signatures are required")
	}
	if bytes.Equal(*first, *second) {
		return nil, fmt.Errorf("duplicate signatures are not permitted")
	}
	return MergeTripleFeePoolSigForSpendTx(txHex, first, second)
}

// VerifySignature 验证ClientB的签名是否正确
func VerifySignature(
	tx *tx.Transaction,
	inputIndex uint32,
	publicKey *ec.PublicKey,
	SignByte *[]byte,
) (bool, error) {
	if tx == nil || publicKey == nil || SignByte == nil || len(*SignByte) < 2 {
		return false, fmt.Errorf("transaction, public key and a DER signature are required")
	}
	// 获取签名哈希
	sigHash := sighash.Flag(sighash.ForkID | sighash.All)

	// 计算交易的签名哈希值
	hash, err := tx.CalcInputSignatureHash(inputIndex, sigHash)
	if err != nil {
		return false, fmt.Errorf("计算签名哈希失败: %w", err)
	}

	// 从签名字节中提取签名（去掉最后一个字节的sighash标志）
	signatureBytes := (*SignByte)[:len(*SignByte)-1]

	// 解析签名
	signature, err := ec.ParseDERSignature(signatureBytes)
	if err != nil {
		return false, fmt.Errorf("解析签名失败: %w", err)
	}

	// 使用B的公钥验证签名
	isValid := ecdsa.Verify(hash, signature, publicKey.ToECDSA())
	if !isValid {
		return false, fmt.Errorf("VerifySignature failed")
	}

	return true, nil
}
