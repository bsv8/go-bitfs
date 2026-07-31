package triple_endpoint

import (
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
func MergeTriplePoolServerA(txHex string, serverSig, aSig *[]byte) (*tx.Transaction, error) {
	return mergeTripleRoleSigs(txHex, serverSig, aSig)
}

// MergeTriplePoolServerB fixes the CHECKMULTISIG order to server then B.
func MergeTriplePoolServerB(txHex string, serverSig, bSig *[]byte) (*tx.Transaction, error) {
	return mergeTripleRoleSigs(txHex, serverSig, bSig)
}

func mergeTripleRoleSigs(txHex string, first, second *[]byte) (*tx.Transaction, error) {
	if first == nil || second == nil || len(*first) == 0 || len(*second) == 0 {
		return nil, fmt.Errorf("two non-empty signatures are required")
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
