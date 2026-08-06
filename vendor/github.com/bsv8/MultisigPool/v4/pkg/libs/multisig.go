package libs

import (
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/script"
	transaction "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

var (
	ErrInvalidPublicKeys = errors.New("invalid public keys")
	ErrNoPrivateKeys     = errors.New("private keys not supplied")
	ErrInvalidM          = errors.New("invalid m value")
)

// MultiSig represents an M-of-N multisig template
type MultiSig struct {
	PrivateKeys []*ec.PrivateKey
	PublicKeys  []*ec.PublicKey
	M           int // Required signatures
	N           int // Total number of public keys
	SigHashFlag *sighash.Flag
}

// Lock creates a P2MS (Pay to Multi-Signature) locking script
func Lock(pubKeys []*ec.PublicKey, m int) (*script.Script, error) {
	n := len(pubKeys)
	if m <= 0 || m > n {
		return nil, ErrInvalidM
	}
	if n == 0 || n > 20 {
		return nil, ErrInvalidPublicKeys
	}

	s := script.NewFromBytes([]byte{})

	// Add M value
	s.AppendOpcodes(byte(script.Op1 + byte(m-1)))

	// Add public keys
	for _, pubKey := range pubKeys {
		if err := s.AppendPushData(pubKey.Compressed()); err != nil {
			return nil, err
		}
	}

	// Add N value and CHECKMULTISIG
	s.AppendOpcodes(byte(script.Op1+byte(n-1)), script.OpCHECKMULTISIG)

	return s, nil
}

// Unlock creates a new MultiSig unlocking instance
func Unlock(privKeys []*ec.PrivateKey, pubKeys []*ec.PublicKey, m int, sigHashFlag *sighash.Flag) (*MultiSig, error) {
	// if len(privKeys) < m {
	// 	fmt.Printf("len(privKeys) < m: %d < %d\n", len(privKeys), m)
	// 	return nil, ErrNoPrivateKeys
	// }

	if sigHashFlag == nil {
		shf := sighash.AllForkID
		sigHashFlag = &shf
	}

	return &MultiSig{
		PrivateKeys: privKeys,
		PublicKeys:  pubKeys,
		M:           m,
		N:           len(pubKeys),
		SigHashFlag: sigHashFlag,
	}, nil
}

// Sign creates an unlocking script for the multisig
func (ms *MultiSig) Sign(tx *transaction.Transaction, inputIndex uint32) (*script.Script, error) {
	if tx.Inputs[inputIndex].SourceTxOutput() == nil {
		return nil, transaction.ErrEmptyPreviousTx
	}

	preimage, _ := tx.CalcInputPreimage(inputIndex, *ms.SigHashFlag)

	if len(preimage) >= 68 {
		hashPrevouts := preimage[4:36]
		hashSequence := preimage[36:68]
		// hashOutputs is located 40 bytes from the end (4 locktime + 4 sighash flag + 32 hashOutputs)
		hashOutputs := preimage[len(preimage)-40-32 : len(preimage)-40]
		_ = hashPrevouts
		_ = hashSequence
		_ = hashOutputs

	}

	sh, err := tx.CalcInputSignatureHash(inputIndex, *ms.SigHashFlag)

	if err != nil {
		return nil, err
	}

	// Create unlocking script
	s := script.NewFromBytes([]byte{})

	// Add OP_0 for the bug in CHECKMULTISIG
	s.AppendOpcodes(script.Op0)

	// Sign with required number of private keys
	for i := 0; i < ms.M; i++ {
		sig, err := ms.PrivateKeys[i].Sign(sh)
		if err != nil {
			return nil, err
		}

		sigBuf := make([]byte, 0)
		sigBuf = append(sigBuf, sig.Serialize()...)
		sigBuf = append(sigBuf, uint8(*ms.SigHashFlag))

		if err = s.AppendPushData(sigBuf); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// 分别签名
func (ms *MultiSig) SignOne(tx *transaction.Transaction, inputIndex uint32, privateKey *ec.PrivateKey) (*[]byte, error) {
	if tx.Inputs[inputIndex].SourceTxOutput() == nil {
		return nil, transaction.ErrEmptyPreviousTx
	}

	preimage, _ := tx.CalcInputPreimage(inputIndex, *ms.SigHashFlag)

	if len(preimage) >= 68 {
		hashPrevouts := preimage[4:36]
		hashSequence := preimage[36:68]
		// hashOutputs is located 40 bytes from the end (4 locktime + 4 sighash flag + 32 hashOutputs)
		hashOutputs := preimage[len(preimage)-40-32 : len(preimage)-40]
		_ = hashPrevouts
		_ = hashSequence
		_ = hashOutputs

	}

	sh, err := tx.CalcInputSignatureHash(inputIndex, *ms.SigHashFlag)

	if err != nil {
		return nil, err
	}

	// Create unlocking script
	// s := script.NewFromBytes([]byte{})

	// Add OP_0 for the bug in CHECKMULTISIG
	// s.AppendOpcodes(script.Op0)

	// Sign with required number of private keys
	// for i := 0; i < ms.M; i++ {
	sig, err := privateKey.Sign(sh)
	if err != nil {
		return nil, err
	}

	sigBuf := make([]byte, 0)
	sigBuf = append(sigBuf, sig.Serialize()...)
	sigBuf = append(sigBuf, uint8(*ms.SigHashFlag))

	// if err = s.AppendPushData(sigBuf); err != nil {
	// 	return nil, err
	// }
	// }

	return &sigBuf, nil
}

// EstimateLength estimates the length of the unlocking script
func (ms *MultiSig) EstimateLength(_ *transaction.Transaction, _ uint32) uint32 {
	// OP_0 + M * (signature + sighash flag)
	return 1 + uint32(ms.M)*(71+1)
}

// FakeSign 创建一个假的签名脚本，方便计算长度
func FakeSign(m uint32) (*script.Script, error) {
	// 创建解锁脚本
	s := script.NewFromBytes([]byte{})

	// 添加 OP_0 用于修复 CHECKMULTISIG 中的 bug
	s.AppendOpcodes(script.Op0)

	// 创建假签名数据
	for i := 0; i < int(m); i++ {
		// 假签名数据：使用72字节的空数据模拟签名（最大DER签名长度）+ 1字节的空SigHashFlag
		fakeSigBuf := make([]byte, 72)
		// 添加一个空的SigHashFlag字节
		fakeSigBuf = append(fakeSigBuf, uint8(0))

		if err := s.AppendPushData(fakeSigBuf); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func BuildSignScript(signs *[][]byte) (*script.Script, error) {
	// 创建解锁脚本
	s := script.NewFromBytes([]byte{})

	// 添加 OP_0 用于修复 CHECKMULTISIG 中的 bug
	s.AppendOpcodes(script.Op0)

	// 添加签名数据
	for _, sign := range *signs {
		sigBuf := make([]byte, 0)
		sigBuf = append(sigBuf, sign...)
		// sigBuf = append(sigBuf, uint8(*sigHashFlag))

		if err := s.AppendPushData(sigBuf); err != nil {
			return nil, err
		}

	}

	return s, nil
}
