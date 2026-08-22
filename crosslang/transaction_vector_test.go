package crosslang_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
)

type txVector struct {
	UnsignedTxHex          string `json:"unsignedTxHex"`
	InputIndex             int    `json:"inputIndex"`
	SourceSatoshis         uint64 `json:"sourceSatoshis"`
	SourceLockingScriptHex string `json:"sourceLockingScriptHex"`
	SighashFlag            int    `json:"sighashFlag"`
	PreimageHex            string `json:"preimageHex"`
	SighashDigestHex       string `json:"sighashDigestHex"`
	BuyerPubkeyHex         string `json:"buyerPubkeyHex"`
	SellerPubkeyHex        string `json:"sellerPubkeyHex"`
	ArbiterPubkeyHex       string `json:"arbiterPubkeyHex"`
	GoDerSignatureHex      string `json:"goDerSignatureHex"`
	TsDerSignatureHex      string `json:"tsDerSignatureHex"`
}

func loadTransactionVector(t *testing.T) *txVector {
	t.Helper()
	raw, err := os.ReadFile("transaction_sighash_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v txVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tsRaw, err := os.ReadFile("ts_to_go_transaction_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var ts struct {
		TsDerSignatureHex string `json:"tsDerSignatureHex"`
		PubkeyHex         string `json:"pubkeyHex"`
		DigestHex         string `json:"sighashDigestHex"`
	}
	if err := json.Unmarshal(tsRaw, &ts); err != nil {
		t.Fatal(err)
	}
	v.TsDerSignatureHex = ts.TsDerSignatureHex
	return &v
}

// TestTransactionSighashVector 回验共享的 MultisigPool v4 交易签名向量：
// 摘要必须是官方 preimage 的 SHA-256d（ForkID|All，绝无二次哈希之外的路径），
// Go 与 TS 的交易 DER 都必须通过固定的 MultisigPool 角色验证入口。
func TestTransactionSighashVector(t *testing.T) {
	v := loadTransactionVector(t)
	unsigned, err := hex.DecodeString(v.UnsignedTxHex)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := hex.DecodeString(v.SourceLockingScriptHex)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(v.SighashDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := hex.DecodeString(v.PreimageHex)
	if err != nil {
		t.Fatal(err)
	}
	state, err := tx.NewTransactionFromBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	state.Inputs[v.InputIndex].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: v.SourceSatoshis, LockingScript: script.NewFromBytes(lock)})
	flag := sighash.Flag(v.SighashFlag)
	if flag != sighash.Flag(sighash.ForkID|sighash.All) {
		t.Fatalf("unexpected sighash flag %d", v.SighashFlag)
	}
	computedPreimage, err := state.CalcInputPreimage(uint32(v.InputIndex), flag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(computedPreimage, preimage) {
		t.Fatalf("preimage drift: %x != %x", computedPreimage, preimage)
	}
	computed, err := state.CalcInputSignatureHash(uint32(v.InputIndex), flag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(computed, digest) {
		t.Fatalf("sighash is not SHA-256d of the committed preimage: %x", computed)
	}
	buyer, err := ec.PublicKeyFromString(v.BuyerPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	seller, err := ec.PublicKeyFromString(v.SellerPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	arbiter, err := ec.PublicKeyFromString(v.ArbiterPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	roles := mp.ArbitratedPoolRoles{Buyer: buyer, Seller: seller, Arbiter: arbiter}
	for name, derHex := range map[string]string{"go": v.GoDerSignatureHex, "ts": v.TsDerSignatureHex} {
		der, err := hex.DecodeString(derHex)
		if err != nil {
			t.Fatal(err)
		}
		valid, err := mp.VerifyArbitratedPoolBuyerSignature(state, v.SourceSatoshis, roles, append(append([]byte(nil), der...), byte(flag)))
		if err != nil || !valid {
			t.Fatalf("%s transaction signature rejected by fixed MultisigPool buyer verifier: %v", name, err)
		}
	}
}

// TestTransactionSighashVectorRejectsTampering 确保向量验证真的绑定到交易内容：
// 改动任一输出金额后，同一签名必须被固定验证入口拒绝。
func TestTransactionSighashVectorRejectsTampering(t *testing.T) {
	v := loadTransactionVector(t)
	unsigned, err := hex.DecodeString(v.UnsignedTxHex)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := hex.DecodeString(v.SourceLockingScriptHex)
	if err != nil {
		t.Fatal(err)
	}
	state, err := tx.NewTransactionFromBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	state.Outputs[0].Satoshis++
	state.Inputs[v.InputIndex].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: v.SourceSatoshis, LockingScript: script.NewFromBytes(lock)})
	flag := sighash.Flag(v.SighashFlag)
	der, err := hex.DecodeString(v.GoDerSignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	buyer, err := ec.PublicKeyFromString(v.BuyerPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	seller, err := ec.PublicKeyFromString(v.SellerPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	arbiter, err := ec.PublicKeyFromString(v.ArbiterPubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	roles := mp.ArbitratedPoolRoles{Buyer: buyer, Seller: seller, Arbiter: arbiter}
	if valid, _ := mp.VerifyArbitratedPoolBuyerSignature(state, v.SourceSatoshis, roles, append(append([]byte(nil), der...), byte(flag))); valid {
		t.Fatal("tampered transaction accepted the committed signature")
	}
}
