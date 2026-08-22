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
	"github.com/bsv8/go-bitfs/pool"
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

// paymentStateVector 是真实的 005 累计付款状态交易向量：expected raw 由 Go
// 唯一的 BuildPaymentUpdate 从 OpeningProof + previous PaymentState + 目标
// sequence/amount 确定性重建，Buyer DER 的签名对象就是这笔重建交易本身，
// 不是 RefundTemplate。
type paymentStateVector struct {
	Algorithm              string `json:"algorithm"`
	PreviousRawTxHex       string `json:"previousRawTxHex"`
	TargetPaymentSequence  uint32 `json:"targetPaymentSequence"`
	SellerAmountAfterSat   uint64 `json:"sellerAmountAfterSat"`
	ExpectedUnsignedRawHex string `json:"expectedUnsignedRawHex"`
	MergedRawTxHex         string `json:"mergedRawTxHex"`
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
	TsDer                  string
}

func loadPaymentStateVector(t *testing.T) *paymentStateVector {
	t.Helper()
	raw, err := os.ReadFile("payment_state_sighash_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v paymentStateVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tsRaw, err := os.ReadFile("ts_to_go_payment_state_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var ts struct {
		TsDerSignatureHex string `json:"tsDerSignatureHex"`
	}
	if err := json.Unmarshal(tsRaw, &ts); err != nil {
		t.Fatal(err)
	}
	v.TsDer = ts.TsDerSignatureHex
	return &v
}

// TestPaymentStateVectorRebuildMatchesFrozenBytes 从向量上下文（固定角色密钥、
// 资金交易与 previous state）独立重建 005 未签名状态交易：重建 bytes 必须与
// 冻结的 expected raw 逐字节相等，Go 与 TS 的 Buyer DER 都必须通过固定的
// MultisigPool 验证入口；改动任一输出后同一签名必须被拒绝。
func TestPaymentStateVectorRebuildMatchesFrozenBytes(t *testing.T) {
	v := loadPaymentStateVector(t)

	buyerKey := mustVectorKey(t, "11")
	sellerKey := mustVectorKey(t, "22")
	arbiterKey := mustVectorKey(t, "33")
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := mp.BuildArbitratedPoolLock(mp.ArbitratedPoolRoles{Buyer: buyerKey.PubKey(), Seller: sellerKey.PubKey(), Arbiter: arbiterKey.PubKey()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: v.SourceSatoshis, LockingScript: lock})
	request, err := pool.NewBuyerPoolAdapter(engine, buyerKey).BuildRefundPresignRequest(nil, pool.OpeningInput{FundingTx: funding.Bytes(), ExpiryLockTime: 500000100, MinerFeeRateSatPerKB: 1, SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, sellerKey).SignSellerRefund(nil, request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(nil, request, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(nil, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	previousRaw, err := hex.DecodeString(v.PreviousRawTxHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previous.RawTx, previousRaw) {
		t.Fatal("rebuilt previous state differs from the frozen vector context")
	}
	rebuilt, err := engine.BuildPaymentUpdate(nil, pool.PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: v.TargetPaymentSequence, SellerAmountAfterSat: v.SellerAmountAfterSat})
	if err != nil {
		t.Fatal(err)
	}
	expectedRaw, err := hex.DecodeString(v.ExpectedUnsignedRawHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.RawTx, expectedRaw) {
		t.Fatalf("rebuilt unsigned payment state differs from frozen expected raw:\n got %x\nwant %x", rebuilt.RawTx, expectedRaw)
	}
	// preimage 与 sighash 绑定到重建交易。
	stateTx, err := tx.NewTransactionFromBytes(expectedRaw)
	if err != nil {
		t.Fatal(err)
	}
	sourceLock, err := hex.DecodeString(v.SourceLockingScriptHex)
	if err != nil {
		t.Fatal(err)
	}
	stateTx.Inputs[v.InputIndex].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: v.SourceSatoshis, LockingScript: script.NewFromBytes(sourceLock)})
	flag := sighash.Flag(v.SighashFlag)
	preimage, err := stateTx.CalcInputPreimage(uint32(v.InputIndex), flag)
	if err != nil {
		t.Fatal(err)
	}
	expectedPreimage, err := hex.DecodeString(v.PreimageHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preimage, expectedPreimage) {
		t.Fatal("recomputed payment-state preimage drifts from the frozen vector")
	}
	digest, err := stateTx.CalcInputSignatureHash(uint32(v.InputIndex), flag)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := hex.DecodeString(v.SighashDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, expectedDigest) {
		t.Fatal("sighash is not SHA-256d of the committed payment-state preimage")
	}
	// 固定 verifier：Go 与 TS 的 DER 都必须对重建交易验证成功。
	for name, derHex := range map[string]string{"go": v.GoDerSignatureHex, "ts": v.TsDer} {
		der, err := hex.DecodeString(derHex)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.VerifyBuyerPayment(rebuilt, append(append([]byte(nil), der...), byte(flag)), proof); err != nil {
			t.Fatalf("%s buyer signature rejected by fixed verifier over the rebuilt payment state: %v", name, err)
		}
	}
	// 重新合并 Buyer+Seller 签名：结果必须与冻结的完整交易逐字节相等。
	sellerAdapter := pool.NewSellerPoolAdapter(engine, sellerKey)
	sellerPaymentSig, sellerErr := sellerAdapter.SignSellerPayment(nil, rebuilt, proof)
	if sellerErr != nil {
		t.Fatal(sellerErr)
	}
	merged, mergeErr := engine.MergeBuyerSellerPayment(rebuilt, append(append([]byte(nil), mustDecodeVectorHex(t, v.GoDerSignatureHex)...), byte(flag)), sellerPaymentSig, proof)
	if mergeErr != nil {
		t.Fatal(mergeErr)
	}
	expectedMerged, mergedHexErr := hex.DecodeString(v.MergedRawTxHex)
	if mergedHexErr != nil {
		t.Fatal(mergedHexErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(merged.RawTx, expectedMerged) {
		t.Fatalf("re-merged transaction differs from frozen merged raw:\n got %x\nwant %x", merged.RawTx, expectedMerged)
	}
	// 篡改任一输出金额后，同一签名必须失败。
	stateTx.Outputs[0].Satoshis++
	if err := engine.VerifyBuyerPayment(&pool.UnsignedPayment{RefundTemplateTxID: rebuilt.RefundTemplateTxID, RawTx: stateTx.Bytes(), PaymentSequence: rebuilt.PaymentSequence, BuyerAmountSat: rebuilt.BuyerAmountSat, SellerAmountSat: rebuilt.SellerAmountSat, ArbiterAmountSat: rebuilt.ArbiterAmountSat, PoolOutputSatoshis: rebuilt.PoolOutputSatoshis, PoolLockingScript: rebuilt.PoolLockingScript}, append(append([]byte(nil), mustDecodeVectorHex(t, v.GoDerSignatureHex)...), byte(flag)), proof); err == nil {
		t.Fatal("tampered output accepted the committed buyer signature")
	}
}

func mustVectorKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(hexByte), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDecodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
