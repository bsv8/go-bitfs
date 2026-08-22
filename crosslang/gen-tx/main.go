// Command gen-tx 生成 Go/TS 共享的 MultisigPool v4 交易签名向量。
//
// 真值：sighash = SHA-256d(BSV preimage)，flag = ForkID|All (0x41)，
// ECDSA(low-S DER) 对该摘要签名，绝不二次哈希。所有数值从固定的
// MultisigPool v4 fixture（角色私钥 11/22/33、100000 satoshis 资金池、
// lockTime 500000100、费率 1 sat/KB）确定性派生。
//
// 输出两份向量：transaction_sighash_vector.json 是规范退款模板（费用池关联
// ID 源）；payment_state_sighash_vector.json 是真实的 005 累计付款状态交易
// ——由 OpeningProof、previous PaymentState、目标 sequence/amount 经唯一的
// BuildPaymentUpdate 确定性重建。二者不是同一笔交易，不能互换或复用签名；
// 005 wire 不携带 raw，跨语言重建以本向量为确定性前提。
//
// 用法：go run ./crosslang/gen-tx [--out-dir crosslang] [--check]
//
//	--out-dir  输出目录（默认 crosslang；必须是已存在的目录）。
//	--check    不写任何文件：在内存中重新生成两份向量并与目标目录中已提交
//	           的 fixture 逐字节比较，任何漂移都以非零码退出。CI 漂移检查
//	           必须使用 --check，绝不能重定向本命令的标准输出。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/pool"
)

func mustKey(hexByte string) *ec.PrivateKey {
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(hexByte), 32)))
	if err != nil {
		panic(err)
	}
	return key
}

const (
	refundVectorFile       = "transaction_sighash_vector.json"
	paymentStateVectorFile = "payment_state_sighash_vector.json"
)

func marshalVector(value any) ([]byte, error) {
	out, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func mustWriteJSON(dir, name string, value any) {
	out, err := marshalVector(value)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), out, 0o644); err != nil {
		panic(err)
	}
}

func main() {
	outDir := flag.String("out-dir", ".", "existing directory that receives the vector JSON files (use --out-dir crosslang from the repository root)")
	check := flag.Bool("check", false, "compare regenerated vectors against the committed fixtures in --out-dir without writing anything")
	flag.Parse()

	buyer := mustKey("11")
	seller := mustKey("22")
	arbiter := mustKey("33")
	engine, err := pool.NewMultisigPoolEngine(pool.MultisigPoolEngineConfig{
		BuyerPubKey:   buyer.PubKey().Compressed(),
		SellerPubKey:  seller.PubKey().Compressed(),
		ArbiterPubKey: arbiter.PubKey().Compressed(),
	})
	if err != nil {
		panic(err)
	}
	lock, err := mp.BuildArbitratedPoolLock(mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()})
	if err != nil {
		panic(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	request, err := pool.NewBuyerPoolAdapter(engine, buyer).BuildRefundPresignRequest(nil, pool.OpeningInput{
		FundingTx:            funding.Bytes(),
		ExpiryLockTime:       500000100,
		MinerFeeRateSatPerKB: 1,
		SellerPubKey:         seller.PubKey().Compressed(),
		ArbiterPubKey:        arbiter.PubKey().Compressed(),
	})
	if err != nil {
		panic(err)
	}
	sellerRefund, err := pool.NewSellerPoolAdapter(engine, seller).SignSellerRefund(nil, request)
	if err != nil {
		panic(err)
	}
	proof, err := engine.BuildOpeningProof(nil, request, sellerRefund, funding.Bytes())
	if err != nil {
		panic(err)
	}
	if err := engine.VerifyOpening(proof); err != nil {
		panic(err)
	}
	details, err := pool.DeriveOpeningDetails(proof)
	if err != nil {
		panic(err)
	}
	state, err := tx.NewTransactionFromBytes(proof.RefundTx)
	if err != nil {
		panic(err)
	}
	state.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: details.PoolOutputSatoshis, LockingScript: script.NewFromBytes(details.PoolLockingScript)})
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	preimage, err := state.CalcInputPreimage(0, flag)
	if err != nil {
		panic(err)
	}
	digest, err := state.CalcInputSignatureHash(0, flag)
	if err != nil {
		panic(err)
	}
	fullSig, err := mp.SignArbitratedPoolAsBuyer(state, details.PoolOutputSatoshis, mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}, buyer)
	if err != nil {
		panic(err)
	}
	if fullSig[len(fullSig)-1] != byte(flag) {
		panic("unexpected sighash flag on buyer signature")
	}
	valid, err := mp.VerifyArbitratedPoolBuyerSignature(state, details.PoolOutputSatoshis, mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}, fullSig)
	if err != nil || !valid {
		panic(fmt.Sprintf("buyer signature self-verification failed: %v", err))
	}
	vector := map[string]any{
		"algorithm":              "MultisigPool v4 transaction sighash: SHA-256d(BSV preimage), ForkID|All, low-S DER over the digest",
		"unsignedTxHex":          hex.EncodeToString(proof.RefundTx),
		"inputIndex":             0,
		"sourceSatoshis":         details.PoolOutputSatoshis,
		"sourceLockingScriptHex": hex.EncodeToString(details.PoolLockingScript),
		"sighashFlag":            int(flag),
		"preimageHex":            hex.EncodeToString(preimage),
		"sighashDigestHex":       hex.EncodeToString(digest),
		"buyerPubkeyHex":         hex.EncodeToString(buyer.PubKey().Compressed()),
		"sellerPubkeyHex":        hex.EncodeToString(seller.PubKey().Compressed()),
		"arbiterPubkeyHex":       hex.EncodeToString(arbiter.PubKey().Compressed()),
		"goDerSignatureHex":      hex.EncodeToString(fullSig[:len(fullSig)-1]),
	}

	// 真实的 005 payment state 向量：与退款模板共用同一个费用池来源，但它是
	// 按 [Buyer, Seller, Arbiter] 三输出分配、携带本轮 PaymentSequence 的
	// 状态交易。Buyer 签名的对象就是这笔确定性重建的交易。
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		panic(err)
	}
	previous, err := engine.ParsePaymentState(nil, initialRaw, proof)
	if err != nil {
		panic(err)
	}
	targetSequence := previous.PaymentSequence + 1
	sellerAmountAfter := uint64(500)
	unsigned, err := engine.BuildPaymentUpdate(nil, pool.PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: targetSequence, SellerAmountAfterSat: sellerAmountAfter})
	if err != nil {
		panic(err)
	}
	stateTx, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		panic(err)
	}
	stateTx.Inputs[0].SetSourceTxOutput(&tx.TransactionOutput{Satoshis: details.PoolOutputSatoshis, LockingScript: script.NewFromBytes(details.PoolLockingScript)})
	paymentPreimage, err := stateTx.CalcInputPreimage(0, flag)
	if err != nil {
		panic(err)
	}
	paymentDigest, err := stateTx.CalcInputSignatureHash(0, flag)
	if err != nil {
		panic(err)
	}
	buyerAdapter := pool.NewBuyerPoolAdapter(engine, buyer)
	buyerPaymentSig, err := buyerAdapter.SignBuyerPayment(nil, unsigned, proof)
	if err != nil {
		panic(err)
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerPaymentSig, proof); err != nil {
		panic(fmt.Sprintf("buyer payment signature self-verification failed: %v", err))
	}
	sellerAdapter := pool.NewSellerPoolAdapter(engine, seller)
	sellerPaymentSig, err := sellerAdapter.SignSellerPayment(nil, unsigned, proof)
	if err != nil {
		panic(err)
	}
	merged, err := engine.MergeBuyerSellerPayment(unsigned, buyerPaymentSig, sellerPaymentSig, proof)
	if err != nil {
		panic(err)
	}
	paymentVector := map[string]any{
		"algorithm":              "MultisigPool v4 005 cumulative payment state rebuilt deterministically by BuildPaymentUpdate; sighash = SHA-256d(BSV preimage), ForkID|All, low-S DER over the digest. This is NOT the RefundTemplate.",
		"previousRawTxHex":       hex.EncodeToString(previous.RawTx),
		"targetPaymentSequence":  targetSequence,
		"sellerAmountAfterSat":   sellerAmountAfter,
		"expectedUnsignedRawHex": hex.EncodeToString(unsigned.RawTx),
		"mergedRawTxHex":         hex.EncodeToString(merged.RawTx),
		"inputIndex":             0,
		"sourceSatoshis":         details.PoolOutputSatoshis,
		"sourceLockingScriptHex": hex.EncodeToString(details.PoolLockingScript),
		"sighashFlag":            int(flag),
		"preimageHex":            hex.EncodeToString(paymentPreimage),
		"sighashDigestHex":       hex.EncodeToString(paymentDigest),
		"buyerPubkeyHex":         hex.EncodeToString(buyer.PubKey().Compressed()),
		"sellerPubkeyHex":        hex.EncodeToString(seller.PubKey().Compressed()),
		"arbiterPubkeyHex":       hex.EncodeToString(arbiter.PubKey().Compressed()),
		"goDerSignatureHex":      hex.EncodeToString(buyerPaymentSig[:len(buyerPaymentSig)-1]),
	}
	regenerated := map[string][]byte{}
	for name, value := range map[string]any{refundVectorFile: vector, paymentStateVectorFile: paymentVector} {
		raw, err := marshalVector(value)
		if err != nil {
			panic(err)
		}
		regenerated[name] = raw
	}

	if *check {
		// 只做内存比较：绝不写文件，避免破坏已提交 fixture。
		failed := false
		for _, name := range []string{refundVectorFile, paymentStateVectorFile} {
			committed, err := os.ReadFile(filepath.Join(*outDir, name))
			if err != nil {
				fmt.Fprintf(os.Stderr, "CHECK FAIL: read committed %s: %v\n", name, err)
				failed = true
				continue
			}
			if !bytes.Equal(committed, regenerated[name]) {
				fmt.Fprintf(os.Stderr, "CHECK FAIL: regenerated %s differs from committed fixture\n", name)
				failed = true
			}
		}
		if failed {
			os.Exit(1)
		}
		fmt.Println("vector drift check OK")
		return
	}

	info, err := os.Stat(*outDir)
	if err != nil || !info.IsDir() {
		panic(fmt.Errorf("--out-dir %q must be an existing directory: %w", *outDir, errors.Join(err, os.ErrInvalid)))
	}
	mustWriteJSON(*outDir, refundVectorFile, vector)
	mustWriteJSON(*outDir, paymentStateVectorFile, paymentVector)
	fmt.Printf("wrote %s and %s into %s\n", refundVectorFile, paymentStateVectorFile, *outDir)
}
