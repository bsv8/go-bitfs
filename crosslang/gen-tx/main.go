// Command gen-tx 生成 Go/TS 共享的 MultisigPool v4 交易签名向量。
//
// 真值：sighash = SHA-256d(BSV preimage)，flag = ForkID|All (0x41)，
// ECDSA(low-S DER) 对该摘要签名，绝不二次哈希。所有数值从固定的
// MultisigPool v4 fixture（角色私钥 11/22/33、100000 satoshis 资金池、
// lockTime 500000100、费率 1 sat/KB）确定性派生。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

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

func main() {
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
	out, _ := json.MarshalIndent(vector, "", "  ")
	fmt.Println(string(out))
}
