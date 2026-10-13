package pool

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv8/go-bitfs/internal/conformance"
	"github.com/bsv8/go-bitfs/protocol"
)

// 本文件把交易层字节（退款模板、合并退款、普通付款、立即关闭、仲裁付款的
// raw/preimage/digest/txid）冻结为 machine-readable manifest
// （testdata/v1/transactions.json）。统一协议只重塑 wire 外壳与消息签名域，
// 交易构造必须与施工前逐字节一致；-update-transaction-manifest 仅允许在给出
// 协议级证据并经人工审查后重建。
var transactionManifestUpdate = flag.Bool("update-transaction-manifest", false, "regenerate testdata/v1/transactions.json")

type transactionManifestEntry struct {
	Name      string `json:"name"`
	RawHex    string `json:"raw_hex,omitempty"`
	TxID      string `json:"txid,omitempty"`
	Preimage  string `json:"preimage,omitempty"`
	Digest    string `json:"sighash_digest,omitempty"`
	Signature string `json:"signature_der_hex,omitempty"`
}

type transactionGoldenManifest struct {
	Protocol    string                     `json:"protocol"`
	WireVersion uint64                     `json:"wire_version"`
	FixedKeys   string                     `json:"fixed_keys"`
	Entries     []transactionManifestEntry `json:"entries"`
}

func mustTxKey(t *testing.T, repeat byte) *ec.PrivateKey {
	t.Helper()
	key, _ := ec.PrivateKeyFromBytes(bytes_Repeat(repeat, 32))
	if key == nil {
		t.Fatal("deterministic key construction failed")
	}
	return key
}

func bytes_Repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestExportTransactionVectors dumps the current implementation's vectors in
// the same name->hex schema as the legacy exporter (GOLDEN_EXPORT env).
func TestExportTransactionVectors(t *testing.T) {
	if os.Getenv("GOLDEN_EXPORT") == "" {
		t.Skip("set GOLDEN_EXPORT=<path> to dump current-implementation vectors for legacy diff evidence")
	}
	out := exportCurrentTransactionVectors(t)
	raw, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("GOLDEN_EXPORT"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// exportCurrentTransactionVectors 构造与旧实现导出器同名的向量集。
func exportCurrentTransactionVectors(t *testing.T) map[string]string {
	t.Helper()
	manifest := buildTransactionManifest(t)
	out := make(map[string]string, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		if entry.Name == "refund_matured_submission" {
			continue // 与 refund_merged 同字节，旧导出器无此键
		}
		if entry.RawHex != "" {
			out[entry.Name] = entry.RawHex
		}
		if entry.TxID != "" {
			out[entry.Name+"_txid"] = entry.TxID
		}
		if entry.Preimage != "" {
			out[entry.Name] = entry.Preimage
		}
		if entry.Digest != "" {
			out[entry.Name] = entry.Digest
		}
		if entry.Signature != "" {
			out[entry.Name] = entry.Signature
		}
	}
	return out
}

func buildTransactionManifest(t *testing.T) *transactionGoldenManifest {
	t.Helper()
	ctx := context.Background()
	buyerKey := mustTxKey(t, 0xb1)
	sellerKey := mustTxKey(t, 0x52)
	arbiterKey := mustTxKey(t, 0xa3)
	buyerSigner := mustSigner(t, buyerKey)
	sellerSigner := mustSigner(t, sellerKey)
	arbiterSigner := mustSigner(t, arbiterKey)

	// 与 demo fixture 同构的最小资金交易：零哈希输入占位，输出 0 为池输出。
	lock, err := Build2of3LockingScript(MultisigPoolPublicKeys{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	var zeroSource chainhash.Hash
	copy(zeroSource[:], bytes_Repeat(0x01, 32))
	funding.AddInput(&tx.TransactionInput{SourceTXID: &zeroSource, SequenceNumber: tx.DefaultSequenceNumber, UnlockingScript: script.NewFromBytes(nil)})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 20000, LockingScript: script.NewFromBytes(lock)})
	fundingRaw := funding.Bytes()

	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewBuyerPoolAdapter(engine, buyerSigner).BuildRefundPresignRequest(ctx, OpeningInput{
		FundingTransactionRaw:           fundingRaw,
		ExpiryLockTime:                  800000,
		MinerFeeRateSatoshisPerKilobyte: 1,
		SellerPublicKey:                 sellerKey.PubKey().Compressed(),
		ArbiterPublicKey:                arbiterKey.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, sellerSigner).SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	opening, err := engine.BuildOpeningProof(request, sellerSig, fundingRaw)
	if err != nil {
		t.Fatal(err)
	}
	refundMerged, err := engine.BuildRefundSubmission(opening)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(refundMerged, opening)
	if err != nil {
		t.Fatal(err)
	}

	manifest := &transactionGoldenManifest{Protocol: protocol.ProtocolFamily, WireVersion: protocol.WireVersion, FixedKeys: "buyer=0xb1*32 seller=0x52*32 arbiter=0xa3*32; funding input zero-hash placeholder"}
	addEntry := func(entry transactionManifestEntry) { manifest.Entries = append(manifest.Entries, entry) }

	templateID, err := DeriveRefundTemplateTxID(opening)
	if err != nil {
		t.Fatal(err)
	}
	addEntry(transactionManifestEntry{Name: "refund_template", RawHex: hexEncode(request.RefundTemplateRaw), TxID: hexEncode(templateID[:])})
	addEntry(transactionManifestEntry{Name: "opening_buyer_signature", Signature: hexEncode(request.BuyerRefundTransactionSignature)})
	addEntry(transactionManifestEntry{Name: "opening_seller_signature", Signature: hexEncode(sellerSig)})
	addEntry(transactionManifestEntry{Name: "refund_merged", RawHex: hexEncode(refundMerged), TxID: hexEncode(txIDOf(t, refundMerged))})

	// 普通累计付款：初始态 → sequence 3。
	unsignedPayment, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: opening, Previous: initial, PaymentSequence: initial.PaymentSequence + 1, SellerAmountAfterSatoshis: initial.SellerAmountSatoshis + 100})
	if err != nil {
		t.Fatal(err)
	}
	buyerPaySig, err := NewBuyerPoolAdapter(engine, buyerSigner).SignBuyerPayment(ctx, unsignedPayment, opening)
	if err != nil {
		t.Fatal(err)
	}
	paymentPreimage, paymentDigest := paymentSighashParts(t, unsignedPayment)
	addEntry(transactionManifestEntry{Name: "payment_unsigned", RawHex: hexEncode(unsignedPayment.RawTx)})
	addEntry(transactionManifestEntry{Name: "payment_preimage", Preimage: paymentPreimage})
	addEntry(transactionManifestEntry{Name: "payment_sighash_digest", Digest: paymentDigest})
	addEntry(transactionManifestEntry{Name: "payment_buyer_signature", Signature: hexEncode(buyerPaySig)})
	sellerPaySig, err := NewSellerPoolAdapter(engine, sellerSigner).SignSellerPayment(ctx, unsignedPayment, opening)
	if err != nil {
		t.Fatal(err)
	}
	paymentSigned, err := engine.MergeBuyerSellerPayment(unsignedPayment, buyerPaySig, sellerPaySig, opening)
	if err != nil {
		t.Fatal(err)
	}
	addEntry(transactionManifestEntry{Name: "payment_merged", RawHex: hexEncode(paymentSigned.RawTx), TxID: hexEncode(txIDOf(t, paymentSigned.RawTx))})

	// 立即关闭：以付款后的状态为 base。
	finalUnsigned, err := engine.BuildImmediateClose(CloseInput{Opening: opening, Base: &paymentSigned.State, SellerAmountAfterSatoshis: paymentSigned.State.SellerAmountSatoshis + 50})
	if err != nil {
		t.Fatal(err)
	}
	closeBuyerSig, err := NewBuyerPoolAdapter(engine, buyerSigner).SignBuyerPayment(ctx, finalUnsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	closeSellerSig, err := NewSellerPoolAdapter(engine, sellerSigner).SignSellerPayment(ctx, finalUnsigned, opening)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := engine.MergeBuyerSellerPayment(finalUnsigned, closeBuyerSig, closeSellerSig, opening)
	if err != nil {
		t.Fatal(err)
	}
	addEntry(transactionManifestEntry{Name: "close_unsigned", RawHex: hexEncode(finalUnsigned.RawTx)})
	addEntry(transactionManifestEntry{Name: "close_merged", RawHex: hexEncode(closed.RawTx), TxID: hexEncode(txIDOf(t, closed.RawTx))})

	// 仲裁付费 candidate：从 Claim primitives 独立重建。
	claimPoolSatoshis := initial.PoolOutputSatoshis
	arbUnsigned, err := BuildArbitrationPaymentFromClaim(claimPoolSatoshis, initial.PoolLockingScript, request.RefundTemplateRaw, 7, 200, 500)
	if err != nil {
		t.Fatalf("build arbitration candidate: %v", err)
	}
	arbSellerSig, err := engine.SignArbitrationSellerPayment(ctx, arbUnsigned, sellerSigner)
	if err != nil {
		t.Fatal(err)
	}
	arbPreimage, arbDigest := arbitrationSighashParts(t, engine, arbUnsigned)
	addEntry(transactionManifestEntry{Name: "arbitration_candidate", RawHex: hexEncode(arbUnsigned.RawTx)})
	addEntry(transactionManifestEntry{Name: "arbitration_preimage", Preimage: arbPreimage})
	addEntry(transactionManifestEntry{Name: "arbitration_sighash_digest", Digest: arbDigest})
	addEntry(transactionManifestEntry{Name: "arbitration_seller_signature", Signature: hexEncode(arbSellerSig)})
	arbiterArbSig, err := engine.SignArbitrationArbiterPayment(ctx, arbUnsigned, arbiterSigner)
	if err != nil {
		t.Fatal(err)
	}
	arbMerged, err := engine.MergeArbitratedPoolSellerArbiterSignatures(arbUnsigned, arbSellerSig, arbiterArbSig)
	if err != nil {
		t.Fatal(err)
	}
	addEntry(transactionManifestEntry{Name: "arbitration_merged", RawHex: hexEncode(arbMerged.RawTx), TxID: hexEncode(txIDOf(t, arbMerged.RawTx))})
	return manifest
}

func TestTransactionGoldenManifestMatchesFrozenFile(t *testing.T) {
	manifest := buildTransactionManifest(t)
	path, err := conformance.FixturePath(".", "transaction_manifest")
	if err != nil {
		t.Fatalf("resolve transaction_manifest from fixtures/manifest.json: %v", err)
	}
	if *transactionManifestUpdate {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("regenerated %s; 必须附协议级证据并经人工审查后才能合入", path)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen transaction manifest: %v", err)
	}
	var frozen transactionGoldenManifest
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	// 顶层元数据与向量一并冻结：任何漂移都阻断。
	if frozen.Protocol != manifest.Protocol || frozen.WireVersion != manifest.WireVersion || frozen.FixedKeys != manifest.FixedKeys {
		t.Fatalf("manifest metadata drifted:\n frozen protocol=%q wire=%d keys=%q\n rebuilt protocol=%q wire=%d keys=%q",
			frozen.Protocol, frozen.WireVersion, frozen.FixedKeys, manifest.Protocol, manifest.WireVersion, manifest.FixedKeys)
	}
	if len(frozen.Entries) != len(manifest.Entries) {
		t.Fatalf("entry count drifted: frozen %d rebuilt %d", len(frozen.Entries), len(manifest.Entries))
	}
	for index, want := range frozen.Entries {
		got := manifest.Entries[index]
		if got.Name != want.Name || got.RawHex != want.RawHex || got.TxID != want.TxID || got.Preimage != want.Preimage || got.Digest != want.Digest || got.Signature != want.Signature {
			t.Fatalf("golden %s drifted:\n got %+v\nwant %+v", want.Name, got, want)
		}
	}
}

// ---- 包内小工具 ----

func txIDOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	parsed, err := ParseCanonicalTransaction(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.TxID().CloneBytes()
}

func paymentSighashParts(t *testing.T, unsigned *UnsignedPayment) (string, string) {
	t.Helper()
	state, err := ParseCanonicalTransaction(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	setPoolSource(state, unsigned.PoolOutputSatoshis, unsigned.PoolLockingScript)
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	preimage, err := state.CalcInputPreimage(0, flag)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := state.CalcInputSignatureHash(0, flag)
	if err != nil {
		t.Fatal(err)
	}
	return hexEncode(preimage), hexEncode(digest)
}

func arbitrationSighashParts(t *testing.T, engine *MultisigPoolEngine, unsigned *UnsignedPayment) (string, string) {
	t.Helper()
	state, err := engine.validateArbitrationUnsignedPayment(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	preimage, err := state.CalcInputPreimage(0, flag)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := state.CalcInputSignatureHash(0, flag)
	if err != nil {
		t.Fatal(err)
	}
	return hexEncode(preimage), hexEncode(digest)
}

func hexEncode(raw []byte) string {
	const table = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = table[b>>4]
		out[i*2+1] = table[b&0x0f]
	}
	return string(out)
}

// TestLegacyTransactionExportMatchesCurrent 独立复现交易层新旧对照证据：
// legacy_95f5a90_transactions.json 由硬切换前提交（95f5a90）的旧 API 导出器
// 生成；current_transactions.json 由当前唯一主 API 导出器生成。本测试用当前
// 实现实时重算全部向量，并要求旧集合同名键全部逐字节相等（当前实现允许是
// 超集）。任何一侧漂移都会被阻断。
func TestLegacyTransactionExportMatchesCurrent(t *testing.T) {
	legacy := loadFrozenMap(t, filepath.Join("testdata", "v1", "legacy_95f5a90_transactions.json"))
	frozenCurrent := loadFrozenMap(t, filepath.Join("testdata", "v1", "current_transactions.json"))
	rebuilt := exportCurrentTransactionVectors(t)

	for name, legacyHex := range legacy {
		currentHex, ok := frozenCurrent[name]
		if !ok {
			t.Fatalf("vector %q missing from frozen current export", name)
		}
		rebuiltHex, ok := rebuilt[name]
		if !ok {
			t.Fatalf("vector %q missing from rebuilt export", name)
		}
		if legacyHex != currentHex || legacyHex != rebuiltHex {
			t.Fatalf("transaction vector %q drifted:\n legacy %s\n frozen %s\n rebuilt %s", name, legacyHex, currentHex, rebuiltHex)
		}
	}
}

func loadFrozenMap(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
