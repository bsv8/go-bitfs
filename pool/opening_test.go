package pool

import (
	"encoding/binary"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"

	"context"
	"encoding/hex"

	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv8/go-bitfs/protocol"
)

func TestParseCanonicalTransactionPreflightsCompactSizeLengths(t *testing.T) {
	// 一个输入声明 uint64 最大值的 unlocking script，但报文仅有几十字节。
	// SDK 交易解析器会按声明长度分配，因此必须先由协议层边界扫描拒绝。
	raw := append([]byte{1, 0, 0, 0, 1}, make([]byte, 36)...)
	raw = append(raw, 0xff)
	length := make([]byte, 8)
	binary.LittleEndian.PutUint64(length, ^uint64(0))
	raw = append(raw, length...)

	if _, err := ParseCanonicalTransaction(raw); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
		t.Fatalf("untrusted CompactSize script length error = %v, want invalid_evidence", err)
	}
}

func TestParseCanonicalTransactionRejectsExcessiveElementCounts(t *testing.T) {
	// 极短报文不能让 SDK 按声明的 2^32-1 个输入循环。
	for _, raw := range [][]byte{
		{1, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff, 0xff},
		{1, 0, 0, 0, 0, 0xfd, 0x11, 0x27, 0, 0, 0, 0},
	} {
		if _, err := ParseCanonicalTransaction(raw); !protocol.IsCode(err, protocol.CodeInvalidEvidence) {
			t.Fatalf("excessive element count %x = %v, want invalid_evidence", raw, err)
		}
	}
}

func TestRefundTemplateTxIDGoldenValueAndByteOrder(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100)
	computed, err := DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	// Golden value: TxID().CloneBytes() of the canonical unsigned RefundTemplateRaw
	// built by mustRefundExpiryFixture; no display-order reversal applied.
	const want = "9e81627f5557c355058d437c30b5ed7637a5a83353e5d2e16d9895e6cd759f56"
	if got := hex.EncodeToString(computed[:]); got != want {
		t.Fatalf("DeriveRefundTemplateTxID = %s, want %s", got, want)
	}
}

func TestRefundTemplateTxIDRequestAndProofEntriesAgree(t *testing.T) {
	ctx := context.Background()
	buyerKey := mustPoolTestKey(t, "11")
	sellerKey := mustPoolTestKey(t, "22")
	arbiterKey := mustPoolTestKey(t, "33")
	keys := MultisigPoolPublicKeys{BuyerPublicKey: buyerKey.PubKey().Compressed(), SellerPublicKey: sellerKey.PubKey().Compressed(), ArbiterPublicKey: arbiterKey.PubKey().Compressed()}
	lock, err := Build2of3LockingScript(keys)
	if err != nil {
		t.Fatal(err)
	}
	funding := txNewFundingForOpeningTest(t, lock)
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: keys.BuyerPublicKey, SellerPublicKey: keys.SellerPublicKey, ArbiterPublicKey: keys.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewBuyerPoolAdapter(engine, mustSigner(t, buyerKey)).BuildRefundPresignRequest(ctx, OpeningInput{FundingTransactionRaw: funding, ExpiryLockTime: 500000100, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: keys.SellerPublicKey, ArbiterPublicKey: keys.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := NewSellerPoolAdapter(engine, mustSigner(t, sellerKey)).SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fromRequest, err := DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(request, sellerSignature, funding)
	if err != nil {
		t.Fatal(err)
	}
	fromProof, err := DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	if fromRequest != fromProof {
		t.Fatalf("request hash %x != proof hash %x", fromRequest, fromProof)
	}
}

func TestMergedOnChainRefundTxidDiffersFromPoolID(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100)
	poolID, err := DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: proof.BuyerPublicKey, SellerPublicKey: proof.SellerPublicKey, ArbiterPublicKey: proof.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	broadcastable, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	onChainTxID, err := engine.TransactionID(broadcastable)
	if err != nil {
		t.Fatal(err)
	}
	if RefundTemplateTxID(onChainTxID) == poolID {
		t.Fatal("merged refund txid must differ from the unsigned RefundTemplateTxID pool ID")
	}
}

func TestNonCanonicalRefundTxProducesNoID(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100)
	tampered := append([]byte(nil), proof.RefundTemplateRaw...)
	tampered[4] ^= 0xff
	if _, err := refundTemplateTxIDFromBytes(tampered); err == nil {
		t.Fatal("non-canonical refund transaction produced an ID")
	}
	if _, err := refundTemplateTxIDFromBytes(nil); err == nil {
		t.Fatal("empty refund transaction produced an ID")
	}
}

func txNewFundingForOpeningTest(t *testing.T, lock []byte) []byte {
	t.Helper()
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: script.NewFromBytes(lock)})
	return funding.Bytes()
}

func requestFromProofForTest(proof *OpeningProof) (*RefundPresignRequest, error) {
	return &RefundPresignRequest{
		RefundTemplateRaw:               append([]byte(nil), proof.RefundTemplateRaw...),
		BuyerPublicKey:                  append([]byte(nil), proof.BuyerPublicKey...),
		SellerPublicKey:                 append([]byte(nil), proof.SellerPublicKey...),
		ArbiterPublicKey:                append([]byte(nil), proof.ArbiterPublicKey...),
		MinerFeeRateSatoshisPerKilobyte: proof.MinerFeeRateSatoshisPerKilobyte,
		BuyerRefundTransactionSignature: append([]byte(nil), proof.BuyerRefundTransactionSignature...),
	}, nil
}

func wrongSellerSignatureForRequest(t *testing.T, request *RefundPresignRequest) []byte {
	t.Helper()
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: request.BuyerPublicKey, SellerPublicKey: request.SellerPublicKey, ArbiterPublicKey: request.ArbiterPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	terms, err := engine.deriveRefundPresignTerms(request)
	if err != nil {
		t.Fatal(err)
	}
	flag := sighash.Flag(sighash.ForkID | sighash.All)
	digest, err := terms.state.CalcInputSignatureHash(0, flag)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := mustPoolTestKey(t, "44")
	signature, err := wrongKey.Sign(digest)
	if err != nil {
		t.Fatal(err)
	}
	return append(signature.Serialize(), byte(flag))
}

func TestRefundTemplateTxIDDerivationRejectsTamperedTemplates(t *testing.T) {
	engine, proof := mustRefundExpiryFixture(t, 500000100)
	validTxID, err := DeriveRefundTemplateTxID(proof)
	if err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
	_ = validTxID

	mustReject := func(name string, mutate func(p *OpeningProof)) {
		t.Helper()
		bad := CloneOpeningProof(proof)
		mutate(bad)
		if _, err := DeriveRefundTemplateTxID(bad); err == nil {
			t.Fatalf("tampered %s was accepted as refund template", name)
		}
	}
	mutateState := func(name string, mutate func(state *tx.Transaction)) {
		t.Helper()
		state, err := tx.NewTransactionFromBytes(proof.RefundTemplateRaw)
		if err != nil {
			t.Fatal(err)
		}
		mutate(state)
		mustReject(name, func(p *OpeningProof) { p.RefundTemplateRaw = state.Bytes() })
	}

	// 角色公钥
	mustReject("arbiter pubkey", func(p *OpeningProof) { p.ArbiterPublicKey = bytes2Mutate() })
	// 费率
	mustReject("fee rate", func(p *OpeningProof) { p.MinerFeeRateSatoshisPerKilobyte *= 1024 })
	// nLockTime 是买方自选字段：篡改不会使模板非法，但必须改变模板身份
	// （重建比较把 locktime 绑定进 TxID 派生）。
	{
		locked := CloneOpeningProof(proof)
		locked.RefundTemplateRaw[len(locked.RefundTemplateRaw)-1] ^= 0x01
		altered, err := DeriveRefundTemplateTxID(locked)
		if err != nil {
			t.Fatalf("locktime is part of the rebuilt template: %v", err)
		}
		if altered == validTxID {
			t.Fatal("nLockTime tampering did not change the template identity")
		}
	}
	// sequence（locktime 前 4 字节）
	mutateState("sequence", func(st *tx.Transaction) { st.Inputs[0].SequenceNumber++ })
	// outpoint index
	mutateState("outpoint index", func(st *tx.Transaction) { st.Inputs[0].SourceTxOutIndex = 1 })
	// unlocking script
	mutateState("unlocking script", func(st *tx.Transaction) { st.Inputs[0].UnlockingScript = script.NewFromBytes([]byte{0x51}) })
	// Seller 金额
	mutateState("seller amount", func(st *tx.Transaction) { st.Outputs[1].Satoshis++ })
	// Buyer 金额
	mutateState("buyer amount", func(st *tx.Transaction) { st.Outputs[0].Satoshis++ })
	// output locking script
	mutateState("output locking script", func(st *tx.Transaction) {
		raw := st.Outputs[0].LockingScript.Bytes()
		raw[0] ^= 0xff
		st.Outputs[0].LockingScript = script.NewFromBytes(raw)
	})
	// output 顺序
	mutateState("output order", func(st *tx.Transaction) { st.Outputs[0], st.Outputs[1] = st.Outputs[1], st.Outputs[0] })

	// 完全签名后的交易不再是模板：通过公开入口验证拒绝。
	signed := CloneOpeningProof(proof)
	merged, err := engine.BuildRefundSubmission(signed)
	if err != nil {
		t.Fatal(err)
	}
	signed.RefundTemplateRaw = merged
	if _, err := DeriveRefundTemplateTxID(signed); err == nil {
		t.Fatal("fully signed refund transaction was accepted as a template")
	}

	// 普通"一进三出"交易冒充退款模板。
	zeroHash, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	generic := tx.NewTransaction()
	generic.AddInput(&tx.TransactionInput{SourceTXID: zeroHash, SourceTxOutIndex: 0, SequenceNumber: 1})
	for i := 0; i < 3; i++ {
		generic.AddOutput(&tx.TransactionOutput{Satoshis: 100, LockingScript: script.NewFromBytes([]byte{0x51})})
	}
	fake := CloneOpeningProof(proof)
	fake.RefundTemplateRaw = generic.Bytes()
	if _, err := DeriveRefundTemplateTxID(fake); err == nil {
		t.Fatal("generic one-in-three-out transaction was accepted as a refund template")
	}
}

func bytes2Mutate() []byte { return append([]byte(nil), make([]byte, 33)...) }
