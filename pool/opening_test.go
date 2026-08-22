package pool

import (
	"github.com/bsv-blockchain/go-sdk/chainhash"

	"context"
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func TestRefundTemplateTxIDGoldenValueAndByteOrder(t *testing.T) {
	_, proof := mustRefundExpiryFixture(t, 500000100)
	computed, err := DeriveRefundTemplateTxID(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	// Golden value: TxID().CloneBytes() of the canonical unsigned RefundTx
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
	keys := MultisigPoolPublicKeys{BuyerPubKey: buyerKey.PubKey().Compressed(), SellerPubKey: sellerKey.PubKey().Compressed(), ArbiterPubKey: arbiterKey.PubKey().Compressed()}
	lock, err := Build2of3LockingScript(keys)
	if err != nil {
		t.Fatal(err)
	}
	funding := txNewFundingForOpeningTest(t, lock)
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: keys.BuyerPubKey, SellerPubKey: keys.SellerPubKey, ArbiterPubKey: keys.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewBuyerPoolAdapter(engine, buyerKey).BuildRefundPresignRequest(ctx, OpeningInput{FundingTx: funding, ExpiryLockTime: 500000100, MinerFeeRateSatPerKB: 1, SellerPubKey: keys.SellerPubKey, ArbiterPubKey: keys.ArbiterPubKey})
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := NewSellerPoolAdapter(engine, sellerKey).SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fromRequest, err := DeriveRefundTemplateTxIDFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(ctx, request, sellerSig, funding)
	if err != nil {
		t.Fatal(err)
	}
	fromProof, err := DeriveRefundTemplateTxID(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if fromRequest != fromProof {
		t.Fatalf("request hash %x != proof hash %x", fromRequest, fromProof)
	}
}

func TestMergedOnChainRefundTxidDiffersFromPoolID(t *testing.T) {
	ctx := context.Background()
	_, proof := mustRefundExpiryFixture(t, 500000100)
	poolID, err := DeriveRefundTemplateTxID(ctx, proof)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: proof.BuyerPubKey, SellerPubKey: proof.SellerPubKey, ArbiterPubKey: proof.ArbiterPubKey})
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
	tampered := append([]byte(nil), proof.RefundTx...)
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
		Version:              MajorVersion,
		RefundTx:             append([]byte(nil), proof.RefundTx...),
		BuyerPubKey:          append([]byte(nil), proof.BuyerPubKey...),
		SellerPubKey:         append([]byte(nil), proof.SellerPubKey...),
		ArbiterPubKey:        append([]byte(nil), proof.ArbiterPubKey...),
		MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB,
		BuyerRefundSignature: append([]byte(nil), proof.BuyerRefundSignature...),
	}, nil
}

func wrongSellerSignatureForRequest(t *testing.T, request *RefundPresignRequest) []byte {
	t.Helper()
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey})
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
	validTxID, err := DeriveRefundTemplateTxID(context.Background(), proof)
	if err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
	_ = validTxID

	mustReject := func(name string, mutate func(p *OpeningProof)) {
		t.Helper()
		bad := CloneOpeningProof(proof)
		mutate(bad)
		if _, err := DeriveRefundTemplateTxID(context.Background(), bad); err == nil {
			t.Fatalf("tampered %s was accepted as refund template", name)
		}
	}
	mutateState := func(name string, mutate func(state *tx.Transaction)) {
		t.Helper()
		state, err := tx.NewTransactionFromBytes(proof.RefundTx)
		if err != nil {
			t.Fatal(err)
		}
		mutate(state)
		mustReject(name, func(p *OpeningProof) { p.RefundTx = state.Bytes() })
	}

	// 角色公钥
	mustReject("arbiter pubkey", func(p *OpeningProof) { p.ArbiterPubKey = bytes2Mutate() })
	// 费率
	mustReject("fee rate", func(p *OpeningProof) { p.MinerFeeRateSatPerKB *= 1024 })
	// nLockTime 是买方自选字段：篡改不会使模板非法，但必须改变模板身份
	// （重建比较把 locktime 绑定进 TxID 派生）。
	{
		locked := CloneOpeningProof(proof)
		locked.RefundTx[len(locked.RefundTx)-1] ^= 0x01
		altered, err := DeriveRefundTemplateTxID(context.Background(), locked)
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
	signed.RefundTx = merged
	if _, err := DeriveRefundTemplateTxID(context.Background(), signed); err == nil {
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
	fake.RefundTx = generic.Bytes()
	if _, err := DeriveRefundTemplateTxID(context.Background(), fake); err == nil {
		t.Fatal("generic one-in-three-out transaction was accepted as a refund template")
	}
}

func bytes2Mutate() []byte { return append([]byte(nil), make([]byte, 33)...) }
