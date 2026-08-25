package pool

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/protocol"
)

// mustDERSignature signs an arbitrary digest with the official BSV private key
// and returns DER bytes; tests use it to craft malformed or foreign signatures.
func mustDERSignature(t *testing.T, key *ec.PrivateKey) []byte {
	t.Helper()
	sig, err := key.Sign(make([]byte, 32))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	der, err := sig.ToDER()
	if err != nil {
		t.Fatalf("der: %v", err)
	}
	return der
}

func TestBuild2of3LockingScriptUsesExplicitParticipantRoles(t *testing.T) {
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")

	lock, err := Build2of3LockingScript(MultisigPoolPublicKeys{
		BuyerPublicKey:   buyer.PubKey().Compressed(),
		SellerPublicKey:  seller.PubKey().Compressed(),
		ArbiterPublicKey: arbiter.PubKey().Compressed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := mp.BuildArbitratedPoolLock(mp.ArbitratedPoolRoles{
		Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lock, expected.Bytes()) {
		t.Fatal("role-explicit locking script differs from the MultisigPool result")
	}
}

func TestParseArbitratedPoolLockingScriptRejectsNonCanonicalRoles(t *testing.T) {
	keys := MultisigPoolPublicKeys{
		BuyerPublicKey:   mustPoolTestKey(t, "11").PubKey().Compressed(),
		SellerPublicKey:  mustPoolTestKey(t, "22").PubKey().Compressed(),
		ArbiterPublicKey: mustPoolTestKey(t, "33").PubKey().Compressed(),
	}
	raw, err := Build2of3LockingScript(keys)
	if err != nil {
		t.Fatal(err)
	}
	badOpcode := append([]byte(nil), raw...)
	badOpcode[0] = byte(script.Op1)
	if _, err := ParseArbitratedPoolLockingScript(badOpcode); err == nil {
		t.Fatal("non-2-of-3 opcode was accepted")
	}
	duplicate := append([]byte(nil), raw...)
	copy(duplicate[36:69], duplicate[2:35])
	if _, err := ParseArbitratedPoolLockingScript(duplicate); err == nil {
		t.Fatal("duplicate role key was accepted")
	}
}

func TestSignerBoundaryRejectsWrongRoleMalformedAndInvalidSignatures(t *testing.T) {
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyer.PubKey().Compressed(), SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	input := OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 500000100, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()}
	if _, err := NewBuyerPoolAdapter(engine, mustSigner(t, seller)).BuildRefundPresignRequest(ctx, input); err == nil {
		t.Fatal("wrong role signer was accepted")
	}
	if _, err := NewBuyerPoolAdapter(engine, mustSigner(t, buyer)).BuildRefundPresignRequest(ctx, input); err != nil {
		t.Fatalf("fixed signing path was rejected: %v", err)
	}
}

func TestBuildRefundPresignRequestRequiresPoolAtOutputZero(t *testing.T) {
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 1, LockingScript: script.NewFromBytes([]byte{0x51})})
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyer.PubKey().Compressed(), SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewBuyerPoolAdapter(engine, mustSigner(t, buyer)).BuildRefundPresignRequest(ctx, OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 500000100, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err == nil {
		t.Fatal("pool output at index 1 was accepted")
	}
}

func TestMultisigPoolV4NormalAndArbitrationDetachedSignatures(t *testing.T) {
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyer.PubKey().Compressed(), SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	buyerPool := NewBuyerPoolAdapter(engine, mustSigner(t, buyer))
	sellerPool := NewSellerPoolAdapter(engine, mustSigner(t, seller))
	arbiterPool := NewArbiterPoolAdapter(engine, mustSigner(t, arbiter))
	request, err := buyerPool.BuildRefundPresignRequest(ctx, OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 500, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := sellerPool.SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(request, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	refund, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(refund, proof)
	if err != nil {
		t.Fatal(err)
	}
	if previous.PaymentSequence != 2 || previous.ArbiterAmountSatoshis != 0 {
		t.Fatalf("opening state = %+v", previous)
	}
	unsigned, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: 3, SellerAmountAfterSatoshis: 1000})
	if err != nil {
		t.Fatal(err)
	}
	buyerSignature, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsigned.RawTx, mustRawUnsigned(t, unsigned)) {
		t.Fatal("buyer signing changed unsigned transaction")
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSignature, proof); err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sellerPool.MergeBuyerSellerPayment(unsigned, buyerSignature, sellerSignature, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(&accepted.State, proof); err != nil {
		t.Fatal(err)
	}
	parsedAccepted, err := engine.ParsePaymentState(accepted.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedAccepted.BuyerTransactionSignature) == 0 || len(parsedAccepted.SellerTransactionSignature) == 0 || len(parsedAccepted.ArbiterTransactionSignature) != 0 {
		t.Fatalf("normal signature metadata = %+v", parsedAccepted)
	}
	accepted.State.RawTx = append([]byte(nil), accepted.RawTx...)
	finalUnsigned, err := engine.BuildImmediateClose(CloseInput{Opening: proof, Base: &accepted.State, SellerAmountAfterSatoshis: accepted.State.SellerAmountSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SignArbitrationSellerPayment(ctx, finalUnsigned, mustSigner(t, seller)); err == nil {
		t.Fatal("seller arbitration signer accepted final sequence")
	}
	if _, err := arbiterPool.SignArbiterPayment(ctx, finalUnsigned, proof); err == nil {
		t.Fatal("arbiter signer accepted final sequence")
	}
	if _, err := engine.SignArbitrationArbiterPayment(ctx, finalUnsigned, mustSigner(t, arbiter)); err == nil {
		t.Fatal("arbitration arbiter signer accepted final sequence")
	}
	if _, err := engine.MergeArbitratedPoolSellerArbiterSignatures(finalUnsigned, nil, nil); err == nil {
		t.Fatal("arbitration merge accepted final sequence")
	}

	details, err := DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationUnsigned, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, 2000, 500)
	if err != nil {
		t.Fatal(err)
	}
	arbitrationSellerSig, err := engine.SignArbitrationSellerPayment(ctx, arbitrationUnsigned, mustSigner(t, seller))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitrationSellerPayment(arbitrationUnsigned, arbitrationSellerSig); err != nil {
		t.Fatal(err)
	}
	arbitrationArbiterSig, err := engine.SignArbitrationArbiterPayment(ctx, arbitrationUnsigned, mustSigner(t, arbiter))
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := engine.MergeArbitratedPoolSellerArbiterSignatures(arbitrationUnsigned, arbitrationSellerSig, arbitrationArbiterSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&arbitrated.State, proof); err != nil {
		t.Fatal(err)
	}
	// 普通 005 验证器必须继续拒绝带非零仲裁金额的状态：只有 007 路径接受付费输出。
	if err := engine.VerifyAcceptedPayment(&arbitrated.State, proof); err == nil {
		t.Fatal("normal 005 verifier accepted an arbitrated state with a non-zero arbiter amount")
	}
	parsedArbitrated, err := engine.ParsePaymentState(arbitrated.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedArbitrated.BuyerTransactionSignature) != 0 || len(parsedArbitrated.SellerTransactionSignature) == 0 || len(parsedArbitrated.ArbiterTransactionSignature) == 0 {
		t.Fatalf("arbitrated signature metadata = %+v", parsedArbitrated)
	}
	for _, amount := range []uint64{0, 1000, 2000, previous.BuyerAmountSatoshis} {
		normal, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: 3, SellerAmountAfterSatoshis: amount})
		if err != nil {
			t.Fatalf("normal candidate amount %d: %v", amount, err)
		}
		if normal.ArbiterAmountSatoshis != 0 {
			t.Fatalf("normal 005 candidate at amount %d carried a non-zero arbiter amount", amount)
		}
		parsedNormal, err := tx.NewTransactionFromBytes(normal.RawTx)
		if err != nil {
			t.Fatal(err)
		}
		if parsedNormal.Outputs[2].Satoshis != 0 {
			t.Fatalf("normal 005 raw output[2] = %d at amount %d, want zero", parsedNormal.Outputs[2].Satoshis, amount)
		}
	}
	tamperedOutpoint := *arbitrationUnsigned
	tamperedTx, err := tx.NewTransactionFromBytes(tamperedOutpoint.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	tamperedID := append([]byte(nil), tamperedTx.Inputs[0].SourceTXID.CloneBytes()...)
	tamperedID[0] ^= 1
	tamperedTx.Inputs[0].SourceTXID, err = chainhash.NewHash(tamperedID)
	if err != nil {
		t.Fatal(err)
	}
	tamperedOutpoint.RawTx = tamperedTx.Bytes()
	if _, err := engine.SignArbitrationSellerPayment(ctx, &tamperedOutpoint, mustSigner(t, seller)); err == nil {
		t.Fatal("arbitration signer accepted a changed funding outpoint")
	}
	tamperedScript := *arbitrationUnsigned
	tamperedScriptTx, err := tx.NewTransactionFromBytes(tamperedScript.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	tamperedScriptTx.Outputs[0].LockingScript = script.NewFromBytes([]byte{script.Op1})
	tamperedScript.RawTx = tamperedScriptTx.Bytes()
	if _, err := engine.SignArbitrationSellerPayment(ctx, &tamperedScript, mustSigner(t, seller)); err == nil {
		t.Fatal("arbitration signer accepted a changed role output script")
	}
	tamperedLockTime := *arbitrationUnsigned
	tamperedLockTimeTx, err := tx.NewTransactionFromBytes(tamperedLockTime.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	tamperedLockTimeTx.LockTime++
	tamperedLockTime.RawTx = tamperedLockTimeTx.Bytes()
	if _, err := engine.SignArbitrationSellerPayment(ctx, &tamperedLockTime, mustSigner(t, seller)); err == nil {
		t.Fatal("arbitration signer accepted a changed locktime")
	}
	tamperedMetadata := *arbitrationUnsigned
	tamperedMetadata.SellerAmountSatoshis++
	if _, err := engine.SignArbitrationSellerPayment(ctx, &tamperedMetadata, mustSigner(t, seller)); err == nil {
		t.Fatal("arbitration signer accepted changed candidate metadata")
	}
	zeroSourceTx, err := tx.NewTransactionFromBytes(proof.RefundTemplateRaw)
	if err != nil {
		t.Fatal(err)
	}
	zeroSource, err := chainhash.NewHash(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	zeroSourceTx.Inputs[0].SourceTXID = zeroSource
	if _, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, zeroSourceTx.Bytes(), 3, 2000, 500); err == nil {
		t.Fatal("arbitration builder accepted an all-zero funding txid")
	}
	malformed, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Outputs = malformed.Outputs[:1]
	malformedUnsigned := *arbitrationUnsigned
	malformedUnsigned.RawTx = malformed.Bytes()
	if err := engine.VerifyBuyerPayment(&malformedUnsigned, buyerSignature, proof); err == nil {
		t.Fatal("malformed detached verification unexpectedly succeeded")
	}
	assertMergeRejectsWithoutPanic(t, func() error {
		_, err := sellerPool.MergeBuyerSellerPayment(&malformedUnsigned, buyerSignature, sellerSignature, proof)
		return err
	})
	assertMergeRejectsWithoutPanic(t, func() error {
		_, err := engine.MergeArbitratedPoolSellerArbiterSignatures(&malformedUnsigned, arbitrationSellerSig, arbitrationArbiterSig)
		return err
	})
}

func assertMergeRejectsWithoutPanic(t *testing.T, call func() error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("proof-bound merge panicked: %v", recovered)
		}
	}()
	if err := call(); err == nil {
		t.Fatal("malformed proof-bound merge unexpectedly succeeded")
	}
}

func callWithoutPanic(call func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("unexpected panic: %v", recovered)
		}
	}()
	return call()
}

func mustUnsignedPaymentFixture(t *testing.T) (*MultisigPoolEngine, *OpeningProof, *UnsignedPayment, *ec.PrivateKey, *ec.PrivateKey, *ec.PrivateKey) {
	t.Helper()
	engine, proof := mustRefundExpiryFixture(t, 500)
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: previous.PaymentSequence + 1, SellerAmountAfterSatoshis: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return engine, proof, unsigned, mustPoolTestKey(t, "11"), mustPoolTestKey(t, "22"), mustPoolTestKey(t, "33")
}

func TestExportedPoolAPIsRejectProofBoundAdversaries(t *testing.T) {
	ctx := context.Background()
	engine, proof, unsigned, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	buyerSigner := mustSigner(t, buyer)
	sellerSigner := mustSigner(t, seller)
	arbiterSigner := mustSigner(t, arbiter)
	buyerPool := NewBuyerPoolAdapter(engine, buyerSigner)
	sellerPool := NewSellerPoolAdapter(engine, sellerSigner)
	arbiterPool := NewArbiterPoolAdapter(engine, arbiterSigner)
	buyerSignature, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSignature, err := arbiterPool.SignArbiterPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	badMetadata := *unsigned
	badMetadata.SellerAmountSatoshis++
	badRaw := append([]byte(nil), unsigned.RawTx...)
	badMetadata.RawTx = badRaw
	cases := []struct {
		name   string
		call   func() error
		signer protocol.Signer
	}{
		{"sign buyer", func() error { _, e := buyerPool.SignBuyerPayment(ctx, &badMetadata, proof); return e }, buyerSigner},
		{"sign seller", func() error { _, e := sellerPool.SignSellerPayment(ctx, &badMetadata, proof); return e }, sellerSigner},
		{"sign seller arbitration", func() error { _, e := engine.SignArbitrationSellerPayment(ctx, &badMetadata, sellerSigner); return e }, sellerSigner},
		{"sign arbiter", func() error { _, e := arbiterPool.SignArbiterPayment(ctx, &badMetadata, proof); return e }, arbiterSigner},
		{"verify buyer", func() error { return engine.VerifyBuyerPayment(&badMetadata, buyerSignature, proof) }, nil},
		{"verify seller", func() error { return engine.VerifySellerPayment(&badMetadata, sellerSignature, proof) }, nil},
		{"verify arbiter", func() error { return engine.VerifyArbiterPayment(&badMetadata, arbiterSignature, proof) }, nil},
		{"merge buyer seller", func() error {
			_, e := engine.MergeBuyerSellerPayment(&badMetadata, buyerSignature, sellerSignature, proof)
			return e
		}, nil},
		{"merge seller arbiter", func() error {
			_, e := engine.MergeSellerArbiterPayment(&badMetadata, sellerSignature, sellerSignature, proof)
			return e
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertMergeRejectsWithoutPanic(t, tc.call)
		})
	}
	nilProofCases := []struct {
		name   string
		call   func() error
		signer protocol.Signer
	}{
		{"sign buyer nil proof", func() error { _, e := buyerPool.SignBuyerPayment(ctx, unsigned, nil); return e }, buyerSigner},
		{"sign seller nil proof", func() error { _, e := sellerPool.SignSellerPayment(ctx, unsigned, nil); return e }, sellerSigner},
		{"sign arbitration seller nil key", func() error { _, e := engine.SignArbitrationSellerPayment(ctx, unsigned, nil); return e }, sellerSigner},
		{"sign arbiter nil proof", func() error { _, e := arbiterPool.SignArbiterPayment(ctx, unsigned, nil); return e }, arbiterSigner},
		{"verify buyer nil proof", func() error { return engine.VerifyBuyerPayment(unsigned, buyerSignature, nil) }, nil},
		{"verify seller nil proof", func() error { return engine.VerifySellerPayment(unsigned, sellerSignature, nil) }, nil},
		{"verify arbiter nil proof", func() error { return engine.VerifyArbiterPayment(unsigned, arbiterSignature, nil) }, nil},
		{"merge normal nil proof", func() error {
			_, e := engine.MergeBuyerSellerPayment(unsigned, buyerSignature, sellerSignature, nil)
			return e
		}, nil},
		{"merge arbitration nil proof", func() error {
			_, e := engine.MergeSellerArbiterPayment(unsigned, sellerSignature, arbiterSignature, nil)
			return e
		}, nil},
	}
	for _, tc := range nilProofCases {
		t.Run(tc.name, func(t *testing.T) {
			assertMergeRejectsWithoutPanic(t, tc.call)
		})
	}
	wrong := *unsigned
	value, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	wrongID := append([]byte(nil), value.Inputs[0].SourceTXID.CloneBytes()...)
	wrongID[0] ^= 1
	value.Inputs[0].SourceTXID, err = chainhash.NewHash(wrongID)
	if err != nil {
		t.Fatal(err)
	}
	wrong.RawTx = value.Bytes()
	if err := engine.VerifyBuyerPayment(&wrong, buyerSignature, proof); err == nil {
		t.Fatal("wrong outpoint was accepted")
	}
}

func TestArbitrationFinalSequenceRejectsBeforeSigner(t *testing.T) {
	ctx := context.Background()
	engine, proof, unsigned, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	_ = unsigned
	_ = seller
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	acceptedUnsigned, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: 3, SellerAmountAfterSatoshis: 1000})
	if err != nil {
		t.Fatal(err)
	}
	acceptedSeller, err := NewSellerPoolAdapter(engine, mustSigner(t, seller)).SignSellerPayment(ctx, acceptedUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	acceptedBuyer, err := NewBuyerPoolAdapter(engine, mustSigner(t, buyer)).SignBuyerPayment(ctx, acceptedUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.MergeBuyerSellerPayment(acceptedUnsigned, acceptedBuyer, acceptedSeller, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted.State.RawTx = accepted.RawTx
	finalUnsigned, err := engine.BuildImmediateClose(CloseInput{Opening: proof, Base: &accepted.State, SellerAmountAfterSatoshis: accepted.State.SellerAmountSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewArbiterPoolAdapter(engine, mustSigner(t, arbiter)).SignArbiterPayment(ctx, finalUnsigned, proof); err == nil {
		t.Fatal("final arbiter payment was accepted")
	}
}

func TestExportedPoolAdaptersRejectNilReceiversWithoutPanic(t *testing.T) {
	ctx := context.Background()
	var input OpeningInput
	checks := []struct {
		name string
		call func() error
	}{
		{"build refund", func() error { _, err := (*BuyerPoolAdapter)(nil).BuildRefundPresignRequest(ctx, input); return err }},
		{"verify buyer", func() error { return (*SellerPoolAdapter)(nil).VerifyBuyerPayment(nil, nil, nil) }},
		{"verify seller", func() error { return (*SellerPoolAdapter)(nil).VerifySellerPayment(nil, nil, nil) }},
		{"merge buyer seller", func() error {
			_, err := (*SellerPoolAdapter)(nil).MergeBuyerSellerPayment(nil, nil, nil, nil)
			return err
		}},
		{"merge seller arbiter", func() error {
			_, err := (*SellerPoolAdapter)(nil).MergeSellerArbiterPayment(nil, nil, nil, nil)
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("nil receiver panicked: %v", recovered)
				}
			}()
			if err := check.call(); err == nil {
				t.Fatal("nil receiver unexpectedly succeeded")
			}
		})
	}
}

func TestEveryExportedPaymentEntryRejectsWrongOutpointAndMalformedProof(t *testing.T) {
	ctx := context.Background()
	engine, proof, unsigned, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	buyerSigner := mustSigner(t, buyer)
	sellerSigner := mustSigner(t, seller)
	arbiterSigner := mustSigner(t, arbiter)
	buyerPool := NewBuyerPoolAdapter(engine, buyerSigner)
	sellerPool := NewSellerPoolAdapter(engine, sellerSigner)
	arbiterPool := NewArbiterPoolAdapter(engine, arbiterSigner)
	buyerSignature, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSignature, err := arbiterPool.SignArbiterPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	wrong := *unsigned
	value, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	wrongID := append([]byte(nil), value.Inputs[0].SourceTXID.CloneBytes()...)
	wrongID[0] ^= 1
	value.Inputs[0].SourceTXID, err = chainhash.NewHash(wrongID)
	if err != nil {
		t.Fatal(err)
	}
	wrong.RawTx = value.Bytes()
	cases := []struct {
		name   string
		call   func(*UnsignedPayment, *OpeningProof) error
		signer protocol.Signer
	}{
		{"buyer sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := buyerPool.SignBuyerPayment(ctx, u, p)
			return e
		}, buyerSigner},
		{"seller sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := sellerPool.SignSellerPayment(ctx, u, p)
			return e
		}, sellerSigner},
		{"arbiter sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := arbiterPool.SignArbiterPayment(ctx, u, p)
			return e
		}, arbiterSigner},
		{"buyer verify", func(u *UnsignedPayment, p *OpeningProof) error {
			return engine.VerifyBuyerPayment(u, buyerSignature, p)
		}, nil},
		{"seller verify", func(u *UnsignedPayment, p *OpeningProof) error {
			return engine.VerifySellerPayment(u, sellerSignature, p)
		}, nil},
		{"arbiter verify", func(u *UnsignedPayment, p *OpeningProof) error {
			return engine.VerifyArbiterPayment(u, arbiterSignature, p)
		}, nil},
		{"buyer seller merge", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := engine.MergeBuyerSellerPayment(u, buyerSignature, sellerSignature, p)
			return e
		}, nil},
		{"seller arbiter merge", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := engine.MergeSellerArbiterPayment(u, sellerSignature, arbiterSignature, p)
			return e
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name+" wrong outpoint", func(t *testing.T) {
			if err := callWithoutPanic(func() error { return tc.call(&wrong, proof) }); err == nil {
				t.Fatal("wrong outpoint unexpectedly accepted")
			}
		})
		t.Run(tc.name+" malformed proof", func(t *testing.T) {
			badProof := CloneOpeningProof(proof)
			badProof.RefundTemplateRaw = []byte{1, 2, 3}
			if err := callWithoutPanic(func() error { return tc.call(unsigned, badProof) }); err == nil {
				t.Fatal("malformed proof unexpectedly accepted")
			}
		})
	}
}

func TestEveryArbitrationEntryRejectsFinalSequenceBeforeSignerOrMerge(t *testing.T) {
	ctx := context.Background()
	engine, proof, _, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.ParsePaymentState(initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(CloseInput{Opening: proof, Base: initial, SellerAmountAfterSatoshis: initial.SellerAmountSatoshis})
	if err != nil {
		t.Fatal(err)
	}
	sellerSigner := mustSigner(t, seller)
	arbiterSigner := mustSigner(t, arbiter)
	checks := []struct {
		name string
		call func() error
	}{
		{"seller arbitration signer", func() error {
			_, e := engine.SignArbitrationSellerPayment(ctx, unsigned, sellerSigner)
			return e
		}},
		{"arbiter payment signer", func() error {
			_, e := NewArbiterPoolAdapter(engine, arbiterSigner).SignArbiterPayment(ctx, unsigned, proof)
			return e
		}},
		{"arbiter candidate signer", func() error {
			_, e := engine.SignArbitrationArbiterPayment(ctx, unsigned, arbiterSigner)
			return e
		}},
		{"arbiter payment verifier", func() error { return engine.VerifyArbiterPayment(unsigned, nil, proof) }},
		{"arbiter candidate verifier", func() error { return engine.VerifyArbitrationArbiterPayment(unsigned, nil) }},
		{"seller arbiter merge", func() error { _, e := engine.MergeSellerArbiterPayment(unsigned, nil, nil, proof); return e }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := callWithoutPanic(check.call); err == nil {
				t.Fatal("final sequence unexpectedly accepted")
			}
		})
	}
	_ = buyer
}

func TestBuildPaymentUpdateRejectsSkipOutpointAndMetadataTampering(t *testing.T) {
	engine, proof, _, _, _, _ := mustUnsignedPaymentFixture(t)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: previous.PaymentSequence + 2, SellerAmountAfterSatoshis: 1000}); err == nil {
		t.Fatal("skip-sequence payment update was accepted")
	}
	wrongPrevious := *previous
	wrongPrevious.RawTx = append([]byte(nil), previous.RawTx...)
	value, err := tx.NewTransactionFromBytes(wrongPrevious.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	wrongID := append([]byte(nil), value.Inputs[0].SourceTXID.CloneBytes()...)
	wrongID[0] ^= 1
	value.Inputs[0].SourceTXID, err = chainhash.NewHash(wrongID)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrevious.RawTx = value.Bytes()
	if _, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: &wrongPrevious, PaymentSequence: previous.PaymentSequence + 1, SellerAmountAfterSatoshis: 1000}); err == nil {
		t.Fatal("wrong previous outpoint was accepted")
	}
	forged := *previous
	forged.SellerAmountSatoshis++
	if _, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: &forged, PaymentSequence: previous.PaymentSequence + 1, SellerAmountAfterSatoshis: 1000}); err == nil {
		t.Fatal("forged previous metadata was accepted")
	}
}

// Deterministic-rebuild regression: the same explicit inputs must always
// rebuild byte-identical unsigned payment state transactions (this is the
// interoperability premise that lets 005 omit the raw transaction), while any
// different opening, previous, sequence, or amount yields different bytes or
// a hard failure.
func TestBuildPaymentUpdateIsDeterministicAndContextBound(t *testing.T) {
	engine, proof, _, _, _, _ := mustUnsignedPaymentFixture(t)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	input := PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: previous.PaymentSequence + 1, SellerAmountAfterSatoshis: 1000}
	first, err := engine.BuildPaymentUpdate(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.BuildPaymentUpdate(ClonePaymentUpdateInput(input))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.RawTx, second.RawTx) {
		t.Fatal("identical inputs rebuilt different payment state transactions")
	}
	differentAmount, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: previous.PaymentSequence + 1, SellerAmountAfterSatoshis: 1001})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.RawTx, differentAmount.RawTx) {
		t.Fatal("different seller amounts rebuilt identical transactions")
	}
	if _, err := engine.BuildPaymentUpdate(PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequence: previous.PaymentSequence + 2, SellerAmountAfterSatoshis: 1000}); err == nil {
		t.Fatal("skip-sequence rebuild was accepted")
	}
}

func mustRawUnsigned(t *testing.T, unsigned *UnsignedPayment) []byte {
	t.Helper()
	value, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	return value.Bytes()
}

func mustPoolTestKey(t *testing.T, hexByte string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(hexByte), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVerifyRefundExpiredAtUsesExplicitTimeAndHeightFacts(t *testing.T) {
	// 显式事实：时间与高度都由调用方传入，SDK 不读系统时钟。
	fixedTime := time.Unix(1_700_000_000, 0).UTC()
	blockHeight := uint32(900_000)

	// height lock（locktime < 500_000_000）：时间是任意值，高度才是判定依据。
	engine, heightProof := mustRefundExpiryFixture(t, 1_000_000)
	if err := engine.VerifyRefundExpiredAt(heightProof, fixedTime, blockHeight-1); !protocol.IsCode(err, protocol.CodeNotMatured) {
		t.Fatalf("height refund before block maturity = %v, want CodeNotMatured", err)
	}
	heightProof = mustRefundExpiryProof(t, 900_000)
	if err := engine.VerifyRefundExpiredAt(heightProof, fixedTime, blockHeight); err != nil {
		t.Fatalf("height refund at block maturity = %v, want success", err)
	}

	// timestamp lock（locktime >= 500_000_000）：高度是任意值，时间是判定依据。
	pastLock := uint32(1_700_000_000 - 3600)
	engine, pastProof := mustRefundExpiryFixture(t, pastLock)
	if err := engine.VerifyRefundExpiredAt(pastProof, fixedTime, blockHeight); err != nil {
		t.Fatalf("expired timestamp refund = %v, want success", err)
	}
	futureLock := uint32(1_700_000_000 + 3600)
	_, futureProof := mustRefundExpiryFixture(t, futureLock)
	if err := engine.VerifyRefundExpiredAt(futureProof, fixedTime, blockHeight); !protocol.IsCode(err, protocol.CodeNotMatured) {
		t.Fatalf("future timestamp refund = %v, want CodeNotMatured", err)
	}
}

func mustRefundExpiryFixture(t *testing.T, lockTime uint32) (*MultisigPoolEngine, *OpeningProof) {
	t.Helper()
	return mustRefundExpiryFixtureWithKeys(t, lockTime)
}

func mustRefundExpiryProof(t *testing.T, lockTime uint32) *OpeningProof {
	t.Helper()
	_, proof := mustRefundExpiryFixtureWithKeys(t, lockTime)
	return proof
}

func mustRefundExpiryFixtureWithKeys(t *testing.T, lockTime uint32) (*MultisigPoolEngine, *OpeningProof) {
	t.Helper()
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 100000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyer.PubKey().Compressed(), SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	buyerPool := NewBuyerPoolAdapter(engine, mustSigner(t, buyer))
	sellerPool := NewSellerPoolAdapter(engine, mustSigner(t, seller))
	request, err := buyerPool.BuildRefundPresignRequest(ctx, OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: lockTime, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := sellerPool.SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(request, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	return engine, proof
}

func TestBuildImmediateCloseAllowsBelowBaseTargetButRejectsOverCapacity(t *testing.T) {
	engine, proof, unsigned, _, _, _ := mustUnsignedPaymentFixture(t)
	details, err := DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	baseRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	base, err := engine.ParsePaymentState(baseRaw, proof)
	if err != nil {
		t.Fatal(err)
	}

	// 目标金额低于基准 Seller 金额是业务决定，SDK 只受容量约束。
	if _, err := engine.BuildImmediateClose(CloseInput{Opening: proof, Base: base, SellerAmountAfterSatoshis: 1}); err != nil {
		t.Fatalf("below-base target rejected by protocol boundary: %v", err)
	}

	// 超过池容量必须拒绝。
	if _, err := engine.BuildImmediateClose(CloseInput{Opening: proof, Base: base, SellerAmountAfterSatoshis: details.PoolOutputSatoshis + 1}); err == nil {
		t.Fatal("over-capacity immediate close was accepted")
	}
	_ = unsigned
}

func mustPoolTermsTxID(t *testing.T, proof *OpeningProof) []byte {
	t.Helper()
	details, err := DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), details.RefundTemplateTxID[:]...)
}

// mustPaidArbitrationFixture builds the canonical paid 007 fixture: a large
// pool opening plus its derived Claim context, so positive-fee boundaries have
// room to maneuver. The returned spendable value is the pool balance after the
// refund-template miner fee.
func mustPaidArbitrationFixture(t *testing.T) (*MultisigPoolEngine, *OpeningProof, *OpeningDetails, uint64) {
	t.Helper()
	ctx := context.Background()
	buyer := mustPoolTestKey(t, "11")
	seller := mustPoolTestKey(t, "22")
	arbiter := mustPoolTestKey(t, "33")
	roles := mp.ArbitratedPoolRoles{Buyer: buyer.PubKey(), Seller: seller.PubKey(), Arbiter: arbiter.PubKey()}
	lock, err := mp.BuildArbitratedPoolLock(roles)
	if err != nil {
		t.Fatal(err)
	}
	funding := tx.NewTransaction()
	funding.AddOutput(&tx.TransactionOutput{Satoshis: 10_000_000, LockingScript: lock})
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPublicKey: buyer.PubKey().Compressed(), SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewBuyerPoolAdapter(engine, mustSigner(t, buyer)).BuildRefundPresignRequest(ctx, OpeningInput{FundingTransactionRaw: funding.Bytes(), ExpiryLockTime: 500000100, MinerFeeRateSatoshisPerKilobyte: 1, SellerPublicKey: seller.PubKey().Compressed(), ArbiterPublicKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := NewSellerPoolAdapter(engine, mustSigner(t, seller)).SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := engine.BuildOpeningProof(request, sellerRefund, funding.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	details, err := DeriveOpeningDetails(proof)
	if err != nil {
		t.Fatal(err)
	}
	refund, err := parseCanonicalTransaction(proof.RefundTemplateRaw)
	if err != nil {
		t.Fatal(err)
	}
	refundOutputs := refund.Outputs[0].Satoshis + refund.Outputs[1].Satoshis + refund.Outputs[2].Satoshis
	// spendable = pool - refund_fee = pool - (pool - refundOutputs) = refundOutputs.
	return engine, proof, details, refundOutputs
}

func TestBuildArbitrationPaymentFromClaimPositiveFeeBoundaries(t *testing.T) {
	_, proof, details, spendable := mustPaidArbitrationFixture(t)
	sellerAmount := uint64(2000)

	zeroFee := func() error {
		_, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, 0)
		return err
	}
	if zeroFee() == nil {
		t.Fatal("zero arbiter fee was accepted by the success builder")
	}

	oneSat, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, 1)
	if err != nil {
		t.Fatalf("one-sat fee candidate rejected: %v", err)
	}
	rawOne, err := tx.NewTransactionFromBytes(oneSat.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if rawOne.Outputs[2].Satoshis != 1 || oneSat.ArbiterAmountSatoshis != 1 {
		t.Fatalf("one-sat fee metadata mismatch: metadata %d raw %d", oneSat.ArbiterAmountSatoshis, rawOne.Outputs[2].Satoshis)
	}
	if rawOne.Outputs[1].Satoshis != sellerAmount || oneSat.SellerAmountSatoshis != sellerAmount {
		t.Fatalf("seller output drifted from Buyer-authorized amount: %d", rawOne.Outputs[1].Satoshis)
	}
	if oneSat.BuyerAmountSatoshis != spendable-sellerAmount-1 || rawOne.Outputs[0].Satoshis != spendable-sellerAmount-1 {
		t.Fatalf("buyer remainder = %d, want %d", oneSat.BuyerAmountSatoshis, spendable-sellerAmount-1)
	}
	if oneSat.BuyerAmountSatoshis+oneSat.SellerAmountSatoshis+oneSat.ArbiterAmountSatoshis+(details.PoolOutputSatoshis-spendable) != details.PoolOutputSatoshis {
		t.Fatal("buyer + seller + arbiter + refund fee did not conserve the pool output")
	}

	// 恰好耗尽 Buyer 余额是合法边界：Buyer 输出为零但三个输出仍然存在。
	maxFee := spendable - sellerAmount
	exhausted, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, maxFee)
	if err != nil {
		t.Fatalf("exactly-exhausting fee rejected: %v", err)
	}
	rawExhausted, err := tx.NewTransactionFromBytes(exhausted.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	if exhausted.BuyerAmountSatoshis != 0 || rawExhausted.Outputs[0].Satoshis != 0 || len(rawExhausted.Outputs) != 3 {
		t.Fatalf("exhausted buyer output = %d over %d outputs", exhausted.BuyerAmountSatoshis, len(rawExhausted.Outputs))
	}

	overByOne, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, maxFee+1)
	if !protocol.IsCode(err, protocol.CodeInsufficientBalance) || overByOne != nil {
		t.Fatalf("fee exceeding balance by one sat = %v, want CodeInsufficientBalance", err)
	}
	_, hugeFeeErr := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, ^uint64(0))
	if !protocol.IsCode(hugeFeeErr, protocol.CodeInsufficientBalance) {
		t.Fatalf("oversized fee error = %v, want CodeInsufficientBalance", hugeFeeErr)
	}
	// Seller 金额本身超过可花费余额时，无论费用多少都拒绝，不得削减修复。
	_, overSeller := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, spendable+1, 1)
	if !protocol.IsCode(overSeller, protocol.CodeInsufficientBalance) {
		t.Fatalf("seller amount beyond spendable error = %v, want CodeInsufficientBalance", overSeller)
	}
}

func TestArbitrationSignaturesBindThirdOutputAmount(t *testing.T) {
	ctx := context.Background()
	engine, proof, details, _ := mustPaidArbitrationFixture(t)
	sellerAmount := uint64(2000)
	fee := uint64(500)

	unsigned, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, fee)
	if err != nil {
		t.Fatal(err)
	}
	sellerSignature, err := engine.SignArbitrationSellerPayment(ctx, unsigned, mustSigner(t, mustPoolTestKey(t, "22")))
	if err != nil {
		t.Fatal(err)
	}
	arbiterSignature, err := engine.SignArbitrationArbiterPayment(ctx, unsigned, mustSigner(t, mustPoolTestKey(t, "33")))
	if err != nil {
		t.Fatal(err)
	}

	for _, driftedFee := range []uint64{fee + 1, fee - 1} {
		shifted, err := BuildArbitrationPaymentFromClaim(details.PoolOutputSatoshis, details.PoolLockingScript, proof.RefundTemplateRaw, 3, sellerAmount, driftedFee)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(shifted.RawTx, unsigned.RawTx) {
			t.Fatalf("fee drift to %d produced identical candidate bytes", driftedFee)
		}
		if err := engine.VerifyArbitrationSellerPayment(shifted, sellerSignature); err == nil {
			t.Fatalf("Seller signature survived a third-output change to %d sats", driftedFee)
		}
		if err := engine.VerifyArbitrationArbiterPayment(shifted, arbiterSignature); err == nil {
			t.Fatalf("Arbiter signature survived a third-output change to %d sats", driftedFee)
		}
	}

	// 直接篡改 raw 第三输出金额同样必须被拒绝。
	tamperedRaw := *unsigned
	tamperedValue, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	tamperedValue.Outputs[2].Satoshis += 1
	tamperedRaw.RawTx = tamperedValue.Bytes()
	if _, err := engine.SignArbitrationArbiterPayment(ctx, &tamperedRaw, mustSigner(t, mustPoolTestKey(t, "33"))); err == nil {
		t.Fatal("signer accepted a raw transaction whose third output was tampered")
	}

	// 元数据与 raw 不一致（错误第三输出金额）必须被拒绝。
	badMetadata := *unsigned
	badMetadata.ArbiterAmountSatoshis++
	if _, err := engine.SignArbitrationSellerPayment(ctx, &badMetadata, mustSigner(t, mustPoolTestKey(t, "22"))); err == nil {
		t.Fatal("signer accepted changed third-output metadata")
	}
}
