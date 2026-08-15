package pool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tx "github.com/bsv-blockchain/go-sdk/transaction"
	mp "github.com/bsv8/MultisigPool/v4/pkg"
	"github.com/bsv8/go-bitfs/bitfs"
)

type testSigner struct{ key *ec.PrivateKey }

func (provider testSigner) PublicKey(context.Context) ([]byte, error) {
	return provider.key.PubKey().Compressed(), nil
}

type malformedSigner struct {
	pub []byte
	sig []byte
}

type countingPoolSigner struct {
	key   *ec.PrivateKey
	signs int
}

func (s *countingPoolSigner) PublicKey(context.Context) ([]byte, error) {
	return s.key.PubKey().Compressed(), nil
}
func (s *countingPoolSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	s.signs++
	sig, err := s.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func (s malformedSigner) PublicKey(context.Context) ([]byte, error)    { return s.pub, nil }
func (s malformedSigner) Sign(context.Context, []byte) ([]byte, error) { return s.sig, nil }

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
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: buyer.PubKey().Compressed(), SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	input := OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500000100, MinerFeeRateSatPerKB: 1, SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()}
	if _, err := NewBuyerPoolAdapter(engine, testSigner{seller}).BuildRefundPresignRequest(ctx, input); err == nil {
		t.Fatal("wrong role signer was accepted")
	}
	if _, err := NewBuyerPoolAdapter(engine, malformedSigner{pub: buyer.PubKey().Compressed(), sig: []byte{1, 2, 3}}).BuildRefundPresignRequest(ctx, input); err == nil {
		t.Fatal("malformed DER signer was accepted")
	}
	other := mustPoolTestKey(t, "44")
	if _, err := NewBuyerPoolAdapter(engine, malformedSigner{pub: buyer.PubKey().Compressed(), sig: func() []byte { s, _ := other.Sign(make([]byte, 32)); return s.Serialize() }()}).BuildRefundPresignRequest(ctx, input); err == nil {
		t.Fatal("cryptographically invalid signer output was accepted")
	}
}
func (provider testSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	sig, err := provider.key.Sign(digest)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
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
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: buyer.PubKey().Compressed(), SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	buyerPool := NewBuyerPoolAdapter(engine, testSigner{buyer})
	sellerPool := NewSellerPoolAdapter(engine, testSigner{seller})
	arbiterPool := NewArbiterPoolAdapter(engine, testSigner{arbiter})
	request, err := buyerPool.BuildRefundPresignRequest(ctx, OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: 500, MinerFeeRateSatPerKB: 1, SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := sellerPool.SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	spend, err := engine.TransactionID(request.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion, RefundTx: request.RefundTx, SpendTxID: spend[:], FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: 0, PoolOutputSatoshis: 100000, PoolLockingScript: request.PoolLockingScript, BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey, MinerFeeRateSatPerKB: 1, BuyerRefundSignature: request.BuyerRefundSignature, SellerRefundSignature: sellerRefund, FundingTx: funding.Bytes()}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	refund, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, refund, proof)
	if err != nil {
		t.Fatal(err)
	}
	if previous.PaymentSequence != 2 || previous.ArbiterAmountSat != 0 {
		t.Fatalf("opening state = %+v", previous)
	}
	unsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 3, SellerAmountAfterSat: 1000})
	if err != nil {
		t.Fatal(err)
	}
	buyerSig, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsigned.RawTx, mustRawUnsigned(t, unsigned)) {
		t.Fatal("buyer signing changed unsigned transaction")
	}
	if err := engine.VerifyBuyerPayment(unsigned, buyerSig, proof); err != nil {
		t.Fatal(err)
	}
	sellerSig, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sellerPool.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyAcceptedPayment(&accepted.State, proof); err != nil {
		t.Fatal(err)
	}
	parsedAccepted, err := engine.ParsePaymentState(ctx, accepted.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedAccepted.BuyerTransactionSignature) == 0 || len(parsedAccepted.SellerTransactionSignature) == 0 || len(parsedAccepted.ArbiterTransactionSignature) != 0 {
		t.Fatalf("normal signature metadata = %+v", parsedAccepted)
	}
	accepted.State.RawTx = append([]byte(nil), accepted.RawTx...)
	finalUnsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: &accepted.State, SellerAmountAfterSat: accepted.State.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sellerPool.SignSellerArbitrationCandidate(ctx, finalUnsigned, proof); err == nil {
		t.Fatal("seller arbitration signer accepted final sequence")
	}
	if _, err := arbiterPool.SignArbiterPayment(ctx, finalUnsigned, proof); err == nil {
		t.Fatal("arbiter signer accepted final sequence")
	}
	if _, err := adapterForArbitration(engine, arbiter).SignArbitrationCandidate(ctx, finalUnsigned.RawTx, proof); err == nil {
		t.Fatal("arbitration adapter accepted final sequence")
	}
	if _, err := sellerPool.MergeSellerArbiterPayment(finalUnsigned, nil, nil, proof); err == nil {
		t.Fatal("arbitration merge accepted final sequence")
	}

	arbitrationUnsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 3, SellerAmountAfterSat: 2000})
	if err != nil {
		t.Fatal(err)
	}
	arbitrationSellerSig, err := sellerPool.SignSellerArbitrationCandidate(ctx, arbitrationUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifySellerPayment(arbitrationUnsigned, arbitrationSellerSig, proof); err != nil {
		t.Fatal(err)
	}
	arbitrationArbiterSig, err := arbiterPool.SignArbiterPayment(ctx, arbitrationUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	arbitrated, err := sellerPool.MergeSellerArbiterPayment(arbitrationUnsigned, arbitrationSellerSig, arbitrationArbiterSig, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyArbitratedPayment(&arbitrated.State, proof); err != nil {
		t.Fatal(err)
	}
	parsedArbitrated, err := engine.ParsePaymentState(ctx, arbitrated.RawTx, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedArbitrated.BuyerTransactionSignature) != 0 || len(parsedArbitrated.SellerTransactionSignature) == 0 || len(parsedArbitrated.ArbiterTransactionSignature) == 0 {
		t.Fatalf("arbitrated signature metadata = %+v", parsedArbitrated)
	}
	malformed, err := tx.NewTransactionFromBytes(unsigned.RawTx)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Outputs = malformed.Outputs[:1]
	malformedUnsigned := *arbitrationUnsigned
	malformedUnsigned.RawTx = malformed.Bytes()
	if err := engine.VerifyBuyerPayment(&malformedUnsigned, buyerSig, proof); err == nil {
		t.Fatal("malformed detached verification unexpectedly succeeded")
	}
	assertMergeRejectsWithoutPanic(t, func() error {
		_, err := sellerPool.MergeBuyerSellerPayment(&malformedUnsigned, buyerSig, sellerSig, proof)
		return err
	})
	assertMergeRejectsWithoutPanic(t, func() error {
		_, err := sellerPool.MergeSellerArbiterPayment(&malformedUnsigned, arbitrationSellerSig, arbitrationArbiterSig, proof)
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
	engine, proof := mustRefundExpiryFixture(t, 500, nil)
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(context.Background(), previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildPaymentUpdate(context.Background(), PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return engine, proof, unsigned, mustPoolTestKey(t, "11"), mustPoolTestKey(t, "22"), mustPoolTestKey(t, "33")
}

func TestExportedPoolAPIsRejectProofBoundAdversaries(t *testing.T) {
	ctx := context.Background()
	engine, proof, unsigned, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	buyerSigner := &countingPoolSigner{key: buyer}
	sellerSigner := &countingPoolSigner{key: seller}
	arbiterSigner := &countingPoolSigner{key: arbiter}
	buyerPool := NewBuyerPoolAdapter(engine, buyerSigner)
	sellerPool := NewSellerPoolAdapter(engine, sellerSigner)
	arbiterPool := NewArbiterPoolAdapter(engine, arbiterSigner)
	buyerSig, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSig, err := arbiterPool.SignArbiterPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	badMetadata := *unsigned
	badMetadata.SellerAmountSat++
	badRaw := append([]byte(nil), unsigned.RawTx...)
	badMetadata.RawTx = badRaw
	cases := []struct {
		name   string
		call   func() error
		signer *countingPoolSigner
	}{
		{"sign buyer", func() error { _, e := buyerPool.SignBuyerPayment(ctx, &badMetadata, proof); return e }, buyerSigner},
		{"sign seller", func() error { _, e := sellerPool.SignSellerPayment(ctx, &badMetadata, proof); return e }, sellerSigner},
		{"sign seller arbitration", func() error { _, e := sellerPool.SignSellerArbitrationCandidate(ctx, &badMetadata, proof); return e }, sellerSigner},
		{"sign arbiter", func() error { _, e := arbiterPool.SignArbiterPayment(ctx, &badMetadata, proof); return e }, arbiterSigner},
		{"verify buyer", func() error { return engine.VerifyBuyerPayment(&badMetadata, buyerSig, proof) }, nil},
		{"verify seller", func() error { return engine.VerifySellerPayment(&badMetadata, sellerSig, proof) }, nil},
		{"verify arbiter", func() error { return engine.VerifyArbiterPayment(&badMetadata, arbiterSig, proof) }, nil},
		{"merge buyer seller", func() error {
			_, e := engine.MergeBuyerSellerPayment(&badMetadata, buyerSig, sellerSig, proof)
			return e
		}, nil},
		{"merge seller arbiter", func() error {
			_, e := engine.MergeSellerArbiterPayment(&badMetadata, sellerSig, sellerSig, proof)
			return e
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := 0
			if tc.signer != nil {
				before = tc.signer.signs
			}
			assertMergeRejectsWithoutPanic(t, tc.call)
			if tc.signer != nil && tc.signer.signs != before {
				t.Fatalf("signer side effect = %d, want 0", tc.signer.signs-before)
			}
		})
	}
	nilProofCases := []struct {
		name   string
		call   func() error
		signer *countingPoolSigner
	}{
		{"sign buyer nil proof", func() error { _, e := buyerPool.SignBuyerPayment(ctx, unsigned, nil); return e }, buyerSigner},
		{"sign seller nil proof", func() error { _, e := sellerPool.SignSellerPayment(ctx, unsigned, nil); return e }, sellerSigner},
		{"sign arbitration seller nil proof", func() error { _, e := sellerPool.SignSellerArbitrationCandidate(ctx, unsigned, nil); return e }, sellerSigner},
		{"sign arbiter nil proof", func() error { _, e := arbiterPool.SignArbiterPayment(ctx, unsigned, nil); return e }, arbiterSigner},
		{"sign arbitration adapter nil proof", func() error {
			_, e := adapterForArbitration(engine, arbiter).SignArbitrationCandidate(ctx, unsigned.RawTx, nil)
			return e
		}, arbiterSigner},
		{"verify buyer nil proof", func() error { return engine.VerifyBuyerPayment(unsigned, buyerSig, nil) }, nil},
		{"verify seller nil proof", func() error { return engine.VerifySellerPayment(unsigned, sellerSig, nil) }, nil},
		{"verify arbiter nil proof", func() error { return engine.VerifyArbiterPayment(unsigned, arbiterSig, nil) }, nil},
		{"merge normal nil proof", func() error { _, e := engine.MergeBuyerSellerPayment(unsigned, buyerSig, sellerSig, nil); return e }, nil},
		{"merge arbitration nil proof", func() error { _, e := engine.MergeSellerArbiterPayment(unsigned, sellerSig, arbiterSig, nil); return e }, nil},
	}
	for _, tc := range nilProofCases {
		t.Run(tc.name, func(t *testing.T) {
			before := 0
			if tc.signer != nil {
				before = tc.signer.signs
			}
			assertMergeRejectsWithoutPanic(t, tc.call)
			if tc.signer != nil && tc.signer.signs != before {
				t.Fatalf("nil-proof signer side effect = %d", tc.signer.signs-before)
			}
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
	if err := engine.VerifyBuyerPayment(&wrong, buyerSig, proof); err == nil {
		t.Fatal("wrong outpoint was accepted")
	}
}

func TestArbitrationFinalSequenceRejectsBeforeSigner(t *testing.T) {
	ctx := context.Background()
	engine, proof, unsigned, buyer, seller, arbiter := mustUnsignedPaymentFixture(t)
	previousRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, previousRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	acceptedUnsigned, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: 3, SellerAmountAfterSat: 1000})
	if err != nil {
		t.Fatal(err)
	}
	acceptedSeller, err := NewSellerPoolAdapter(engine, testSigner{seller}).SignSellerPayment(ctx, acceptedUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	acceptedBuyer, err := NewBuyerPoolAdapter(engine, testSigner{buyer}).SignBuyerPayment(ctx, acceptedUnsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := engine.MergeBuyerSellerPayment(acceptedUnsigned, acceptedBuyer, acceptedSeller, proof)
	if err != nil {
		t.Fatal(err)
	}
	accepted.State.RawTx = accepted.RawTx
	finalUnsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: &accepted.State, SellerAmountAfterSat: accepted.State.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	count := &countingPoolSigner{key: arbiter}
	if _, err := NewArbiterPoolAdapter(engine, count).SignArbiterPayment(ctx, finalUnsigned, proof); err == nil {
		t.Fatal("final arbiter payment was accepted")
	}
	if count.signs != 0 {
		t.Fatalf("final arbitration signer calls = %d", count.signs)
	}
	_ = unsigned
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
		{"verify opening", func() error { return (*MultisigPoolAdapter)(nil).VerifyOpening(nil) }},
		{"sign arbitration", func() error {
			_, err := (*MultisigPoolAdapter)(nil).SignArbitrationCandidate(ctx, nil, nil)
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
	buyerSigner := &countingPoolSigner{key: buyer}
	sellerSigner := &countingPoolSigner{key: seller}
	arbiterSigner := &countingPoolSigner{key: arbiter}
	buyerPool := NewBuyerPoolAdapter(engine, buyerSigner)
	sellerPool := NewSellerPoolAdapter(engine, sellerSigner)
	arbiterPool := NewArbiterPoolAdapter(engine, arbiterSigner)
	buyerSig, err := buyerPool.SignBuyerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	sellerSig, err := sellerPool.SignSellerPayment(ctx, unsigned, proof)
	if err != nil {
		t.Fatal(err)
	}
	arbiterSig, err := arbiterPool.SignArbiterPayment(ctx, unsigned, proof)
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
	terms := &bitfs.ContentRequestTerms{MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB, BasePaymentSequence: uint64(unsigned.PaymentSequence - 1), PaymentSequenceAfter: uint64(unsigned.PaymentSequence), SellerAmountAfterSat: unsigned.SellerAmountSat}
	cases := []struct {
		name   string
		call   func(*UnsignedPayment, *OpeningProof) error
		signer *countingPoolSigner
	}{
		{"buyer sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := buyerPool.SignBuyerPayment(ctx, u, p)
			return e
		}, buyerSigner},
		{"seller sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := sellerPool.SignSellerPayment(ctx, u, p)
			return e
		}, sellerSigner},
		{"seller arbitration sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := sellerPool.SignSellerArbitrationCandidate(ctx, u, p)
			return e
		}, sellerSigner},
		{"arbiter sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := arbiterPool.SignArbiterPayment(ctx, u, p)
			return e
		}, arbiterSigner},
		{"arbiter arbitration sign", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := (&MultisigPoolAdapter{Engine: engine, ArbiterKey: arbiterSigner}).SignArbitrationCandidate(ctx, u.RawTx, p)
			return e
		}, arbiterSigner},
		{"buyer verify", func(u *UnsignedPayment, p *OpeningProof) error { return engine.VerifyBuyerPayment(u, buyerSig, p) }, nil},
		{"seller verify", func(u *UnsignedPayment, p *OpeningProof) error { return engine.VerifySellerPayment(u, sellerSig, p) }, nil},
		{"arbiter verify", func(u *UnsignedPayment, p *OpeningProof) error { return engine.VerifyArbiterPayment(u, arbiterSig, p) }, nil},
		{"buyer seller merge", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := engine.MergeBuyerSellerPayment(u, buyerSig, sellerSig, p)
			return e
		}, nil},
		{"seller arbiter merge", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := engine.MergeSellerArbiterPayment(u, sellerSig, arbiterSig, p)
			return e
		}, nil},
		{"arbitration verify", func(u *UnsignedPayment, p *OpeningProof) error {
			_, e := (&MultisigPoolAdapter{Engine: engine, ArbiterKey: arbiterSigner}).VerifyArbitrationCandidate(ctx, u.RawTx, p, terms, sellerSig)
			return e
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name+" wrong outpoint", func(t *testing.T) {
			before := 0
			if tc.signer != nil {
				before = tc.signer.signs
			}
			if err := callWithoutPanic(func() error { return tc.call(&wrong, proof) }); err == nil {
				t.Fatal("wrong outpoint unexpectedly accepted")
			}
			if tc.signer != nil && tc.signer.signs != before {
				t.Fatalf("signer side effect = %d", tc.signer.signs-before)
			}
		})
		t.Run(tc.name+" malformed proof", func(t *testing.T) {
			badProof := CloneOpeningProof(proof)
			badProof.RefundTx = []byte{1, 2, 3}
			before := 0
			if tc.signer != nil {
				before = tc.signer.signs
			}
			if err := callWithoutPanic(func() error { return tc.call(unsigned, badProof) }); err == nil {
				t.Fatal("malformed proof unexpectedly accepted")
			}
			if tc.signer != nil && tc.signer.signs != before {
				t.Fatalf("malformed proof signer side effect = %d", tc.signer.signs-before)
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
	initial, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := engine.BuildImmediateClose(ctx, CloseInput{Opening: proof, Latest: initial, SellerAmountAfterSat: initial.SellerAmountSat})
	if err != nil {
		t.Fatal(err)
	}
	sellerSigner := &countingPoolSigner{key: seller}
	arbiterSigner := &countingPoolSigner{key: arbiter}
	terms := &bitfs.ContentRequestTerms{MinerFeeRateSatPerKB: proof.MinerFeeRateSatPerKB, BasePaymentSequence: uint64(finalPoolSequence - 1), PaymentSequenceAfter: uint64(finalPoolSequence), SellerAmountAfterSat: unsigned.SellerAmountSat}
	checks := []struct {
		name string
		call func() error
	}{
		{"seller candidate signer", func() error {
			_, e := NewSellerPoolAdapter(engine, sellerSigner).SignSellerArbitrationCandidate(ctx, unsigned, proof)
			return e
		}},
		{"arbiter payment signer", func() error {
			_, e := NewArbiterPoolAdapter(engine, arbiterSigner).SignArbiterPayment(ctx, unsigned, proof)
			return e
		}},
		{"arbiter candidate signer", func() error {
			_, e := (&MultisigPoolAdapter{Engine: engine, ArbiterKey: arbiterSigner}).SignArbitrationCandidate(ctx, unsigned.RawTx, proof)
			return e
		}},
		{"arbiter payment verifier", func() error { return engine.VerifyArbiterPayment(unsigned, nil, proof) }},
		{"arbiter candidate verifier", func() error {
			_, e := (&MultisigPoolAdapter{Engine: engine, ArbiterKey: arbiterSigner}).VerifyArbitrationCandidate(ctx, unsigned.RawTx, proof, terms, nil)
			return e
		}},
		{"seller arbiter merge", func() error { _, e := engine.MergeSellerArbiterPayment(unsigned, nil, nil, proof); return e }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := callWithoutPanic(check.call); err == nil {
				t.Fatal("final sequence unexpectedly accepted")
			}
		})
	}
	if sellerSigner.signs != 0 || arbiterSigner.signs != 0 {
		t.Fatalf("arbitration final signer calls seller=%d arbiter=%d", sellerSigner.signs, arbiterSigner.signs)
	}
	_ = buyer
}

func TestBuildPaymentUpdateRejectsSkipOutpointAndMetadataTampering(t *testing.T) {
	ctx := context.Background()
	engine, proof, _, _, _, _ := mustUnsignedPaymentFixture(t)
	initialRaw, err := engine.BuildRefundSubmission(proof)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := engine.ParsePaymentState(ctx, initialRaw, proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: previous, PaymentSequenceAfter: previous.PaymentSequence + 2, SellerAmountAfterSat: 1000}); err == nil {
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
	if _, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: &wrongPrevious, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: 1000}); err == nil {
		t.Fatal("wrong previous outpoint was accepted")
	}
	forged := *previous
	forged.SellerAmountSat++
	if _, err := engine.BuildPaymentUpdate(ctx, PaymentUpdateInput{Opening: proof, Previous: &forged, PaymentSequenceAfter: previous.PaymentSequence + 1, SellerAmountAfterSat: 1000}); err == nil {
		t.Fatal("forged previous metadata was accepted")
	}
}

func adapterForArbitration(engine *MultisigPoolEngine, key *ec.PrivateKey) *MultisigPoolAdapter {
	return &MultisigPoolAdapter{Engine: engine, ArbiterKey: testSigner{key: key}}
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

func TestVerifyRefundExpiredUsesOnlyTheConfiguredLockTimeClock(t *testing.T) {
	blockHeight := uint32(900_000)
	engine, heightProof := mustRefundExpiryFixture(t, 1_000_000, func() uint32 { return blockHeight })
	if err := engine.VerifyRefundExpired(heightProof, time.Unix(2_000_000_000, 0)); !errors.Is(err, ErrNotExpired) {
		t.Fatalf("height refund before block maturity = %v, want ErrNotExpired", err)
	}
	heightProof = mustRefundExpiryProof(t, 900_000, func() uint32 { return blockHeight })
	if err := engine.VerifyRefundExpired(heightProof, time.Unix(2_000_000_000, 0)); err != nil {
		t.Fatalf("height refund at block maturity = %v, want success", err)
	}

	engine, timeProof := mustRefundExpiryFixture(t, 2_000_000_000, func() uint32 { return blockHeight })
	if err := engine.VerifyRefundExpired(timeProof, time.Unix(1_999_999_999, 0)); !errors.Is(err, ErrNotExpired) {
		t.Fatalf("time refund before timestamp maturity = %v, want ErrNotExpired", err)
	}
	if err := engine.VerifyRefundExpired(timeProof, time.Unix(2_000_000_000, 0)); err != nil {
		t.Fatalf("time refund at timestamp maturity = %v, want success", err)
	}

	noHeightEngine, noHeightProof := mustRefundExpiryFixture(t, 1_000_000, nil)
	if err := noHeightEngine.VerifyRefundExpired(noHeightProof, time.Unix(2_000_000_000, 0)); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("height refund without block provider = %v, want ErrInvalidEvidence", err)
	}
}

func mustRefundExpiryFixture(t *testing.T, lockTime uint32, blockHeight func() uint32) (*MultisigPoolEngine, *OpeningProof) {
	t.Helper()
	return mustRefundExpiryFixtureWithKeys(t, lockTime, blockHeight)
}

func mustRefundExpiryProof(t *testing.T, lockTime uint32, blockHeight func() uint32) *OpeningProof {
	t.Helper()
	_, proof := mustRefundExpiryFixtureWithKeys(t, lockTime, blockHeight)
	return proof
}

func mustRefundExpiryFixtureWithKeys(t *testing.T, lockTime uint32, blockHeight func() uint32) (*MultisigPoolEngine, *OpeningProof) {
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
	engine, err := NewMultisigPoolEngine(MultisigPoolEngineConfig{BuyerPubKey: buyer.PubKey().Compressed(), SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed(), BlockHeight: blockHeight})
	if err != nil {
		t.Fatal(err)
	}
	buyerPool := NewBuyerPoolAdapter(engine, testSigner{buyer})
	sellerPool := NewSellerPoolAdapter(engine, testSigner{seller})
	request, err := buyerPool.BuildRefundPresignRequest(ctx, OpeningInput{FundingTx: funding.Bytes(), PoolOutputIndex: 0, ExpiryLockTime: lockTime, MinerFeeRateSatPerKB: 1, SellerPubKey: seller.PubKey().Compressed(), ArbiterPubKey: arbiter.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	sellerRefund, err := sellerPool.SignSellerRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	spend, err := engine.TransactionID(request.RefundTx)
	if err != nil {
		t.Fatal(err)
	}
	proof := &OpeningProof{Version: MajorVersion, MultisigProtocol: MultisigProtocol, MultisigVersion: MultisigVersion, RefundTx: request.RefundTx, SpendTxID: spend[:], FundingTxID: funding.TxID().CloneBytes(), PoolOutputIndex: 0, PoolOutputSatoshis: 100000, PoolLockingScript: request.PoolLockingScript, BuyerPubKey: request.BuyerPubKey, SellerPubKey: request.SellerPubKey, ArbiterPubKey: request.ArbiterPubKey, MinerFeeRateSatPerKB: 1, BuyerRefundSignature: request.BuyerRefundSignature, SellerRefundSignature: sellerRefund, FundingTx: funding.Bytes()}
	if err := engine.VerifyOpening(proof); err != nil {
		t.Fatal(err)
	}
	return engine, proof
}
