package docs_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/arbitration"
	"github.com/bsv8/go-bitfs/bitfs"
	"github.com/bsv8/go-bitfs/docs/cddltool"
	"github.com/bsv8/go-bitfs/protocol"
	"github.com/bsv8/go-bitfs/wire"
	"github.com/fxamacker/cbor/v2"
)

// TestSpecV1CddlParsesAndConforms drives the real CDDL parser over
// spec/v1/wire-messages.cddl and then validates every wire Kind against the
// published grammar:
//
//	positives: SDK-encoded messages for all eleven kinds plus the two Kind 11
//	           branches must validate against the top-level bitfs-wire-message
//	           union AND against their own kind rule;
//	negatives: wrong version, unknown kind, branch/attachment mismatches,
//	           unknown discriminators, wrong ID/nonce/signature widths, empty
//	           hash batches, zero arbiter amounts, and out-of-range sequences
//	           must all be rejected by the grammar alone.
func TestSpecV1CddlParsesAndConforms(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "spec", "v1", "wire-messages.cddl"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := cddltool.Parse(string(raw))
	if err != nil {
		t.Fatalf("spec/v1/wire-messages.cddl does not parse: %v", err)
	}
	for _, requiredRule := range []string{
		"wire-version", "wire-kind", "pubkey", "signature", "sha256",
		"content-hashes", "content-payloads",
		"kind-1-file-quote", "kind-2-refund-presign-request",
		"kind-3-refund-presign-response", "kind-4-funding-transaction-delivery",
		"kind-5-content-request", "kind-6-content-delivery",
		"kind-7-payment-update", "kind-8-arbitration-request",
		"kind-9-arbitration-response", "kind-10-content-retrieval-request",
		"kind-11-content-retrieval-response", "bitfs-wire-message",
	} {
		found := false
		for _, name := range spec.RuleNames() {
			if name == requiredRule {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cddl is missing rule %q", requiredRule)
		}
	}

	f := newCddlFixtures(t)
	for _, positive := range f.positives {
		if err := spec.Validate("bitfs-wire-message", positive.raw); err != nil {
			t.Errorf("%s rejected by the top-level union: %v", positive.name, err)
			continue
		}
		if err := spec.Validate(positive.rule, positive.raw); err != nil {
			t.Errorf("%s rejected by its own rule %s: %v", positive.name, positive.rule, err)
		}
	}
	for _, negative := range f.negatives {
		if err := spec.Validate("bitfs-wire-message", negative.raw); err == nil {
			t.Errorf("%s was accepted by the grammar but must be rejected", negative.name)
		}
	}

	// Discrimination sanity: a Kind 5 message must not satisfy Kind 6's rule
	// and vice versa; the union must pick exactly the right alternative.
	if err := spec.Validate("kind-6-content-delivery", f.positives["kind-5-content-request"].raw); err == nil {
		t.Error("Kind 5 bytes satisfied the Kind 6 rule")
	}
	if err := spec.Validate("kind-5-content-request", f.positives["kind-6-content-delivery"].raw); err == nil {
		t.Error("Kind 6 bytes satisfied the Kind 5 rule")
	}
}

type cddlMessage struct {
	name string
	rule string
	raw  []byte
}

type cddlFixtures struct {
	positives map[string]cddlMessage
	negatives []cddlMessage
}

func cddlKey(t *testing.T, repeat string) *ec.PrivateKey {
	t.Helper()
	key, err := ec.PrivateKeyFromHex(string(bytes.Repeat([]byte(repeat), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func cddlEnc(t *testing.T, value interface{}) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enc.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// b wraps possibly-nil byte slices so canonical marshalling emits empty bstr
// instead of nil.
func cddlB(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func newCddlFixtures(t *testing.T) *cddlFixtures {
	t.Helper()
	buyerKey := cddlKey(t, "44")
	sellerKey := cddlKey(t, "22")
	arbiterKey := cddlKey(t, "33")

	hash := bytes.Repeat([]byte{1}, 32)
	txid := bytes.Repeat([]byte{9}, 32)
	signature := bytes.Repeat([]byte{7}, 70)
	keyBytes := sellerKey.PubKey().Compressed()

	out := &cddlFixtures{positives: map[string]cddlMessage{}}
	add := func(name, rule string, raw []byte) {
		out.positives[name] = cdlMessage(name, rule, raw)
	}

	// ---- Kind 1 · FileQuote（真实 SDK 编码器）。----
	arbiters, err := bitfs.EncodeSupportedArbiterPublicKeys([][]byte{arbiterKey.PubKey().Compressed()})
	if err != nil {
		t.Fatal(err)
	}
	quote, err := bitfs.NewSignedFileQuote(&bitfs.FileQuoteTerms{
		SeedHash:                       hash,
		BuyerPublicKey:                 buyerKey.PubKey().Compressed(),
		SeedPriceSatoshis:              100,
		FullBlockPriceSatoshis:         1000,
		FileSizeBytes:                  4096,
		QuoteExpiresAtUnixSeconds:      2000000000,
		SupportedArbiterPublicKeysCBOR: arbiters,
	}, sellerKey, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	quoteRaw, err := wire.MarshalFileQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-1-file-quote", "kind-1-file-quote", quoteRaw)

	// ---- Kind 2/3/4（结构性正例：语法合法、语义由 SDK 层负责）。----
	refundTemplate := bytes.Repeat([]byte{4}, 250)
	add("kind-2-refund-presign-request", "kind-2-refund-presign-request",
		cddlEnc(t, []interface{}{uint64(1), uint64(2), cddlB(refundTemplate), buyerKey.PubKey().Compressed(), keyBytes, arbiterKey.PubKey().Compressed(), uint64(1), signature}))
	add("kind-3-refund-presign-response", "kind-3-refund-presign-response",
		cddlEnc(t, []interface{}{uint64(1), uint64(3), cddlB(txid), signature}))
	add("kind-4-funding-transaction-delivery", "kind-4-funding-transaction-delivery",
		cddlEnc(t, []interface{}{uint64(1), uint64(4), cddlB(txid), cddlB(bytes.Repeat([]byte{5}, 128))}))

	// ---- Kind 5 · ContentRequest（真实 SDK 编码器）。----
	hashes, err := bitfs.EncodeContentHashes([][]byte{bytes.Repeat([]byte{6}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	quoteID, err := bitfs.FileQuoteTermsID(quote.FileQuoteTermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	request, err := bitfs.NewSignedContentRequest(&bitfs.PaymentAuthorization{
		FileQuoteTermsID:            quoteID,
		RefundTemplateTxID:          append([]byte(nil), txid...),
		PaymentSequence:             3,
		SellerAmountAfterSatoshis:   1100,
		ContentHashesCBOR:           hashes,
		DeliveryDeadlineUnixSeconds: 1999999000,
	}, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	kind5, err := wire.MarshalContentRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-5-content-request", "kind-5-content-request", kind5)

	// ---- Kind 6 · ContentDelivery（真实 SDK 编码器）。----
	authID, err := bitfs.PaymentAuthorizationID(request.PaymentAuthorizationCBOR)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := bitfs.NewSignedContentDelivery(authID, [][]byte{bytes.Repeat([]byte{8}, 512)}, sellerKey)
	if err != nil {
		t.Fatal(err)
	}
	kind6, err := wire.MarshalContentDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-6-content-delivery", "kind-6-content-delivery", kind6)

	// ---- Kind 7 · PaymentUpdate。----
	add("kind-7-payment-update", "kind-7-payment-update",
		cddlEnc(t, []interface{}{uint64(1), uint64(7), cddlB(authID[:]), signature}))

	// ---- Kind 8 · ArbitrationRequest（嵌套结构正例）。----
	poolScript := bytes.Repeat([]byte{2}, 105)
	authDoc := cddlEnc(t, []interface{}{
		cddlB(quoteID[:]), cddlB(txid), uint64(3), uint64(1100), cddlB(hashes), int64(1999999000),
	})
	buyerAuthSignature := signature // 结构正例：CDDL 只约束宽度，不验证密码学
	claim := cddlEnc(t, []interface{}{
		uint64(100000), cddlB(poolScript), cddlB(refundTemplate), cddlB(authDoc), buyerAuthSignature,
	})
	payloadBundle := func(payload []byte) []byte {
		raw, err := bitfs.EncodeContentPayloads([][]byte{payload})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}(bytes.Repeat([]byte{8}, 512))
	add("kind-8-arbitration-request", "kind-8-arbitration-request",
		cddlEnc(t, []interface{}{uint64(1), uint64(8), cddlB(claim), signature, cddlB(payloadBundle)}))

	// ---- Kind 9 · ArbitrationResponse。----
	receipt := cddlEnc(t, []interface{}{
		cddlB(bytes.Repeat([]byte{3}, 32)), uint64(500), signature,
	})
	add("kind-9-arbitration-response", "kind-9-arbitration-response",
		cddlEnc(t, []interface{}{uint64(1), uint64(9), cddlB(receipt), signature}))

	// ---- Kind 10/11（真实 SDK 编码器）。----
	var claimID protocol.ArbitrationClaimID
	copy(claimID[:], bytes.Repeat([]byte{3}, 32))
	nonce := bytes.Repeat([]byte{4}, 32)
	retrievalRequest, err := arbitration.NewContentRetrievalRequest(claimID, nonce, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	kind10, err := arbitration.MarshalContentRetrievalRequest(retrievalRequest)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-10-content-retrieval-request", "kind-10-content-retrieval-request", kind10)

	requestID := protocol.ContentRetrievalRequestID(hash)
	unavailable, err := arbitration.BuildContentRetrievalUnavailable(requestID, arbitration.RetrievalCustodyGone, arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	kind11Unavailable, err := arbitration.MarshalContentRetrievalResponse(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-11-unavailable", "kind-11-content-retrieval-response", kind11Unavailable)

	available, err := arbitration.BuildContentRetrievalAvailableRaw(requestID, payloadBundle, arbiterKey)
	if err != nil {
		t.Fatal(err)
	}
	kind11Available, err := arbitration.MarshalContentRetrievalResponse(available)
	if err != nil {
		t.Fatal(err)
	}
	add("kind-11-available", "kind-11-content-retrieval-response", kind11Available)

	// ------------------------- 反例 -------------------------
	wrongVersion := cddlEnc(t, []interface{}{uint64(2), uint64(5), cddlB(request.PaymentAuthorizationCBOR), signature})
	out.negatives = append(out.negatives,
		cdlMessage("wrong wire version", "", wrongVersion),
		cdlMessage("unknown kind 12", "", cddlEnc(t, []interface{}{uint64(1), uint64(12), cddlB(hash)})),
		cdlMessage("unavailable branch carrying an attachment", "", append(kind11Unavailable, cddlB(payloadBundle)...)),
		cdlMessage("available branch missing its attachment", "", cddlEnc(t, []interface{}{uint64(1), uint64(11), cddlB(available.ContentRetrievalResultCBOR), available.ArbiterContentRetrievalResultSignature})),
		cdlMessage("unavailable result inside an attached five-element shell", "", func() []byte {
			result := cddlEnc(t, []interface{}{cddlB(requestID[:]), uint64(0), uint64(2)})
			return cddlEnc(t, []interface{}{uint64(1), uint64(11), cddlB(result), signature, cddlB(payloadBundle)})
		}()),
		cdlMessage("unknown unavailable reason", "", func() []byte {
			result := cddlEnc(t, []interface{}{cddlB(requestID[:]), uint64(0), uint64(7)})
			return cddlEnc(t, []interface{}{uint64(1), uint64(11), cddlB(result), signature})
		}()),
		cdlMessage("31-byte nonce", "", func() []byte {
			doc := cddlEnc(t, []interface{}{cddlB(bytes.Repeat([]byte{3}, 31)), cddlB(bytes.Repeat([]byte{4}, 31))})
			return cddlEnc(t, []interface{}{uint64(1), uint64(10), cddlB(doc), signature})
		}()),
		cdlMessage("31-byte claim id", "", func() []byte {
			doc := cddlEnc(t, []interface{}{cddlB(bytes.Repeat([]byte{3}, 31)), cddlB(nonce)})
			return cddlEnc(t, []interface{}{uint64(1), uint64(10), cddlB(doc), signature})
		}()),
		cdlMessage("oversized signature", "", cddlEnc(t, []interface{}{uint64(1), uint64(5), cddlB(request.PaymentAuthorizationCBOR), bytes.Repeat([]byte{7}, 300)})),
		cdlMessage("empty hash batch", "", func() []byte {
			emptyHashes := cddlEnc(t, []interface{}{})
			authDoc := cddlEnc(t, []interface{}{cddlB(quoteID[:]), cddlB(txid), uint64(3), uint64(1100), cddlB(emptyHashes), int64(1999999000)})
			return cddlEnc(t, []interface{}{uint64(1), uint64(5), cddlB(authDoc), signature})
		}()),
		cdlMessage("zero arbiter amount in receipt", "", func() []byte {
			zeroReceipt := cddlEnc(t, []interface{}{cddlB(bytes.Repeat([]byte{3}, 32)), uint64(0), signature})
			return cddlEnc(t, []interface{}{uint64(1), uint64(9), cddlB(zeroReceipt), signature})
		}()),
		cdlMessage("payment sequence above uint32 ceiling", "", func() []byte {
			badSeq := cddlEnc(t, []interface{}{cddlB(quoteID[:]), cddlB(txid), uint64(4294967295), uint64(1100), cddlB(hashes), int64(1999999000)})
			return cddlEnc(t, []interface{}{uint64(1), uint64(5), cddlB(badSeq), signature})
		}()),
		// 非最短编码反例：能被宽松 decoder 接受，但违反 core deterministic CBOR。
		cdlMessage("non-shortest integer head for the wire version", "", func() []byte {
			doc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, nonce)
			if err != nil {
				t.Fatal(err)
			}
			sig := signature
			body := append([]byte{0x19, 0x00, 0x01, 0x0a}, append(cddlEnc(t, doc), cddlEnc(t, sig)...)...)
			return append([]byte{0x84}, body...)
		}()),
		cdlMessage("non-shortest array length head for Kind 10", "", func() []byte {
			doc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, nonce)
			if err != nil {
				t.Fatal(err)
			}
			raw := append([]byte{0x98, 0x04}, cddlEnc(t, uint64(1))...)
			raw = append(raw, cddlEnc(t, uint64(10))...)
			raw = append(raw, cddlEnc(t, doc)...)
			raw = append(raw, cddlEnc(t, signature)...)
			return raw
		}()),
		cdlMessage("non-shortest bstr length head inside Kind 10", "", func() []byte {
			doc, err := arbitration.EncodeContentRetrievalRequestDocument(claimID, nonce)
			if err != nil {
				t.Fatal(err)
			}
			// doc 为 69 字节：规范长度头是 0x58 0x45；这里改用三字节 0x59 0x00 0x45。
			if len(doc) != 69 {
				t.Fatalf("test premise broken: request document length = %d, want 69", len(doc))
			}
			raw := []byte{0x84, 0x01, 0x0a, 0x59, 0x00, byte(len(doc))}
			raw = append(raw, doc...)
			raw = append(raw, cddlEnc(t, signature)...)
			return raw
		}()),
	)
	return out
}

func cdlMessage(name, rule string, raw []byte) cddlMessage {
	return cddlMessage{name: name, rule: rule, raw: raw}
}
