package seller

import (
	"context"
	"errors"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv8/go-bitfs/bitfs"
)

type nilSellerQuoteStore struct{}

func sellerTestPubkey(hexKey string) []byte {
	key, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		panic(err)
	}
	return key.PubKey().Compressed()
}

func (nilSellerQuoteStore) SaveQuote(context.Context, *bitfs.SignedFileQuote) error { return nil }
func (nilSellerQuoteStore) LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error) {
	return nil, nil
}

func TestDeliverRequestedContentRejectsNilQuoteFromStore(t *testing.T) {
	terms, err := bitfs.EncodeContentRequestTerms(&bitfs.ContentRequestTerms{
		QuoteTermsHash:        make([]byte, 32),
		SpendTxID:             make([]byte, 32),
		BasePaymentSequence:   2,
		PaymentSequenceAfter:  3,
		SellerAmountAfterSat:  1,
		MinerFeeRateSatPerKB:  1,
		BuyerPubkey:           sellerTestPubkey("1111111111111111111111111111111111111111111111111111111111111111"),
		SellerPubkey:          sellerTestPubkey("2222222222222222222222222222222222222222222222222222222222222222"),
		SelectedArbiterPubkey: sellerTestPubkey("3333333333333333333333333333333333333333333333333333333333333333"),
		ContentType:           bitfs.ContentSeed,
		ContentHash:           make([]byte, 32),
		DeliveryDeadlineUnix:  2_000_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	workflow := &Workflow{quotes: nilSellerQuoteStore{}}
	request := &bitfs.SignedContentRequest{TermsCBOR: terms, BuyerSignature: []byte{1}}
	if _, err := workflow.DeliverRequestedContent(context.Background(), request); !errors.Is(err, bitfs.ErrInvalidEvidence) {
		t.Fatalf("DeliverRequestedContent() error = %v, want ErrInvalidEvidence", err)
	}
}
