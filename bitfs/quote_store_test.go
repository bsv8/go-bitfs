package bitfs

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestFileQuoteStoreRehydratesSignedQuote(t *testing.T) {
	quote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestPubkey(), "report.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "quotes.json")
	first, err := NewFileQuoteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SaveQuote(context.Background(), quote); err != nil {
		t.Fatal(err)
	}
	hash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}

	second, err := NewFileQuoteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := second.LoadQuote(context.Background(), Hash32(hash))
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !bytes.Equal(loaded.TermsCBOR, quote.TermsCBOR) || !bytes.Equal(loaded.TermsSignature, quote.TermsSignature) {
		t.Fatalf("loaded quote = %#v", loaded)
	}
	loaded.TermsCBOR[0] ^= 0xff
	again, err := second.LoadQuote(context.Background(), Hash32(hash))
	if err != nil {
		t.Fatal(err)
	}
	if again == nil || !bytes.Equal(again.TermsCBOR, quote.TermsCBOR) {
		t.Fatal("LoadQuote returned mutable internal quote bytes")
	}
}

func TestFileQuoteStoreInstancesReloadBeforeMutating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quotes.json")
	first, err := NewFileQuoteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileQuoteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	firstQuote, err := NewSignedFileQuote(quoteTestTerms(t), quoteTestPubkey(), "first.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	terms := quoteTestTerms(t)
	terms.FullBlockPriceSat++
	secondQuote, err := NewSignedFileQuote(terms, quoteTestPubkey(), "second.bin", quoteTestSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.SaveQuote(context.Background(), firstQuote); err != nil {
		t.Fatal(err)
	}
	if err := second.SaveQuote(context.Background(), secondQuote); err != nil {
		t.Fatal(err)
	}
	firstHash, err := FileQuoteTermsHash(firstQuote.TermsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := second.LoadQuote(context.Background(), Hash32(firstHash)); err != nil || loaded == nil {
		t.Fatalf("second instance did not observe first instance write: quote=%#v err=%v", loaded, err)
	}
}
