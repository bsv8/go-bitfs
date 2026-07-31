package bitfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileQuoteStore is a durable, atomic-snapshot implementation of the quote
// store ports used by buyer and seller. It persists the signed quote bytes and
// indexes them by the canonical FileQuoteTerms hash.
//
// It uses an advisory process lock and reloads the current snapshot for each
// operation, so cooperating Unix processes do not lose each other's quotes.
// A transactional database is still preferable for indexed queries and
// stronger crash-recovery/locking guarantees.
type FileQuoteStore struct {
	mu     sync.Mutex
	path   string
	quotes map[Hash32]*SignedFileQuote
}

type quoteStoreSnapshot struct {
	Version uint8             `json:"version"`
	Quotes  []quoteStoreEntry `json:"quotes"`
}

type quoteStoreEntry struct {
	TermsHash Hash32           `json:"terms_hash"`
	Quote     *SignedFileQuote `json:"quote"`
}

func NewFileQuoteStore(path string) (*FileQuoteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("quote store path is required")
	}
	store := &FileQuoteStore{path: path, quotes: make(map[Hash32]*SignedFileQuote)}
	if err := withProcessFileLock(path, false, store.reloadLocked); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FileQuoteStore) SaveQuote(_ context.Context, quote *SignedFileQuote) error {
	if store == nil {
		return fmt.Errorf("quote store is required")
	}
	if quote == nil {
		return fmt.Errorf("quote is required")
	}
	input := cloneSignedFileQuote(quote)
	if _, err := EncodeSignedFileQuote(input); err != nil {
		return err
	}
	hash, err := FileQuoteTermsHash(input.TermsCBOR)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return withProcessFileLock(store.path, true, func() error {
		if err := store.reloadLocked(); err != nil {
			return err
		}
		previous := cloneQuoteMap(store.quotes)
		if err := store.put(Hash32(hash), input); err != nil {
			return err
		}
		if err := store.flushLocked(); err != nil {
			store.quotes = previous
			return err
		}
		return nil
	})
}

func (store *FileQuoteStore) LoadQuote(_ context.Context, termsHash Hash32) (*SignedFileQuote, error) {
	if store == nil {
		return nil, fmt.Errorf("quote store is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var result *SignedFileQuote
	err := withProcessFileLock(store.path, false, func() error {
		if err := store.reloadLocked(); err != nil {
			return err
		}
		result = cloneSignedFileQuote(store.quotes[termsHash])
		return nil
	})
	return result, err
}

func (store *FileQuoteStore) reloadLocked() error {
	data, err := os.ReadFile(store.path)
	if os.IsNotExist(err) {
		store.quotes = make(map[Hash32]*SignedFileQuote)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read quote store: %w", err)
	}
	var snapshot quoteStoreSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode quote store: %w", err)
	}
	if snapshot.Version != 1 {
		return fmt.Errorf("unsupported quote store snapshot version %d", snapshot.Version)
	}
	loaded := &FileQuoteStore{quotes: make(map[Hash32]*SignedFileQuote)}
	for _, entry := range snapshot.Quotes {
		if err := loaded.put(entry.TermsHash, entry.Quote); err != nil {
			return fmt.Errorf("restore quote store: %w", err)
		}
	}
	store.quotes = loaded.quotes
	return nil
}

func (store *FileQuoteStore) put(expected Hash32, quote *SignedFileQuote) error {
	if quote == nil {
		return fmt.Errorf("quote is required")
	}
	if _, err := EncodeSignedFileQuote(quote); err != nil {
		return err
	}
	hash, err := FileQuoteTermsHash(quote.TermsCBOR)
	if err != nil {
		return err
	}
	if Hash32(hash) != expected {
		return fmt.Errorf("quote terms hash does not match store key")
	}
	cloned := cloneSignedFileQuote(quote)
	if old := store.quotes[expected]; old != nil && !quotesEqual(old, cloned) {
		return fmt.Errorf("quote terms hash already maps to different quote")
	}
	store.quotes[expected] = cloned
	return nil
}

func (store *FileQuoteStore) flushLocked() error {
	snapshot := quoteStoreSnapshot{Version: 1}
	for termsHash, quote := range store.quotes {
		snapshot.Quotes = append(snapshot.Quotes, quoteStoreEntry{TermsHash: termsHash, Quote: cloneSignedFileQuote(quote)})
	}
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create quote store directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(store.path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create quote store snapshot: %w", err)
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := json.NewEncoder(temporary).Encode(snapshot); err != nil {
		return fmt.Errorf("encode quote store snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync quote store snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, store.path); err != nil {
		return fmt.Errorf("replace quote store snapshot: %w", err)
	}
	keep = true
	return nil
}

func cloneQuoteMap(source map[Hash32]*SignedFileQuote) map[Hash32]*SignedFileQuote {
	cloned := make(map[Hash32]*SignedFileQuote, len(source))
	for key, quote := range source {
		cloned[key] = cloneSignedFileQuote(quote)
	}
	return cloned
}

func quotesEqual(left, right *SignedFileQuote) bool {
	if left == nil || right == nil {
		return left == right
	}
	return string(left.TermsCBOR) == string(right.TermsCBOR) && string(left.SellerPubkey) == string(right.SellerPubkey) && string(left.TermsSignature) == string(right.TermsSignature) && left.RecommendedFilename == right.RecommendedFilename
}

var _ interface {
	SaveQuote(context.Context, *SignedFileQuote) error
	LoadQuote(context.Context, Hash32) (*SignedFileQuote, error)
} = (*FileQuoteStore)(nil)
