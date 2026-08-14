package buyer

import (
	"testing"

	masterseed "github.com/bsv8/MasterSeed"
)

func TestContentSizeMatchesDuplicateOrdinaryAndTailPositions(t *testing.T) {
	matches := masterseed.BlockMatches{MatchCount: 3, FirstIndex: 0, LastIndex: 2}
	fileSize := 2*uint64(masterseed.BlockSize) + 1
	if !contentSizeMatchesBlock(fileSize, masterseed.BlockSize, matches) {
		t.Fatal("full ordinary duplicate position was rejected")
	}
	if !contentSizeMatchesBlock(fileSize, 1, matches) {
		t.Fatal("tail duplicate position was rejected")
	}
	if contentSizeMatchesBlock(fileSize, 9, matches) {
		t.Fatal("nonmatching duplicate size was accepted")
	}
}

func TestContentSizeMatchesRequiresAtLeastOneMatch(t *testing.T) {
	if contentSizeMatchesBlock(masterseed.BlockSize, masterseed.BlockSize, masterseed.BlockMatches{}) {
		t.Fatal("zero-match block accepted")
	}
}
