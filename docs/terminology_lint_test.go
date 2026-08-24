package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCurrentDocumentsExcludeRetiredProtocol pins the single-truth rule for
// every current document tree: the retired pre-v1 protocol must only be
// described under legacy archives and historical work-order records.
//
// Checked patterns:
//   - "spec/v4"                          — spec/v1 is the only current CDDL truth;
//   - `[4,` including whitespace/newline — old signing domains and shells leak
//     into copies across line breaks;
//   - "BitFS v2/v3/v4" (any case)        — the BitFS protocol itself is v1;
//     the vendored dependency "MultisigPool v4" stays legal because the
//     pattern requires the "bitfs" prefix;
//   - retired identifier word roots (TermsCBOR, PaymentAuthorizationHash,
//     QuoteTermsHash, bare ClaimID/RequestID, ArbiterAmountSat,
//     SellerAmountAfterSat, ...) that must read as their v1 counterparts.
//
// Excluded directories are exactly the ones allowed to describe history:
// legacy doc trees, historical construction tickets, build output, generated
// artifacts, vendored dependencies, and the website node toolchain.
func TestCurrentDocumentsExcludeRetiredProtocol(t *testing.T) {
	banned := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"spec/v4", regexp.MustCompile(`spec/v[2-9]`)},
		{"legacy four-element shell [4,", regexp.MustCompile(`\[\s*4\s*,`)},
		{"retired BitFS major", regexp.MustCompile(`(?i)\bbitfs\s+v[234]\b`)},
		{"TermsCBOR", regexp.MustCompile(`\bTermsCBOR\b`)},
		{"TermsSignature", regexp.MustCompile(`\bTermsSignature\b`)},
		{"FileQuoteTermsHash", regexp.MustCompile(`\bFileQuoteTermsHash\b|\bfile_quote_terms_hash\b|\bQuoteTermsHash\b|\bquote_terms_hash\b`)},
		{"PaymentAuthorizationHash", regexp.MustCompile(`\bPaymentAuthorizationHash\b|\bpayment_authorization_hash\b`)},
		{"bare ClaimID", regexp.MustCompile(`\bClaimID\b`)},
		{"bare RequestID", regexp.MustCompile(`\bRequestID\b`)},
		{"ArbiterAmountSat", regexp.MustCompile(`\bArbiterAmountSat\b`)},
		{"SellerAmountAfterSat", regexp.MustCompile(`\bSellerAmountAfterSat\b`)},
		{"SellerAmountSat", regexp.MustCompile(`\bSellerAmountSat\b`)},
		{"SeedPriceSat", regexp.MustCompile(`\bSeedPriceSat\b`)},
		{"FullBlockPriceSat", regexp.MustCompile(`\bFullBlockPriceSat\b`)},
		{"BuyerPubKey", regexp.MustCompile(`\bBuyerPubKey\b`)},
		{"bare 32-byte authorization hash", regexp.MustCompile(`bare 32-byte|裸授权哈希`)},
		{"NonceReused", regexp.MustCompile(`\bNonceReused\b`)},
		{"FundingTxDelivery", regexp.MustCompile(`FundingTxDelivery|PoolFundingTxDelivery|pool\.FundingTxDelivery`)},
		{"authorization-hash index wording", regexp.MustCompile(`授权哈希索引|授权哈希查找`)},
	}
	// GoDoc 静态门禁：发布文档由这些注释生成，旧 004 描述一旦回归会直接
	// 传播到 generated API 与翻译页。
	goDocBanned := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"exact 32-byte authorization hash", regexp.MustCompile(`exact 32-byte authorization hash`)},
		{"four-element 004", regexp.MustCompile(`four-element 004`)},
		{"SignMessage path", regexp.MustCompile(`SignMessage path`)},
	}
	excludedSegments := []string{
		"/legacy/", "/build/", "/node_modules/", "/vendor/", "/.git/",
		"/generated-api/", "/.docusaurus/",
		// Regenerated on every website build from Go comments + catalog.
		"/docusaurus-plugin-content-docs-api/",
	}
	excludedNames := map[string]bool{"package-lock.json": true}
	allowedSuffixes := []string{".md", ".mdx", ".json", ".js", ".mjs"}

	root := ".."
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative := filepath.ToSlash(path)
		if entry.IsDir() {
			for _, segment := range excludedSegments {
				if strings.Contains(relative+"/", segment) {
					return filepath.SkipDir
				}
			}
			if strings.HasPrefix(entry.Name(), ".") && relative != ".." {
				return filepath.SkipDir
			}
			return nil
		}
		if relative == "../docs/施工单" || strings.Contains(relative, "/施工单/") {
			return nil // historical work orders intentionally record the switch
		}
		if excludedNames[entry.Name()] {
			return nil
		}
		allowed := false
		for _, suffix := range allowedSuffixes {
			if strings.HasSuffix(entry.Name(), suffix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, bannedPhrase := range banned {
			if loc := bannedPhrase.pattern.FindStringIndex(text); loc != nil {
				line := 1 + strings.Count(text[:loc[0]], "\n")
				t.Errorf("%s:%d still contains banned phrase %q", relative, line, bannedPhrase.name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// GoDoc 静态门禁：发布文档由 Go 注释生成，旧 004 描述一旦回归会直接
	// 传播到 generated API 与翻译页。扫描除 vendor/legacy/施工单外的全部
	// Go 源（含测试），防止任何形式的复制回潮。
	goDocRoot := ".."
	goDocErr := filepath.WalkDir(goDocRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative := filepath.ToSlash(path)
		if entry.IsDir() {
			for _, segment := range excludedSegments {
				if strings.Contains(relative+"/", segment) {
					return filepath.SkipDir
				}
			}
			if relative == "../docs/施工单" || strings.Contains(relative, "/施工单/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bannedPhrase := range goDocBanned {
			if bannedPhrase.pattern.Match(data) {
				t.Errorf("%s still contains banned GoDoc phrase %q", relative, bannedPhrase.name)
			}
		}
		return nil
	})
	if goDocErr != nil {
		t.Fatal(goDocErr)
	}

	// Site metadata must advertise v1, never a retired version.
	for _, meta := range []string{
		filepath.Join("..", "website", "docusaurus.config.js"),
		filepath.Join("..", "website", "src", "pages", "index.js"),
		filepath.Join("..", "website", "i18n", "zh-CN", "code.json"),
	} {
		configBytes, err := os.ReadFile(meta)
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`(?i)bitfs\s+v[234]`).Match(configBytes) {
			t.Errorf("%s still advertises a retired BitFS version", meta)
		}
	}
}
