package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCurrentDocumentsExcludeRetiredProtocol pins the single-truth rule for
// every current document tree: the retired pre-v1 protocol and the retired
// pre-hard-switch SDK surface must only be described under legacy archives and
// historical work-order records.
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
//     SellerAmountAfterSat, ...) that must read as their v1 counterparts;
//   - 2026-08-24 硬切换禁词：旧 import 路径、旧 Workflow 构造器、隐藏时钟、
//     Packet/Marshal(any) 主入口、旧方法名与重复错误真值。带 \b 前缀的旧方法
//     名只拦截独立入口，避免误伤包含同段子串的新角色方法名（例如买方
//     VerifyDeliveryAndPreparePayment 与被禁的 PreparePayment 的关系）。
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
		// ---- 2026-08-24 硬切换禁词：一次性切换后旧入口不得回潮 ----
		{"old import path bitfs/", regexp.MustCompile(`go-b` + `itfs/b` + `itfs\b|"github\.com/bsv8/go-b` + `itfs/b` + `itfs"`)},
		{"direct private-key workflow config", regexp.MustCompile(`\bWorkflowConfig\b`)},
		{"hidden clock package", regexp.MustCompile(`protoclock`)},
		{"retired Packet envelope", regexp.MustCompile(`\bwire\.Packet\b|\bPacket\{Kind:`)},
		{"retired Marshal(any) entry", regexp.MustCompile(`wire\.Marshal\(|wire\.Unmarshal\(|MarshalFileQuote\(|UnmarshalFileQuote\(|MarshalContentRequest\(|UnmarshalContentRequest\(|MarshalContentDelivery\(|UnmarshalContentDelivery\(|MarshalRefundPresignRequest\(|MarshalPaymentUpdate\(|MarshalArbitrationRequest\(|MarshalArbitrationResponse\(|MarshalContentRetrievalRequest\(|MarshalContentRetrievalResponse\(`)},
		{"duplicate invalid-evidence sentinels", regexp.MustCompile(`bitfs\.ErrInvalidEvidence|pool\.ErrInvalidEvidence|content\.ErrInvalidEvidence|pool\.ErrStalePaymentSequence|pool\.ErrInsufficientBalance|arbitration\.ErrContentUnavailable`)},
		{"retired buyer methods", regexp.MustCompile(`AcceptDelivery\(|BuildImmediateClose\(|BuildContentRequest\(|BuildRefundAfterExpiry\(|BuildArbitrationContentRequest\(|BuildFundingTransactionDelivery\(|CompleteImmediateClose\( |AcceptRefundPresign\(|AcceptArbitratedContent\(`)},
		{"retired seller methods", regexp.MustCompile(`PresignPoolOpening\(|AcceptPoolFunding\(|BuildContentDelivery\(|AcceptPayment\(|SignImmediateClose\(|BuildArbitrationRequest\( `)},
		{"retired arbitration workflow", regexp.MustCompile(`arbitration\.NewWorkflow|\bPreparePayment\(|\bSignPreparedPayment\(|PreparedPayment\b`)},
	}
	// GoDoc 静态门禁：发布文档由这些注释生成，旧 004 描述一旦回归会直接
	// 传播到 generated API 与翻译页。
	goDocBanned := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"exact-32-byte authorization-hash phrasing", regexp.MustCompile(`exact 32-byte auth` + `orization hash`)},
		{"four-element-shell phrasing", regexp.MustCompile(`four-element 0` + `04`)},
		{"legacy SignMessage-entry phrasing", regexp.MustCompile(`SignMessage pa` + `th`)},
	}
	excludedSegments := []string{
		// 验收报告与历史施工单同属"记录硬切换删除事实"的点对点证据，
		// 报告正文必须能列出被删除的旧符号，因此与施工单同等豁免。
		"/acceptance/",
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
	// Go 源（含测试），防止任何形式的复制回潮。硬切换禁词对 Go 源同样生效：
	// 生产与测试代码都不得再引用旧 import、旧构造器、旧方法或重复错误真值。
	goBanned := append(goDocBanned, []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"old import path bitfs", regexp.MustCompile(`go-b` + `itfs/b` + `itfs`)},
		{"hidden clock package", regexp.MustCompile(`internal/pr` + `otoclock|pr` + `otoclock\.Now`)},
		{"retired Packet/Marshal(any)", regexp.MustCompile(`\bwire\.Packet\b|wire\.Marshal\(|wire\.Unmarshal\(`)},
		{"duplicate sentinels", regexp.MustCompile(`bitfs\.ErrInvalidEvidence|pool\.ErrInvalidEvidence|content\.ErrInvalidEvidence|pool\.ErrStalePaymentSequence|pool\.ErrInsufficientBalance|arbitration\.ErrContentUnavailable`)},
		{"direct private-key workflow config", regexp.MustCompile(`buyer\.WorkflowConfig|seller\.WorkflowConfig|arbitration\.WorkflowConfig`)},
	}...)
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
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bannedPhrase := range goBanned {
			if bannedPhrase.pattern.Match(data) {
				t.Errorf("%s still contains banned Go source phrase %q", relative, bannedPhrase.name)
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
