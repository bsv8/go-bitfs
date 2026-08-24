package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cddlDefinitionLine 匹配顶层 "name = ..." 定义（含 /= 扩展）。
var (
	cddlDefLine  = regexp.MustCompile(`(?m)^([a-zA-Z][A-Za-z0-9-]*)\s*=/?(=)?\s`)
	cddlComment  = regexp.MustCompile(`;.*$`)
	cddlRefToken = regexp.MustCompile(`\b[a-z][a-z0-9-]*\b`)
	cddlLiterals = map[string]bool{"uint": true, "int": true, "bstr": true, "tstr": true, "true": true, "false": true}
	bracketPairs = map[rune]rune{')': '(', ']': '['}
)

// stripCddlCommentsAndStrings 去掉注释，避免注释里的标识符与括号干扰分析。
func stripCddlComments(t *testing.T, text string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	out := make([]string, len(lines))
	for i, line := range lines {
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = line[:idx]
		}
		out[i] = line
	}
	return strings.Join(out, "\n")
}

// TestSpecV1CddlStructuralIntegrity 对唯一现行 CDDL 真值做结构化 lint：
// 每个被引用的标识符都有定义、没有重复定义、括号平衡。它不是完整 CDDL
// parser，但能挡住"引用未定义组 / 拼错词根 / 手工编辑破坏结构"这类回归，
// 避免规范文件退化为纯字符串。
func TestSpecV1CddlStructuralIntegrity(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "spec", "v1", "wire-messages.cddl"))
	if err != nil {
		t.Fatal(err)
	}
	text := stripCddlComments(t, string(raw))

	defined := map[string]bool{}
	duplicate := map[string]bool{}
	for _, match := range cddlDefLine.FindAllStringSubmatch(text, -1) {
		name := match[1]
		switch name {
		case "wire-version", "wire-kind":
			// 这些是字面量别名定义，同样计入。
		}
		if defined[name] {
			duplicate[name] = true
		}
		defined[name] = true
	}
	for name := range duplicate {
		t.Errorf("cddl group %q is defined more than once", name)
	}

	// 引用检查：成员标签（"name: type"）的左侧不是组引用；控制算子
	// (.size/.gt/.cbor/...) 与数值范围也不是。只收集右侧的小写词根。
	controlOps := regexp.MustCompile(`\.[a-z-]+`)
	memberLabel := regexp.MustCompile(`^\s*[a-zA-Z][A-Za-z0-9-]*\s*:`)
	rangeExpr := regexp.MustCompile(`\d+\.\.\d+`)
	unresolved := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || cddlDefLine.MatchString(line) {
			continue
		}
		if idx := strings.Index(line, ":"); idx >= 0 && memberLabel.MatchString(line) {
			line = line[idx+1:]
		}
		line = rangeExpr.ReplaceAllString(line, "")
		line = controlOps.ReplaceAllString(line, "")
		for _, token := range cddlRefToken.FindAllString(line, -1) {
			if cddlLiterals[token] || defined[token] {
				continue
			}
			unresolved[token] = true
		}
	}
	for token := range unresolved {
		t.Errorf("cddl references undefined group %q", token)
	}

	// 括号平衡。
	balance := 0
	for _, r := range text {
		switch r {
		case '(', '[':
			balance++
		case ')', ']':
			balance--
			if balance < 0 {
				t.Fatal("cddl has an unbalanced closing bracket")
			}
		}
	}
	if balance != 0 {
		t.Fatalf("cddl bracket balance = %d, want 0", balance)
	}

	// 关键真值锚点：防止结构性 lint 通过但语义漂移。
	required := []string{
		"wire-version = 1",
		"wire-kind = 1..11",
		"content-hashes = [1*64 sha256]",
		"content-payloads = [1*64 payload]",
		"payload = bstr .size (1..262144)",
		"buyer-payment-authorization-signature",
		"custody-gone = 2",
		"nonce = bstr .size 32",
	}
	for _, phrase := range required {
		if !strings.Contains(string(raw), phrase) {
			t.Errorf("spec/v1/wire-messages.cddl is missing anchor %q", phrase)
		}
	}
	forbidden := []string{
		"(1..64) sha256 .within",   // 已废弃的错误数量语法
		"bstr .size (1..16777216)", // 单块上限不得等于批次总上限
		"authorizationsignature",   // 词根拼接拼写错误
	}
	for _, phrase := range forbidden {
		if strings.Contains(string(raw), phrase) {
			t.Errorf("spec/v1/wire-messages.cddl still contains stale fragment %q", phrase)
		}
	}
}
