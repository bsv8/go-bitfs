package docs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestRoleWorkflowAPIDocSignaturesMatchSource 锁定"文档示例与真实签名一致"：
// 从 buyer/seller/arbiter 三个角色包的 AST 提取全部导出方法与包级函数的
// 参数/返回值类型序列，再在 website 的 role-workflow-api.md（英文源）中查找
// 同名声明行并比对类型序列。参数名可以自由命名，但类型顺序必须逐位一致；
// 源里存在而文档缺失的公开符号同样失败——防止"语法合法但 API 已过期"的
// 示例再次漂移。
func TestRoleWorkflowAPIDocSignaturesMatchSource(t *testing.T) {
	symbols := collectRoleSymbols(t)
	if len(symbols) < 10 {
		t.Fatalf("collected %d symbols, extraction is broken", len(symbols))
	}
	docPath := filepath.Join("..", "website", "docs", "sdk", "role-workflow-api.md")
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	docSegments := splitByPackage(string(docBytes))

	for _, sym := range symbols {
		docLine, ok := findDocDeclaration(docSegments[sym.Package], sym.Name)
		if !ok {
			t.Errorf("%s.%s: missing from role-workflow-api.md (every exported role symbol must be documented with a real signature)", sym.Package, sym.Name)
			continue
		}
		if !reflect.DeepEqual(sym.ParamTypes, docLine.ParamTypes) {
			t.Errorf("%s.%s parameter types drifted:\n source %v\n doc    %v\n line: %s",
				sym.Package, sym.Name, sym.ParamTypes, docLine.ParamTypes, docLine.Raw)
		}
		if !reflect.DeepEqual(sym.ResultTypes, docLine.ResultTypes) {
			t.Errorf("%s.%s result types drifted:\n source %v\n doc    %v\n line: %s",
				sym.Package, sym.Name, sym.ResultTypes, docLine.ResultTypes, docLine.Raw)
		}
	}
}

// splitByPackage 按 "// package <name>" 分节切分文档；同名的 Workflow 方法
// 在三个角色包各自拥有独立签名，必须按包作用域查找。
func splitByPackage(doc string) map[string]string {
	segments := map[string]string{}
	marker := regexp.MustCompile(`(?m)^\s*//\s*package\s+([a-z]+)\s*$`)
	matches := marker.FindAllStringSubmatchIndex(doc, -1)
	for i, m := range matches {
		pkg := doc[m[2]:m[3]]
		end := len(doc)
		if i+1 < len(matches) {
			end = matches[i+1][0] // 下一分节的标记起点
		}
		segments[pkg] = segments[pkg] + doc[m[1]:end]
	}
	return segments
}

type roleSymbol struct {
	Package     string
	Name        string
	ParamTypes  []string
	ResultTypes []string
}

type docDeclaration struct {
	Raw         string
	ParamTypes  []string
	ResultTypes []string
}

// stripAll 对整条类型序列剥包限定前缀。
func stripAll(types []string) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = stripQualifiers(t)
	}
	return out
}

// collectRoleSymbols 遍历三个角色包的非测试 Go 文件。
func collectRoleSymbols(t *testing.T) []roleSymbol {
	t.Helper()
	var out []roleSymbol
	for _, pkg := range []string{"buyer", "seller", "arbiter"} {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil || !fn.Name.IsExported() {
					continue
				}
				// 只锁定角色公开面：*Workflow 方法 + 包级函数。
				isWorkflowMethod := false
				if fn.Recv != nil && len(fn.Recv.List) == 1 {
					star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
					if ok {
						if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "Workflow" {
							isWorkflowMethod = true
						}
					}
				}
				if fn.Recv != nil && !isWorkflowMethod {
					continue
				}
				out = append(out, roleSymbol{
					Package:     pkg,
					Name:        fn.Name.Name,
					ParamTypes:  stripAll(fieldTypes(fn.Type.Params)),
					ResultTypes: stripAll(fieldTypes(fn.Type.Results)),
				})
			}
		}
	}
	return out
}

// fieldTypes 展开参数/结果字段的类型序列：具名字段按个数展开，匿名按 1 个。
func fieldTypes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var out []string
	for _, field := range fields.List {
		typeName := exprToTypeString(field.Type)
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			out = append(out, typeName)
		}
	}
	return out
}

// exprToTypeString 还原文档中书写类型的规范形态（去掉空格差异）。
func exprToTypeString(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprToTypeString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToTypeString(v.X)
	case *ast.ArrayType:
		return "[]" + exprToTypeString(v.Elt)
	case *ast.Ellipsis:
		return "..." + exprToTypeString(v.Elt)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return "?"
	}
}

var docFuncRe = regexp.MustCompile(`\bfunc\b[^A-Za-z(]*`)

// findDocDeclaration 在文档中定位同名声明的完整签名（可能跨多行），并抽取
// 参数与返回值类型序列。正确处理接收者括号与嵌套括号：参数区间是紧跟在
// 函数名后的那对平衡括号。
func findDocDeclaration(doc, name string) (*docDeclaration, bool) {
	lines := strings.Split(doc, "\n")
	for index, line := range lines {
		loc := docFuncRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		header := line
		end := index
		for skip := 0; skip < 6; skip++ {
			if extractFuncHeaderName(header) == name {
				break
			}
			// 名字可能在下一行（如 "func (w *Workflow)" 后换行接名字）。
			if end+1 >= len(lines) {
				break
			}
			end++
			header += " " + strings.TrimSpace(lines[end])
		}
		if extractFuncHeaderName(header) != name {
			continue
		}
		paramsText, rest, ok := splitSignature(header)
		if !ok {
			continue
		}
		results := []string{}
		if rest != "" {
			results = splitTopLevel(rest)
		}
		return &docDeclaration{
			Raw:         header,
			ParamTypes:  normalizeTypes(splitTopLevel(paramsText)),
			ResultTypes: normalizeTypes(results),
		}, true
	}
	return nil, false
}

// extractFuncHeaderName 返回签名头中的函数名；无接收者/名字时返回空串。
func extractFuncHeaderName(header string) string {
	i := strings.Index(header, "func")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(header[i+len("func"):])
	if strings.HasPrefix(rest, "(") {
		closeIdx := matchParen(rest, 0)
		if closeIdx < 0 {
			return ""
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	nameEnd := strings.IndexFunc(rest, func(r rune) bool { return r == '(' || r == ' ' || r == '\t' })
	if nameEnd < 0 {
		return rest
	}
	return rest[:nameEnd]
}

// splitSignature 把 "func [(recv)] Name(params) (results)" 拆成参数文本与
// 返回值文本。results 可为单类型（无括号）或元组。
func splitSignature(header string) (paramsText, results string, ok bool) {
	i := strings.Index(header, "func")
	if i < 0 {
		return "", "", false
	}
	rest := strings.TrimSpace(header[i+4:])
	if strings.HasPrefix(rest, "(") {
		closeIdx := matchParen(rest, 0)
		if closeIdx < 0 {
			return "", "", false
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	openRel := strings.Index(rest, "(")
	if openRel < 0 {
		return "", "", false
	}
	name := strings.TrimSpace(rest[:openRel])
	if name == "" {
		return "", "", false
	}
	closeRel := matchParen(rest, openRel)
	if closeRel < 0 {
		return "", "", false
	}
	paramsText = rest[openRel+1 : closeRel]
	results = strings.TrimSpace(rest[closeRel+1:])
	// 仅当整体是顶层平衡元组时才去括号；绝不能剥掉 (*T, error) 的星号。
	if strings.HasPrefix(results, "(") && matchParen(results, 0) == len(results)-1 {
		results = results[1 : len(results)-1]
	}
	return paramsText, results, true
}

// matchParen 返回与 text[start] 的左括号配对的右括号下标；不配对返回 -1。
func matchParen(text string, start int) int {
	depth := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// predeclaredTypes 是不能当作"具名参数名字"的内建类型。
var predeclaredTypes = map[string]bool{"error": true, "string": true, "bool": true, "any": true,
	"byte": true, "rune": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true}

// bareIdentifier 报告片段是否是纯小写驼峰标识符（即具名参数的名字部分，
// 不含任何类型语法字符）；内建类型名不算名字。
func bareIdentifier(part string) bool {
	if predeclaredTypes[part] {
		return false
	}
	if part == "" {
		return false
	}
	for _, r := range part {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// repoQualifiers 是仓库内可能出现的包限定前缀；两侧统一剥离后按裸类型名
// 比较，避免"同包选择符省略"造成的假漂移（如源里 *PreparedArbitration vs
// 文档 *arbitration.PreparedArbitration）。
var repoQualifiers = [...]string{"buyer.", "seller.", "arbiter.", "content.", "pool.", "protocol.", "arbitration.", "wire.", "time.", "context.", "ec."}

// stripQualifiers 剥离已知包限定前缀；允许前导 */[] 等类型符号。
func stripQualifiers(t string) string {
	prefix := ""
	for strings.HasPrefix(t, "*") || strings.HasPrefix(t, "[]") {
		if strings.HasPrefix(t, "*") {
			prefix += "*"
			t = strings.TrimPrefix(t, "*")
		} else {
			prefix += "[]"
			t = strings.TrimPrefix(t, "[]")
		}
	}
	for {
		changed := false
		for _, q := range repoQualifiers {
			if strings.HasPrefix(t, q) {
				t = strings.TrimPrefix(t, q)
				changed = true
			}
		}
		if !changed {
			return prefix + t
		}
	}
}

// normalizeTypes 把逗号切分后的片段还原为纯类型序列：
//   - 具名分组 "rawKind1, rawKind5, openingProofCBOR []byte" 中，无类型的
//     纯标识符片段属于下一个带类型的片段（名字数量决定展开个数）；
//   - "ctx context.Context" 取末段为类型；
//   - 最后统一剥离包限定前缀。
func normalizeTypes(parts []string) []string {
	out := make([]string, 0, len(parts))
	names := 0 // 待展开的具名个数
	for _, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) > 1 {
			names += len(fields) - 1 // 具名分组：累计名字个数
			part = fields[len(fields)-1]
		} else if bareIdentifier(part) {
			names++
			continue
		}
		t := stripQualifiers(strings.NewReplacer(" ", "", "\t", "").Replace(part))
		count := names
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			out = append(out, t)
		}
		names = 0
	}
	return out
}

// splitTopLevel 按逗号切分（忽略括号内逗号）。
func splitTopLevel(text string) []string {
	var parts []string
	depth := 0
	current := strings.Builder{}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, current.String())
				current.Reset()
				continue
			}
		}
		current.WriteByte(text[i])
	}
	if tail := strings.TrimSpace(current.String()); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}
