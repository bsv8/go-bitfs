package docs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// TestExportedStructFieldsHaveChineseDocs 落实 AGENTS.md 的仓库要求：
// 程序与文档中的字段必须有中文说明。扫描七个公开包的全部非测试 Go 文件，
// 要求每个 exported struct type 的每个 exported 字段都带有相邻注释
// （字段上方 doc comment 或行尾 comment），且注释至少包含一个中文字符。
// 中文说明必须回答：业务含义、单位与绝对/增量语义、exact CBOR / ID / 签名
// 绑定对象、是否进入 wire 与签名预映像还是仅 attachment，以及可空条件与
// 分支约束。
func TestExportedStructFieldsHaveChineseDocs(t *testing.T) {
	packages := []string{"content", "pool", "buyer", "seller", "arbiter", "arbitration", "wire", "protocol"}

	for _, pkg := range packages {
		pkgDir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(pkgDir)
		if err != nil {
			t.Fatalf("read %s: %v", pkgDir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(pkgDir, name)
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, path, source, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			relative := filepath.ToSlash(path)
			ast.Inspect(file, func(node ast.Node) bool {
				typeSpec, ok := node.(*ast.TypeSpec)
				if !ok || typeSpec.Name == nil || !ast.IsExported(typeSpec.Name.Name) {
					return true
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range structType.Fields.List {
					exportedFieldName := ""
					for _, fieldName := range field.Names {
						if ast.IsExported(fieldName.Name) {
							exportedFieldName = fieldName.Name
							break
						}
					}
					if exportedFieldName == "" {
						continue // 内嵌未导出类型或私有字段不在签收范围
					}
					comment := fieldComment(field)
					if !containsHan(comment) {
						position := fileSet.Position(field.Pos())
						t.Errorf("%s:%d exported field %s.%s lacks a Chinese doc comment",
							relative, position.Line, typeSpec.Name.Name, exportedFieldName)
					}
				}
				return true
			})
		}
	}
}

// fieldComment 拼接字段上方 doc comment 与行尾 comment。
func fieldComment(field *ast.Field) string {
	var parts []string
	if field.Doc != nil {
		for _, comment := range field.Doc.List {
			parts = append(parts, strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(comment.Text), "//"), " "))
		}
	}
	if field.Comment != nil {
		for _, comment := range field.Comment.List {
			parts = append(parts, strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(comment.Text), "//"), " "))
		}
	}
	return strings.Join(parts, "\n")
}

// containsHan 报告文本中是否至少包含一个中日韩统一表意文字。
func containsHan(text string) bool {
	for _, runeValue := range text {
		if unicode.Is(unicode.Han, runeValue) {
			return true
		}
	}
	return false
}
