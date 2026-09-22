.PHONY: test test-go test-typescript conformance fmt-check-go

# test 是本仓库统一测试入口：两种语言必须全部通过。
test: test-go test-typescript

# test-go 运行 Go SDK、共享真值与网络适配测试。
test-go:
	go test ./...

# test-typescript 运行 TypeScript 类型检查、构建与测试。
test-typescript:
	npm ci --prefix typescript
	npm run typecheck --prefix typescript
	npm run build --prefix typescript
	npm test --prefix typescript

# conformance 明确表示 Go 与 TypeScript 消费同一套 fixtures。
conformance:
	go test ./internal/conformance ./wire ./pool -run 'Manifest|SharedInvalidWireFixtures'
	npm run test:conformance --prefix typescript

fmt-check-go:
	test -z "$$(gofmt -l $$(find . -path ./vendor -prune -o -path ./typescript -prune -o -name '*.go' -print))"
