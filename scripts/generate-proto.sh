#!/usr/bin/env bash

# generate-proto.sh 根据仓库内 .proto 源码重新生成 Go 代码。
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in protoc protoc-gen-go protoc-gen-go-grpc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is required" >&2
        exit 1
    fi
done

protoc -I . \
    --go_out=module=github.com/bsv8/go-bitfs:. \
    --go-grpc_out=module=github.com/bsv8/go-bitfs:. \
    proto/bitfs/*.proto proto/pool2of3/*.proto
