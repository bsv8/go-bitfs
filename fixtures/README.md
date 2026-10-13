# BitFS 双语言共享测试真值

本目录是 Go 与 TypeScript 一致性测试的唯一入口。`manifest.json` 中的字段含义：

- `format`：fixture 集合格式名；用于防止误读其他项目的测试数据。
- `version`：fixture 清单版本；它不等同于 wire 协议版本。
- `wire_manifest`：Kind 1–13 完整 CBOR 报文、SHA-256 与子文档 ID 的冻结向量；Kind 12 携带买方费用池 ID、未签关闭交易与买方交易签名，Kind 13 携带卖方费用池 ID 与完整关闭交易。
- `transaction_manifest`：开池、付款、关闭、仲裁交易与签名的冻结真值路径。
- `protocol_schema`：Wire v1 的 CDDL 规范路径。
- `transport_profile`：bitcoin-libp2p Protocol ID、uvarint 分帧和接收上限真值路径。
- `invalid_wire`：Go/TypeScript 必须映射到相同稳定错误分类的畸形输入。
- `role_manifest`：固定 Signer 下的角色纯函数真值（已覆盖 Kind 1–13 报文与交易原文，包括买方发 Kind 12、卖方回 Kind 13 与买方验收）、
  计价向量（seed/整块/末块/组合/边界/溢出）与语义拒绝向量（两语言必须同码拒绝）。

清单路径均相对仓库根目录。两种语言不得复制或在各自目录维护第二份期望值。
更新 frozen JSON 必须经过协议兼容性审查，不能为了让测试通过而自动重写。
`role-v1.json` 由 `go test ./internal/conformance -run TestRoleFixtureMatchesFrozenFile -update-role-fixtures`
在人工审查后重建；TypeScript 只消费，不生成。
