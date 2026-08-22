// 生成 TS→Go 交易签名向量：用 @bsv/sdk 官方 preimage 路径计算 MultisigPool
// sighash（SHA-256d(preimage)，ForkID|All），再用 ECDSA 对该摘要直接签名，
// 绝不二次哈希。--check 时在内存中重算并与已提交 fixture 比较，不写文件。
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, LockingScript, PrivateKey, BigNumber, ECDSA } from "@bsv/sdk";

const check = process.argv.includes("--check");

const fixture = JSON.parse(readFileSync(new URL("./transaction_sighash_vector.json", import.meta.url), "utf8"));
const bytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const sha256d = (data) => createHash("sha256").update(createHash("sha256").update(data).digest()).digest();

// 官方交易签名路径第一步：解析 raw tx 并挂上同一份 source output。
const spend = Transaction.fromHex(fixture.unsignedTxHex);
const source = new Transaction();
source.addOutput({
  satoshis: fixture.sourceSatoshis,
  lockingScript: LockingScript.fromHex(fixture.sourceLockingScriptHex),
});
spend.inputs[fixture.inputIndex].sourceTransaction = source;

// 第二步：官方 preimage（默认 scope 即 ForkID|All），再 SHA-256d 得到 sighash 摘要。
const preimage = Uint8Array.from(spend.preimage(fixture.inputIndex, fixture.sighashFlag));
const preimageHex = Buffer.from(preimage).toString("hex");
if (preimageHex !== fixture.preimageHex) {
  console.error("FAIL: TS preimage differs from Go preimage");
  process.exit(1);
}
const digest = sha256d(preimage);
const digestHex = digest.toString("hex");
if (digestHex !== fixture.sighashDigestHex) {
  console.error(`FAIL: TS sighash ${digestHex} != Go digest ${fixture.sighashDigestHex}`);
  process.exit(1);
}
if (fixture.sighashFlag !== 65) {
  console.error("FAIL: unexpected sighash flag, want 65 (ForkID|All)");
  process.exit(1);
}

// 第三步：官方 ECDSA 直接对已算好的摘要签名（forceLowS），不再哈希。
const key = PrivateKey.fromHex("1111111111111111111111111111111111111111111111111111111111111111");
if (key.toPublicKey().toString() !== fixture.buyerPubkeyHex) {
  console.error("FAIL: TS pubkey does not match fixture buyer role");
  process.exit(1);
}
const signature = ECDSA.sign(new BigNumber([...digest]), key, true);
const derHex = signature.toDER("hex");

// 第四步：TS 复验 Go 产生的交易 DER 在 verify-go-transaction-vector.mjs 完成。

const result = JSON.stringify(
  {
    algorithm: "MultisigPool v4 transaction sighash: SHA-256d(BSV preimage), ForkID|All, low-S DER over the digest",
    unsignedTxHex: fixture.unsignedTxHex,
    inputIndex: fixture.inputIndex,
    sourceSatoshis: fixture.sourceSatoshis,
    sourceLockingScriptHex: fixture.sourceLockingScriptHex,
    sighashFlag: fixture.sighashFlag,
    sighashDigestHex: digestHex,
    pubkeyHex: key.toPublicKey().toString(),
    tsDerSignatureHex: derHex,
    signer: "typescript @bsv/sdk Transaction.preimage + SHA-256d + ECDSA.sign (no extra hashing)",
  },
  null,
  2,
) + "\n";

if (check) {
  const committed = readFileSync(new URL("./ts_to_go_transaction_vector.json", import.meta.url), "utf8");
  if (committed !== result) {
    console.error("FAIL: regenerated transaction vector differs from committed ts_to_go_transaction_vector.json");
    process.exit(1);
  }
  console.log("transaction vector drift check OK");
} else {
  writeFileSync(new URL("./ts_to_go_transaction_vector.json", import.meta.url), result);
  console.log("ts_to_go_transaction_vector.json written");
}
