// 生成 TS→Go 005 payment state 签名向量：解析 Go 确定性重建的 expected
// unsigned raw，用 @bsv/sdk 官方 preimage 路径计算 sighash（SHA-256d，
// ForkID|All），再用 ECDSA 对该摘要直接低 S 签名，绝不二次哈希。--check 时
// 在内存中重算并与已提交 fixture 比较，不写文件。
//
// 承诺边界：本脚本不包含 BuildPaymentUpdate 的 TS 等价构造——它证明的是
// TS 能对 Go 重建出的精确状态交易计算相同 preimage/sighash 并互验 DER，
// 而不是 TS 能从 OpeningProof/previous/sequence/amount 独立重建交易。
// 在补齐等价构造并通过向量之前，v4 005 只承诺 Go 实现互操作。
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, LockingScript, PrivateKey, BigNumber, ECDSA } from "@bsv/sdk";

const check = process.argv.includes("--check");

const fixture = JSON.parse(readFileSync(new URL("./payment_state_sighash_vector.json", import.meta.url), "utf8"));
const bytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));
const sha256d = (data) => createHash("sha256").update(createHash("sha256").update(data).digest()).digest();

const spend = Transaction.fromHex(fixture.expectedUnsignedRawHex);
const source = new Transaction();
source.addOutput({
  satoshis: fixture.sourceSatoshis,
  lockingScript: LockingScript.fromHex(fixture.sourceLockingScriptHex),
});
spend.inputs[fixture.inputIndex].sourceTransaction = source;

const preimage = Uint8Array.from(spend.preimage(fixture.inputIndex, fixture.sighashFlag));
if (Buffer.from(preimage).toString("hex") !== fixture.preimageHex) {
  console.error("FAIL: TS preimage differs from Go preimage");
  process.exit(1);
}
const digest = sha256d(preimage);
const digestHex = digest.toString("hex");
if (digestHex !== fixture.sighashDigestHex) {
  console.error(`FAIL: TS sighash ${digestHex} != Go digest ${fixture.sighashDigestHex}`);
  process.exit(1);
}

// TS 复算的签名对象必须是重建出的 005 状态交易本身。
if (spend.outputs.length !== 3) {
  console.error("FAIL: 005 payment state must carry the three [Buyer, Seller, Arbiter] outputs");
  process.exit(1);
}

const key = PrivateKey.fromHex("1111111111111111111111111111111111111111111111111111111111111111");
if (key.toPublicKey().toString() !== fixture.buyerPubkeyHex) {
  console.error("FAIL: TS pubkey does not match fixture buyer role");
  process.exit(1);
}
const signature = ECDSA.sign(new BigNumber([...digest]), key, true);
const derHex = signature.toDER("hex");

const result = JSON.stringify(
  {
    algorithm: "MultisigPool v4 005 cumulative payment state rebuilt deterministically by BuildPaymentUpdate; sighash = SHA-256d(BSV preimage), ForkID|All, low-S DER over the digest. This is NOT the RefundTemplate.",
    expectedUnsignedRawHex: fixture.expectedUnsignedRawHex,
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
  const committed = readFileSync(new URL("./ts_to_go_payment_state_vector.json", import.meta.url), "utf8");
  if (committed !== result) {
    console.error("FAIL: regenerated payment state vector differs from committed ts_to_go_payment_state_vector.json");
    process.exit(1);
  }
  console.log("payment state vector drift check OK");
} else {
  writeFileSync(new URL("./ts_to_go_payment_state_vector.json", import.meta.url), result);
  console.log("ts_to_go_payment_state_vector.json written");
}
