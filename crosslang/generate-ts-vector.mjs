// 生成 TS→Go 普通消息向量：用 @bsv/sdk 私钥对固定 canonical CBOR 签名。
// PrivateKey.sign(message) 自行做一次 SHA-256 —— 与 Go 侧 SignMessage 一致。
// --check 时在内存中重算并与已提交 fixture 比较，不同则退出码 1，绝不写文件。
import { writeFileSync, readFileSync } from "node:fs";
import { PrivateKey } from "@bsv/sdk";
import { createHash } from "node:crypto";

const check = process.argv.includes("--check");

const go = JSON.parse(readFileSync(new URL("./go_to_ts_vector.json", import.meta.url), "utf8"));
const messageHex = go.messageHex; // 同一类 canonical 001 quote terms CBOR

const key = PrivateKey.fromHex("1111111111111111111111111111111111111111111111111111111111111111");
const message = Uint8Array.from(messageHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const sig = key.sign(message); // 内部恰好一次 SHA-256
let derHex;
try {
  derHex = sig.toDER(); // 若返回 string
} catch {
  derHex = [...sig.toDERBytes?.() ?? sig.toBytes()].map((b) => b.toString(16).padStart(2, "0")).join("");
}
if (typeof derHex !== "string") {
  derHex = [...derHex].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const digest = createHash("sha256").update(message).digest();
const digestHex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");

const result = JSON.stringify(
  {
    algorithm: "ECDSA-over-secp256k1, message hashed once with SHA-256",
    messageHex,
    digestHex,
    pubkeyHex: key.toPublicKey().toString(),
    derSigHex: derHex,
    signer: "typescript @bsv/sdk PrivateKey.sign (single SHA-256)",
  },
  null,
  2,
) + "\n";

if (check) {
  const committed = readFileSync(new URL("./ts_to_go_vector.json", import.meta.url), "utf8");
  if (committed !== result) {
    console.error("FAIL: regenerated message vector differs from committed ts_to_go_vector.json");
    process.exit(1);
  }
  console.log("message vector drift check OK");
} else {
  writeFileSync(new URL("./ts_to_go_vector.json", import.meta.url), result);
  console.log("ts_to_go_vector.json written");
}
