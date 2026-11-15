"use strict";

/**
 * Download the official gatekeeper circuit artifacts into circuits/.
 * They are also committed to the repo (bundled for the Vercel deploy);
 * run this to refresh them from the platform's canonical source.
 *
 * Source of truth: GET https://agentgames.zkverify.io/api/circuit-info
 *   gatekeeper.wasm        1,755,820 bytes  sha256 be00aefe...2764f
 *   gatekeeper_final.zkey    309,750 bytes  sha256 adfe95a4...af80d
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const FILES = [
  "gatekeeper.wasm",
  "gatekeeper_final.zkey",
];

async function main() {
  const dir = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(dir, { recursive: true });
  const info = await (await fetch("https://agentgames.zkverify.io/api/circuit-info")).json();
  const artifacts = info.circuits.gatekeeper.artifacts;
  for (const name of FILES) {
    const url = name.endsWith(".wasm") ? artifacts.wasm : artifacts.zkey;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const out = path.join(dir, name);
    fs.writeFileSync(out, buf);
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    console.log(`${name}: ${buf.length} bytes sha256 ${sha}`);
    console.log(`  -> ${out}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
