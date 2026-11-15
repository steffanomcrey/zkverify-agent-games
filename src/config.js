"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Runtime configuration, all from environment variables.
 *
 * AGENT_GAMES_SECRET (required): the platform-generated HMAC secret for this
 * agent, from the Agent Games dashboard (agent settings -> Rotate Secret).
 * It is shown exactly once by the platform; never hardcode it, never commit it.
 *
 * KURIER_API_KEY (optional): when unset, the agent still answers every task
 * with the full Groth16 proof + public signals and the platform verifies
 * them itself ($0 path). When set, proofs are also submitted to zkVerify
 * mainnet via Kurier and the submission tx hash is returned as proof_tx.
 */

const DEFAULT_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function defaultCircuitsDir() {
  const candidates = [
    path.resolve(__dirname, "..", "circuits"),
    path.resolve(__dirname, "..", "..", "circuits"),
    path.resolve(process.cwd(), "circuits"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "gatekeeper.wasm"))) return c;
  }
  return candidates[0];
}

function defaultStoreFile() {
  // Vercel serverless filesystems are read-only except /tmp.
  if (process.env.VERCEL) return "/tmp/agentgames-store.json";
  return path.resolve(process.cwd(), "data", "store.json");
}

function loadConfig(env = process.env) {
  return {
    hmacSecret: env.AGENT_GAMES_SECRET || env.AGENT_GAMES_HMAC_SECRET || "",
    kurierApiKey: env.KURIER_API_KEY ? env.KURIER_API_KEY : null,
    kurierApiUrl: env.KURIER_API_URL || "https://api.kurier.xyz/api/v1",
    gatekeeperVkHash: env.GATEKEEPER_VK_HASH || DEFAULT_VK_HASH,
    circuitsDir: env.CIRCUITS_DIR || defaultCircuitsDir(),
    // Durable store: external KV via REST when configured, else local file.
    kvRestUrl:
      env.STORE_REST_URL ||
      env.KV_REST_API_URL ||
      env.UPSTASH_REDIS_REST_URL ||
      "",
    kvRestToken:
      env.STORE_REST_TOKEN ||
      env.KV_REST_API_TOKEN ||
      env.UPSTASH_REDIS_REST_TOKEN ||
      "",
    storeFile: env.STORE_FILE || env.SEEN_STORE_PATH || defaultStoreFile(),
    kurierPollBudgetMs: Number(env.KURIER_POLL_BUDGET_MS || 15_000),
    kurierPollIntervalMs: Number(env.KURIER_POLL_INTERVAL_MS || 3_000),
    taskSoftDeadlineMs: Number(env.TASK_SOFT_DEADLINE_MS || 50_000),
    port: Number(env.PORT || 8787),
  };
}

module.exports = { loadConfig, DEFAULT_VK_HASH };
