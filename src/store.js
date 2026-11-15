"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Durable store for the two datasets the protocol depends on:
 *
 *  - seen-set of judged `input.proof_tx` values. This is a SECURITY
 *    control, not an optimization: the PROOF_REUSED trap class is a
 *    replayed proof, possibly delivered days later, and it must still be
 *    caught. Losing the seen-set silently re-opens that trap.
 *  - task_id -> serialized response cache, so a redelivered task is
 *    answered idempotently (byte-identical) instead of being re-evaluated
 *    or misread as proof reuse.
 *
 * Backends, in priority order:
 *  1. External KV over REST (Upstash-compatible) when STORE_REST_URL +
 *     STORE_REST_TOKEN (or KV_REST_API_URL / KV_REST_API_TOKEN, or
 *     UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN) are configured.
 *     This is the right backend on serverless (Vercel), where the local
 *     filesystem is ephemeral. KV calls are time-bounded and fail soft
 *     to the in-memory layer.
 *  2. Local JSON file (STORE_FILE), for local runs and long-lived hosts.
 *
 * An in-memory layer fronts both backends for speed within an instance.
 */

const KV_TIMEOUT_MS = 2000;

function normalizeTx(tx) {
  return (tx ?? "").trim().toLowerCase();
}

class Store {
  constructor(cfg) {
    this.cfg = cfg;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.kvEnabled = Boolean(cfg.kvRestUrl && cfg.kvRestToken);
    if (!this.kvEnabled) this.loadFile();
  }

  // ---- file backend ----------------------------------------------------

  loadFile() {
    try {
      const raw = fs.readFileSync(this.cfg.storeFile, "utf8");
      const data = JSON.parse(raw);
      for (const tx of data.proofTx ?? []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses ?? {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing/corrupt file -> start empty */
    }
  }

  persistFile() {
    try {
      fs.mkdirSync(path.dirname(this.cfg.storeFile), { recursive: true });
      const tmp = `${this.cfg.storeFile}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, this.cfg.storeFile);
    } catch (err) {
      console.error("[store] persist failed:", err.message);
    }
  }

  // ---- KV REST backend (Upstash-compatible) ----------------------------

  async kv(command) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), KV_TIMEOUT_MS);
    try {
      const res = await fetch(this.cfg.kvRestUrl, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.cfg.kvRestToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(command),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return data.result ?? null;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---- public API --------------------------------------------------------

  async hasProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key) return false;
    if (this.seenProofTx.has(key)) return true;
    if (this.kvEnabled) {
      try {
        const v = await this.kv(["GET", `seen:${key}`]);
        if (v !== null && v !== undefined) {
          this.seenProofTx.add(key);
          return true;
        }
      } catch (err) {
        console.error("[store] KV hasProofTx failed:", err.message);
      }
    }
    return false;
  }

  /** Synchronous snapshot check used by the decision step. */
  hasProofTxSync(proofTx) {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  async recordProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key) return;
    const isNew = !this.seenProofTx.has(key);
    this.seenProofTx.add(key);
    if (this.kvEnabled) {
      try {
        await this.kv(["SET", `seen:${key}`, "1"]);
      } catch (err) {
        console.error("[store] KV recordProofTx failed:", err.message);
      }
    } else if (isNew) {
      this.persistFile();
    }
  }

  async getResponse(taskId) {
    if (this.responseByTaskId.has(taskId)) {
      return this.responseByTaskId.get(taskId);
    }
    if (this.kvEnabled) {
      try {
        const v = await this.kv(["GET", `resp:${taskId}`]);
        if (typeof v === "string") {
          this.responseByTaskId.set(taskId, v);
          return v;
        }
      } catch (err) {
        console.error("[store] KV getResponse failed:", err.message);
      }
    }
    return null;
  }

  async recordResponse(taskId, serializedResponse) {
    if (!this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, serializedResponse);
      if (this.kvEnabled) {
        try {
          await this.kv(["SET", `resp:${taskId}`, serializedResponse]);
        } catch (err) {
          console.error("[store] KV recordResponse failed:", err.message);
        }
      } else {
        this.persistFile();
      }
    }
  }

  get size() {
    return this.seenProofTx.size;
  }
}

module.exports = { Store, normalizeTx };
