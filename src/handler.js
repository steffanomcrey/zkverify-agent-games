"use strict";

const { deriveSalt, signBody, verifyBodySignature } = require("./hmac");
const { buildCircuitInputs, evaluate, parseInput } = require("./decision");
const { Prover } = require("./prover");
const { submitProofAndPoll } = require("./kurier");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";

/**
 * Framework-agnostic request handling shared by the local server
 * (server.js) and the Vercel function (api/agent.js).
 *
 * Pipeline:
 *   1. HMAC over the RAW body vs x-agent-games-signature — before JSON
 *      parsing. Failure -> 401, no processing.
 *   2. Preflight (type = agent-games.preflight.v1) -> signed
 *      { ok: true, protocolVersion: "v1" }.
 *   3. Task (type = agent-games.proof-gatekeeper.v1): idempotency cache,
 *      timestamp sanity, deterministic policy evaluation, local Groth16
 *      proof (except PROOF_REUSED), optional Kurier submission, signed
 *      response. Any error or uncertainty fails closed to REJECT.
 *   4. GET health -> { ok: true, protocolVersion: "v1" } (unsigned).
 */
class AgentHandler {
  constructor(cfg, store) {
    this.cfg = cfg;
    this.store = store;
    this.prover = new Prover(cfg.circuitsDir);
  }

  health() {
    return {
      status: 200,
      body: JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION }),
      signature: null,
    };
  }

  async handlePost(rawBody, signatureHeader) {
    const startedAt = Date.now();

    if (!this.cfg.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({
          error: "server_misconfigured",
          detail: "AGENT_GAMES_SECRET not set",
        }),
        signature: null,
      };
    }

    // 1. Authenticate the raw body BEFORE parsing.
    if (!verifyBodySignature(this.cfg.hmacSecret, rawBody, signatureHeader)) {
      return {
        status: 401,
        body: JSON.stringify({ error: "invalid_signature" }),
        signature: null,
      };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 2. Preflight handshake.
    if (envelope.type === PREFLIGHT_TYPE) {
      return this.signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (envelope.type !== TASK_TYPE) {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 3. Task.
    try {
      return await this.handleTask(envelope, startedAt);
    } catch (err) {
      // Fail closed: never approve on an internal error.
      console.error("[agent] task handling error:", err.message);
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
  }

  async handleTask(task, startedAt) {
    // Idempotent redelivery: answer from the cache, never re-evaluate
    // (a redelivery must not be mistaken for proof reuse).
    if (task.task_id) {
      const cached = await this.store.getResponse(task.task_id);
      if (cached) return this.signedRaw(200, cached);
    }

    // Timestamp / deadline sanity (HMAC already authenticates the sender;
    // this is anti-replay hygiene). Unparseable timestamps are tolerated —
    // only a clearly-past deadline fails the task.
    const now = Date.now();
    const deadlineMs = parseTimestamp(task.deadline_at);
    const issuedMs = parseTimestamp(task.issued_at);
    if (deadlineMs !== null && now > deadlineMs) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
    if (issuedMs !== null && issuedMs > now + 5 * 60_000) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const parsed = parseInput(task.input);
    if (!parsed || !task.task_id) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // Warm the seen-set from the durable backend before deciding, so a
    // replayed proof is caught even across instances/restarts.
    await this.store.hasProofTx(parsed.proofTx);
    const evaluation = evaluate(parsed, (tx) => this.store.hasProofTxSync(tx));

    const response = {
      decision: evaluation.decision,
      reason_code: evaluation.reason_code,
    };

    if (evaluation.provable) {
      const salt = deriveSalt(this.cfg.hmacSecret, task.task_id);
      const circuitInputs = buildCircuitInputs(
        task,
        parsed,
        evaluation.decision,
        salt,
      );
      try {
        const { proof, publicSignals } = await this.prover.prove(circuitInputs);
        response.proof = proof;
        response.public_signals = publicSignals;

        // Optional zkVerify submission via Kurier, bounded so the
        // response stays well inside the 60 s deadline. Skipped entirely
        // when no KURIER_API_KEY is configured ($0 path): the response
        // already carries the full proof + public signals for the
        // platform to verify itself.
        const remaining = this.cfg.taskSoftDeadlineMs - (Date.now() - startedAt);
        const budget = Math.min(
          this.cfg.kurierPollBudgetMs,
          Math.max(0, remaining),
        );
        const kurier = await submitProofAndPoll(
          this.cfg,
          proof,
          publicSignals,
          budget,
        );
        response.proof_tx = kurier?.txHash ? kurier.txHash : parsed.proofTx;
      } catch (err) {
        // Proving failed: fail closed. A claimed APPROVE without a valid
        // proof is the worst outcome, so downgrade to REJECT with no proof.
        console.error("[agent] proof generation failed:", err.message);
        return this.signed(200, {
          decision: "REJECT",
          reason_code:
            evaluation.decision === "APPROVE"
              ? "INVALID_TASK"
              : evaluation.reason_code,
          proof_tx: parsed.proofTx,
        });
      }
    } else {
      // PROOF_REUSED: documented as having no proof to submit; echo the
      // judged reference, matching the documented sample response shape.
      response.proof_tx = parsed.proofTx;
    }

    const result = this.signed(200, response);
    // Record only after a successful evaluation, so a task never flags itself.
    await this.store.recordProofTx(parsed.proofTx);
    await this.store.recordResponse(task.task_id, result.body);
    return result;
  }

  signed(status, obj) {
    return this.signedRaw(status, JSON.stringify(obj));
  }

  signedRaw(status, body) {
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }
}

/** Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms. */
function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string") {
    const asNum = Number(v);
    if (/^[0-9]+$/.test(v.trim()) && Number.isFinite(asNum)) {
      return asNum < 1e12 ? asNum * 1000 : asNum;
    }
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

module.exports = {
  AgentHandler,
  TASK_TYPE,
  PREFLIGHT_TYPE,
  PROTOCOL_VERSION,
  SIGNATURE_HEADER,
  parseTimestamp,
};
