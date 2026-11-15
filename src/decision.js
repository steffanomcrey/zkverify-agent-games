"use strict";

const crypto = require("crypto");
const { BN128_PRIME } = require("./hmac");

/**
 * Deterministic policy for Proof Gatekeeper. No model involvement: the
 * final call is made here, fail-closed. Checks map 1:1 onto the trap
 * taxonomy on the event page:
 *
 *   proof_vk != registered_vk          -> VK_SUBSTITUTION
 *   proof_tx already in the seen-set   -> PROOF_REUSED (no proof to submit)
 *   public_balance < minimum           -> THRESHOLD_MISMATCH
 *   current_block >= expiry_block      -> EXPIRED_CONDITION
 *   recipient != condition_recipient   -> RECIPIENT_MISMATCH
 *   amount > max_transfer              -> AMOUNT_OVERFLOW
 *   otherwise                          -> APPROVE / VALID_CONDITION
 *
 * The gatekeeper circuit enforces exactly these comparisons on its public
 * inputs: the `decision` input must equal the AND of the five field checks,
 * or witness generation fails. The off-chain evaluation here must therefore
 * mirror them precisely, including the boundary semantics: balance >=
 * minimum passes, amount <= max_transfer passes, current_block <
 * expiry_block passes. (Proof reuse is stateful and deliberately NOT in
 * the circuit; a PROOF_REUSED rejection is unprovable by construction and
 * the protocol exempts it from proof submission.)
 *
 * Precedence when several checks fail at once follows the production-proven
 * participant implementation: VK_SUBSTITUTION -> PROOF_REUSED ->
 * THRESHOLD_MISMATCH -> EXPIRED_CONDITION -> RECIPIENT_MISMATCH ->
 * AMOUNT_OVERFLOW. Platform tasks are designed single-trap, so this order
 * should rarely decide anything.
 */

const REASON_CODES = [
  "VALID_CONDITION",
  "VK_SUBSTITUTION",
  "PROOF_REUSED",
  "THRESHOLD_MISMATCH",
  "EXPIRED_CONDITION",
  "RECIPIENT_MISMATCH",
  "AMOUNT_OVERFLOW",
];

function normalizeHex(v) {
  return (v ?? "").trim().toLowerCase();
}

/** Parse a non-negative integer given as a decimal string, hex string, or number. */
function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/** Structural validation + parsing. Returns null on any malformed field. */
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null ||
    publicBalance === null ||
    amount === null ||
    maxTransfer === null ||
    expiryBlock === null ||
    currentBlock === null
  ) {
    return null;
  }
  if (
    typeof input.registered_vk !== "string" ||
    !input.registered_vk ||
    typeof input.proof_vk !== "string" ||
    !input.proof_vk ||
    typeof input.recipient !== "string" ||
    !input.recipient ||
    typeof input.condition_recipient !== "string" ||
    !input.condition_recipient ||
    typeof input.proof_tx !== "string" ||
    !input.proof_tx
  ) {
    return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

/**
 * Evaluate the six checks. `isProofTxSeen` is a synchronous predicate over
 * the caller's seen-set snapshot.
 * Returns { decision, reason_code, provable } — provable is false only for
 * PROOF_REUSED, which carries no proof by protocol design.
 */
function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    // Documented special case: a reused-proof task has no proof to submit.
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Convert an envelope value to a BN128 field element (decimal string).
 * Hex values are reduced mod p (a 32-byte hash does not fit the field);
 * reduction preserves equality, which is all the circuit checks. Free-form
 * identifiers (e.g. a task_id like "gk_24_9d1") are hashed (SHA-256) into
 * the field.
 */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  const reduced = ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
  return reduced.toString(10);
}

/**
 * Circuit inputs for gatekeeper.wasm. Signal names were recovered from the
 * artifact itself and confirmed by proving against the live platform:
 *   inputs: taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *           expiryBlock, currentBlock, recipient, conditionRecipient,
 *           amount, maxTransfer, decision, salt (private)
 *   public signals: [commitment, registeredVkHash, proofVkHash, minimum,
 *           publicBalance, expiryBlock, currentBlock, recipient,
 *           conditionRecipient, amount, maxTransfer, decision, taskId]
 * where commitment = Poseidon(taskId, salt) is the circuit's output signal.
 */
function buildCircuitInputs(envelope, parsed, decision, salt) {
  return {
    taskId: toFieldElement(envelope.task_id),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

module.exports = {
  REASON_CODES,
  normalizeHex,
  parseUint,
  parseInput,
  evaluate,
  toFieldElement,
  buildCircuitInputs,
};
