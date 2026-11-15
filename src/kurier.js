"use strict";

/**
 * Kurier (zkVerify) proof submission — mainnet. OPTIONAL enhancement:
 * only used when KURIER_API_KEY is configured. Without a key the agent
 * still answers with the full proof + public signals and the platform
 * verifies them itself (the $0 path).
 *
 *   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
 *   { proofType: "groth16", vkRegistered: true,
 *     proofOptions: { library: "snarkjs", curve: "bn128" },
 *     proofData: { proof, publicSignals, vk: <vk_hash> } }
 *   -> { jobId, optimisticVerify }
 *   GET {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
 *   lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock ->
 *              Finalized | Failed
 *
 * The txHash exists from the Submitted status onward, so polling returns
 * as soon as a txHash is known instead of blocking the task response on
 * finalization; the Kurier job keeps finalizing server-side regardless.
 * The gatekeeper vk_hash is already registered on mainnet by the
 * platform, so vkRegistered: true and no register-vk call is needed.
 *
 * This module never throws: any failure returns null / a non-final
 * outcome and the caller still answers the task.
 */
async function submitProofAndPoll(cfg, proof, publicSignals, budgetMs) {
  if (!cfg.kurierApiKey) {
    console.log("[kurier] KURIER_API_KEY not set — skipping zkVerify submission");
    return null;
  }
  const key = cfg.kurierApiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${cfg.kurierApiUrl}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: cfg.gatekeeperVkHash },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }
    console.log(
      `[kurier] job ${job.jobId} submitted (optimisticVerify=${job.optimisticVerify ?? "n/a"})`,
    );

    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(
        Math.min(cfg.kurierPollIntervalMs, Math.max(0, deadline - Date.now())),
      );
      const statusRes = await fetch(
        `${cfg.kurierApiUrl}/job-status/${key}/${job.jobId}`,
      );
      if (!statusRes.ok) {
        console.error(`[kurier] job-status HTTP ${statusRes.status}`);
        continue;
      }
      const s = await statusRes.json();
      status = s.status ?? status;
      const txHash = s.txHash ?? s.transactionInfo?.txHash;
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        // The on-chain transaction exists from Submitted onward; return
        // its hash now and let finalization complete server-side.
        return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
      }
    }
    console.log(
      `[kurier] job ${job.jobId} produced no txHash within budget (last status=${status})`,
    );
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err.message);
    return null;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { submitProofAndPoll };
