"use strict";

const path = require("path");
const snarkjs = require("snarkjs");

/**
 * Local Groth16 proving with snarkjs fullProve against the official
 * gatekeeper artifacts downloaded from
 * https://agentgames.zkverify.io/circuits/ (see /api/circuit-info).
 * Kurier does NOT prove; the agent generates the proof itself.
 * Measured at ~0.3-1.3 s per proof for this circuit, comfortably inside
 * the 60 s task deadline.
 */
class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
  }

  async prove(circuitInputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof, publicSignals };
  }
}

module.exports = { Prover };
