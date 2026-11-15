"use strict";

/**
 * Vercel serverless entry for the agent endpoint.
 *
 * vercel.json rewrites /agent -> /api/agent, so the registered endpoint
 * URL is https://<deployment>/agent (the full handler path, as the
 * platform requires). The raw request body is read from the stream
 * untouched — HMAC verification happens over the exact bytes received,
 * before any JSON parsing.
 *
 * The handler/store are created once per warm instance; the durable
 * seen-set lives in the external KV when configured (see src/store.js).
 */

const { loadConfig } = require("../src/config");
const { AgentHandler, SIGNATURE_HEADER } = require("../src/handler");
const { Store } = require("../src/store");

let handler = null;
function getHandler() {
  if (!handler) {
    const cfg = loadConfig();
    handler = new AgentHandler(cfg, new Store(cfg));
  }
  return handler;
}

const MAX_BODY_BYTES = 1_048_576;

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("payload_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  const h = getHandler();

  if (req.method === "GET") {
    const r = h.health();
    res.status(r.status);
    res.setHeader("content-type", "application/json");
    res.send(r.body);
    return;
  }

  if (req.method !== "POST") {
    res.status(405);
    res.setHeader("content-type", "application/json");
    res.send(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch {
    res.status(413);
    res.setHeader("content-type", "application/json");
    res.send(JSON.stringify({ error: "payload_too_large" }));
    return;
  }

  const signature = req.headers[SIGNATURE_HEADER];
  const result = await h.handlePost(
    rawBody,
    Array.isArray(signature) ? signature[0] : signature,
  );
  res.status(result.status);
  res.setHeader("content-type", "application/json");
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.send(result.body);
};

// Ask Vercel not to pre-parse the body; the handler needs the raw bytes.
module.exports.config = { api: { bodyParser: false } };
