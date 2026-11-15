"use strict";

const http = require("http");
const { loadConfig } = require("./src/config");
const { AgentHandler, SIGNATURE_HEADER } = require("./src/handler");
const { Store } = require("./src/store");

/**
 * Plain Node HTTP server for local runs and non-serverless hosting.
 * Routes:
 *   POST /agent   — the registered agent endpoint (tasks + preflight)
 *   GET  /agent   — health check { ok: true, protocolVersion: "v1" }
 *   GET  /health  — same health payload
 */
const MAX_BODY_BYTES = 1_048_576;

function createAgentServer(cfg = loadConfig()) {
  const handler = new AgentHandler(cfg, new Store(cfg));

  return http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const isAgentPath = url.pathname === "/agent" || url.pathname === "/";

    if (req.method === "GET" && (isAgentPath || url.pathname === "/health")) {
      const r = handler.health();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }

    if (req.method === "POST" && isAgentPath) {
      const chunks = [];
      let size = 0;
      let rejected = false;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          rejected = true;
          res.writeHead(413, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "payload_too_large" }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", async () => {
        if (rejected) return;
        const rawBody = Buffer.concat(chunks);
        const signature = req.headers[SIGNATURE_HEADER];
        try {
          const result = await handler.handlePost(
            rawBody,
            Array.isArray(signature) ? signature[0] : signature,
          );
          const headers = { "content-type": "application/json" };
          if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
          res.writeHead(result.status, headers);
          res.end(result.body);
        } catch (err) {
          console.error("[agent] unhandled error:", err);
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "internal_error" }));
        }
      });
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
}

if (require.main === module) {
  const cfg = loadConfig();
  if (!cfg.hmacSecret) {
    console.warn(
      "[agent] WARNING: AGENT_GAMES_SECRET is not set — POSTs will fail with 500 until it is.",
    );
  }
  const server = createAgentServer(cfg);
  server.listen(cfg.port, () => {
    console.log(`[agent] listening on :${cfg.port} (POST /agent, GET /health)`);
    console.log(`[agent] circuits: ${cfg.circuitsDir}`);
    console.log(
      `[agent] kurier: ${cfg.kurierApiKey ? "enabled" : "disabled (no KURIER_API_KEY — $0 path)"}`,
    );
    console.log(
      `[agent] store: ${cfg.kvRestUrl ? "external KV (REST)" : `local file ${cfg.storeFile}`}`,
    );
  });
}

module.exports = { createAgentServer };
