// tools/web_selftest.js — dev-only Node harness for web/verifier.html.
//
// NOT a build or runtime dependency (same category as tests/golden/generate_golden.py
// and tools/bench_median.py). It exists because the page's own self-test button
// needs a human to click it, and shipping the JS verification core unverified is
// not acceptable. This script extracts the VERIFICATION CORE block from
// web/verifier.html, evaluates it under Node with a minimal DOM shim, and runs
// selfTest() against every backend backends() reports (WebCrypto via Node's
// crypto.subtle, plus the bundled hand-written SHA-256/HMAC) — exercising both
// implementations the same way the manual click would, just without a human.
//
// Usage: node tools/web_selftest.js
// Exit code: 0 if every backend passes every check, 1 otherwise.

"use strict";

const fs = require("fs");
const path = require("path");

const HTML_PATH = path.join(__dirname, "..", "web", "verifier.html");
const VECTORS_PATH = path.join(__dirname, "..", "docs", "pf_test_vectors.json");

const START_MARKER = "/* ===== VERIFICATION CORE";
const END_MARKER = "/* ===== END VERIFICATION CORE ===== */";

function extractCore(html) {
  const startIdx = html.indexOf(START_MARKER);
  if (startIdx === -1) throw new Error("start marker not found in " + HTML_PATH);
  const endIdx = html.indexOf(END_MARKER, startIdx);
  if (endIdx === -1) throw new Error("end marker not found in " + HTML_PATH);
  // Include the end marker's closing text position but not the marker itself
  // (the marker is a comment, harmless either way, but keep the extracted
  // region exactly the "core" as documented).
  return html.slice(startIdx, endIdx);
}

function main() {
  const html = fs.readFileSync(HTML_PATH, "utf-8");
  const vectorsText = fs.readFileSync(VECTORS_PATH, "utf-8");
  const coreSrc = extractCore(html);

  // Minimal DOM shim: only document.getElementById("pf-test-vectors") is used
  // by the core (inside loadVectors()), and only its .textContent is read.
  const document = {
    getElementById(id) {
      if (id === "pf-test-vectors") {
        return { textContent: vectorsText };
      }
      throw new Error("web_selftest.js shim: unexpected getElementById(" + id + ")");
    },
  };

  // Node 22.14.0 provides crypto.subtle, TextEncoder and BigInt as globals,
  // so the WebCrypto backend branch in backends() is genuinely exercised
  // here, not just the bundled JS branch.
  const sandbox = { document, window: {}, crypto, TextEncoder, BigInt, console };

  const wrapped =
    "(function(document, window, crypto, TextEncoder, BigInt, console) {\n" +
    coreSrc +
    "\nreturn window.PFCore;\n})";

  const factory = eval(wrapped); // eslint-disable-line no-eval
  const PFCore = factory(
    sandbox.document, sandbox.window, sandbox.crypto,
    sandbox.TextEncoder, sandbox.BigInt, sandbox.console
  );

  if (!PFCore || typeof PFCore.selfTest !== "function") {
    console.error("FAIL: window.PFCore.selfTest was not produced by the extracted core");
    process.exit(1);
  }

  (async () => {
    const list = await PFCore.backends();
    if (list.length === 0) {
      console.error("FAIL: backends() returned zero backends");
      process.exit(1);
    }

    let anyFailed = false;
    for (const b of list) {
      const r = await PFCore.selfTest(b);
      const status = r.failed ? "FAIL" : "PASS";
      console.log(`${status} ${b.name}: ${r.passed} passed, ${r.failed} failed`);
      if (r.failed) {
        anyFailed = true;
        for (const f of r.failures) console.log("   FAIL " + f);
      }
    }

    console.log(anyFailed ? "SELF-TEST FAILED" : "SELF-TEST PASSED");
    process.exit(anyFailed ? 1 : 0);
  })().catch((e) => {
    console.error("FAIL: uncaught exception during self-test:", e);
    process.exit(1);
  });
}

main();
