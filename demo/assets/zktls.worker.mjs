import init, { Prover, initialize } from "./wasm/zktls.js";
import { event } from "./log.mjs";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

const MAX_SENT_DATA = 1 << 12;
const MAX_RECV_DATA = 1 << 14;

const post = (kind, payload = {}) => self.postMessage({ kind, ...payload });

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

async function writePreamble(stream, line) {
  const writer = stream.writable.getWriter();
  await writer.write(new TextEncoder().encode(line));
  writer.releaseLock();
}

function buildProverInputs(config) {
  return {
    serverName: "swissbank.tlsnotary.org",
    serverCertDer: [],
    maxSentData: MAX_SENT_DATA,
    maxRecvData: MAX_RECV_DATA,
    requestMethod: "GET",
    requestUri: "/balances",
    requestHeaders: [
      ["Host", "swissbank.tlsnotary.org"],
      ["Authorization", "Bearer random_auth_token"],
      ["Accept-Encoding", "identity"],
      ["Connection", "close"],
    ],
    requestRevealConfig: {
      revealHeaders: [],
      commitHeaders: ["authorization"],
      revealBodyFields: [],
      commitBodyFields: [],
      revealKeysCommitValues: [],
    },
    responseRevealConfig: {
      revealHeaders: [],
      commitHeaders: [],
      revealBodyFields: [
        { quoted: ".accounts.CHF" },
        { quoted: ".last_audit" },
      ],
      // Each POSEIDON2 commitment is a separate mpz_zk proof consuming Ferret
      // OTs; committing many fields exhausts the 4 GB WASM heap. Keep the count
      // low (≈ reference profile). Add more only if memory allows.
      commitBodyFields: [
        { quoted: ".account_id" },
      ],
      revealKeysCommitValues: [],
    },
  };
}

async function installSpawnBlobPatch() {
  const ZKTLS_ABS = new URL("/assets/wasm/zktls.js", location.origin).href;

  const zktlsText = await fetch(ZKTLS_ABS).then((r) => r.text());
  const match = zktlsText.match(/['"](\.[^'"]*web-spawn[^'"]*spawn\.js)['"]/);
  if (!match) throw new Error("could not find spawn.js path in zktls.js");
  const SPAWN_PATH = new URL(match[1], ZKTLS_ABS).href;

  let text = await fetch(SPAWN_PATH).then((r) => r.text());

  text = text
    .replaceAll("'../../../zktls.js'", `'${ZKTLS_ABS}'`)
    .replaceAll('"../../../zktls.js"', `"${ZKTLS_ABS}"`)
    .replaceAll("'../../..'", `'${ZKTLS_ABS}'`)
    .replaceAll('"../../.."', `"${ZKTLS_ABS}"`);

  text = text.replace(
    /new URL\(\s*'\.\/spawn\.js',\s*import\.meta\.url\s*\)/g,
    "new URL(import.meta.url)",
  );

  const blob = new Blob([text], { type: "application/javascript" });
  const blobUrl = URL.createObjectURL(blob);

  const OriginalWorker = self.Worker;
  self.Worker = class extends OriginalWorker {
    constructor(url, options) {
      const s = String(url);
      if (s.includes("/spawn.js") || s.includes("web-spawn")) {
        super(blobUrl, options);
      } else {
        super(url, options);
      }
    }
  };
}

async function runProve(config) {
  event("zktls.worker.wasm.init.start");
  await init();
  event("zktls.worker.wasm.init.done");

  event("zktls.worker.pool.start");
  await installSpawnBlobPatch();
  await initialize();
  event("zktls.worker.pool.ready");

  event("zktls.transport.session.opening");
  const session = new WebTransport(config.connectUrl, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hexToBytes(config.certHashHex) }],
  });
  try {
    await session.ready;
    event("zktls.transport.session.ready");

    event("zktls.transport.streams.creating");
    const verifierStream = await session.createBidirectionalStream();
    const proxyStream = await session.createBidirectionalStream();
    await writePreamble(verifierStream, "VERIFY\n");
    await writePreamble(proxyStream, "CONNECT swissbank.tlsnotary.org:443\n");
    event("zktls.transport.streams.preambles_written");

    const prover = new Prover();
    const inputsJson = JSON.stringify(buildProverInputs(config));

    event("zktls.prover.prove_streams.start");
    const output = await prover.prove_streams(inputsJson, verifierStream, proxyStream);
    event("zktls.prover.prove_streams.done");

    return {
      chfBalance: output.chfBalance,
      timestamp: output.timestamp,
    };
  } finally {
    try {
      await session.close({ closeCode: 0, reason: "prove-done" });
      event("zktls.transport.session.closed");
    } catch (err) {
      event("zktls.transport.session.close_failed", {
        message: err?.message || String(err),
      });
    }
  }
}

self.addEventListener("message", async (ev) => {
  if (ev.data?.kind !== "start") return;
  try {
    const result = await runProve(ev.data.config);
    post("result", { result });
  } catch (err) {
    post("error", { message: err?.stack || err?.message || String(err) });
  }
});
