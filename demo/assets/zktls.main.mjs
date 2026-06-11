import { onLog, eventErr } from "./log.mjs";
import { startWorker, installPageErrorForwarders } from "./flow.mjs";

installPageErrorForwarders();

const proveBtn = document.getElementById("prove-btn");
const logEl = document.getElementById("log");

function appendLog(line) {
  logEl.textContent += line + "\n";
}

onLog((entry, line) => appendLog(line));

function readConfig() {
  const d = document.body.dataset;
  return {
    connectUrl: new URL("/connect", location.origin).toString(),
    certHashHex: d.certHash,
    serverCertDerHex: d.serverCertDerHex,
  };
}

let currentWorker = null;

function start() {
  if (currentWorker) return;
  logEl.textContent = "";
  proveBtn.disabled = true;

  currentWorker = startWorker("/assets/zktls.worker.mjs", (msg) => {
    if (msg.kind === "result") {
      appendLog(`\nCHF: ${msg.result.chfBalance}  ·  as of: ${msg.result.timestamp}`);
      currentWorker = null;
      proveBtn.disabled = false;
    } else if (msg.kind === "error") {
      appendLog(`\nERROR: ${msg.message}`);
      eventErr("zktls.notarize.failed", { message: msg.message });
      currentWorker = null;
      proveBtn.disabled = false;
    }
  });

  currentWorker.postMessage({ kind: "start", config: readConfig() });
}

proveBtn.addEventListener("click", start);
