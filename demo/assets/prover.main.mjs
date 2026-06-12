import { onLog, eventErr } from "./log.mjs";
import { startWorker, installPageErrorForwarders } from "./flow.mjs";

installPageErrorForwarders();

const proveBtn = document.getElementById("prove-btn");
const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");
const resultBadge = document.getElementById("result-badge");
const resultBalance = document.getElementById("result-balance");
const resultDate = document.getElementById("result-date");
const resultNote = resultEl.querySelector(".note");
const resultNoteHtml = resultNote.innerHTML;

function appendLog(line) {
  logEl.textContent += line + "\n";
}

onLog((entry, line) => appendLog(line));

function stripQuotes(s) {
  return String(s).replace(/^"|"$/g, "");
}

function formatChf(raw) {
  const v = stripQuotes(raw).replaceAll("_", "");
  const n = Number(v);
  return Number.isFinite(n)
    ? n.toLocaleString("de-CH", { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : v;
}

function formatDate(raw) {
  const v = stripQuotes(raw);
  const d = new Date(v);
  return Number.isNaN(d.getTime())
    ? v
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function showResult(result) {
  resultBalance.textContent = formatChf(result.chfBalance);
  resultDate.textContent = formatDate(result.lastAudit);
  resultBadge.textContent = "✓ Balance verified";
  resultNote.innerHTML = resultNoteHtml;
  resultEl.classList.remove("err");
  resultEl.classList.add("show", "ok");
}

function showError(message) {
  resultBadge.textContent = "✗ Verification failed";
  resultBalance.textContent = "—";
  resultDate.textContent = "—";
  resultEl.classList.remove("ok");
  resultEl.classList.add("show", "err");
  resultNote.textContent = message;
}

function readConfig() {
  const d = document.body.dataset;
  return {
    connectUrl: new URL("/connect", location.origin).toString(),
    certHashHex: d.certHash,
  };
}

let currentWorker = null;

function start() {
  if (currentWorker) return;
  logEl.textContent = "";
  resultEl.classList.remove("show", "ok", "err");
  proveBtn.disabled = true;

  currentWorker = startWorker("/assets/prover.worker.mjs", (msg) => {
    if (msg.kind === "result") {
      showResult(msg.result);
      currentWorker = null;
      proveBtn.disabled = false;
    } else if (msg.kind === "error") {
      appendLog(`\nERROR: ${msg.message}`);
      eventErr("prover.notarize.failed", { message: msg.message });
      showError(msg.message);
      currentWorker = null;
      proveBtn.disabled = false;
    }
  });

  currentWorker.postMessage({ kind: "start", config: readConfig() });
}

proveBtn.addEventListener("click", start);
