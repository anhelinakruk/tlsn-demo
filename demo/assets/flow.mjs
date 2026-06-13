import { eventErr, relayFromWorker } from "./log.mjs";

function detail(ev) {
  return [
    ev.message || null,
    ev.filename ? `at ${ev.filename}:${ev.lineno}:${ev.colno}` : null,
    ev.error ? ev.error.stack || ev.error.message || String(ev.error) : null,
  ]
    .filter(Boolean)
    .join(" | ");
}

export function startWorker(url, onMessage) {
  const worker = new Worker(url, { type: "module" });
  worker.addEventListener("message", (ev) => {
    const data = ev.data;
    if (data?.kind === "log") {
      relayFromWorker(data.entry, data.line);
      return;
    }
    onMessage(data);
  });
  worker.addEventListener("error", (ev) => {
    ev.preventDefault?.();
    onMessage({ kind: "error", message: "worker error: " + (detail(ev) || "(no detail)") });
  });
  worker.addEventListener("messageerror", (ev) => {
    onMessage({
      kind: "error",
      message: "worker messageerror: " + (ev.data ? JSON.stringify(ev.data) : "unknown"),
    });
  });
  return worker;
}

export function installPageErrorForwarders() {
  window.addEventListener("error", (e) => {
    eventErr("runtime.page.error", { message: e.error?.stack || e.message });
  });
  window.addEventListener("unhandledrejection", (e) => {
    eventErr("runtime.page.unhandled_rejection", {
      message: e.reason?.stack || String(e.reason),
    });
  });
}

export function installWorkerErrorForwarder() {
  self.addEventListener("error", (ev) => {
    self.postMessage({
      kind: "error",
      message: "worker self error: " + (detail(ev) || "(no detail)"),
    });
  });
  self.addEventListener("unhandledrejection", (ev) => {
    const r = ev.reason;
    self.postMessage({
      kind: "error",
      message: "worker unhandledrejection: " + (r?.stack || r?.message || String(r)),
    });
  });
}
