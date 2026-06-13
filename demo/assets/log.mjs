const inWorker = typeof self !== "undefined" && typeof window === "undefined";
const listeners = new Set();

function fmtField(v) {
  if (typeof v === "boolean" || typeof v === "number" || v === null || v === undefined) {
    return String(v);
  }
  if (typeof v === "string" && /^[A-Za-z0-9_.-]+$/.test(v)) return v;
  return JSON.stringify(v);
}

function formatLine(entry) {
  let line = `${entry.ts}  ${entry.level} ${entry.name}`;
  for (const [k, v] of Object.entries(entry.fields)) {
    line += ` ${k}=${fmtField(v)}`;
  }
  return line;
}

function emit(level, name, fields) {
  const entry = { ts: new Date().toISOString(), level, name, fields: fields ?? {} };
  const line = formatLine(entry);
  (level === "ERROR" ? console.error : console.log)(line);
  if (inWorker) {
    try {
      self.postMessage({ kind: "log", entry, line });
    } catch {
      // postMessage może fail zanim kanał jest podłączony; console.log jest fallbackiem
    }
  } else {
    for (const fn of listeners) {
      try {
        fn(entry, line);
      } catch (err) {
        console.error("log listener threw:", err);
      }
    }
  }
}

export const event = (name, fields) => emit("INFO", name, fields);
export const eventWarn = (name, fields) => emit("WARN", name, fields);
export const eventErr = (name, fields) => emit("ERROR", name, fields);

export function onLog(fn) {
  if (inWorker) return () => {};
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function relayFromWorker(entry, line) {
  if (inWorker) return;
  const prefixed = `[worker] ${line}`;
  (entry.level === "ERROR" ? console.error : console.log)(prefixed);
  for (const fn of listeners) {
    try {
      fn(entry, line);
    } catch (err) {
      console.error("log listener threw:", err);
    }
  }
}
