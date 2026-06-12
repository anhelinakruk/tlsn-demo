# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Demo server (native)
```bash
cargo build --release -p demo
cargo run --release -p demo          # starts on https://localhost:8444
RUST_LOG=demo=trace cargo run --release -p demo
```

### WASM prover
```bash
# Requires nightly-2025-07-14 (newer nightlies break parking_lot in WASM)
RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build --release --target wasm32-unknown-unknown -p tlsn-prover

wasm-bindgen --target web \
  --out-name prover \
  --out-dir demo/assets/wasm \
  target/wasm32-unknown-unknown/release/tlsn_prover.wasm
```
Rebuild WASM only after changes in `tlsn-prover/`. Changing `demo/assets/prover.worker.mjs` alone does not require a rebuild.

### Check / lint
```bash
cargo check -p demo
cargo check -p tlsn-prover
cargo clippy -p demo
```

### Toolchain notes
- Native builds use `rust-toolchain.toml` (1.95.0).
- WASM requires `nightly-2025-07-14` + `rust-src` component + `wasm-bindgen-cli 0.2.123` (version must match exactly).
- LLVM must be installed (`brew install llvm`); `.cargo/config.toml` points at `/opt/homebrew/opt/llvm/bin`.

## Architecture

Two crates in one workspace:

```
tlsn-demo/
├── demo/          # server: verifier + TCP proxy + static file host
└── tlsn-prover/   # prover: native rlib + WASM cdylib
```

### Flow

```
Browser (WASM prover)          Demo server :8444 (verifier + proxy)
  │                                │
  │  WebTransport (HTTP/3) ───────▶│
  │  Stream 1 "VERIFY\n"    ──────▶│  MPC-TLS verifier (balance_verifier.rs)
  │  Stream 2 "CONNECT …\n" ──────▶│  TCP proxy ──▶ swissbank.tlsnotary.org:443
  │                                │
  │  GET /balances (over MPC-TLS)
  │◀── JSON frame {status, chf, last_audit}
```

The server dispatches streams by preamble (`connect.rs::parse_role`): `VERIFY` → runs `verify_balance`; `CONNECT host:port` → opens a raw TCP connection and pipes bytes. The TCP proxy is blind to content — it sees only ciphertext.

### `demo/` crate

- **`connect.rs`** — WebTransport handler; reads preamble, dispatches to verifier or proxy; writes `VerificationOutcome` JSON frame back to prover after MPC session. `MAX_FRAME_BYTES` here must match the same constant in `tlsn-prover/src/wasm/prover.rs`.
- **`balance_verifier.rs`** — wraps the tlsn `Session`/`Verifier` API; enforces `server_name == "swissbank.tlsnotary.org"`, `MAX_SENT_DATA`/`MAX_RECV_DATA` policy, and extracts `.CHF` + `.last_audit` from the partial transcript. The outer `Result` covers MPC-level failures; the inner `Result` covers post-session validation so the caller can send a clean `Failure` frame.
- **`tls.rs`** — generates a self-signed ECDSA cert (13-day validity for Chrome's `serverCertificateHashes` limit of 14 days). `load_or_generate` caches cert+key in `demo/.cert/server-cert.json` and renews when <2 days remain — Chrome remembers the cert between restarts.
- **`service.rs`** — Salvo router; serves HTML + WASM assets; injects `data-cert-hash` for WebTransport; adds COOP/COEP/CORP headers required for `SharedArrayBuffer`/WASM threads.

### `tlsn-prover/` crate

Compiles to both `rlib` (used by `demo/` for the `SmolRuntime` and parser) and `cdylib` (WASM).

- **`prover.rs`** — core prove flow: `setup_and_connect` → `execute_http_exchange` → `build_prove_config` → `generate_proof`. The HTTP exchange and MPC handshake run concurrently via `join!`.
- **`reveal.rs`** — translates `RevealConfig` (keypaths, header names) into byte ranges and feeds them to `ProveConfigBuilder`/`TranscriptCommitConfigBuilder`. `KeyValueCommitConfig::value_range` applies `commitment_length` padding so commitments don't leak value length.
- **`parser/`** — PEG parser (pest) for HTTP/JSON. Produces `HashMap<keypath, Body>` where values are **byte ranges** in the raw transcript, not strings. Two modes: `parse_standard_body` (recursive, full plaintext, used by prover) and `parse_redacted_body` (flat, tolerates gaps, used by verifier). Nested JSON flattens to top-level keys in the redacted parser — `.accounts.CHF` in the full transcript surfaces as `.CHF` in the redacted one.
- **`wasm/prover.rs`** — wasm-bindgen entry point; deserialises `JsProverInputs` JSON, calls `CoreProver::prove`, reads the `VerificationOutcome` frame from the verifier stream, returns `JsProverOutput` to JS.

### Commitments and memory

Every commitment (regardless of hash algorithm) runs inside the binary VOLE-ZK VM (`mpz_zk`). Memory ≈ **(number of commitments) × (circuit cost per hash)**. POSEIDON2 (current default) is expensive per commitment — empirically 6 commitments OOM, 2 are fine. Each call to `commit_sent`/`commit_recv` in `reveal.rs` creates one commitment. Multiple fields can share one commitment via `RangeSet` but then must be revealed together.

Current config: 2 commitments — `authorization` header (sent) + `.account_id` (recv).

### JS assets

- **`prover.worker.mjs`** — Web Worker; configures `RevealConfig`, installs a `spawn.js` blob-URL patch (Rayon workers need absolute WASM URLs), opens two WebTransport streams, calls `prover.prove_streams()`.
- **`prover.main.mjs`** — main thread; starts the worker, shows result card on success, formats CHF balance (`Number` after stripping `_` separators) and audit date.
