# prover-swiss-demo

A TLS notarization (TLSNotary) demo. It cryptographically proves the CHF balance
of an account at `swissbank.tlsnotary.org`, disclosing to the verifier only the
`.accounts.CHF` and `.last_audit` fields while committing to the rest of the
response without revealing it.

The browser acts as the **prover** (WASM); the demo server (`:8444`) acts as the
**verifier** and as a TCP proxy to the bank.

## Flow architecture

```
Browser (prover, WASM)                  Demo server :8444 (verifier + proxy)
  │                                       │
  │  WebTransport (HTTP/3) ──────────────▶│
  │  Stream 1: "VERIFY\n"          ──────▶│ verify_balance()  (MPC-TLS, crypto)
  │  Stream 2: "CONNECT swissbank…:443\n"▶│ TCP proxy ───▶ swissbank.tlsnotary.org:443
  │                                       │
  │  GET /balances (over MPC-TLS, via the proxy)
  │                                       │
  │◀── JSON frame: {status, chf, timestamp}
  ▼
  UI: "✓ CHF balance: …  ·  as of: …"
```

## Requirements

- **Rust** — the native build uses `rust-toolchain.toml` (1.95.0). The WASM build
  requires **`nightly-2025-07-14`** (newer nightlies don't report
  `target_feature="atomics"`, which makes `parking_lot` panic in WASM):
  ```bash
  rustup toolchain install nightly-2025-07-14
  rustup component add rust-src --toolchain nightly-2025-07-14   # for build-std
  rustup target add wasm32-unknown-unknown --toolchain nightly-2025-07-14
  ```
- **LLVM (Homebrew)** — `.cargo/config.toml` points at `/opt/homebrew/opt/llvm/bin`
  for `clang`/`llvm-ar` on the WASM target:
  ```bash
  brew install llvm
  ```
- **wasm-bindgen-cli `0.2.123`** — the version must match the schema baked into
  the built WASM *exactly*:
  ```bash
  cargo install wasm-bindgen-cli --version 0.2.123 --locked
  ```
- **Chrome** — required for WebTransport with `serverCertificateHashes`. The server
  generates a self-signed cert valid for 13 days (Chrome rejects certs > 14 days
  for this mechanism).

## Build

### 1. WASM (prover)

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build --release --target wasm32-unknown-unknown -p tlsn-prover

wasm-bindgen --target web \
  --out-name prover \
  --out-dir demo/assets/wasm \
  target/wasm32-unknown-unknown/release/tlsn_prover.wasm
```

Produces `demo/assets/wasm/prover.js` + `prover_bg.wasm`, which the server serves
statically. Re-run after any change in `tlsn-prover/`.

> Note: the WASM build links a ~39 MB binary and needs plenty of free disk space.

### 2. Demo server (verifier + proxy)

```bash
cargo build --release -p demo
```

## Running

```bash
cargo run --release -p demo
```

On startup the server resolves `swissbank.tlsnotary.org:443` (the allowed proxy
target) and listens on `0.0.0.0:8444` (QUIC/HTTP-3 + TCP, self-signed TLS).

Open in **Chrome**:

```
https://localhost:8444/prover
```

Click the prove button and watch the steps: `init → pool → connect → streams →
prove → result`. The result shows the disclosed CHF balance and the last audit date.

## Notes: commitments and WASM memory

The prover commits transcript fields using the hash set in
`tlsn-prover/src/wasm/prover.rs` (`hash_alg`). **Every** commitment (regardless of
algorithm) computes the hash **inside** the binary VOLE-ZK VM (`mpz_zk`,
correlated-OT from Ferret) — see `tlsn::transcript_internal::commit::hash`. Memory
≈ **(number of commitments) × (gates per hash)**, with a hard 4 GB WASM heap cap.

Symptom of exceeding it during `prove()`:
```
RuntimeError: unreachable  (__rg_oom)
  mpz_ot_core::ferret::receiver::Receiver::finish_extend
```

The difference between algorithms is the **circuit cost of a single hash**, not a
separate code path:

- **POSEIDON2** — a field hash (M31). In the binary VM, field multiplications are
  emulated with many gates → an **expensive** circuit per commitment. Verified
  empirically: **6 commitments = OOM, 2 = OK**. Slower even at 2. Upside:
  SNARK-friendly — such a commitment can later be proven inside a SNARK circuit.
- **BLAKE3** — natively bit/word-oriented (XOR/ADD/rotations) → a **cheap** circuit,
  fits more commitments and is faster. Not SNARK-friendly.

Keep `commitBodyFields` + `commitHeaders` in `demo/assets/prover.worker.mjs` short.
Current config: 2 POSEIDON2 commitments (`authorization` + `.account_id`).

> After changing `hash_alg` or the commitment config, rebuild the WASM (Build
> section). Changing only `commitBodyFields` in `prover.worker.mjs` does not require
> a WASM rebuild.

## Logs

Default filter: `demo=debug,salvo=info`. Override with `RUST_LOG`:

```bash
RUST_LOG=demo=trace cargo run --release -p demo
```

## Project layout

```
tlsn-demo/
├── Cargo.toml              # workspace: members = ["demo", "tlsn-prover"]
├── .cargo/config.toml      # WASM flags (atomics, shared-memory) + LLVM paths
├── rust-toolchain.toml     # native toolchain (1.95.0)
├── demo/                   # server: verifier + proxy + static
│   ├── src/
│   │   ├── main.rs             # bootstrap, resolve bank addr, :8444
│   │   ├── service.rs          # Salvo routing, QUIC/TCP, static assets
│   │   ├── connect.rs          # WebTransport: dispatch VERIFY / CONNECT
│   │   ├── balance_verifier.rs # verifier logic + balance validation
│   │   └── tls.rs              # server self-signed cert (WebTransport)
│   └── assets/
│       ├── prover.main.mjs      # UI, spawns the worker
│       ├── prover.worker.mjs    # prover: config, spawn.js blob patch
│       └── wasm/               # wasm-bindgen output (prover.js, prover_bg.wasm)
└── tlsn-prover/            # prover crate (native rlib + WASM cdylib)
    └── src/
        ├── prover.rs          # core: setup → http exchange → generate_proof
        ├── reveal.rs          # maps reveal/commit config onto TLSN
        ├── parser/            # HTTP/JSON parser (pest) for field redaction
        └── wasm/              # wasm-bindgen: Prover, WebTransport I/O
```
