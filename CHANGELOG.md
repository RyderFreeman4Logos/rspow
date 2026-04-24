# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-04-24

### Added

- `#[doc(hidden)]` on internal helper modules to reduce public API surface (PR-D).
- `ProofBundle::deserialize_bounded`, `ProofBundleLimits`, and `BoundedDeserError`
  for safe deserialization with caller-defined size limits (PR-E, audit F008).
- 8 new `Error` variants, 3 `SubmissionBuilderError` variants, and
  `NsError::ConfigReadHandleClosed` for structured error handling without panics
  (PR-F, audit F006).
- 12 integration tests and `proptest` dev-dependency for property-based testing
  (PR-G, audit F007).
- Rustdoc on every public item and `#![deny(missing_docs)]` (PR-C).
- Random `client_nonce` generation in the `near_stateless_demo` example (PR-H, audit F009).

### Changed

- CHANGELOG restructured to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
  format (PR-H).
- README wasm32 performance claim qualified as anecdotal (PR-H).
- MSRV declared as 1.91; `rust-version` field added to `Cargo.toml` (PR-B).
- wasm32-unknown-unknown CI lanes added for build-check coverage (PR-B).

### Removed

- 5 unused direct dependencies: `argon2`, `hex`, `ripemd`, `scrypt`,
  `serde_json` (PR-C.0).
- Misleading `"argon2"` keyword from `Cargo.toml` (PR-C.0).

### Fixed

- Replay cache atomicity bug in near-stateless verifier (pre-batch).
- Dead `wasm_pipeline.sh` script removed (PR-A).

### Breaking

- `NearStatelessVerifier::issue_params` now returns `Result<SolveParams, NsError>`
  instead of `SolveParams` (PR-F, audit F006).

## [0.5.0] - 2025-12-03

Initial production-readiness release. Major rewrite of the crate internals.

### Added

- EquiX proof-of-work backend behind `features = ["equix"]`.
- Near-stateless PoW toolkit behind `features = ["near-stateless"]`: time-windowed,
  replay-protected server/client helpers with deterministic nonce derivation,
  pluggable replay cache (`MokaReplayCache`), and injectable time provider.
- `EquixEngine` with `Arc<AtomicU64>` progress counter for solve tracking.
- `ProofBundle` type with master-challenge binding, bundle verify, and postcard
  serialization.
- Streaming and parallel solvers with deduplication (`flume` channels).
- Lock-free runtime config updates via `left-right` (`set_config`).
- `near_stateless_demo` async example with progress bar.
- Feature-gated default features (empty by default).

### Changed

- Crate rewritten around feature-gated backends; default features are now empty.
- `NearStatelessVerifier` owns the `server_secret`; `issue_params` requires no
  extra secret arguments.
- Time windows must be whole seconds (subsecond windows rejected).

### Fixed

- Bundle verify enforces minimum difficulty and proof count.
- Window lower bound accepted inclusively.
- Config updates made lock-free to avoid blocking verifier under contention.

---

<details>
<summary>Commit digest (audit trail)</summary>

```
c4ae994 chore(todo): track equix multithread tasks
9113729 feat(equix): add streaming solver and shared dispatcher
f460310 refactor(equix): use flume channel and restore Copy
aaa926a feat(equix): add bundle auto solver and strict verify
```

</details>
