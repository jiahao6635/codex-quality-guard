# Pinned ModelTrace reference

Upstream: <https://github.com/xqy2006/ModelTrace/tree/df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8>.
License: MIT, Copyright (c) 2026 xqy2006; the complete notice is retained in `LICENSE`.

`bank.json`, `reference.mjs`, and `challenge-reference.mjs` are unmodified public
files from that revision. Their source paths and SHA-256 hashes are recorded in
`provenance.json`. The reference corpus is labeled by upstream; we have not
independently authenticated the backend identity of its enrollment samples.
No customer credentials, prompts, responses, or prior live test captures are included.

`backend/src/scorer.rs` ports the single-output score with `calibration["1"]`.
Challenge wording and the 292–332 integer range follow the upstream generator;
selection uses a reproducible seed instead of browser randomness.

Input acceptance is intentionally stricter than the website: the entire output
must be one comma/whitespace-separated integer list or a JSON integer array,
with exactly the requested count and all values in 1–355. Surrounding prose,
code fences, signs, decimal/exponent forms, incomplete arrays, and excessive or
missing integers are rejected. No extraction, truncation, deduplication, or
repair is applied. The caller must separately require a completed upstream
response without transport errors or tool calls. Strict acceptance may reject
otherwise usable samples; rejected samples are inconclusive, not mismatches.

Weights describe similarity within the pinned candidate bank. They are not
calibrated probabilities of true backend identity for this deployment, and do
not identify the model used for a different business request. New models, changed
serving conditions, or reference drift require independent validation.

Run `node scripts/verify-scorer.mjs` from the project root. It checks source hashes,
recomputes deterministic synthetic fixtures with the upstream JavaScript scorer,
and runs Rust parity and strict-input tests. `--write-golden` regenerates only
the synthetic fixture file; it makes no network calls and sends no inference.
