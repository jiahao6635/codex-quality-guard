# Pinned ModelTrace reference

Upstream: <https://github.com/xqy2006/ModelTrace/tree/df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8>.
License: MIT, Copyright (c) 2026 xqy2006; the complete notice is retained in `LICENSE`.

`bank.json`, `reference.mjs`, and `challenge-reference.mjs` are unmodified public
files from that revision. Their source paths and SHA-256 hashes are recorded in
`provenance.json`. The reference corpus is labeled by upstream; we have not
independently authenticated the backend identity of its enrollment samples.
No customer credentials, prompts, responses, or prior live test captures are included.

`backend/src/scorer.rs` ports the reference feature extraction and aggregation.
Each response is parsed and scored independently. The raw per-model fused scores
are averaged across responses before one softmax with the matching
`calibration["1"|"2"|"3"]` coefficient. A completed plugin probe requires three
independent valid responses; a one-response score remains available for offline
compatibility checks. The result includes all ranked candidate probabilities.
Challenge wording and the 292–332 integer range follow the upstream generator;
selection uses a reproducible seed instead of browser randomness.

The parser receives each complete text, retains its longest number run, ignores
values outside 1–355, and splits runs at alphabetic prose. It preserves order,
duplicates and all accepted numbers without clipping to the requested length.
The minimum accepted run has `max(80, ceil(expected_count * 0.55))` numbers, as in
the reference. The caller must separately require a completed upstream response
without transport errors or tool calls: a long enough partial response is not a
completed response. Outputs larger than 16 KiB are rejected without truncation.

Weights describe similarity within the pinned candidate bank. They are not
calibrated probabilities of true backend identity for this deployment, and do
not identify the model used for a different business request. New models, changed
serving conditions, or reference drift require independent validation.

Run `node scripts/verify-scorer.mjs` from the project root. It checks source hashes,
recomputes deterministic synthetic fixtures with the upstream JavaScript scorer,
and runs Rust parity tests for single, double and triple outputs, complete-text
parsing, all ranked probabilities, and invalid-input rejection. `--write-golden` regenerates only
the synthetic fixture file; it makes no network calls and sends no inference.
