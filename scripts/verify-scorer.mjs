// Offline parity check against the reviewed, pinned MIT ModelTrace reference.
// Fixtures are synthetic numbers, never real request/response captures.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { analyzeGlobalOutputs } from '../data/modeltrace/reference.mjs';

const root = new URL('../', import.meta.url);
const data = new URL('data/modeltrace/', root);
const provenance = JSON.parse(readFileSync(new URL('provenance.json', data)));
assert.equal(provenance.commit, 'df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8');
for (const [name, metadata] of Object.entries(provenance.files)) {
  assert.equal(createHash('sha256').update(readFileSync(new URL(name, data))).digest('hex'), metadata.sha256, `${name}: pinned source digest changed`);
}
const bank = JSON.parse(readFileSync(new URL('bank.json', data)));
const cases = bank.models.map((model, index) => {
  const expected_count = [292, 293, 300, 319, 320, 321, 331, 332][index % 8];
  let state = (index + 1) >>> 0;
  const numbers = Array.from({ length: expected_count }, (_, position) => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    if (index === 0) return 7;
    if (index === 1) return 355;
    if (index === 2) return position % 355 + 1;
    if (index === 3) return [1, 355, 42, 137][position % 4];
    return state % 355 + 1;
  });
  const text = index % 3 === 0 ? JSON.stringify(numbers) : numbers.join(index % 3 === 1 ? ', ' : '\n');
  const result = analyzeGlobalOutputs([{ text, expected_count }], bank);
  return {
    text, expected_count, expected_model: model.id,
    score: {
      predicted_model: result.prediction,
      predicted_probability: result.probability,
      expected_probability: result.results.find((row) => row.model === model.id).probability,
    },
  };
});
const goldenPath = new URL('golden.json', data);
if (process.argv.includes('--write-golden')) {
  writeFileSync(goldenPath, `${JSON.stringify(cases, null, 2)}\n`);
  console.log(`Wrote ${cases.length} synthetic reference fixtures.`);
} else {
  assert.deepEqual(JSON.parse(readFileSync(goldenPath)), cases, 'golden fixtures differ from pinned JavaScript reference');
  const result = spawnSync('cargo', ['test', '--lib', '--manifest-path', fileURLToPath(new URL('backend/Cargo.toml', root)), 'scorer::tests::golden_parity_and_strict_validation', '--', '--nocapture'], { encoding: 'utf8' });
  process.stdout.write(result.stdout || '');
  process.stderr.write(result.stderr || '');
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Rust/JavaScript scorer parity or strict validation failed');
  assert.match(result.stdout, /test scorer::tests::golden_parity_and_strict_validation \.\.\. ok/, 'expected parity test did not run');
  console.log(`Verified ${cases.length} synthetic golden cases and strict input rejection; no network or model calls.`);
}
