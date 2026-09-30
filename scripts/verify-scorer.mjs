// Offline parity check against the reviewed, pinned MIT ModelTrace reference.
// Fixtures are synthetic numbers, never real request/response captures.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { analyzeGlobalOutputs, parseNumbers } from '../data/modeltrace/reference.mjs';

const root = new URL('../', import.meta.url);
const data = new URL('data/modeltrace/', root);
const provenance = JSON.parse(readFileSync(new URL('provenance.json', data)));
assert.equal(provenance.commit, 'df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8');
for (const [name, metadata] of Object.entries(provenance.files)) {
  assert.equal(createHash('sha256').update(readFileSync(new URL(name, data))).digest('hex'), metadata.sha256, `${name}: pinned source digest changed`);
}
const bank = JSON.parse(readFileSync(new URL('bank.json', data)));
const singles = bank.models.map((model, index) => {
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
  return { text, expected_count };
});
const batches = singles.map((output, index) => ({ outputs: [output], expected_model: bank.models[index].id }));
batches.push(
  { outputs: [singles[5], singles[4]], expected_model: 'gpt-6-astra' },
  { outputs: [singles[5], singles[4], singles[7]], expected_model: 'gpt-6-astra' },
  { outputs: [singles[4], singles[4], singles[4]], expected_model: 'gpt-5.6-luna' },
  { outputs: [
    { text: `请求300个数字，以下是完整回答：\n\`\`\`text\n${Array(165).fill('7').join(', ')}\n\`\`\`\n完成165项。`, expected_count: 300 },
    { text: `选取1到355。\n${Array(340).fill('1, 355, 42').join('; ')}\n结束。`, expected_count: 332 },
    { text: `1,2,3说明${Array(200).fill('007, 0, 356, 99999999999999999999999999999999999999').join('，')}结束3项。`, expected_count: 292 },
  ], expected_model: 'gpt-6-astra' },
);
const cases = batches.map(({ outputs, expected_model }) => {
  const result = analyzeGlobalOutputs(outputs, bank);
  assert.equal(result.used_outputs, outputs.length);
  return {
    outputs, expected_model,
    parsed_counts: outputs.map(({ text }) => parseNumbers(text).length),
    score: {
      predicted_model: result.prediction,
      predicted_probability: result.probability,
      expected_probability: result.results.find((row) => row.model === expected_model).probability,
      candidates: result.results.map(({ model, probability }) => ({ model, probability })),
      sample_count: result.used_outputs,
    },
  };
});
const goldenPath = new URL('golden.json', data);
if (process.argv.includes('--write-golden')) {
  writeFileSync(goldenPath, `${JSON.stringify(cases, null, 2)}\n`);
  console.log(`Wrote ${cases.length} synthetic reference fixtures.`);
} else {
  assert.deepEqual(JSON.parse(readFileSync(goldenPath)), cases, 'golden fixtures differ from pinned JavaScript reference');
  const result = spawnSync('cargo', ['test', '--lib', '--manifest-path', fileURLToPath(new URL('backend/Cargo.toml', root)), 'scorer::tests::golden_batch_parity_and_validation', '--', '--nocapture'], { encoding: 'utf8' });
  process.stdout.write(result.stdout || '');
  process.stderr.write(result.stderr || '');
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Rust/JavaScript batch scorer parity or output validation failed');
  assert.match(result.stdout, /test scorer::tests::golden_batch_parity_and_validation \.\.\. ok/, 'expected parity test did not run');
  console.log(`Verified ${cases.length} synthetic single/batch cases and complete-output parsing; no network or model calls.`);
}
