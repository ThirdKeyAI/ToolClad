import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import TOML from '@iarna/toml';
import { buildCommand } from '../src/executor.js';
import { splitTemplate } from '../src/contracts.js';
const cases = JSON.parse(readFileSync(new URL('../../tests/execution_vectors.json', import.meta.url))).cases;
for (const c of cases) test(c.name, () => {
  const manifest = TOML.parse(c.manifest);
  if (c.error) assert.throws(() => buildCommand(manifest, c.args));
  else assert.deepEqual(splitTemplate(buildCommand(manifest, c.args).command), c.expected_argv);
});
