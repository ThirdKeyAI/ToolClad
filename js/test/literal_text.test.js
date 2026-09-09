import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateArguments } from '../src/contracts.js';
import { validateArg, validateArgWithCustomTypes } from '../src/validator.js';
const cases = JSON.parse(readFileSync(new URL('../../tests/literal_text_vectors.json', import.meta.url))).cases;
for (const c of cases) for (const custom of [false, true]) test(`literal_text ${c.name} custom=${custom}`, () => {
  const value = c.value.repeat(c.repeat);
  const def = {type: 'literal_text', required: true, ...(c.pattern !== null ? {pattern: c.pattern} : {})};
  const check = () => custom ? validateArgWithCustomTypes({...def, type:'source_text'}, value,
    {source_text: {base:'literal_text', ...(c.pattern !== null ? {pattern:c.pattern} : {})}}) : validateArg(def, value);
  if (c.error) assert.throws(check); else assert.equal(check(), value);
});
for (const value of ['\ud800', '\udfff', 1, false, null, {}, []]) test(`literal_text refuses ${JSON.stringify(value)}`, () => {
  assert.throws(() => validateArg({type:'literal_text'}, value));
  assert.throws(() => validateArgWithCustomTypes({type:'source_text'}, value, {source_text:{base:'literal_text'}}));
});

for (const value of [null, undefined, 1, false, {}, []]) test(`literal_text contract refuses ${String(value)}`, () => {
  const manifest = {args:{content:{type:'literal_text',default:'fallback'}}};
  assert.throws(() => validateArguments(manifest, {content:value}));
});
