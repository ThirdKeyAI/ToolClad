import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {validateArg, validateArgWithCustomTypes} from '../src/validator.js';
const cases = JSON.parse(readFileSync(new URL('../../tests/path_vectors.json', import.meta.url))).cases;

test('relative path and credential contracts including aliases', () => {
  const old = process.cwd();
  const root = mkdtempSync(join(tmpdir(), 'toolclad-path-'));
  try {
    process.chdir(root);
    for (const c of cases) if (!c.error) {
      mkdirSync(dirname(c.value), {recursive:true});
      writeFileSync(c.value, 'synthetic fixture');
    }
    for (const kind of ['path','credential_file']) for (const custom of [false,true]) {
      for (const c of cases) {
        const check = () => custom ? validateArgWithCustomTypes({type:'relative_file'},c.value,{relative_file:{base:kind}}) : validateArg({type:kind},c.value);
        if (c.error) assert.throws(check, c.name); else assert.equal(check(),c.value,c.name);
      }
    }
    for (const value of ['data','missing.txt']) assert.throws(() => validateArg({type:'credential_file'},value));
  } finally { process.chdir(old); rmSync(root,{recursive:true,force:true}); }
});
