import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadManifest } from '../src/manifest.js';

const cases = JSON.parse(readFileSync(new URL('../../tests/session_finalization_vectors.json', import.meta.url)));
for (const fixture of cases) {
  test(`session finalization: ${fixture.name}`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'toolclad-finalize-'));
    try {
      const path = join(directory, 'terminal.clad.toml');
      writeFileSync(path, fixture.manifest);
      if (fixture.expected === null) assert.throws(() => loadManifest(path));
      else assert.equal(loadManifest(path).session.commands.finish.finalize, fixture.expected);
    } finally {
      rmSync(directory, { recursive: true });
    }
  });
}
