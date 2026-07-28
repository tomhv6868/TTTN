import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeAlertEvent, summarizeLiveFamilies } from './liveFamilyStats.js';

test('filters terminal Benign decisions regardless of case', () => {
  const stats = summarizeLiveFamilies([
    { decision: 'Benign', candidate: 'FTP-Bruteforce' },
    { decision: 'benign', candidate: 'PortScan' },
    { decision: 'PortScan', candidate: 'PortScan' },
    { decision: 'DoS', candidate: 'DoS' },
  ]);

  assert.deepEqual(stats, {
    byFam: { PortScan: 1, DoS: 1 },
    total: 2,
  });
});

test('keeps F9 attack decisions unchanged', () => {
  const stats = summarizeLiveFamilies([
    { decision: 'known_attack', candidate: 'DDoS' },
    { decision: 'unknown_candidate', candidate: 'DoS GoldenEye' },
  ]);

  assert.deepEqual(stats, {
    byFam: { DDoS: 1, 'DoS GoldenEye': 1 },
    total: 2,
  });
});

test('normalizes legacy terminal classes without changing F9 labels', () => {
  assert.deepEqual(
    normalizeAlertEvent({ decision: 'DoS', candidate: 'DoS' }, 'terminal'),
    { decision: 'known_attack', candidate: 'DoS', terminal_class: 'DoS' },
  );
  assert.deepEqual(
    normalizeAlertEvent({ decision: 'Benign', candidate: 'FTP-Bruteforce' }, 'terminal'),
    { decision: 'benign', candidate: 'FTP-Bruteforce', terminal_class: 'Benign' },
  );
  const f9 = { decision: 'unknown_candidate', candidate: 'DDoS' };
  assert.equal(normalizeAlertEvent(f9, 'f9'), f9);
});
