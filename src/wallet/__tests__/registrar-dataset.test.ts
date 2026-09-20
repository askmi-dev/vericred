import { beforeEach, expect, it, vi } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { registrarDataset, inspectRegistrarDataset, registrationInfo } from '../registration.js';
import { registrarFixture } from '../../../tests/helpers/registrar-fixture.js';

const paths = { issuer: join(process.env.DATA_DIR!, 'issuer-dataset.json'), verifier: join(process.env.DATA_DIR!, 'verifier-dataset.json') };
function provision(role: 'issuer' | 'verifier', value: unknown) {
  writeFileSync(paths[role], JSON.stringify(value));
  process.env['EUDI_' + role.toUpperCase() + '_REGISTRAR_DATASET_PATH'] = paths[role];
}
beforeEach(() => {
  delete process.env.EUDI_REGISTRATION_POLICY;
  for (const role of ['ISSUER', 'VERIFIER']) delete process.env['EUDI_' + role + '_REGISTRAR_DATASET_PATH'];
});
it('requires each role under required policy, retaining explicit optional behavior', () => {
  expect(registrarDataset('issuer')).toBeUndefined();
  process.env.EUDI_REGISTRATION_POLICY = 'required';
  expect(() => registrarDataset('issuer')).toThrow('not configured');
  expect(() => registrarDataset('verifier')).toThrow('not configured');
});
it('preserves externally supplied fields and role separation without fetching registrars', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unexpected network'));
  try {
    const issuer = { ...registrarFixture('issuer'), extension: { registeredValue: 'unchanged' } };
    provision('issuer', issuer); provision('verifier', registrarFixture('verifier'));
    expect(registrarDataset('issuer')).toEqual(issuer);
    expect(await registrationInfo('issuer')).toEqual([{ format: 'registrar_dataset', data: issuer }]);
    expect(registrarDataset('verifier')).toEqual(registrarFixture('verifier'));
    expect(fetcher).not.toHaveBeenCalled();
  } finally { fetcher.mockRestore(); }
});
it.each(['issuer', 'verifier'] as const)('redacts %s diagnostics and rereads replaced invalid material', role => {
  provision(role, registrarFixture(role)); expect(inspectRegistrarDataset(role)).toEqual({ configured: true, valid: true });
  writeFileSync(paths[role], '{private-sentinel');
  expect(inspectRegistrarDataset(role)).toEqual({ configured: true, valid: false });
  expect(() => registrarDataset(role)).toThrow('Registrar dataset failed local validation');
  expect(JSON.stringify(inspectRegistrarDataset(role))).not.toContain('private-sentinel');
});
it.each([
  ['empty object', {}], ['array wrapper', []], ['string', 'private-sentinel'],
  ['missing identifier', { ...registrarFixture('issuer'), identifier: undefined }],
  ['scalar identifier', { ...registrarFixture('issuer'), identifier: 'wrong' }],
  ['missing identifier type', { ...registrarFixture('issuer'), identifier: [{ identifier: 'wrong' }] }],
  ['empty description', { ...registrarFixture('issuer'), srvDescription: [] }],
  ['unsupported nested description', { ...registrarFixture('issuer'), srvDescription: [[{ lang: 'en', content: 'nested' }]] }],
  ['invalid locale shape', { ...registrarFixture('issuer'), srvDescription: [{ lang: 'english', content: 'wrong' }] }],
  ['empty attestation scope', { ...registrarFixture('issuer'), providesAttestations: [] }],
  ['wrong attestation shape', { ...registrarFixture('issuer'), providesAttestations: [{ format: 'dc+sd-jwt', meta: {} }] }],
  ['HTTP registrar', { ...registrarFixture('issuer'), registryURI: 'http://registrar.example.invalid' }],
  ['registrar userinfo', { ...registrarFixture('issuer'), registryURI: 'https://secret:password@registrar.example.invalid' }],
  ['credential_ids', { ...registrarFixture('issuer'), credential_ids: ['id'] }],
])('rejects %s even with optional registration policy', (_name, value) => {
  provision('issuer', value); expect(() => registrarDataset('issuer')).toThrow('failed local validation');
});
it.each(['intendedUseIdentifier', 'purpose', 'policyURI'])('requires verifier %s and rejects an issuer-only dataset', field => {
  const value: Record<string, unknown> = registrarFixture('verifier'); delete value[field];
  provision('verifier', value); expect(() => registrarDataset('verifier')).toThrow('failed local validation');
  provision('verifier', registrarFixture('issuer')); expect(() => registrarDataset('verifier')).toThrow('failed local validation');
});
it('rejects oversized, deeply nested and mutation-key extension data', () => {
  provision('issuer', { ...registrarFixture('issuer'), extension: 'x'.repeat(128 * 1024) });
  expect(() => registrarDataset('issuer')).toThrow('failed local validation');
  let nested: unknown = 'deep'; for(let i=0;i<20;i++) nested={ child:nested };
  provision('issuer', { ...registrarFixture('issuer'), extension: nested });
  expect(() => registrarDataset('issuer')).toThrow('failed local validation');
  provision('issuer', { ...registrarFixture('issuer'), extension: JSON.parse('{"__proto__":{"polluted":true}}') });
  expect(() => registrarDataset('issuer')).toThrow('failed local validation');
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
});
