import { beforeAll, afterAll, expect, it } from 'vitest';
import { createServer, type Server } from 'node:https';
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from 'jose';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { attestationFixture } from './helpers/attestation-fixture.js';
const exec = promisify(execFile);
let server: Server, fixture: Awaited<ReturnType<typeof attestationFixture>>, proof: string, caPath: string;
let statusJwt: string, requests = 0;
beforeAll(async () => {
  fixture = await attestationFixture();
  server = createServer({ key: await exportPKCS8(fixture.status.privateKey), cert: fixture.status.certificate.toString() }, (_req, res) => {
    requests++; res.writeHead(200, { 'Content-Type': 'application/statuslist+jwt' }); res.end(statusJwt);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'https://127.0.0.1:' + (server.address() as { port: number }).port;
  const uri = origin + '/lists/one';
  fixture.policy.providers[0].statusListPrefixes = [origin + '/lists/']; fixture.provision();
  const holder = await generateKeyPair('ES256');
  const now = Math.floor(Date.now() / 1000);
  const ka = await fixture.attestation([await exportJWK(holder.publicKey)], 'tls-nonce', {
    key_storage_status: { status: { status_list: { idx: 0, uri } }, exp: now + 172800 },
  });
  proof = await new SignJWT({ aud: 'https://issuer.example.invalid', nonce: 'tls-nonce', iat: now })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', kid: '0', key_attestation: ka }).sign(holder.privateKey);
  statusJwt = await fixture.statusToken({ sub: uri });
  caPath = join(fixture.dir, 'status-tls-trust.pem'); writeFileSync(caPath, fixture.status.certificate.toString());
});
afterAll(async () => { if (server) await new Promise<void>(resolve => server.close(() => resolve())); });
function run(trustTls: boolean) {
  const env = { ...process.env, EUDI_WALLET_ATTESTATION_POLICY_PATH: fixture.policyPath, TEST_ATTESTED_PROOF: proof, NODE_TLS_REJECT_UNAUTHORIZED: '1' };
  delete env.NODE_EXTRA_CA_CERTS;
  if (trustTls) env.NODE_EXTRA_CA_CERTS = caPath;
  return exec(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    "import { verifyHolderProofJwt } from './src/oid4vci/proof.ts'; try { await verifyHolderProofJwt(process.env.TEST_ATTESTED_PROOF, 'https://issuer.example.invalid', 'tls-nonce', 86400); console.log('PASS'); } catch { console.error('status validation failed'); process.exitCode=1; }"],
    { env, windowsHide: true, timeout: 20000 });
}
it('retrieves and verifies a signed status list over actual trusted local TLS', async () => {
  const result = await run(true); expect(result.stdout.trim()).toBe('PASS'); expect(requests).toBe(1);
});
it('rejects an untrusted TLS endpoint even though its status signing pin is approved', async () => {
  const before = requests; await expect(run(false)).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining('status validation failed') }); expect(requests).toBe(before);
});
