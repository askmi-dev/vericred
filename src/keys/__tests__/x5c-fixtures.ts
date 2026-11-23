import { spawnSync } from 'child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Generates the TEST-ONLY X.509 chain for x5c.test.ts at test time, so no
// private key is committed (AGENTS.md rule 4): root (self-signed trust
// anchor) -> intermediate CA -> issuer leaf. Requires openssl on the PATH.

export const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

// Git-for-Windows openssl would rewrite "/CN=..." as a path without this.
const env = { ...process.env, MSYS_NO_PATHCONV: '1' };

const ossl = (cwd: string, ...args: string[]) => {
  const r = spawnSync('openssl', args, { cwd, env, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${r.stderr}`);
};

const EC = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];

/** Creates root.pem, intermediate.pem, leaf.pem, leaf.key and chain.pem in a fresh temp dir. */
export function generateX5cFixtures(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vericred-x5c-'));
  ossl(dir, 'req', '-x509', ...EC, '-keyout', 'root.key', '-out', 'root.pem', '-days', '36500',
    '-subj', '/CN=VeriCred Test Root',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');

  ossl(dir, 'req', ...EC, '-keyout', 'intermediate.key', '-out', 'intermediate.csr',
    '-subj', '/CN=VeriCred Test Intermediate');
  writeFileSync(join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n');
  ossl(dir, 'x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
    '-CAcreateserial', '-out', 'intermediate.pem', '-days', '36500', '-extfile', 'ca.ext');

  ossl(dir, 'req', ...EC, '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=issuer.example.test');
  writeFileSync(join(dir, 'leaf.ext'),
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
    'subjectAltName=URI:https://issuer.example.test,DNS:issuer.example.test\n');
  ossl(dir, 'x509', '-req', '-in', 'leaf.csr', '-CA', 'intermediate.pem', '-CAkey', 'intermediate.key',
    '-CAcreateserial', '-out', 'leaf.pem', '-days', '36500', '-extfile', 'leaf.ext');

  writeFileSync(join(dir, 'chain.pem'),
    readFileSync(join(dir, 'leaf.pem'), 'utf-8') + readFileSync(join(dir, 'intermediate.pem'), 'utf-8'));
  for (const f of ['root.key', 'intermediate.key']) rmSync(join(dir, f));
  return dir;
}
