import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import net from 'node:net';

// Isolated local operator preview. This never uses the project's .env or existing issuer data.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = join(root, '.validation-artifacts', 'local-walkthrough');
const markerPath = join(fixture, 'fixture.json');
const origin = 'http://127.0.0.1:3310';
const dataDir = join(fixture, 'data');
const purpose = 'vericred-local-walkthrough';
if (!existsSync(join(root, 'dist', 'server.js')) || !existsSync(join(root, 'stitch-out', 'dist', 'console', 'monitor', 'index.html'))) {
  throw new Error('Build the application first with npm run build.');
}
if (existsSync(markerPath)) {
  const marker = JSON.parse(readFileSync(markerPath, 'utf8'));
  if (marker.purpose !== purpose || marker.origin !== origin) throw new Error('Unrecognized walkthrough fixture; refusing to reuse data.');
} else {
  if (existsSync(fixture) && readdirSync(fixture).length) throw new Error('Unrecognized non-empty walkthrough directory; refusing to overwrite.');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  writeFileSync(join(fixture, 'secrets.json'), JSON.stringify({ adminApiKey: randomBytes(32).toString('hex'), pseudonymSecret: randomBytes(32).toString('hex') }, null, 2), { flag: 'wx', mode: 0o600 });
  const holders = [
    { id: 'walkthrough-adult', firstName: 'Alex', lastName: 'Example', email: 'alex@example.invalid', dateOfBirth: '1990-01-01', organization: 'VeriCred Example', role: 'Engineer', membershipType: 'Standard', region: 'Graz' },
    { id: 'walkthrough-young', firstName: 'Robin', lastName: 'Example', email: 'robin@example.invalid', dateOfBirth: '2015-01-01', organization: 'VeriCred Example', role: 'Student', membershipType: 'Junior', region: 'Vienna' },
  ];
  writeFileSync(join(dataDir, 'holders.json'), JSON.stringify(holders, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(join(dataDir, 'vericred.config.json'), JSON.stringify({
    revision: 1,
    issuer: { name: 'VeriCred Local Walkthrough', url: origin, did: 'did:web:127.0.0.1%3A3310' },
    credential: { type: 'AgeCredential', format: 'dc+sd-jwt', expiresInDays: 30 },
    dataSource: { type: 'json', path: join(dataDir, 'holders.json') },
    fieldMappings: { dateOfBirth: 'dateOfBirth' },
    templateOptions: { ageThresholds: [18, 21], jurisdiction: 'AT' },
    templateMappings: { AgeCredential: { dateOfBirth: 'dateOfBirth' }, EmployeeCredential: { given_name: 'firstName', family_name: 'lastName', organization: 'organization', role: 'role' }, MembershipCredential: { organization: 'organization', membershipType: 'membershipType' } },
  }, null, 2), { flag: 'wx', mode: 0o600 });
  writeFileSync(markerPath, JSON.stringify({ purpose, origin, createdAt: new Date().toISOString() }, null, 2), { flag: 'wx', mode: 0o600 });
}
const secrets = JSON.parse(readFileSync(join(fixture, 'secrets.json'), 'utf8'));
if (!secrets.adminApiKey || !secrets.pseudonymSecret) throw new Error('Walkthrough secrets missing.');
// Refuse to attach to an existing service or steal its port.
await new Promise((resolvePromise, reject) => { const probe = net.createServer(); probe.once('error', reject); probe.listen(3310, '127.0.0.1', () => probe.close(resolvePromise)); });
const tmp = join(root, '.validation-artifacts', 'tmp'); mkdirSync(tmp, { recursive: true });
const child = spawn(process.execPath, [join(root, 'dist', 'server.js')], {
  cwd: fixture, stdio: 'inherit', windowsHide: true,
  env: { ...process.env, NODE_ENV: 'development', HOST: '127.0.0.1', PORT: '3310', DATA_DIR: dataDir,
    ISSUER_URL: origin, ADMIN_API_KEY: secrets.adminApiKey, PSEUDO_SECRET: secrets.pseudonymSecret,
    WALLET_PROFILE: 'custom', DEMO_MODE: 'false', PII_ADMIN_MODE: 'false', TRUSTED_PROXY_CIDRS: '',
    FRONTEND_DIST_PATH: join(root, 'stitch-out', 'dist'), TEMP: tmp, TMP: tmp },
});
console.log('Local walkthrough: ' + origin + '/admin/login');
console.log('Use adminApiKey from ' + join(fixture, 'secrets.json') + '. The key is not printed.');
console.log('Synthetic local HTTP/custom profile only. Independent EUDI wallet acceptance: NOT RUN.');
console.log('Run npm run walkthrough:flow in another terminal for the automated data flow; Ctrl+C stops this instance.');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => child.kill(signal));
child.once('error', error => { console.error(error.message); process.exitCode = 1; });
child.once('exit', code => { process.exitCode = code ?? 0; });
