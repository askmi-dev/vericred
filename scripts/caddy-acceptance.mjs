import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import https from 'node:https';
import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { createSyntheticEudiMaterial } from './lib/synthetic-eudi-material.mjs';

// Disposable local proxy evidence only. Never points at production data or a public hostname.
const appImage = process.argv[2] ?? 'vericred:acceptance-20260920-provisioning';
const caddyImage = 'caddy:2.11.4-alpine';
assert.match(appImage, /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/);
assert(process.argv.length <= 3, 'Usage: node scripts/caddy-acceptance.mjs [local-application-image]');
const exec = promisify(execFile);
const id = randomUUID(), label = 'com.vericred.caddy-test';
const network = 'vericred-caddy-' + id;
const frontendNetwork = network + '-frontend';
const proxy = network + '-proxy', probe = network + '-probe', gateway = network + '-gateway';
const containers = [gateway, proxy, probe];
const artifacts = resolve('.validation-artifacts'); mkdirSync(artifacts, { recursive: true });
const fixture = mkdtempSync(join(artifacts, 'caddy-test-'));
let environment = { ...process.env }, stage = 'fixture', summary, origin;
async function docker(args, timeout = 60000) {
  return (await exec('docker', args, { env: environment, encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 1024 * 1024 })).stdout.trim();
}
async function removeOwned(kind, name) {
  const list = await docker(kind === 'container' ? ['ps', '-a', '--format', '{{.Names}}'] : ['network', 'ls', '--format', '{{.Name}}']);
  if (!list.split(/\r?\n/).includes(name)) return;
  const inspected = JSON.parse(await docker([kind, 'inspect', name]))[0];
  assert.equal((kind === 'container' ? inspected.Config.Labels : inspected.Labels)?.[label], id, 'Refuse removal without this run ownership');
  await docker(kind === 'container' ? ['rm', '-f', '-v', name] : ['network', 'rm', name]);
}
let ca;
async function request(base, path, { method = 'GET', headers = {}, body, trusted = true } = {}) {
  const url = new URL(path, base);
  return new Promise((resolveRequest, reject) => {
    const tls = url.protocol === 'https:';
    const req = (tls ? https : http).request(url, { method, headers,
      ...(tls ? { servername: url.hostname, ...(trusted ? { ca } : {}) } : {}), rejectUnauthorized: true,
      lookup: (_hostname, options, callback) => options?.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4),
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 1024 * 1024) res.destroy(new Error('Response too large')); else chunks.push(chunk); });
      res.on('error', reject);
      res.on('end', () => resolveRequest({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(10000, () => req.destroy(new Error('Local request timed out')));
    req.on('error', reject); if (body) req.write(body); req.end();
  });
}
const noisyHeaders = { Forwarded: 'for=203.0.113.41;proto=http;host=attacker.invalid',
  'X-Forwarded-For': '203.0.113.41', 'X-Forwarded-Proto': 'http', 'X-Forwarded-Host': 'attacker.invalid' };
try {
  const material = await createSyntheticEudiMaterial(fixture, 'https://localhost');
  environment = { ...environment, ADMIN_API_KEY: material.adminApiKey, PSEUDO_SECRET: material.pseudonymSecret };
  ca = readFileSync(join(fixture, 'material', 'tls-cert.pem'));
  const template = readFileSync('deploy/Caddyfile.acceptance', 'utf8');
  assert(template.includes('{$ACCEPTANCE_HOST} {'), 'Expected prepared acceptance host block');
  // Preserve every prepared proxy directive; only fixture TLS and admin listener differ.
  const caddyfile = '{\n    admin off\n}\n' + template.replace('{$ACCEPTANCE_HOST} {', '{$ACCEPTANCE_HOST} {\n    tls /run/eudi/tls-cert.pem /run/eudi/tls-key.pem');
  writeFileSync(join(fixture, 'Caddyfile'), caddyfile, { mode: 0o600 });
  stage = 'images';
  const appId = await docker(['image', 'inspect', appImage, '--format', '{{.Id}}']);
  try { await docker(['image', 'inspect', caddyImage, '--format', '{{.Id}}']); }
  catch { await docker(['pull', caddyImage], 180000); }
  const caddyId = await docker(['image', 'inspect', caddyImage, '--format', '{{.Id}}']);
  stage = 'isolated proxy'; console.log('Caddy acceptance: isolated proxy and forwarding-header probe');
  await docker(['network', 'create', '--internal', '--label', label + '=' + id, network]);
  await docker(['network', 'create', '--label', label + '=' + id, frontendNetwork]);
  const echo = 'require("node:http").createServer((req,res)=>{res.setHeader("content-type","application/json");res.end(JSON.stringify({marker:"synthetic-header-probe",headers:req.headers}))}).listen(3100,"0.0.0.0")';
  await docker(['run', '-d', '--name', probe, '--label', label + '=' + id, '--network', network, '--network-alias', 'gateway', '--read-only', appImage, 'node', '-e', echo]);
  await docker(['run', '-d', '--name', proxy, '--label', label + '=' + id, '--network', frontendNetwork,
    '-p', '127.0.0.1::443', '-p', '127.0.0.1::80', '-e', 'ACCEPTANCE_HOST=localhost',
    '--mount', 'type=bind,src=' + join(fixture, 'Caddyfile') + ',dst=/etc/caddy/Caddyfile,readonly',
    '--mount', 'type=bind,src=' + join(fixture, 'material') + ',dst=/run/eudi,readonly', caddyImage]);
  await docker(['network', 'connect', network, proxy]);
  const proxyState = JSON.parse(await docker(['inspect', '--format', '{{json .State}}', proxy]));
  assert(proxyState.Running, 'Caddy exited during startup');
  const port = Number((await docker(['port', proxy, '443/tcp'])).split(':').at(-1));
  const httpPort = Number((await docker(['port', proxy, '80/tcp'])).split(':').at(-1));
  origin = 'https://localhost:' + port;
  let probed;
  for (let attempt = 0; attempt < 40; attempt++) {
    try { const response = await request(origin, '/probe', { headers: noisyHeaders }); if (response.status === 200) { probed = JSON.parse(response.body); break; } } catch {}
    await delay(500);
  }
  assert.equal(probed?.marker, 'synthetic-header-probe', 'Proxy must serve the isolated probe');
  assert.equal(probed.headers.forwarded, undefined, 'Remove the standardized Forwarded header');
  assert.equal(probed.headers['x-forwarded-proto'], 'https');
  assert(!probed.headers['x-forwarded-for'].includes('203.0.113.41'), 'Replace client-supplied forwarding address');
  assert.equal(probed.headers['x-forwarded-host'], new URL(origin).host);
  const rejectedHost = await request(origin, '/probe', { headers: { Host: 'attacker.invalid' } });
  assert(!rejectedHost.body.includes('synthetic-header-probe'), 'An unrelated Host must not reach the upstream');
  await assert.rejects(request(origin, '/probe', { trusted: false }), 'Untrusted fixture TLS must fail');
  const redirect = await request('http://localhost:' + httpPort, '/admin/login?fixture=1');
  assert([301, 302, 307, 308].includes(redirect.status));
  const destination = new URL(redirect.headers.location);
  assert.equal(destination.protocol, 'https:'); assert.equal(destination.hostname, 'localhost');
  assert.equal(destination.pathname + destination.search, '/admin/login?fixture=1');
  await removeOwned('container', probe);
  stage = 'EUDI gateway'; console.log('Caddy acceptance: actual EUDI gateway, pinned metadata and secure admin cookie');
  const configPath = join(fixture, 'data', 'vericred.config.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  config.issuer.url = origin; config.issuer.did = 'did:web:localhost%3A' + port;
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  const proxyIp = JSON.parse(await docker(['inspect', proxy]))[0].NetworkSettings.Networks[network].IPAddress;
  assert.match(proxyIp, /^\d+\.\d+\.\d+\.\d+$/);
  await docker(['run', '-d', '--name', gateway, '--label', label + '=' + id, '--network', network, '--network-alias', 'gateway',
    '--init', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--mount', 'type=bind,src=' + join(fixture, 'data') + ',dst=/app/data',
    '--mount', 'type=bind,src=' + join(fixture, 'material') + ',dst=/run/eudi,readonly',
    '-e', 'NODE_ENV=production', '-e', 'DATA_DIR=/app/data', '-e', 'WALLET_PROFILE=eudi-android', '-e', 'EUDI_REGISTRATION_POLICY=required',
    '-e', 'EUDI_ISSUER_REGISTRAR_DATASET_PATH=/run/eudi/issuer-registrar-dataset.json', '-e', 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH=/run/eudi/verifier-registrar-dataset.json',
    '-e', 'ADMIN_API_KEY', '-e', 'PSEUDO_SECRET', '-e', 'TRUSTED_PROXY_CIDRS=' + proxyIp + '/32',
    '-e', 'EUDI_ISSUER_CERT_CHAIN_PATH=/run/eudi/issuer-chain.pem', '-e', 'EUDI_VERIFIER_CERT_CHAIN_PATH=/run/eudi/verifier-chain.pem',
    '-e', 'EUDI_VERIFIER_KEY_PATH=/run/eudi/verifier-key.pem', '-e', 'EUDI_ISSUER_REGISTRATION_CERT_PATH=/run/eudi/issuer-registration.jwt',
    '-e', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH=/run/eudi/verifier-registration.jwt', '-e', 'EUDI_WALLET_ATTESTATION_POLICY_PATH=/run/eudi/wallet-attestation-policy.json', appImage]);
  let healthy = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    const state = JSON.parse(await docker(['inspect', '--format', '{{json .State}}', gateway]));
    assert(state.Running, 'Gateway exited before readiness');
    try { const r = await request(origin, '/health'); if (r.status === 200 && JSON.parse(r.body).status === 'ok') { healthy = true; break; } } catch {}
    await delay(500);
  }
  assert(healthy, 'Gateway must become healthy');
  const preflight = await exec(process.execPath, ['scripts/https-preflight.mjs', origin], { windowsHide: true, timeout: 60000,
    env: { ...environment, NODE_EXTRA_CA_CERTS: join(fixture, 'material', 'tls-cert.pem'), NODE_TLS_REJECT_UNAUTHORIZED: '1',
      NODE_OPTIONS: '--dns-result-order=ipv4first', EUDI_ISSUER_CERT_SHA256: material.issuerFingerprint } });
  assert.equal(JSON.parse(preflight.stdout).status, 'PASS');
  const metadata = await request(origin, '/.well-known/openid-credential-issuer', { headers: { ...noisyHeaders, Accept: 'application/json' } });
  assert.equal(JSON.parse(metadata.body).credential_issuer, origin); assert(metadata.headers['strict-transport-security']);
  assert.equal((await request(origin, '/admin/api/readiness')).status, 401);
  const login = await request(origin, '/admin/login', { method: 'POST', headers: { ...noisyHeaders, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ apiKey: material.adminApiKey }).toString() });
  assert.equal(login.status, 302); assert.equal(login.headers.location, '/console/dashboard');
  const cookie = login.headers['set-cookie']?.[0];
  assert(cookie && /;\s*Secure(?:;|$)/i.test(cookie) && /;\s*HttpOnly(?:;|$)/i.test(cookie) && /;\s*SameSite=Strict(?:;|$)/i.test(cookie), 'Secure admin cookie flags');
  const readiness = await request(origin, '/admin/api/readiness', { headers: { Cookie: cookie.split(';')[0] } });
  assert.equal(readiness.status, 200); assert.match(readiness.headers['cache-control'] ?? '', /no-store/); const ready = JSON.parse(readiness.body);
  assert.equal(ready.configurationReady, true); assert.equal(ready.releaseAccepted, false);
  assert.equal(ready.checks.find(check => check.id === 'registration_on_acceptance').status, 'not_verified');
  stage = 'forwarding abuse'; console.log('Caddy acceptance: forged forwarding headers must not bypass login limits');
  let limited = false;
  for (let index = 1; index <= 22; index++) {
    const failed = await request(origin, '/admin/login', { method: 'POST', headers: { ...noisyHeaders, 'X-Forwarded-For': '198.51.100.' + index, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'apiKey=synthetic-invalid-key' });
    if (failed.status === 429) { limited = true; break; }
    assert.equal(failed.status, 302);
  }
  assert(limited, 'Rotating spoofed addresses must not bypass rate limiting');
  summary = { status: 'PASS', scope: 'Isolated Caddy/local TLS and synthetic EUDI material; not independent wallet or public HTTPS acceptance',
    checkedAt: new Date().toISOString(), appImage, appId, caddyImage, caddyId,
    proxyTemplateSha256: createHash('sha256').update(template).digest('hex'),
    harnessSha256: createHash('sha256').update(readFileSync('scripts/caddy-acceptance.mjs')).digest('hex'),
    checks: ['forwarded header removal/replacement', 'unrelated Host isolation', 'trusted/untrusted local TLS', 'HTTP redirect', 'signed metadata preflight', 'secure admin cookie', 'readiness boundaries', 'login rate-limit spoofing rejection'],
    publicHttpsAcceptance: 'NOT RUN', independentWalletAcceptance: 'NOT RUN', registrationPolicyOnAcceptance: 'NOT RUN', providerTrustAcceptance: 'NOT RUN' };
} catch (error) {
  console.error('Caddy acceptance failed at ' + stage + ': ' + error.message); process.exitCode = 1;
  for (const name of [proxy, gateway]) {
    try { const logs = await exec('docker', ['logs', name], { windowsHide: true, timeout: 10000, maxBuffer: 256 * 1024 }); writeFileSync(join(fixture, name.endsWith('-proxy') ? 'proxy-failure.log' : 'gateway-failure.log'), logs.stdout + logs.stderr); } catch {}
  }
} finally {
  try { for (const name of containers) await removeOwned('container', name); await removeOwned('network', network); await removeOwned('network', frontendNetwork); }
  catch (error) { console.error('Owned test resource cleanup failed: ' + error.message); process.exitCode = 1; }
}
if (summary && !process.exitCode) {
  summary.cleanup = 'PASS'; writeFileSync(join(fixture, 'result.json'), JSON.stringify(summary, null, 2));
  writeFileSync(join(artifacts, 'caddy-acceptance-result.json'), JSON.stringify(summary, null, 2));
  console.log('Caddy acceptance PASS: local TLS, EUDI metadata, secure cookies, proxy boundaries and cleanup.');
}
