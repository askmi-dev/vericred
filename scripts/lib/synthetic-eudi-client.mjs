import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair, importJWK, importPKCS8, jwtVerify, SignJWT } from 'jose';

// Local synthetic protocol evidence only. Never log credentials, tokens or keys.
function check(condition, message) { if (!condition) throw new Error(message); }
function localOrigin(origin) {
  const url = new URL(origin);
  check(url.protocol === 'https:' && ['localhost', '127.0.0.1'].includes(url.hostname) &&
    !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash,
  'Synthetic client requires a loopback HTTPS origin');
  return url.origin;
}
function header(response, name) {
  return typeof response.headers?.get === 'function' ? response.headers.get(name) : response.headers?.[name.toLowerCase()];
}
function body(response, label, mediaType) {
  check(response.status === 200, label + ' failed (HTTP ' + response.status + ')');
  check(typeof response.body === 'string' && Buffer.byteLength(response.body) <= 1024 * 1024,
    label + ' returned an invalid response size');
  if (mediaType) check(String(header(response, 'content-type')).split(';')[0] === mediaType, label + ' returned an unexpected media type');
  return response.body;
}
function parse(value, label) {
  try { return JSON.parse(value); } catch { throw new Error(label + ' returned invalid JSON'); }
}
async function json(request, path, payload, token) {
  const response = await request(path, { method: 'POST', headers: {
    'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}),
  }, body: JSON.stringify(payload) });
  return parse(body(response, path, 'application/json'), path);
}
async function issuerCertificate(materialDir) {
  const certificate = new X509Certificate(await readFile(join(materialDir, 'issuer-chain.pem')));
  check(Date.parse(certificate.validFrom) <= Date.now() && Date.now() < Date.parse(certificate.validTo),
    'Synthetic issuer certificate is not currently valid');
  return certificate;
}
async function verifySigned(compact, certificate, origin, typ, subject) {
  let verified;
  try { verified = await jwtVerify(compact, certificate.publicKey, {
    algorithms: ['ES256'], issuer: origin, typ, ...(subject ? { subject } : {}),
    requiredClaims: ['iat', 'exp'], maxTokenAge: 300,
  }); } catch { throw new Error('Synthetic client could not verify ' + typ); }
  const now = Math.floor(Date.now() / 1000), payload = verified.payload;
  check(Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) &&
    payload.iat <= now + 30 && payload.exp > payload.iat, 'Signed response has invalid time claims');
  check(verified.protectedHeader.x5c?.[0] === certificate.raw.toString('base64'),
    'Signed response does not carry the fixture certificate');
  return payload;
}
async function tokenStatus({ request, origin, certificate, listId }) {
  check(typeof listId === 'string' && /^[a-zA-Z0-9-]{1,128}$/.test(listId), 'Invalid Token Status List identifier');
  const path = '/status/token/' + listId;
  const response = await request(path, { headers: { Accept: 'application/statuslist+jwt' } });
  const payload = await verifySigned(body(response, 'Token Status List', 'application/statuslist+jwt'),
    certificate, origin, 'statuslist+jwt', origin + path);
  check(payload.ttl === 60 && payload.exp - payload.iat <= 300, 'Token Status List freshness contract mismatch');
  check(payload.status_list?.bits === 1 && typeof payload.status_list.lst === 'string' &&
    /^[A-Za-z0-9_-]+$/.test(payload.status_list.lst), 'Invalid one-bit Token Status List');
  let bitmap;
  try { bitmap = inflateSync(Buffer.from(payload.status_list.lst, 'base64url'), { maxOutputLength: 1024 * 1024 }); }
  catch { throw new Error('Token Status List could not be decoded'); }
  check(bitmap.length === 131072 / 8, 'Token Status List bitmap has an unexpected length');
  return bitmap;
}

/** Issue with locally generated attested holder keys; not independent wallet acceptance. */
export async function issueSyntheticEudiCredential({ request, origin, materialDir, adminApiKey, statusUri }) {
  origin = localOrigin(origin);
  const certificate = await issuerCertificate(materialDir);
  const response = await request('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/jwt' } });
  const metadata = await verifySigned(body(response, 'Signed metadata', 'application/jwt'), certificate,
    origin, 'openidvci-issuer-metadata+jwt', origin);
  check(metadata.credential_issuer === origin && metadata.credential_endpoint === origin + '/credentials' &&
    metadata.nonce_endpoint === origin + '/nonce', 'Synthetic metadata endpoints disagree');
  const registration = metadata.issuer_info?.filter(entry => entry.format === 'registration_cert');
  const datasets = metadata.issuer_info?.filter(entry => entry.format === 'registrar_dataset');
  const expectedDataset = parse(await readFile(join(materialDir, 'issuer-registrar-dataset.json'), 'utf8'), 'Synthetic issuer dataset');
  const expectedCertificate = (await readFile(join(materialDir, 'issuer-registration.jwt'), 'utf8')).trim();
  check(registration?.length === 1 && registration[0].data === Buffer.from(expectedCertificate).toString('base64url') &&
    datasets?.length === 1 && JSON.stringify(datasets[0].data) === JSON.stringify(expectedDataset),
  'Signed metadata does not preserve the provisioned registration material');
  const configuration = metadata.credential_configurations_supported?.AgeCredential;
  check(configuration?.format === 'dc+sd-jwt' && configuration.vct === 'urn:vericred:credential:AgeCredential:1',
    'Synthetic AgeCredential contract is unavailable');
  const requirements = configuration.proof_types_supported?.jwt?.key_attestations_required;
  check(requirements?.key_storage?.includes('iso_18045_high') && requirements?.user_authentication?.includes('iso_18045_high'),
    'Synthetic attestation assurance contract is unavailable');
  check(metadata.credential_request_encryption?.encryption_required === true &&
    metadata.credential_response_encryption?.encryption_required === true &&
    metadata.credential_request_encryption.enc_values_supported?.includes('A128GCM') &&
    metadata.credential_response_encryption.enc_values_supported?.includes('A128GCM') &&
    metadata.credential_response_encryption.alg_values_supported?.includes('ECDH-ES'),
  'EUDI request/response encryption is unavailable');
  const requestJwk = metadata.credential_request_encryption.jwks?.keys?.find(key =>
    key.alg === 'ECDH-ES' && key.use === 'enc' && key.kty === 'EC' && key.crv === 'P-256' && !key.d);
  check(requestJwk, 'Synthetic metadata lacks a public request encryption key');
  const offer = await json(request, '/offer', { holderId: 'synthetic-adult', credentialType: 'AgeCredential' }, adminApiKey);
  check(offer.offer?.credential_issuer === origin && offer.offer.credential_configuration_ids?.[0] === 'AgeCredential',
    'Synthetic offer contract mismatch');
  const code = offer.offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'];
  check(typeof code === 'string' && code.length > 0, 'Synthetic offer has no pre-authorized code');
  const token = await json(request, '/token', { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code });
  check(typeof token.access_token === 'string' && token.access_token.length > 0, 'Synthetic token response is invalid');
  const nonce = await json(request, '/nonce', {});
  check(typeof nonce.c_nonce === 'string' && nonce.c_nonce.length > 0, 'Synthetic nonce response is invalid');
  const holder = await generateKeyPair('ES256', { extractable: true });
  const holderJwk = await exportJWK(holder.publicKey);
  const provider = new X509Certificate(await readFile(join(materialDir, 'wallet-provider-cert.pem')));
  const providerKey = await importPKCS8(await readFile(join(materialDir, 'wallet-provider-key.pem'), 'utf8'), 'ES256');
  const policy = parse(await readFile(join(materialDir, 'wallet-attestation-policy.json'), 'utf8'), 'Synthetic attestation policy');
  const providerPolicy = policy.providers?.find(item => item.signingCertificateSha256?.includes(createHash('sha256').update(provider.raw).digest('hex')));
  check(providerPolicy?.keyStorage?.includes('iso_18045_high') && providerPolicy?.userAuthentication?.includes('iso_18045_high') &&
    providerPolicy?.certifications?.includes('https://wallet-provider.example.invalid/certification/synthetic') &&
    providerPolicy?.statusListPrefixes?.some(prefix => typeof statusUri === 'string' && statusUri.startsWith(prefix)),
  'Synthetic provider material does not match its provisioned policy');
  const now = Math.floor(Date.now() / 1000);
  const attestation = await new SignJWT({
    iat: now, exp: now + 300, nonce: nonce.c_nonce, attested_keys: [holderJwk],
    key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'],
    certification: 'https://wallet-provider.example.invalid/certification/synthetic',
    key_storage_status: { status: { status_list: { idx: 0, uri: statusUri } }, exp: now + 400 * 86400 },
  }).setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt', x5c: [provider.raw.toString('base64')] }).sign(providerKey);
  const proof = await new SignJWT({ nonce: nonce.c_nonce }).setAudience(origin).setIssuedAt()
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', kid: '0', key_attestation: attestation }).sign(holder.privateKey);
  const responseKey = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
  const responseJwk = { ...await exportJWK(responseKey.publicKey), alg: 'ECDH-ES', kid: 'synthetic-response' };
  const encrypted = await new CompactEncrypt(Buffer.from(JSON.stringify({
    credential_configuration_id: 'AgeCredential', proofs: { jwt: [proof] },
    credential_response_encryption: { jwk: responseJwk, enc: 'A128GCM' },
  }))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: requestJwk.kid }).encrypt(await importJWK(requestJwk, 'ECDH-ES'));
  const issued = await request('/credentials', { method: 'POST', headers: {
    'Content-Type': 'application/jwt', Authorization: 'Bearer ' + token.access_token,
  }, body: encrypted });
  let plaintext;
  try {
    const decrypted = await compactDecrypt(body(issued, 'Encrypted issuance', 'application/jwt'), responseKey.privateKey,
      { keyManagementAlgorithms: ['ECDH-ES'], contentEncryptionAlgorithms: ['A128GCM'] });
    plaintext = Buffer.from(decrypted.plaintext).toString('utf8');
  } catch { throw new Error('Synthetic encrypted issuance failed (HTTP ' + issued.status + ')'); }
  const credential = parse(plaintext, 'Encrypted issuance').credentials?.[0]?.credential;
  check(typeof credential === 'string' && credential.endsWith('~'), 'Synthetic issuer did not return an SD-JWT credential');
  const [issuerJwt, ...disclosures] = credential.split('~').filter(Boolean);
  const claims = await verifySigned(issuerJwt, certificate, origin, 'dc+sd-jwt');
  check(claims.vct === configuration.vct && claims._sd_alg === 'sha-256' && Array.isArray(claims._sd), 'Issued SD-JWT schema mismatch');
  check(['kty', 'crv', 'x', 'y'].every(name => claims.cnf?.jwk?.[name] === holderJwk[name]) && !claims.cnf.jwk.d,
    'Issued SD-JWT does not bind to the attested holder key');
  check(disclosures.length > 0 && disclosures.every(value => claims._sd.includes(createHash('sha256').update(value).digest('base64url'))),
    'Issued SD-JWT disclosures do not match their signed digests');
  check(typeof claims.jti === 'string' && claims.jti.startsWith('urn:uuid:'), 'Issued credential identifier is invalid');
  const status = claims.status?.status_list;
  check(Number.isSafeInteger(status?.idx) && status.idx >= 0 && status.idx < 131072 &&
    typeof status.uri === 'string' && status.uri.startsWith(origin + '/status/token/'), 'Issued Token Status List reference is invalid');
  const listId = status.uri.slice((origin + '/status/token/').length);
  const bitmap = await tokenStatus({ request, origin, certificate, listId });
  check(((bitmap[Math.floor(status.idx / 8)] >> (status.idx % 8)) & 1) === 0, 'Newly issued credential is already revoked');
  return { credentialId: claims.jti, listId, statusIndex: status.idx, accessToken: token.access_token };
}

/** Verify every index of the restored EUDI Token Status List is retired. */
export async function verifyRetiredTokenStatus({ request, origin, materialDir, listId }) {
  origin = localOrigin(origin);
  const bitmap = await tokenStatus({ request, origin, certificate: await issuerCertificate(materialDir), listId });
  check(bitmap.every(value => value === 0xff), 'Restored Token Status List contains a non-retired index');
}
