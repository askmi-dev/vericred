/**
 * npm run csr -- [--cn <name>] [--org <name>] [--country DE] [--out <file>]
 *
 * Writes a certificate signing request for the CURRENT issuer key, for the
 * registrar CA. The private key never leaves this process. SAN defaults to
 * issuer.url (URI) and its host (DNS), which is what x5c validation requires.
 */
import { writeFileSync } from 'fs';
import { parseArgs } from 'util';
import type { KeyObject } from 'crypto';
import { loadConfig } from '../config/loader.js';
import { loadExistingIssuerKeyPair, ISSUER_KEY_PATH } from '../keys/manager.js';
import { buildCsr } from '../keys/csr.js';

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      cn: { type: 'string' },
      org: { type: 'string' },
      country: { type: 'string' },
      out: { type: 'string', default: 'issuer.csr.pem' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) {
    console.log('Usage: npm run csr -- [--cn <name>] [--org <name>] [--country DE] [--out issuer.csr.pem]');
    return 0;
  }

  const keys = await loadExistingIssuerKeyPair();
  if (!keys) {
    console.error(`No issuer key at ${ISSUER_KEY_PATH}. Start VeriCred once (or set DATA_DIR to its key folder) so the CSR is for the key it signs with.`);
    return 1;
  }

  const config = loadConfig();
  const url = new URL(config.issuer.url);
  if (url.protocol !== 'https:' || ['localhost', '127.0.0.1'].includes(url.hostname)) {
    console.warn(`Warning: issuer.url is ${config.issuer.url}. A registrar will only certify a public https URL; set ISSUER_URL first.`);
  }

  const uri = config.issuer.url.replace(/\/+$/, '');
  const subject = {
    commonName: values.cn ?? url.hostname,
    organization: values.org ?? config.issuer.name,
    country: values.country?.toUpperCase(),
  };
  const pem = buildCsr({
    privateKey: keys.privateKey as KeyObject,
    publicKey: keys.publicKey as KeyObject,
    subject,
    sanUris: [uri],
    sanDns: [url.hostname],
  });
  writeFileSync(values.out, pem);

  console.log(`Wrote ${values.out}
  key:     ${ISSUER_KEY_PATH} (kid ${keys.kid})
  subject: CN=${subject.commonName}${subject.organization ? `, O=${subject.organization}` : ''}${subject.country ? `, C=${subject.country}` : ''}
  SAN:     URI:${uri}, DNS:${url.hostname}

Next:
  1. Send ${values.out} to the registrar. It contains no secret.
  2. Save the chain you get back as PEM: your certificate first, then intermediates, without the root.
  3. Set "issuer": { "certificateChain": "<path>" } in vericred.config.json and restart.
  After a key rotation, run this again: the old certificate no longer matches.`);
  return 0;
}

main().then(code => process.exit(code), (e: Error) => { console.error(e.message); process.exit(1); });
