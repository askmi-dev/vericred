/**
 * VeriCred Cryptographic Service
 * Uses Web Crypto API (ECDSA P-256) for secure, browser-native signing and verification.
 * Includes deterministic canonicalization to protect against JSON key-ordering issues.
 */

/**
 * Recursively canonicalizes an object or array, sorting all object keys alphabetically.
 * This guarantees deterministic JSON stringification.
 */
export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(canonicalize);
  }
  const sortedKeys = Object.keys(obj).sort();
  const sortedObj = {};
  for (const key of sortedKeys) {
    sortedObj[key] = canonicalize(obj[key]);
  }
  return sortedObj;
}

/**
 * Returns a deterministic JSON string representation of any object.
 */
export function deterministicStringify(obj) {
  return JSON.stringify(canonicalize(obj));
}

/**
 * Converts an ArrayBuffer to a hex string.
 */
export function bufToHex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * Converts a hex string back to an ArrayBuffer.
 */
export function hexToBuf(hexString) {
  const cleanHex = hexString.replace(/\s+/g, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const numBytes = cleanHex.length / 2;
  const byteArray = new Uint8Array(numBytes);
  for (let i = 0; i < numBytes; i++) {
    byteArray[i] = parseInt(cleanHex.substring(i * 2, (i * 2) + 2), 16);
  }
  return byteArray.buffer;
}

/**
 * Generates an ECDSA P-256 KeyPair (Private and Public) for digital signatures.
 */
export async function generateKeyPair() {
  try {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true, // keys are extractable (for export/import)
      ['sign', 'verify']
    );
  } catch (error) {
    console.error('Failed to generate ECDSA Keypair:', error);
    throw error;
  }
}

/**
 * Exports a CryptoKey object into a portable JSON Web Key (JWK) format.
 */
export async function exportKeyToJWK(key) {
  try {
    return await window.crypto.subtle.exportKey('jwk', key);
  } catch (error) {
    console.error('Failed to export key to JWK:', error);
    throw error;
  }
}

/**
 * Imports a Public Key from its JWK format.
 */
export async function importPublicKeyFromJWK(jwk) {
  try {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['verify']
    );
  } catch (error) {
    console.error('Failed to import public key from JWK:', error);
    throw error;
  }
}

/**
 * Imports a Private Key from its JWK format.
 */
export async function importPrivateKeyFromJWK(jwk) {
  try {
    return await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign']
    );
  } catch (error) {
    console.error('Failed to import private key from JWK:', error);
    throw error;
  }
}

/**
 * Digitally signs a payload with a private CryptoKey, returning a hex-encoded signature.
 */
export async function signPayload(privateKey, payload) {
  try {
    const serialized = deterministicStringify(payload);
    const encoder = new TextEncoder();
    const data = encoder.encode(serialized);
    
    const signatureBuffer = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      privateKey,
      data
    );
    
    return bufToHex(signatureBuffer);
  } catch (error) {
    console.error('Failed to sign payload:', error);
    throw error;
  }
}

/**
 * Verifies a hex-encoded signature against a payload and a public CryptoKey.
 */
export async function verifyPayload(publicKey, payload, hexSignature) {
  try {
    const serialized = deterministicStringify(payload);
    const encoder = new TextEncoder();
    const data = encoder.encode(serialized);
    const signatureBuffer = hexToBuf(hexSignature);
    
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signatureBuffer,
      data
    );
  } catch (error) {
    console.error('Failed to verify payload signature:', error);
    return false;
  }
}

/**
 * Verifies a hex-encoded signature against a payload directly using a public JWK.
 */
export async function verifyWithJWK(jwkPublicKey, payload, hexSignature) {
  try {
    const publicKey = await importPublicKeyFromJWK(jwkPublicKey);
    return await verifyPayload(publicKey, payload, hexSignature);
  } catch (error) {
    console.error('JWK Import & signature verification failed:', error);
    return false;
  }
}

/**
 * Computes the SHA-256 hash of a text string, returning a hex-encoded string.
 */
export async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return bufToHex(hashBuffer);
}

/**
 * Converts an ArrayBuffer to a Base64URL string.
 */
export function bufToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Computes an RFC 7638 EC JWK public key thumbprint.
 * Alpha-sorts crv, kty, x, y and hashes to Base64URL.
 */
export async function calculateJWKThumbprint(jwk) {
  try {
    const canonicalObj = {
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y
    };
    const serialized = JSON.stringify(canonicalObj);
    const encoder = new TextEncoder();
    const data = encoder.encode(serialized);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return bufToBase64Url(hashBuffer);
  } catch (error) {
    console.error('Failed to compute JWK thumbprint:', error);
    throw error;
  }
}

/**
 * Performs a standard Web Crypto HMAC-SHA256 hash calculation, returning Base64URL.
 */
export async function calculateHMAC(secretStr, dataString) {
  try {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secretStr);
    const messageData = encoder.encode(dataString);
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      false,
      ['sign']
    );
    const sigBuffer = await window.crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return bufToBase64Url(sigBuffer);
  } catch (error) {
    console.error('HMAC-SHA256 calculation failed:', error);
    throw error;
  }
}

/**
 * Simulates a miTch Wallet generating a Presentation Proof.
 * Bundles a base credential (signed by EUDI base issuer) and a holder proof of possession (ECDSA).
 */
export async function createMitchPresentation(claims, holderKeyPair, nonce, aud, issuerKeyPair, issuerId = 'did:mitch:trust-anchor-1') {
  try {
    const holderPubJWK = await exportKeyToJWK(holderKeyPair.publicKey);
    const holderThumb = await calculateJWKThumbprint(holderPubJWK);
    
    const baseCredential = {
      issuer: issuerId,
      subject: {
        holder_jwk_thumbprint: holderThumb
      },
      claims: claims,
      signature: null
    };
    
    // Sign base credential using issuer's private key
    // Canonicalize base payload structure first
    const basePayloadToSign = {
      issuer: baseCredential.issuer,
      subject: baseCredential.subject,
      claims: baseCredential.claims
    };
    const baseSignature = await signPayload(issuerKeyPair.privateKey, basePayloadToSign);
    baseCredential.signature = baseSignature;
    
    // Sign holder binding proof of possession
    // Payload contains challenge (nonce + aud) plus a link to the base signature
    const bindingPayload = {
      nonce,
      aud,
      expires_at: Date.now() + 300000, // 5 minutes TTL
      baseCredentialSignature: baseSignature
    };
    const proof_of_possession = await signPayload(holderKeyPair.privateKey, bindingPayload);
    
    return {
      format: 'SD-JWT-VC',
      version: '1.0',
      baseCredential,
      holder_binding: {
        nonce,
        aud,
        expires_at: bindingPayload.expires_at,
        holder_jwk: holderPubJWK,
        proof_of_possession
      }
    };
  } catch (error) {
    console.error('Failed to create miTch presentation proof:', error);
    throw error;
  }
}

/**
 * Executes the sequential, fail-closed verification pipeline on a miTch Presentation Envelope.
 */
export async function verifyMitchPresentationSequential(envelope, expectedNonce, trustList, baseStatusList = {}, consumeNonceFn = null) {
  // 1. Parse & Structural Validation
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('Verification Failed (Parse): Envelope is not a valid object.');
  }
  if (!envelope.baseCredential || !envelope.holder_binding) {
    throw new Error('Verification Failed (Parse): Missing baseCredential or holder_binding sections.');
  }
  const baseCred = envelope.baseCredential;
  const hb = envelope.holder_binding;
  
  if (!baseCred.subject || !baseCred.subject.holder_jwk_thumbprint || !baseCred.signature) {
    throw new Error('Verification Failed (Parse): Invalid baseCredential structure.');
  }
  if (!hb.nonce || !hb.aud || !hb.expires_at || !hb.holder_jwk || !hb.proof_of_possession) {
    throw new Error('Verification Failed (Parse): Invalid holder_binding structure.');
  }
  
  // 2. Format & Version Check
  if (envelope.format !== 'SD-JWT-VC') {
    throw new Error(`Verification Failed (Version): Format '${envelope.format}' is unsupported. Must be 'SD-JWT-VC'.`);
  }
  if (envelope.version !== '1.0') {
    throw new Error(`Verification Failed (Version): Schema version '${envelope.version}' is unsupported. Must be '1.0'.`);
  }
  
  // 3. Replay Protection & Expiry
  if (hb.aud !== 'VeriCred-Gateway') {
    throw new Error(`Verification Failed (Replay): Audience mismatch. Expected 'VeriCred-Gateway', found '${hb.aud}'.`);
  }
  if (hb.nonce !== expectedNonce) {
    throw new Error(`Verification Failed (Replay): Challenge Nonce mismatch or expired. Received '${hb.nonce}'.`);
  }
  if (hb.expires_at < Date.now()) {
    throw new Error(`Verification Failed (Replay): Presentation proof has expired.`);
  }

  // Atomically consume the nonce once all structural and basic validation checks pass
  if (consumeNonceFn) {
    const isNonceValid = consumeNonceFn(hb.nonce);
    if (!isNonceValid) {
      throw new Error('Verification Failed (Replay): Challenge Nonce has already been consumed or has expired.');
    }
  }
  
  // 3b. Validate that the transient holder_jwk matches the Canonical holder_jwk_thumbprint
  const actualThumb = await calculateJWKThumbprint(hb.holder_jwk);
  if (actualThumb !== baseCred.subject.holder_jwk_thumbprint) {
    throw new Error('Verification Failed (Holder Binding): Transient holder key does not match the holder_jwk_thumbprint inside the base credential.');
  }
  
  // 4. Issuer Trust Anchor Check
  const issuerId = baseCred.issuer;
  const issuerPubKeyJWK = trustList[issuerId];
  if (!issuerPubKeyJWK) {
    throw new Error(`Verification Failed (Issuer Trust): Issuer '${issuerId}' is not registered on the Trust List.`);
  }
  
  // 5. Issuer Signature Check
  const basePayloadToVerify = {
    issuer: baseCred.issuer,
    subject: baseCred.subject,
    claims: baseCred.claims
  };
  const isIssuerSigValid = await verifyWithJWK(issuerPubKeyJWK, basePayloadToVerify, baseCred.signature);
  if (!isIssuerSigValid) {
    throw new Error('Verification Failed (Issuer Signature): Base credential signature is mathematically invalid.');
  }
  
  // 6. Holder Binding Check (Proof of Possession)
  const bindingPayloadToVerify = {
    nonce: hb.nonce,
    aud: hb.aud,
    expires_at: hb.expires_at,
    baseCredentialSignature: baseCred.signature
  };
  const isHolderSigValid = await verifyWithJWK(hb.holder_jwk, bindingPayloadToVerify, hb.proof_of_possession);
  if (!isHolderSigValid) {
    throw new Error('Verification Failed (Holder Binding): Key Binding signature is invalid. Presenter does not control the key.');
  }
  
  // 7. Revocation Check (StatusList)
  const mitchProofHash = await sha256(JSON.stringify(envelope));
  if (baseStatusList[mitchProofHash] === true) {
    throw new Error('Verification Failed (Revocation): The base credential has been marked as REVOKED.');
  }
  
  return {
    isValid: true,
    holderJwkThumbprint: baseCred.subject.holder_jwk_thumbprint,
    mitchProofHash,
    baseClaims: baseCred.claims,
    holderJwk: hb.holder_jwk
  };
}

/**
 * Converts a string to a Base64URL-encoded representation.
 */
export function stringToBase64Url(str) {
  const bytes = new TextEncoder().encode(str);
  return bufToBase64Url(bytes.buffer);
}

/**
 * Decodes a Base64URL-encoded string back to its UTF-8 representation.
 */
export function base64UrlToString(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Converts a Base64URL-encoded string into its hexadecimal representation.
 */
export function base64UrlToHex(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  const binary = atob(b64);
  let hex = '';
  for (let i = 0; i < binary.length; i++) {
    const code = binary.charCodeAt(i);
    hex += code.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Verifies a compact JWS signature (ES256) over the standard input headers and payload.
 */
export async function verifyCompactJWS(compactJWS, publicKeyObj) {
  const parts = compactJWS.split('.');
  if (parts.length !== 3) return false;
  const signatureInput = `${parts[0]}.${parts[1]}`;
  const sigHex = base64UrlToHex(parts[2]);
  const encoder = new TextEncoder();
  const inputBytes = encoder.encode(signatureInput);
  const sigBuffer = hexToBuf(sigHex);
  
  return await window.crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    publicKeyObj,
    sigBuffer,
    inputBytes
  );
}

/**
 * Computes standard RFC 9901 SD-JWT Compact Serialization.
 */
export async function serializeToCompactSDJWT(issuerDid, holderPseudonym, claims, salts, issuerPrivateKeyObj, holderJwk, mitchProofHash = null) {
  const disclosures = [];
  const sdArray = [];

  const keys = Object.keys(claims);
  for (const key of keys) {
    const value = claims[key];
    const salt = salts[key];
    
    // Standard structure: [salt, claim_key, claim_value]
    const disclosureArray = [salt, key, value];
    const disclosureJson = JSON.stringify(disclosureArray);
    
    const disclosureB64Url = stringToBase64Url(disclosureJson);
    disclosures.push(disclosureB64Url);

    // Hash over the US-ASCII bytes of the base64url disclosure string
    const asciiBytes = new TextEncoder().encode(disclosureB64Url);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', asciiBytes);
    const hashB64Url = bufToBase64Url(hashBuffer);
    sdArray.push(hashB64Url);
  }

  // Sort _sd list alphabetically for standard compatibility
  sdArray.sort();

  // Signed JWS Payload
  const jwsPayload = {
    iss: issuerDid,
    sub: holderPseudonym,
    vct: "WorkCertificate",
    _sd_alg: "sha-256",
    _sd: sdArray,
    cnf: {
      jwk: holderJwk
    },
    mitchProofHash,
    formatVersion: "1.1.0",
    iat: Math.floor(Date.now() / 1000)
  };

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const headerB64 = stringToBase64Url(JSON.stringify(header));
  const payloadB64 = stringToBase64Url(JSON.stringify(jwsPayload));
  const signatureInput = `${headerB64}.${payloadB64}`;
  
  const sigBuffer = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    issuerPrivateKeyObj,
    new TextEncoder().encode(signatureInput)
  );
  const signatureB64 = bufToBase64Url(sigBuffer);

  const jwsCompact = `${headerB64}.${payloadB64}.${signatureB64}`;

  // Complete SD-JWT: JWS_Compact~disclosure1~disclosure2~...~
  return `${jwsCompact}~${disclosures.join('~')}~`;
}

/**
 * Parses and verifies an RFC 9901 Compact SD-JWT string.
 */
export async function parseCompactSDJWT(compactStr, trustListKeys = {}) {
  const parts = compactStr.trim().split('~');
  if (parts.length < 2) {
    throw new Error("Invalid SD-JWT Compact format: Missing tilde separators.");
  }

  const jwsCompact = parts[0];
  const disclosureB64s = parts.slice(1).filter(Boolean);

  const jwsParts = jwsCompact.split('.');
  if (jwsParts.length !== 3) {
    throw new Error("Invalid JWS Compact structure in SD-JWT.");
  }

  const header = JSON.parse(base64UrlToString(jwsParts[0]));
  const payload = JSON.parse(base64UrlToString(jwsParts[1]));

  const issuerDid = payload.iss;
  const issuerPublicKeyJWK = trustListKeys[issuerDid];
  if (!issuerPublicKeyJWK) {
    throw new Error(`Untrusted issuer key anchor: ${issuerDid} is not in the gateway trust list.`);
  }

  const issuerPublicKeyObj = await importPublicKeyFromJWK(issuerPublicKeyJWK);
  const signatureValid = await verifyCompactJWS(jwsCompact, issuerPublicKeyObj);
  if (!signatureValid) {
    throw new Error("Invalid JWS Compact Signature: Verification failed.");
  }

  const claims = {};
  const salts = {};
  const recomputedHashes = [];

  for (const disclosureB64 of disclosureB64s) {
    const disclosureJson = base64UrlToString(disclosureB64);
    let disclosureArray;
    try {
      disclosureArray = JSON.parse(disclosureJson);
    } catch (e) {
      throw new Error(`Failed to parse disclosure JSON: ${disclosureJson}`);
    }

    if (!Array.isArray(disclosureArray) || disclosureArray.length !== 3) {
      throw new Error("Standard SD-JWT disclosures must be a JSON array of exactly 3 elements: [salt, key, value].");
    }

    const [salt, key, value] = disclosureArray;
    claims[key] = value;
    salts[key] = salt;

    const asciiBytes = new TextEncoder().encode(disclosureB64);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', asciiBytes);
    const hashB64Url = bufToBase64Url(hashBuffer);
    recomputedHashes.push(hashB64Url);
  }

  const payloadSdList = payload._sd || [];
  for (const h of recomputedHashes) {
    if (!payloadSdList.includes(h)) {
      throw new Error(`Security breach: disclosure hash ${h} is not registered in the Signed JWS payload's _sd array!`);
    }
  }

  return {
    format: "SD-JWT-VC",
    formatVersion: payload.formatVersion || "1.0.0",
    issuedAt: payload.iat ? payload.iat * 1000 : Date.now(),
    issuer: issuerDid,
    holderPseudonym: payload.sub,
    mitchProofHash: payload.mitchProofHash || null,
    claims,
    salts,
    signature: base64UrlToHex(jwsParts[2]),
    _sd_alg: payload._sd_alg || "sha-256",
    _sd: payload._sd,
    cnf: payload.cnf,
    header,
    payload
  };
}

/**
 * Self-test routine executed at load to guarantee environment cryptographic sanity.
 */
export async function runSelfTest() {
  try {
    const keyPair = await generateKeyPair();
    const testPayload = { test: 'integrity_check', timestamp: Date.now() };
    const signature = await signPayload(keyPair.privateKey, testPayload);
    const isValid = await verifyPayload(keyPair.publicKey, testPayload, signature);
    
    if (!isValid) {
      throw new Error('Self-test signature mismatch');
    }
    
    // Test JWK export/import
    const pubJWK = await exportKeyToJWK(keyPair.publicKey);
    const isJWKValid = await verifyWithJWK(pubJWK, testPayload, signature);
    
    if (!isJWKValid) {
      throw new Error('JWK export/import verification mismatch');
    }
    
    console.log('✅ Web Crypto self-test completed successfully.');
    return true;
  } catch (error) {
    console.error('❌ Web Crypto self-test failed:', error);
    return false;
  }
}

