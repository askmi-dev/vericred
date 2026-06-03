/**
 * VeriCred State Management & Store (Amended miTch Evidence-Bridge Gateway)
 * 
 * Implements standard-conforming EUDI trust lists, atomic challenge nonces, 
 * preservative ledger self-repair (quarantines broken chains but leaves keys intact),
 * and PII-minimized seed generation with claim commitments.
 */

import { 
  generateKeyPair, 
  exportKeyToJWK, 
  signPayload, 
  sha256, 
  calculateJWKThumbprint, 
  calculateHMAC, 
  createMitchPresentation 
} from './crypto-service.js';
import { createBlock, createTransaction, generateGenesisBlock } from './blockchain.js';

// LocalStorage Keys
const STORAGE_CHAIN_KEY = 'vericred_ledger_chain';
const STORAGE_ISSUERS_KEY = 'vericred_known_issuers';
const STORAGE_WORKER_KEYS = 'vericred_worker_identity_keys';
const STORAGE_EMPLOYER_KEYS = 'vericred_employer_identity_keys';
const STORAGE_GATEWAY_SECRET = 'vericred_gateway_secret';
const SCHEMA_VERSION_KEY = 'vericred_schema_version';
const CURRENT_SCHEMA_VERSION = '2.0-mitch-bridge';

export const store = {
  chain: [],
  pendingTransactions: [],
  
  // EUDI/VeriCred Trust List
  knownIssuers: {},
  
  // Isolated cryptographical identities
  workerKeys: null,
  employerKeys: null,
  localGatewaySecret: null,
  
  // Challenge Nonce Cache (nonce -> expiryTimestamp)
  activeNonces: {},
  
  // Volatile Revocation Status Registries
  baseStatusList: {},    // mitchProofHash -> boolean (true = revoked)
  gatewayStatusList: {}, // credentialHash -> boolean (true = revoked)
  
  // Lab Trust Override (Sandbox simulation parameter)
  isLabTrustOverrideActive: false,
  
  isMining: false,
  isChainCorrupt: false,
  corruptionReport: null,

  async initialize() {
    // 1. Initialize persistent identities (preserve keys where valid)
    try {
      await this.initializeIdentities();
    } catch (err) {
      console.error('Failed to load identities. Resetting keys...', err);
      localStorage.removeItem(STORAGE_WORKER_KEYS);
      localStorage.removeItem(STORAGE_EMPLOYER_KEYS);
      await this.initializeIdentities();
    }

    // 2. Persistent Local Gateway Secret (used for scoped pairwise DIDs)
    await this.initializeGatewaySecret();

    // 3. Schema version & preservative self-repair check
    const storedVersion = localStorage.getItem(SCHEMA_VERSION_KEY);
    const versionMismatch = storedVersion !== CURRENT_SCHEMA_VERSION;

    if (versionMismatch) {
      console.warn(`Schema mismatch (Expected '${CURRENT_SCHEMA_VERSION}', got '${storedVersion}'). Executing preservative quarantine & reseed...`);
      const existingChain = localStorage.getItem(STORAGE_CHAIN_KEY);
      if (existingChain) {
        // Quarantine old chain
        localStorage.setItem(`vericred_ledger_chain_quarantine_${Date.now()}`, existingChain);
      }
      localStorage.removeItem(STORAGE_CHAIN_KEY);
      localStorage.removeItem(STORAGE_ISSUERS_KEY);
      localStorage.setItem(SCHEMA_VERSION_KEY, CURRENT_SCHEMA_VERSION);
    }

    const storedChain = localStorage.getItem(STORAGE_CHAIN_KEY);
    const storedIssuers = localStorage.getItem(STORAGE_ISSUERS_KEY);

    if (storedChain && storedIssuers && !versionMismatch) {
      try {
        this.chain = JSON.parse(storedChain);
        this.knownIssuers = JSON.parse(storedIssuers);
        console.log('📦 Ledger loaded successfully. Blocks:', this.chain.length);
        
        // Quick structural schema check
        if (!Array.isArray(this.chain) || this.chain.length === 0 || !this.chain[0].hash) {
          throw new Error('Corrupt block format in loaded chain.');
        }
      } catch (err) {
        console.error('Ledger parsing failed. Preserving keys, quarantining chain, and reseeding...', err);
        localStorage.setItem(`vericred_ledger_chain_quarantine_${Date.now()}`, storedChain || '');
        localStorage.removeItem(STORAGE_CHAIN_KEY);
        localStorage.removeItem(STORAGE_ISSUERS_KEY);
        await this.generateSeedData();
      }
    } else {
      console.log('⚡ Reseeding ledger database with PII-minimized block structures...');
      await this.generateSeedData();
    }
    
    // 4. Seed active nonces and status lists on startup
    this.activeNonces = {};
    this.baseStatusList = {};
    this.gatewayStatusList = {};
    this.verifiedMitchProofs = {};

    const storedAliceProof = localStorage.getItem('vericred_seed_mitch_proof_alice');
    if (storedAliceProof) {
      try {
        const parsed = JSON.parse(storedAliceProof);
        const hash = await sha256(JSON.stringify(parsed));
        this.verifiedMitchProofs[hash] = parsed;
      } catch (e) {
        console.error('Failed to load alice proof into memory cache', e);
      }
    }
  },

  /**
   * Initializes persistent cryptographic keys for worker and employer
   */
  async initializeIdentities() {
    // Worker Identity KeyPair
    const storedWorker = localStorage.getItem(STORAGE_WORKER_KEYS);
    if (storedWorker) {
      this.workerKeys = JSON.parse(storedWorker);
    } else {
      const kp = await generateKeyPair();
      this.workerKeys = {
        publicKey: await exportKeyToJWK(kp.publicKey),
        privateKey: await exportKeyToJWK(kp.privateKey)
      };
      localStorage.setItem(STORAGE_WORKER_KEYS, JSON.stringify(this.workerKeys));
    }

    // Employer/Gateway Identity KeyPair
    const storedEmployer = localStorage.getItem(STORAGE_EMPLOYER_KEYS);
    if (storedEmployer) {
      this.employerKeys = JSON.parse(storedEmployer);
    } else {
      const kp = await generateKeyPair();
      this.employerKeys = {
        publicKey: await exportKeyToJWK(kp.publicKey),
        privateKey: await exportKeyToJWK(kp.privateKey)
      };
      localStorage.setItem(STORAGE_EMPLOYER_KEYS, JSON.stringify(this.employerKeys));
    }
  },

  /**
   * Initializes persistent gateway secret for pairwise HMAC computations
   */
  async initializeGatewaySecret() {
    let secret = localStorage.getItem(STORAGE_GATEWAY_SECRET);
    if (!secret) {
      const array = new Uint8Array(32);
      window.crypto.getRandomValues(array);
      secret = Array.prototype.map.call(array, x => ('00' + x.toString(16)).slice(-2)).join('');
      localStorage.setItem(STORAGE_GATEWAY_SECRET, secret);
    }
    this.localGatewaySecret = secret;
  },

  /**
   * Generates an in-memory single-use challenge nonce with a 5-minute TTL
   */
  generateNonce() {
    const array = new Uint8Array(8);
    window.crypto.getRandomValues(array);
    const nonce = 'nonce_' + Array.prototype.map.call(array, x => ('00' + x.toString(16)).slice(-2)).join('');
    
    const expiry = Date.now() + 300000; // 5 mins
    this.activeNonces[nonce] = expiry;
    return nonce;
  },

  /**
   * Pops and invalidates a nonce on the first structurally valid check (atomic consumption)
   */
  consumeNonce(nonce) {
    if (!nonce || !this.activeNonces[nonce]) {
      return false;
    }
    const expiry = this.activeNonces[nonce];
    delete this.activeNonces[nonce]; // Remove atomically to prevent replays
    
    if (expiry < Date.now()) {
      return false; // Nonce has expired
    }
    return true;
  },

  /**
   * Rotates Employer key pair, registering the new public key on the local Trust List
   */
  async rotateEmployerKeys() {
    const kp = await generateKeyPair();
    this.employerKeys = {
      publicKey: await exportKeyToJWK(kp.publicKey),
      privateKey: await exportKeyToJWK(kp.privateKey)
    };
    localStorage.setItem(STORAGE_EMPLOYER_KEYS, JSON.stringify(this.employerKeys));
    
    // Update local gateway trust anchor key
    this.knownIssuers['did:vericred:issuer-gateway'] = this.employerKeys.publicKey;
    this.persistChain();
  },

  /**
   * Generates standard-compliant seed data (PII-Minimized Ledger Block)
   */
  async generateSeedData() {
    const genesis = await generateGenesisBlock();
    this.chain = [genesis];
    
    // Generate real, usable mock EUDI Trust Anchor KeyPair (e.g. for Google Base Credentials)
    const googleKeyPair = await generateKeyPair();
    const googlePubJWK = await exportKeyToJWK(googleKeyPair.publicKey);
    
    this.knownIssuers = {
      'did:mitch:trust-anchor-1': googlePubJWK,
      'did:vericred:issuer-gateway': this.employerKeys.publicKey
    };
    
    // ----------------------------------------------------
    // Seed Block 1 Creation (Simulates Alice Vance's seed credential)
    // ----------------------------------------------------
    // Alice's simulated miTch base identity claims
    const aliceBaseClaims = {
      is_legal_resident: true,
      degree_level: 'Bachelor',
      at_least_18: true
    };
    
    // Import Worker local keys to sign the key-binding proof
    const workerPrivateKeyObj = await crypto.subtle.importKey(
      'jwk', this.workerKeys.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
    );
    const workerPublicKeyObj = await crypto.subtle.importKey(
      'jwk', this.workerKeys.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
    );
    const workerKeyPair = { publicKey: workerPublicKeyObj, privateKey: workerPrivateKeyObj };
    
    // Create a mock presentation envelope
    const mockMitchProof = await createMitchPresentation(
      aliceBaseClaims,
      workerKeyPair,
      'nonce_seed_genesis',
      'VeriCred-Gateway',
      googleKeyPair,
      'did:mitch:trust-anchor-1'
    );
    
    const mitchProofHash = await sha256(JSON.stringify(mockMitchProof));
    const holderThumb = await calculateJWKThumbprint(this.workerKeys.publicKey);
    
    // Compute scoped pairwise pseudonym: HMAC(localGatewaySecret, "vericred-holder-v1|holderJwkThumbprint|issuerDid|credentialType|mitchProofHash")
    const msg = `vericred-holder-v1|${holderThumb}|did:vericred:issuer-gateway|WorkCertificate|${mitchProofHash}`;
    const holderPseudonym = 'did:vericred:pairwise:' + await calculateHMAC(this.localGatewaySecret, msg);
    
    // Generate Salts for off-chain Claims
    const salts = {
      jobTitle: 'salt_google_job_17e3',
      duration: 'salt_google_dur_8bb1',
      skills: 'salt_google_ski_48c2',
      workSamplesHash: 'salt_google_wsh_2d90'
    };
    
    // Compute PII-minimized Claim Commitments: SHA256(ClaimValue + Salt)
    const jobTitleCommitment = await sha256('Senior UX Architect' + salts.jobTitle);
    const durationCommitment = await sha256('2023 - 2025' + salts.duration);
    const skillsCommitment = await sha256(['Figma', 'System Design', 'User Research'].join(',') + salts.skills);
    const workSamplesCommitment = await sha256('6d29da75a6c1e3458ef183c27ae131976037ae41e4649b934ca495991b7852b8' + salts.workSamplesHash);
    
    // Create off-chain Credential JSON (to export to holder)
    const seedCredential = {
      format: 'SD-JWT-VC',
      formatVersion: '1.1.0',
      issuedAt: 1782390100000,
      issuer: 'did:vericred:issuer-gateway',
      holderPseudonym,
      mitchProofHash,
      claims: {
        jobTitle: 'Senior UX Architect',
        duration: '2023 - 2025',
        skills: ['Figma', 'System Design', 'User Research'],
        workSamplesHash: '6d29da75a6c1e3458ef183c27ae131976037ae41e4649b934ca495991b7852b8'
      },
      salts,
      signature: null
    };
    
    const employerPrivateKeyObj = await crypto.subtle.importKey(
      'jwk', this.employerKeys.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
    );
    
    // Sign the complete off-chain credential
    const credSignature = await signPayload(employerPrivateKeyObj, {
      format: seedCredential.format,
      formatVersion: seedCredential.formatVersion,
      issuedAt: seedCredential.issuedAt,
      issuer: seedCredential.issuer,
      holderPseudonym: seedCredential.holderPseudonym,
      mitchProofHash: seedCredential.mitchProofHash,
      claims: seedCredential.claims,
      salts: seedCredential.salts
    });
    seedCredential.signature = credSignature;
    const credentialHash = await sha256(JSON.stringify(seedCredential));
    
    // Build PII-minimized on-chain transaction
    const piiMinimizedTxPayload = {
      holderPseudonym,
      mitchProofHash,
      credentialHash,
      claimCommitments: {
        jobTitle: jobTitleCommitment,
        duration: durationCommitment,
        skills: skillsCommitment,
        workSamplesHash: workSamplesCommitment
      },
      issuerId: 'did:vericred:issuer-gateway',
      statusListIndex: 0
    };
    
    // Sign on-chain transaction
    const txSignature = await signPayload(employerPrivateKeyObj, piiMinimizedTxPayload);
    const onChainTx = createTransaction('ISSUE_CREDENTIAL', piiMinimizedTxPayload, txSignature, this.employerKeys.publicKey);
    
    // Create Block #1
    const block1 = await createBlock(1, [onChainTx], genesis.hash, 0, '', 1782390100);
    const block1Mined = await this.seedMine(block1, 1);
    this.chain.push(block1Mined);
    
    // Save Seed credential JSON in LocalStorage for easy Alice preview loading
    localStorage.setItem('vericred_seed_credential_alice', JSON.stringify(seedCredential));
    localStorage.setItem('vericred_seed_mitch_proof_alice', JSON.stringify(mockMitchProof));

    this.persistChain();
  },

  async seedMine(block, difficulty) {
    const targetPrefix = '0'.repeat(difficulty);
    const headerString = `${block.index}${block.previousHash}${block.transactionsHash}${block.timestamp}`;
    let nonce = 0;
    while (true) {
      const hash = await sha256(headerString + nonce);
      if (hash.substring(0, difficulty) === targetPrefix) {
        block.nonce = nonce;
        block.hash = hash;
        return block;
      }
      nonce++;
    }
  },

  persistChain() {
    localStorage.setItem(STORAGE_CHAIN_KEY, JSON.stringify(this.chain));
    localStorage.setItem(STORAGE_ISSUERS_KEY, JSON.stringify(this.knownIssuers));
  },

  restoreChain() {
    const storedChain = localStorage.getItem(STORAGE_CHAIN_KEY);
    const storedIssuers = localStorage.getItem(STORAGE_ISSUERS_KEY);
    if (storedChain && storedIssuers) {
      this.chain = JSON.parse(storedChain);
      this.knownIssuers = JSON.parse(storedIssuers);
      this.isChainCorrupt = false;
      this.corruptionReport = null;
    }
  },

  async hardReset() {
    localStorage.removeItem(STORAGE_CHAIN_KEY);
    localStorage.removeItem(STORAGE_ISSUERS_KEY);
    localStorage.removeItem(STORAGE_WORKER_KEYS);
    localStorage.removeItem(STORAGE_EMPLOYER_KEYS);
    localStorage.removeItem(STORAGE_GATEWAY_SECRET);
    localStorage.removeItem(SCHEMA_VERSION_KEY);
    localStorage.removeItem('vericred_seed_credential_alice');
    localStorage.removeItem('vericred_seed_mitch_proof_alice');
    this.pendingTransactions = [];
    this.isChainCorrupt = false;
    this.corruptionReport = null;
    await this.initialize();
  },

  registerIssuer(name, jwkPublicKey) {
    this.knownIssuers[name] = jwkPublicKey;
    localStorage.setItem(STORAGE_ISSUERS_KEY, JSON.stringify(this.knownIssuers));
  },

  tamperWithPayload(blockIndex, txIndex, fieldName, fakeValue) {
    if (this.chain[blockIndex] && this.chain[blockIndex].transactions[txIndex]) {
      const tx = this.chain[blockIndex].transactions[txIndex];
      if (tx.payload[fieldName] !== undefined) {
        tx.payload[fieldName] = fakeValue;
      } else if (tx.payload.claimCommitments && tx.payload.claimCommitments[fieldName] !== undefined) {
        // Tampering with commitment hash
        tx.payload.claimCommitments[fieldName] = fakeValue;
      }
    }
  },

  addPendingTransaction(tx) {
    this.pendingTransactions.push(tx);
  }
};
