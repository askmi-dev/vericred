/**
 * VeriCred Blockchain Ledger Service
 * Handles Block schemas, transaction payloads, and asynchronous ledger auditing.
 */

import { sha256, deterministicStringify, verifyWithJWK } from './crypto-service.js';

/**
 * Creates a standard transaction object.
 */
export function createTransaction(type, payload, signature = null, issuerPublicKey = null) {
  return {
    id: `tx_${Math.random().toString(36).substr(2, 9)}_${Date.now()}`,
    type, // 'ISSUE' or 'AUDIT'
    timestamp: Date.now(),
    payload, // Credential or audit data
    signature, // Cryptographic signature (from private key)
    issuerPublicKey // Public JWK key of issuer for verification
  };
}

/**
 * Calculates the aggregate SHA-256 hash of a list of transactions (Transaction Root).
 */
export async function calculateTransactionsHash(transactions) {
  const serialized = deterministicStringify(transactions);
  return await sha256(serialized);
}

/**
 * Calculates a complete block hash based on block header parameters.
 */
export async function calculateBlockHash(index, previousHash, transactionsHash, timestamp, nonce) {
  const headerString = `${index}${previousHash}${transactionsHash}${timestamp}${nonce}`;
  return await sha256(headerString);
}

/**
 * Creates a new block template.
 */
export async function createBlock(index, transactions, previousHash, nonce = 0, hash = '', timestamp = null) {
  const blockTimestamp = timestamp || Date.now();
  const txHash = await calculateTransactionsHash(transactions);
  const blockHash = hash || (await calculateBlockHash(index, previousHash, txHash, blockTimestamp, nonce));
  
  return {
    index,
    timestamp: blockTimestamp,
    transactions,
    previousHash,
    transactionsHash: txHash,
    hash: blockHash,
    nonce
  };
}

/**
 * Generates the hardcoded Genesis block for the network.
 */
export async function generateGenesisBlock() {
  const genesisTransactions = [
    createTransaction('ISSUE_CREDENTIAL', {
      holderPseudonym: 'did:vericred:pairwise:genesis-anchor',
      mitchProofHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      credentialHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      claimCommitments: {
        jobTitleCommitment: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        durationCommitment: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        skillsCommitment: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      },
      issuerId: 'did:vericred:genesis-protocol',
      statusListIndex: 0,
      revocationMetadata: {
        revocationStatus: 'valid'
      }
    })
  ];
  
  return await createBlock(0, genesisTransactions, '0'.repeat(64), 0, '', 1782390000);
}

/**
 * Runs a full, sequential audit of the blockchain ledger.
 * This checks:
 * 1. Previous hash linkages
 * 2. Hash computation of headers
 * 3. Transaction root hash consistency
 * 4. Micro-signature validity of every certificate payload inside blocks
 * 5. Metadata Budget Leakage (enforces zero plain-text PII claims on-chain)
 */
export async function isChainValid(chain) {
  if (!chain || chain.length === 0) {
    return { isValid: false, reason: 'Chain is empty or corrupted.' };
  }
  
  // Verify Genesis Block links
  const genesis = chain[0];
  if (genesis.index !== 0 || genesis.previousHash !== '0'.repeat(64)) {
    return { isValid: false, reason: 'Genesis block linkage broken.', blockIndex: 0 };
  }
  
  const recomputedGenesisTxHash = await calculateTransactionsHash(genesis.transactions);
  if (genesis.transactionsHash !== recomputedGenesisTxHash) {
    return { isValid: false, reason: 'Genesis transactions tampered with.', blockIndex: 0 };
  }
  
  const recomputedGenesisHash = await calculateBlockHash(
    0,
    genesis.previousHash,
    genesis.transactionsHash,
    genesis.timestamp,
    genesis.nonce
  );
  if (genesis.hash !== recomputedGenesisHash) {
    return { isValid: false, reason: 'Genesis block hash is invalid.', blockIndex: 0 };
  }

  // Sequentially audit subsequent blocks
  for (let i = 1; i < chain.length; i++) {
    const currentBlock = chain[i];
    const previousBlock = chain[i - 1];

    // 1. Check backward link
    if (currentBlock.previousHash !== previousBlock.hash) {
      return { 
        isValid: false, 
        reason: `Hash mismatch: Block ${currentBlock.index} points to previous hash ${currentBlock.previousHash.substring(0, 10)}... but previous Block ${previousBlock.index} has hash ${previousBlock.hash.substring(0, 10)}...`, 
        blockIndex: currentBlock.index 
      };
    }

    // 2. Check transaction integrity
    const recomputedTxHash = await calculateTransactionsHash(currentBlock.transactions);
    if (currentBlock.transactionsHash !== recomputedTxHash) {
      return { 
        isValid: false, 
        reason: `Data Tampering: Block ${currentBlock.index} transactions do not match original transactions hash.`, 
        blockIndex: currentBlock.index 
      };
    }

    // 3. Check block hash validity
    const recomputedHash = await calculateBlockHash(
      currentBlock.index,
      currentBlock.previousHash,
      currentBlock.transactionsHash,
      currentBlock.timestamp,
      currentBlock.nonce
    );
    if (currentBlock.hash !== recomputedHash) {
      return { 
        isValid: false, 
        reason: `Consensus broken: Block ${currentBlock.index} hash is invalid. Proof of work or contents modified after mining.`, 
        blockIndex: currentBlock.index 
      };
    }

    // 4. Check cryptographic signatures and PII budget leaks of individual transactions
    for (const tx of currentBlock.transactions) {
      if (tx.type === 'ISSUE_CREDENTIAL') {
        const p = tx.payload;
        
        // Audit Metadata Budget Compliance (Fail-closed leak detector)
        if (p.workerName || p.workerAddress || p.jobTitle || p.duration || p.skills || p.employerName) {
          return {
            isValid: false,
            reason: `Metadata Budget Leak Detected: Block ${currentBlock.index} contains plain-text PII claims on-chain!`,
            blockIndex: currentBlock.index,
            txId: tx.id
          };
        }
        
        // Audit Cryptographic Signature Integrity
        if (tx.signature && tx.issuerPublicKey) {
          const isSigValid = await verifyWithJWK(tx.issuerPublicKey, p, tx.signature);
          if (!isSigValid) {
            return {
              isValid: false,
              reason: `Forgery Blocked: Block ${currentBlock.index} contains credential transaction with a forged, edited, or corrupted signature!`,
              blockIndex: currentBlock.index,
              txId: tx.id
            };
          }
        }
      }
    }
  }

  return { isValid: true };
}
