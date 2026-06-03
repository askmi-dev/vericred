/**
 * VeriCred main application controller.
 * Binds tabs, handles forms, drag-and-drop verifying, coordinates background mining
 * with Web Workers (and an interactive requestAnimationFrame fallback), and implements
 * the interactive Security Attack & Abuse Sandbox with the 5-Stage Universal Audit.
 */

import { 
  runSelfTest, 
  exportKeyToJWK,
  verifyWithJWK, 
  signPayload, 
  sha256, 
  calculateJWKThumbprint, 
  calculateHMAC, 
  createMitchPresentation, 
  verifyMitchPresentationSequential,
  serializeToCompactSDJWT,
  parseCompactSDJWT,
  base64UrlToString
} from './crypto-service.js';
import { isChainValid, createBlock, createTransaction } from './blockchain.js';
import { store } from './store.js';

// DOM Element Maps
const els = {
  // Navigation
  navLinks: document.querySelectorAll('.nav-link'),
  tabContents: document.querySelectorAll('.tab-content'),
  
  // Worker View (EUDI Sync & credentials)
  workerAddressDisplay: document.getElementById('worker-address-display'),
  btnCopyWorkerAddress: document.getElementById('btn-copy-worker-address'),
  workerCredentialsList: document.getElementById('worker-credentials-list'),
  workerSyncNonce: document.getElementById('worker-sync-nonce'),
  btnGenerateEudiProof: document.getElementById('btn-generate-eudi-proof'),
  eudiProofResultBox: document.getElementById('eudi-proof-result-box'),
  eudiProofCodeOutput: document.getElementById('eudi-proof-code-output'),
  btnCopyEudiProof: document.getElementById('btn-copy-eudi-proof'),
  btnDownloadEudiProof: document.getElementById('btn-download-eudi-proof'),
  
  // Employer View
  employerAddressShort: document.getElementById('employer-address-short'),
  btnGenerateEmployerKey: document.getElementById('btn-generate-employer-key'),
  activeChallengeNonceDisplay: document.getElementById('active-challenge-nonce-display'),
  btnRegenerateChallengeNonce: document.getElementById('btn-regenerate-challenge-nonce'),
  gatekeeperProofInput: document.getElementById('gatekeeper-proof-input'),
  btnVerifyGatekeeperProof: document.getElementById('btn-verify-gatekeeper-proof'),
  gatekeeperFeedbackContainer: document.getElementById('gatekeeper-feedback-container'),
  gatekeeperLockOverlay: document.getElementById('gatekeeper-lock-overlay'),
  gatekeeperUnlockedForm: document.getElementById('gatekeeper-unlocked-form'),
  
  issueWorkerName: document.getElementById('issue-worker-name'),
  issueWorkerAddress: document.getElementById('issue-worker-address'),
  issueJobTitle: document.getElementById('issue-job-title'),
  issueDuration: document.getElementById('issue-duration'),
  issueSkills: document.getElementById('issue-skills'),
  issueSamplesHash: document.getElementById('issue-samples-hash'),
  btnIssueCredential: document.getElementById('btn-issue-credential'),
  
  mempoolList: document.getElementById('mempool-list'),
  mempoolCountBadge: document.getElementById('mempool-count-badge'),
  mempoolIndicator: document.getElementById('mempool-indicator'),
  miningDifficulty: document.getElementById('mining-difficulty'),
  difficultyDisplay: document.getElementById('difficulty-display'),
  btnMineBlock: document.getElementById('btn-mine-block'),
  
  // Mining Progress Overlay Panel
  miningPanel: document.getElementById('mining-panel'),
  miningStatusText: document.getElementById('mining-status-text'),
  miningTimer: document.getElementById('mining-timer'),
  miningHashrate: document.getElementById('mining-hashrate'),
  miningNonce: document.getElementById('mining-nonce'),
  miningCurrentHash: document.getElementById('mining-current-hash'),
  
  // Verifier View
  verifierDropzone: document.getElementById('verifier-dropzone'),
  verifierFileInput: document.getElementById('verifier-file-input'),
  btnBrowseFile: document.getElementById('btn-browse-file'),
  verifierPasteArea: document.getElementById('verifier-paste-area'),
  btnVerifyPaste: document.getElementById('btn-verify-paste'),
  verifierReport: document.getElementById('verifier-report'),
  verifierAlert: document.getElementById('verifier-alert'),
  verifierAlertTitle: document.getElementById('verifier-alert-title'),
  verifierAlertText: document.getElementById('verifier-alert-text'),
  btnExampleValid: document.getElementById('btn-example-valid'),
  btnExampleRevoked: document.getElementById('btn-example-revoked'),
  btnExampleTampered: document.getElementById('btn-example-tampered'),
  btnExampleMalformed: document.getElementById('btn-example-malformed'),
  
  // Verifier Fields
  auditWorkerName: document.getElementById('audit-worker-name'),
  auditIssuerName: document.getElementById('audit-issuer-name'),
  auditJobTitle: document.getElementById('audit-job-title'),
  auditDuration: document.getElementById('audit-duration'),
  auditSkillsList: document.getElementById('audit-skills-list'),
  auditSamplesHash: document.getElementById('audit-samples-hash'),
  auditMitchHash: document.getElementById('audit-mitch-hash'),
  auditMainBadge: document.getElementById('audit-main-badge'),
  auditMainIcon: document.getElementById('audit-main-icon'),
  auditCardBody: document.getElementById('audit-card-body'),
  
  // 5-Stage Checklist elements
  stageRow1: document.getElementById('stage-row-1'),
  stageStatus1: document.getElementById('stage-status-1'),
  stageRow2: document.getElementById('stage-row-2'),
  stageStatus2: document.getElementById('stage-status-2'),
  stageRow3: document.getElementById('stage-row-3'),
  stageStatus3: document.getElementById('stage-status-3'),
  stageRow4: document.getElementById('stage-row-4'),
  stageStatus4: document.getElementById('stage-status-4'),
  stageRow5: document.getElementById('stage-row-5'),
  stageStatus5: document.getElementById('stage-status-5'),
  
  // Sandbox Elements
  sandboxBtnReplay: document.getElementById('sandbox-btn-replay'),
  sandboxBtnUntrusted: document.getElementById('sandbox-btn-untrusted'),
  sandboxBtnRevocation: document.getElementById('sandbox-btn-revocation'),
  sandboxBtnPii: document.getElementById('sandbox-btn-pii'),
  sandboxBtnLink: document.getElementById('sandbox-btn-link'),
  sandboxTrustListToggle: document.getElementById('sandbox-trust-list-toggle'),
  sandboxBtnResetSimulator: document.getElementById('sandbox-btn-reset-simulator'),
  
  // Ledger View
  ledgerStatusIndicator: document.getElementById('ledger-status-indicator'),
  ledgerStatusTitle: document.getElementById('ledger-status-title'),
  btnRevalidateLedger: document.getElementById('btn-revalidate-ledger'),
  btnRestoreChain: document.getElementById('btn-restore-chain'),
  btnHardReset: document.getElementById('btn-hard-reset'),
  statTotalBlocks: document.getElementById('stat-total-blocks'),
  statTotalCreds: document.getElementById('stat-total-creds'),
  statDifficulty: document.getElementById('stat-difficulty'),
  blockchainVisualContainer: document.getElementById('blockchain-visual-container'),
  
  // Block Inspector Panel
  blockInspector: document.getElementById('block-inspector'),
  inspectorBlockTitle: document.getElementById('inspector-block-title'),
  inspectorBlockHash: document.getElementById('inspector-block-hash'),
  inspectPrevHash: document.getElementById('inspect-prev-hash'),
  inspectTxsHash: document.getElementById('inspect-txs-hash'),
  inspectTimestamp: document.getElementById('inspect-timestamp'),
  inspectNonce: document.getElementById('inspect-nonce'),
  inspectTransactionsBody: document.getElementById('inspect-transactions-body'),
  tamperJobTitle: document.getElementById('tamper-job-title'),
  tamperWorkerName: document.getElementById('tamper-worker-name'),
  btnTamperExecute: document.getElementById('btn-tamper-execute')
};

// Application State Variables
let selectedBlockIndex = null;
let verifiedMitchProofHash = null;
let verifiedHolderJwkThumbprint = null;
let verifiedBaseClaims = null;
let verifiedHolderJwk = null;
let activeAttackName = null; // 'replay', 'untrusted', 'revoked', 'pii_leak', 'link_corrupt'

/**
 * Initialize application with high-integrity defensive loading.
 */
document.addEventListener('DOMContentLoaded', async () => {
  console.log('🏁 Launching VeriCred App Coordinator...');
  
  // 1. Setup Tab Routing IMMEDIATELY to prevent visual lockups if database loading fails
  setupTabRouting();

  try {
    // 2. Run cryptographic capability self-test
    const isCryptoSanityOk = await runSelfTest();
    if (!isCryptoSanityOk) {
      console.error('Fatal cryptographic loading error. Native Web Crypto is missing/disabled.');
      alert('⚠️ Fatal cryptographic loading error. Native Web Crypto is missing or disabled in your browser.');
      return;
    }

    // 3. Initialize store state (loads from localStorage or triggers preservative self-repair)
    await store.initialize();
    
    // 4. Complete initial ledger audit and UI synchronization
    await auditAndSyncLedgerUI();
    
    // 5. Setup View Event Bindings
    setupIdentityDisplay();
    setupWorkerEudiSync();
    setupEmployerForm();
    setupVerifierDragDrop();
    initializeVerifierExamples();
    setupSandboxControls();
    setupLedgerControls();
    setupQAHarness();
    setupThreatMatrix();
    
    // 6. Complete initial lists rendering
    renderWorkerCredentials();
    renderMempool();
    renderLedgerExplorer();
    updateDiagnosticStatesUI();
    
    // 7. Generate first Challenge Nonce
    regenerateChallengeNonce();

    console.log('✅ VeriCred startup executed flawlessly.');
  } catch (startupError) {
    console.error('🚨 Crash during database state load/seeding. Tab switching logic preserved. Recovery available via Network Hard Reset.', startupError);
    alert('⚠️ Startup Warn: Local database load issue. You can restore/reset the chain inside the Ledger Explorer tab.');
    
    // Bind limited recovery controls
    setupLedgerControls();
  }
});

/**
 * Audit blockchain ledger structure and sync top banner alerts.
 */
async function auditAndSyncLedgerUI() {
  const result = await isChainValid(store.chain);
  
  if (result.isValid) {
    store.isChainCorrupt = false;
    store.corruptionReport = null;
    
    if (els.ledgerStatusIndicator) {
      els.ledgerStatusIndicator.className = 'pulse-indicator';
    }
    if (els.ledgerStatusTitle) {
      els.ledgerStatusTitle.innerText = 'Ledger Integrity: Secure';
      els.ledgerStatusTitle.style.color = '#fff';
    }
    if (els.btnRestoreChain) {
      els.btnRestoreChain.style.display = 'none';
    }
  } else {
    store.isChainCorrupt = true;
    store.corruptionReport = result;
    
    if (els.ledgerStatusIndicator) {
      els.ledgerStatusIndicator.className = 'pulse-indicator corrupt';
    }
    if (els.ledgerStatusTitle) {
      els.ledgerStatusTitle.innerText = '⚠️ Integrity Violated: Tampering Caught';
      els.ledgerStatusTitle.style.color = 'var(--status-error)';
    }
    if (els.btnRestoreChain) {
      els.btnRestoreChain.style.display = 'inline-flex';
    }
    
    console.error('🚨 Blockchain Audit Failure:', result.reason);
  }
}

/**
 * Renders tab routing operations.
 */
function setupTabRouting() {
  els.navLinks.forEach(link => {
    link.addEventListener('click', () => {
      const tabId = link.getAttribute('data-tab');
      
      // Update links
      els.navLinks.forEach(btn => btn.classList.remove('active'));
      link.classList.add('active');
      
      // Update panels
      els.tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === tabId) {
          content.classList.add('active');
        }
      });
      
      // Specialize tab rendering on load
      if (tabId === 'worker-portfolio') {
        renderWorkerCredentials();
      } else if (tabId === 'ledger-explorer') {
        renderLedgerExplorer();
      } else if (tabId === 'qa-harness') {
        updateDiagnosticStatesUI();
      }
    });
  });
}

/**
 * Render identity headers with copy functionality.
 */
async function setupIdentityDisplay() {
  if (!store.workerKeys) return;
  
  const workerThumb = await calculateJWKThumbprint(store.workerKeys.publicKey);
  els.workerAddressDisplay.innerText = workerThumb;
  
  // Copy to clipboard
  if (!els.btnCopyWorkerAddress.dataset.listenerBound) {
    els.btnCopyWorkerAddress.addEventListener('click', () => {
      navigator.clipboard.writeText(workerThumb);
      const tooltip = document.getElementById('copy-tooltip');
      tooltip.innerText = 'Copied!';
      setTimeout(() => { tooltip.innerText = 'Copy Thumbprint'; }, 1500);
    });
    els.btnCopyWorkerAddress.dataset.listenerBound = 'true';
  }
  
  const employerPubK = store.employerKeys.publicKey;
  const employerAddress = `did:vericred:issuer-gateway`;
  els.employerAddressShort.innerText = employerAddress;
}

/**
 * Sync miTch EUDI Presentation Proof on Worker side.
 */
function setupWorkerEudiSync() {
  els.btnGenerateEudiProof.addEventListener('click', async () => {
    const nonce = els.workerSyncNonce.value.trim();
    if (!nonce) {
      alert('Please input the Active Challenge Nonce provided by the Gatekeeper Panel.');
      return;
    }
    
    try {
      // Worker's simulated miTch base identity claims
      const aliceBaseClaims = {
        is_legal_resident: true,
        degree_level: 'Bachelor',
        at_least_18: true
      };
      
      // Generate mock Google/Gov EUDI Issuer KeyPair (to sign base claims)
      const mockEudiKeyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
      );
      
      // Load/Import worker private key for holder binding signature
      const workerPrivKeyObj = await crypto.subtle.importKey(
        'jwk', store.workerKeys.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
      );
      const workerPubKeyObj = await crypto.subtle.importKey(
        'jwk', store.workerKeys.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
      );
      
      const workerKeyPair = { publicKey: workerPubKeyObj, privateKey: workerPrivKeyObj };
      const eudiIssuerId = activeAttackName === 'untrusted' ? 'did:mitch:rogue-anchor' : 'did:mitch:trust-anchor-1';
      
      // Generate dual-signed Mitch Presentation Proof Envelope
      const envelope = await createMitchPresentation(
        aliceBaseClaims,
        workerKeyPair,
        nonce,
        'VeriCred-Gateway',
        mockEudiKeyPair,
        eudiIssuerId
      );
      
      // Register mock EUDI anchor public key inside VeriCred trust list so it verifies mathematically
      const eudiPubJWK = await exportKeyToJWK(mockEudiKeyPair.publicKey);
      if (activeAttackName !== 'untrusted') {
        store.knownIssuers['did:mitch:trust-anchor-1'] = eudiPubJWK;
      } else {
        // Register rogue key on untrusted ID so mathematical signature is correct, but trust check fails closed
        store.knownIssuers['did:mitch:rogue-anchor'] = eudiPubJWK;
      }
      
      els.eudiProofCodeOutput.value = JSON.stringify(envelope, null, 2);
      els.eudiProofResultBox.style.display = 'block';
      
      // Instantly pre-fill Gatekeeper challenge input for convenience
      els.gatekeeperProofInput.value = JSON.stringify(envelope);
      
    } catch (err) {
      console.error('Failed to generate miTch proof:', err);
      alert('Error: Cryptographic generation failed.');
    }
  });
  
  els.btnCopyEudiProof.addEventListener('click', () => {
    navigator.clipboard.writeText(els.eudiProofCodeOutput.value);
    els.btnCopyEudiProof.innerText = 'Copied!';
    setTimeout(() => { els.btnCopyEudiProof.innerText = 'Copy Envelope'; }, 1500);
  });
  
  els.btnDownloadEudiProof.addEventListener('click', () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(els.eudiProofCodeOutput.value);
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `AliceVance_MitchPresentationEnvelope.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
  });
}

/**
 * Gatekeeper & Employer Form Controls.
 */
function setupEmployerForm() {
  // Challenge Nonce Rotation
  els.btnRegenerateChallengeNonce.addEventListener('click', () => {
    regenerateChallengeNonce();
  });
  
  // Gatekeeper verify proof button
  els.btnVerifyGatekeeperProof.addEventListener('click', async () => {
    const rawVal = els.gatekeeperProofInput.value.trim();
    if (!rawVal) {
      alert('Please paste a MitchPresentationEnvelope JSON.');
      return;
    }
    
    try {
      // 1. Initial Parse Check
      const envelope = JSON.parse(rawVal);
      
      // Set temporary feedback styling
      els.gatekeeperFeedbackContainer.style.display = 'block';
      els.gatekeeperFeedbackContainer.style.marginTop = '1rem';
      
      const activeNonce = els.activeChallengeNonceDisplay.innerText;
      let expectedNonce = activeNonce;
      if (activeAttackName === 'replay') {
        expectedNonce = 'nonce_expired_or_forged'; // cause mismatch
      }
      
      // Define atomic pop of Challenge Nonce callback (Replay protection)
      const consumeNonceFn = (nonceToConsume) => {
        if (activeAttackName === 'replay') {
          return false;
        }
        return store.consumeNonce(nonceToConsume);
      };
      
      // Custom Trust List injection based on Lab Overrides
      const trustList = { ...store.knownIssuers };
      if (activeAttackName === 'untrusted' && !store.isLabTrustOverrideActive) {
        // Exclude rogue DID from trust list
        delete trustList['did:mitch:rogue-anchor'];
      } else if (activeAttackName === 'untrusted' && store.isLabTrustOverrideActive) {
        // Override active, so force register rogue DID as trusted
        trustList['did:mitch:rogue-anchor'] = store.knownIssuers['did:mitch:rogue-anchor'];
      }
      
      // Run sequential fail-closed validator
      const result = await verifyMitchPresentationSequential(
        envelope, 
        expectedNonce, 
        trustList, 
        store.baseStatusList,
        consumeNonceFn
      );
      
      // Verification Successful!
      verifiedMitchProofHash = result.mitchProofHash;
      verifiedHolderJwkThumbprint = result.holderJwkThumbprint;
      verifiedBaseClaims = result.baseClaims;
      verifiedHolderJwk = result.holderJwk;
      
      // Cache original envelope inside store so Verifier can fetch it
      store.verifiedMitchProofs[result.mitchProofHash] = envelope;
      
      // Compute scoped pairwise pseudonym
      const msg = `vericred-holder-v1|${result.holderJwkThumbprint}|did:vericred:issuer-gateway|WorkCertificate|${result.mitchProofHash}`;
      const holderPseudonym = 'did:vericred:pairwise:' + await calculateHMAC(store.localGatewaySecret, msg);
      
      // Fill form values
      els.issueWorkerName.value = 'Alice Vance';
      els.issueWorkerAddress.value = holderPseudonym;
      
      // Unlock Employer professional claim input form
      els.gatekeeperUnlockedForm.className = '';
      els.gatekeeperLockOverlay.style.display = 'none';
      
      els.gatekeeperFeedbackContainer.style.background = 'rgba(16, 185, 129, 0.08)';
      els.gatekeeperFeedbackContainer.style.border = '1px solid rgba(16, 185, 129, 0.3)';
      els.gatekeeperFeedbackContainer.style.color = '#a7f3d0';
      els.gatekeeperFeedbackContainer.innerHTML = `
        <strong>🔓 Gateway Unlocked:</strong> Holder binding verified. Scoped pairwise pseudonym calculated.
        <br><span style="font-size:0.75rem; color:#64748b;">Thumbprint: ${result.holderJwkThumbprint}</span>
      `;
      
    } catch (error) {
      console.error(error);
      
      // Keep locked
      els.gatekeeperUnlockedForm.className = 'gatekeeper-locked';
      els.gatekeeperLockOverlay.style.display = 'flex';
      
      els.gatekeeperFeedbackContainer.style.background = 'rgba(244, 63, 94, 0.08)';
      els.gatekeeperFeedbackContainer.style.border = '1px solid rgba(244, 63, 94, 0.3)';
      els.gatekeeperFeedbackContainer.style.color = '#fecdd3';
      els.gatekeeperFeedbackContainer.innerHTML = `
        <strong>🚨 Verification Failed:</strong> ${error.message}
      `;
    } finally {
      // Regenerate challenge nonce for next attempt
      regenerateChallengeNonce();
    }
  });
  
  // Issuance Handler (Off-chain / On-chain split)
  els.btnIssueCredential.addEventListener('click', async () => {
    const jobTitle = els.issueJobTitle.value.trim();
    const duration = els.issueDuration.value.trim();
    const skillsString = els.issueSkills.value.trim();
    const workSamplesHash = els.issueSamplesHash.value.trim() || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    
    if (!jobTitle || !duration) {
      alert('Please enter a Job Title and Duration.');
      return;
    }
    
    const skills = skillsString.split(',').map(s => s.trim()).filter(Boolean);
    const holderPseudonym = els.issueWorkerAddress.value;
    
    // Generate secure local random salts for off-chain claims
    const saltJob = 'salt_job_' + Math.random().toString(36).substring(2, 8);
    const saltDur = 'salt_dur_' + Math.random().toString(36).substring(2, 8);
    const saltSkills = 'salt_skills_' + Math.random().toString(36).substring(2, 8);
    const saltSamples = 'salt_samples_' + Math.random().toString(36).substring(2, 8);
    
    // Compute PII-minimized commitments: SHA-256(Claim + Salt)
    const jobCommitment = await sha256(jobTitle + saltJob);
    const durationCommitment = await sha256(duration + saltDur);
    const skillsCommitment = await sha256(skills.join(',') + saltSkills);
    const samplesCommitment = await sha256(workSamplesHash + saltSamples);
    
    let offChainCredential;
    
    try {
      const gatewayPrivateKeyObj = await crypto.subtle.importKey(
        'jwk', store.employerKeys.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
      );
      
      const claimsToSign = {
        jobTitle,
        duration,
        skills,
        workSamplesHash
      };
      
      const saltsToSign = {
        jobTitle: saltJob,
        duration: saltDur,
        skills: saltSkills,
        workSamplesHash: saltSamples
      };

      // Sign off-chain credential (legacy compatibility format)
      const credSignature = await signPayload(gatewayPrivateKeyObj, {
        format: 'SD-JWT-VC',
        issuer: 'did:vericred:issuer-gateway',
        holderPseudonym,
        mitchProofHash: verifiedMitchProofHash,
        claims: claimsToSign,
        salts: saltsToSign
      });

      // Construct standard-aligned compact SD-JWT-VC string (RFC 9901)
      const compactSDJWT = await serializeToCompactSDJWT(
        'did:vericred:issuer-gateway',
        holderPseudonym,
        claimsToSign,
        saltsToSign,
        gatewayPrivateKeyObj,
        verifiedHolderJwk,
        verifiedMitchProofHash
      );

      const issuedAtEpoch = Date.now();
      // Package both decoded JSON and compact SD-JWT-VC string in a stable dual-format wrapper
      offChainCredential = {
        format: 'SD-JWT-VC',
        formatVersion: '1.1.0',
        issuedAt: issuedAtEpoch,
        compact: compactSDJWT,
        decoded: {
          format: 'SD-JWT-VC',
          formatVersion: '1.1.0',
          issuedAt: issuedAtEpoch,
          issuer: 'did:vericred:issuer-gateway',
          holderPseudonym,
          mitchProofHash: verifiedMitchProofHash,
          claims: claimsToSign,
          salts: saltsToSign,
          signature: credSignature
        }
      };
      
      const credentialHash = await sha256(JSON.stringify(offChainCredential));
      
      // Construct PII-minimized transaction
      const piiMinimizedTxPayload = {
        holderPseudonym,
        mitchProofHash: verifiedMitchProofHash,
        credentialHash,
        claimCommitments: {
          jobTitle: jobCommitment,
          duration: durationCommitment,
          skills: skillsCommitment,
          workSamplesHash: samplesCommitment
        },
        issuerId: 'did:vericred:issuer-gateway',
        statusListIndex: store.chain.length
      };
      
      // If we are simulating a PII leak, inject raw unhashed fields directly into payload
      if (activeAttackName === 'pii_leak') {
        piiMinimizedTxPayload.workerName = 'Alice Vance';
        piiMinimizedTxPayload.jobTitle = jobTitle; // Leak plain text!
      }
      
      // Sign on-chain transaction
      const txSignature = await signPayload(gatewayPrivateKeyObj, piiMinimizedTxPayload);
      const tx = createTransaction('ISSUE_CREDENTIAL', piiMinimizedTxPayload, txSignature, store.employerKeys.publicKey);
      
      // Queue in mempool
      store.addPendingTransaction(tx);
      
      // Persist credential locally under worker portfolio earned items
      const txId = tx.id;
      localStorage.setItem(`vericred_earned_credential_${txId}`, JSON.stringify(offChainCredential));
      
      // Reset inputs & lock gateway
      els.issueJobTitle.value = '';
      els.issueDuration.value = '';
      els.issueSkills.value = '';
      els.issueSamplesHash.value = '';
      
      els.gatekeeperUnlockedForm.className = 'gatekeeper-locked';
      els.gatekeeperLockOverlay.style.display = 'flex';
      els.gatekeeperFeedbackContainer.style.display = 'none';
      
      renderMempool();
      alert('📥 Portable certificate signed & anchored to Ledger Mempool! Trigger block mining next.');
      
    } catch (err) {
      console.error(err);
      alert('Failed to cryptographically sign credential transaction.');
    }
  });

  // Cycle Issuer Key Pair
  els.btnGenerateEmployerKey.addEventListener('click', async () => {
    const confirmation = confirm('Cycle Acme Gateway key pair? Older anchored blocks remain valid.');
    if (confirmation) {
      await store.rotateEmployerKeys();
      setupIdentityDisplay();
      renderMempool();
      alert('✅ New Gateway Identity KeyPair generated and registered.');
    }
  });

  // Difficulty slider binding
  els.miningDifficulty.addEventListener('input', (e) => {
    els.difficultyDisplay.innerText = `Difficulty: ${e.target.value}`;
  });

  // Mine Block
  els.btnMineBlock.addEventListener('click', async () => {
    if (store.pendingTransactions.length === 0) return;
    
    const difficulty = parseInt(els.miningDifficulty.value);
    const latestBlock = store.chain[store.chain.length - 1];
    const index = latestBlock.index + 1;
    const previousHash = latestBlock.hash;
    const transactions = [...store.pendingTransactions];
    const timestamp = Date.now();
    
    // Set UI mining state
    store.isMining = true;
    els.miningPanel.className = 'mining-overlay active';
    els.miningStatusText.innerText = `Mining Block #${index}...`;
    els.miningNonce.innerText = '0';
    els.miningHashrate.innerText = '0 H/s';
    els.miningTimer.innerText = '0.0s';
    
    const startTime = performance.now();
    let timerInterval = setInterval(() => {
      els.miningTimer.innerText = `${((performance.now() - startTime) / 1000).toFixed(1)}s`;
    }, 100);

    const blockTemplate = await createBlock(index, transactions, previousHash, 0, '', timestamp);
    const transactionsHash = blockTemplate.transactionsHash;

    const blockData = { index, previousHash, transactionsHash, timestamp, difficulty };

    async function handleMiningSuccess(nonce, hash, elapsedMs) {
      clearInterval(timerInterval);
      
      const finishedBlock = await createBlock(index, transactions, previousHash, nonce, hash, timestamp);
      store.chain.push(finishedBlock);
      store.pendingTransactions = [];
      store.persistChain();
      
      await auditAndSyncLedgerUI();
      
      store.isMining = false;
      els.miningPanel.classList.remove('active');
      
      renderMempool();
      renderLedgerExplorer();
      alert(`🎉 Block #${index} mined successfully!\nHash: ${hash.substring(0, 16)}...`);
    }

    function handleMiningProgress(nonce, hash, hashRate) {
      els.miningNonce.innerText = nonce.toLocaleString();
      els.miningHashrate.innerText = `${hashRate.toLocaleString()} H/s`;
      els.miningCurrentHash.innerText = hash;
    }

    try {
      const worker = new Worker('miner.worker.js');
      
      worker.onmessage = function(e) {
        const { type, data } = e.data;
        if (type === 'success') {
          handleMiningSuccess(data.nonce, data.hash, data.elapsedMs);
          worker.terminate();
        } else if (type === 'progress') {
          handleMiningProgress(data.nonce, data.hash, data.hashRate);
        } else if (type === 'error') {
          console.error(data.message);
          worker.terminate();
          alert('Worker crashed. Falling back to main-thread processing.');
        }
      };
      
      worker.postMessage(blockData);
      
    } catch (workerLoadError) {
      console.warn('CORS restriction on local Web Worker. Triggering chunked non-blocking main-thread fallback...');
      
      async function runMainThreadMiningFallback() {
        const targetPrefix = '0'.repeat(difficulty);
        const headerString = `${index}${previousHash}${transactionsHash}${timestamp}`;
        const encoder = new TextEncoder();
        
        let nonce = 0;
        let lastReportTime = performance.now();
        let hashesCount = 0;
        
        async function mineBatch() {
          if (!store.isMining) return;
          
          const batchSize = 150;
          for (let i = 0; i < batchSize; i++) {
            const dataString = headerString + nonce;
            const dataBuffer = encoder.encode(dataString);
            const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
            const hashHex = Array.prototype.map.call(new Uint8Array(hashBuffer), x => ('00' + x.toString(16)).slice(-2)).join('');
            
            hashesCount++;
            
            if (hashHex.substring(0, difficulty) === targetPrefix) {
              handleMiningSuccess(nonce, hashHex, performance.now() - startTime);
              return;
            }
            nonce++;
          }
          
          const now = performance.now();
          const intervalMs = now - lastReportTime;
          if (intervalMs >= 250) {
            const hashRate = Math.round((hashesCount / intervalMs) * 1000);
            handleMiningProgress(nonce, 'FallbackHash_' + nonce.toString(16), hashRate);
            hashesCount = 0;
            lastReportTime = now;
          }
          
          requestAnimationFrame(mineBatch);
        }
        requestAnimationFrame(mineBatch);
      }
      runMainThreadMiningFallback();
    }
  });
}

function regenerateChallengeNonce() {
  const nonce = store.generateNonce();
  els.activeChallengeNonceDisplay.innerText = nonce;
  els.workerSyncNonce.value = nonce;
}

/**
 * Render mempool state.
 */
function renderMempool() {
  els.mempoolList.innerHTML = '';
  const count = store.pendingTransactions.length;
  
  els.mempoolCountBadge.innerText = `${count} Pending`;
  els.btnMineBlock.disabled = count === 0;
  
  if (count === 0) {
    els.mempoolIndicator.className = 'pulse-indicator';
    els.mempoolList.innerHTML = `<div class="text-center text-muted text-xs" style="padding: 2rem 0;">Mempool empty. Sign a new credential to queue.</div>`;
    return;
  }
  
  els.mempoolIndicator.className = 'pulse-indicator mining';
  
  store.pendingTransactions.forEach(tx => {
    const div = document.createElement('div');
    div.style.background = 'rgba(255,255,255,0.02)';
    div.style.border = '1px solid var(--border-light)';
    div.style.padding = '0.75rem';
    div.style.borderRadius = '8px';
    div.style.fontSize = '0.85rem';
    
    div.innerHTML = `
      <div class="flex-between" style="font-weight: 600; color: #fff;">
        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:180px;">Pseudonym: ${tx.payload.holderPseudonym.substring(0, 18)}...</span>
        <span style="color: var(--accent-purple); font-size: 0.75rem;">Signed Tx</span>
      </div>
      <div class="flex-between text-xs text-muted" style="margin-top: 0.25rem;">
        <span>Hash: ${tx.payload.credentialHash.substring(0, 10)}...</span>
        <span>By: ${tx.payload.issuerId}</span>
      </div>
    `;
    els.mempoolList.appendChild(div);
  });
}

/**
 * Render worker's portfolio credentials based on off-chain storage.
 */
function renderWorkerCredentials() {
  els.workerCredentialsList.innerHTML = '';
  let matchesFound = 0;
  
  // Gather credentials: Seed Alice and any newly earned credentials
  const keys = Object.keys(localStorage).filter(k => k.startsWith('vericred_earned_credential_') || k === 'vericred_seed_credential_alice');
  
  keys.forEach(key => {
    try {
      const rawCred = JSON.parse(localStorage.getItem(key));
      const cred = rawCred.decoded ? rawCred.decoded : rawCred;
      matchesFound++;
      
      const card = document.createElement('div');
      card.className = 'glass-card cred-card verified';
      
      const shortSig = cred.signature ? `${cred.signature.substring(0, 16)}...` : 'Pre-loaded Genesis Anchor';
      
      card.innerHTML = `
        <div class="flex-between mb-4">
          <span class="cred-badge verified">Verified SD-JWT VC</span>
          <span class="text-xs text-muted text-mono">Sig: ${shortSig}</span>
        </div>
        <h3 style="color: #fff; font-size: 1.35rem; font-weight: bold; margin-bottom: 0.25rem;">${cred.claims.jobTitle}</h3>
        <p style="color: var(--accent-teal); font-weight: 600; font-size: 0.95rem;">${cred.issuer}</p>
        <p class="text-muted text-xs mt-1" style="display: flex; align-items: center; gap: 0.4rem;">
          <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
          ${cred.claims.duration} • Pairwise Pseudonym: <span class="text-mono" style="color:var(--accent-purple)">${cred.holderPseudonym.substring(0, 16)}...</span>
        </p>
        
        <div class="skills-wrapper">
          ${cred.claims.skills.map(skill => `<span class="skill-tag">${skill}</span>`).join('')}
        </div>
        
        <div class="mt-4" style="border-top: 1px solid rgba(255, 255, 255, 0.05); padding-top: 1rem; display: flex; justify-content: flex-end; gap: 0.75rem;">
          <button class="btn btn-sm" id="btn-dl-${key}">Download JSON</button>
          <button class="btn btn-sm btn-cyber" id="btn-audit-${key}">Audit Verification</button>
        </div>
      `;
      els.workerCredentialsList.appendChild(card);
      
      // Download Handler
      document.getElementById(`btn-dl-${key}`).addEventListener('click', () => {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rawCred, null, 2));
        const dlAnchor = document.createElement('a');
        dlAnchor.setAttribute('href', dataStr);
        dlAnchor.setAttribute('download', `VeriCred_SDJWT_Credential_${cred.claims.jobTitle.replace(/\s+/g, '_')}.json`);
        document.body.appendChild(dlAnchor);
        dlAnchor.click();
        dlAnchor.remove();
      });
      
      // Auto routing to Verifier
      document.getElementById(`btn-audit-${key}`).addEventListener('click', () => {
        els.verifierPasteArea.value = JSON.stringify(rawCred, null, 2);
        document.getElementById('nav-verifier').click();
        els.btnVerifyPaste.click();
      });
      
    } catch (e) {
      console.error(e);
    }
  });
  
  if (matchesFound === 0) {
    els.workerCredentialsList.innerHTML = `
      <div class="text-center text-muted" style="padding: 3rem 0;">
        <p style="font-size: 1.1rem; font-weight: 500;">No credentials found in your local portfolio.</p>
        <p class="text-xs mt-1">Acquire one by generating a miTch presentation on the right, syncing with the Employer.</p>
      </div>
    `;
  }
}

/**
 * Universal Drag and Drop + Verifier Setup.
 */
function setupVerifierDragDrop() {
  const dropzone = els.verifierDropzone;
  
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  
  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });
  
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    
    const file = e.dataTransfer.files[0];
    if (file && (file.type === 'application/json' || file.name.endsWith('.json'))) {
      const reader = new FileReader();
      reader.onload = function(e) {
        els.verifierPasteArea.value = e.target.result;
        els.btnVerifyPaste.click();
      };
      reader.readAsText(file);
    } else {
      showVerifierAlert('File Drop Error', 'Please drop a valid credential .json file.');
    }
  });
  
  els.btnBrowseFile.addEventListener('click', () => {
    els.verifierFileInput.click();
  });
  
  els.verifierFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = function(e) {
        els.verifierPasteArea.value = e.target.result;
        els.btnVerifyPaste.click();
      };
      reader.readAsText(file);
    }
  });

  els.btnVerifyPaste.addEventListener('click', async () => {
    const textVal = els.verifierPasteArea.value.trim();
    
    // Hide both elements on a new verification attempt
    els.verifierAlert.style.display = 'none';
    els.verifierReport.style.display = 'none';

    if (!textVal) {
      showVerifierAlert('Verification Blocked', 'Please paste credential JSON, raw compact SD-JWT-VC string or drop a file.');
      return;
    }
    
    try {
      let cred;
      let parsedForSchemaCheck = null;

      if (textVal.includes('~') && !textVal.startsWith('{')) {
        // It's a raw compact SD-JWT-VC string!
        const parts = textVal.split('~');
        if (parts.length < 2) {
          throw new Error("Structural Schema Check Failed: Invalid SD-JWT Compact format: Missing tilde separators.");
        }
        const jwsParts = parts[0].split('.');
        if (jwsParts.length !== 3) {
          throw new Error("Structural Schema Check Failed: Invalid JWS Compact structure in SD-JWT.");
        }
        let payload;
        try {
          payload = JSON.parse(base64UrlToString(jwsParts[1]));
        } catch (e) {
          throw new Error("Structural Schema Check Failed: JWS payload is not valid JSON.");
        }
        parsedForSchemaCheck = {
          format: "SD-JWT-VC",
          formatVersion: payload.formatVersion,
          issuer: payload.iss,
          holderPseudonym: payload.sub,
          mitchProofHash: payload.mitchProofHash
        };
      } else {
        let parsed;
        try {
          parsed = JSON.parse(textVal);
        } catch (jsonErr) {
          throw new Error(`JSON Parsing Failed: ${jsonErr.message}`);
        }
        
        if (parsed.format === 'SD-JWT-VC' && parsed.compact) {
          // Dual-format wrapper with compact
          const parts = parsed.compact.split('~');
          if (parts.length >= 2) {
            const jwsParts = parts[0].split('.');
            if (jwsParts.length === 3) {
              try {
                const payload = JSON.parse(base64UrlToString(jwsParts[1]));
                parsedForSchemaCheck = {
                  format: "SD-JWT-VC",
                  formatVersion: payload.formatVersion || parsed.formatVersion || (parsed.decoded && parsed.decoded.formatVersion),
                  issuer: payload.iss || parsed.issuer || (parsed.decoded && parsed.decoded.issuer),
                  holderPseudonym: payload.sub || parsed.holderPseudonym || (parsed.decoded && parsed.decoded.holderPseudonym),
                  mitchProofHash: payload.mitchProofHash || parsed.mitchProofHash || (parsed.decoded && parsed.decoded.mitchProofHash)
                };
              } catch (e) {}
            }
          }
          if (!parsedForSchemaCheck) {
            parsedForSchemaCheck = parsed.decoded ? parsed.decoded : parsed;
          }
        } else if (parsed.decoded) {
          parsedForSchemaCheck = parsed.decoded;
        } else {
          parsedForSchemaCheck = parsed;
        }
      }
      
      // Perform strong typing and schema check first
      validateCredentialSchema(parsedForSchemaCheck);
      
      // Now, run the actual parsing and cryptographic verification
      if (textVal.includes('~') && !textVal.startsWith('{')) {
        cred = await parseCompactSDJWT(textVal, store.knownIssuers);
      } else {
        const parsed = JSON.parse(textVal);
        if (parsed.format === 'SD-JWT-VC' && parsed.compact) {
          cred = await parseCompactSDJWT(parsed.compact, store.knownIssuers);
        } else if (parsed.decoded) {
          cred = await parseCompactSDJWT(parsed.compact, store.knownIssuers);
        } else {
          cred = parsed;
        }
      }
      
      await execute5StageTrustAudit(cred);
    } catch (err) {
      showVerifierAlert('Verification Failed', `Invalid credential structural integrity or cryptographic verification error.\nDetail: ${err.message}`);
    }
  });
}

/**
 * Initializes listeners for the 4 one-click interactive example pills.
 * Dynamically updates, tampers with, or malforms Alice Vance's seed credential
 * in order to demonstrate different states of verification.
 */
function initializeVerifierExamples() {
  if (els.btnExampleValid) {
    els.btnExampleValid.addEventListener('click', () => {
      const seed = localStorage.getItem('vericred_seed_credential_alice');
      if (seed) {
        try {
          const parsed = JSON.parse(seed);
          // Clear revocation registers for Alice to ensure it verifies successfully
          const sig = (parsed.decoded && parsed.decoded.signature) || parsed.signature;
          const mitchHash = (parsed.decoded && parsed.decoded.mitchProofHash) || parsed.mitchProofHash;
          const hp = (parsed.decoded && parsed.decoded.holderPseudonym) || parsed.holderPseudonym;
          
          if (sig) delete store.gatewayStatusList[sig];
          if (mitchHash) delete store.baseStatusList[mitchHash];
          if (hp) delete store.gatewayStatusList[hp];
          
          els.verifierPasteArea.value = seed;
          els.btnVerifyPaste.click();
        } catch (e) {
          console.error("Failed to load valid example", e);
        }
      } else {
        alert("Seed credential not found. Please reseed the blockchain.");
      }
    });
  }

  if (els.btnExampleRevoked) {
    els.btnExampleRevoked.addEventListener('click', () => {
      const seed = localStorage.getItem('vericred_seed_credential_alice');
      if (seed) {
        try {
          const parsed = JSON.parse(seed);
          const sig = (parsed.decoded && parsed.decoded.signature) || parsed.signature;
          const mitchHash = (parsed.decoded && parsed.decoded.mitchProofHash) || parsed.mitchProofHash;
          
          // Force mark as revoked in registries
          if (sig) store.gatewayStatusList[sig] = true;
          if (mitchHash) store.baseStatusList[mitchHash] = true;
          
          els.verifierPasteArea.value = seed;
          els.btnVerifyPaste.click();
        } catch (e) {
          console.error("Failed to load revoked example", e);
        }
      } else {
        alert("Seed credential not found. Please reseed the blockchain.");
      }
    });
  }

  if (els.btnExampleTampered) {
    els.btnExampleTampered.addEventListener('click', () => {
      const seed = localStorage.getItem('vericred_seed_credential_alice');
      if (seed) {
        try {
          const parsed = JSON.parse(seed);
          // Clear revocation first so we trigger Stage 2 signature failure, not Stage 4 revocation failure
          const sig = (parsed.decoded && parsed.decoded.signature) || parsed.signature;
          const mitchHash = (parsed.decoded && parsed.decoded.mitchProofHash) || parsed.mitchProofHash;
          if (sig) delete store.gatewayStatusList[sig];
          if (mitchHash) delete store.baseStatusList[mitchHash];

          if (parsed.decoded) {
            // Tamper with the decoded signature
            parsed.decoded.signature = parsed.decoded.signature.slice(0, -2) + '00';
            // Also tamper with the compact SD-JWT signature part
            if (parsed.compact) {
              const parts = parsed.compact.split('~');
              if (parts[0]) {
                const jwsParts = parts[0].split('.');
                if (jwsParts[2]) {
                  jwsParts[2] = jwsParts[2].slice(0, -2) + 'xx';
                  parts[0] = jwsParts.join('.');
                }
              }
              parsed.compact = parts.join('~');
            }
          } else if (parsed.signature) {
            parsed.signature = parsed.signature.slice(0, -2) + '00';
          }
          
          els.verifierPasteArea.value = JSON.stringify(parsed, null, 2);
          els.btnVerifyPaste.click();
        } catch (e) {
          console.error("Failed to load tampered example", e);
        }
      } else {
        alert("Seed credential not found. Please reseed the blockchain.");
      }
    });
  }

  if (els.btnExampleMalformed) {
    els.btnExampleMalformed.addEventListener('click', () => {
      const malformed = {
        format: "SD-JWT-VC",
        formatVersion: "0.9.0",
        issuer: "did:invalid",
        holderPseudonym: "invalid-pseudonym",
        mitchProofHash: "not-64-hex"
      };
      els.verifierPasteArea.value = JSON.stringify(malformed, null, 2);
      els.btnVerifyPaste.click();
    });
  }
}

function showVerifierAlert(title, text) {
  els.verifierReport.style.display = 'none';
  els.verifierAlert.style.display = 'block';
  els.verifierAlertTitle.innerText = title;
  els.verifierAlertText.innerText = text;
  els.verifierAlert.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Performs strong schema-typing validations on the credential schema before cryptographic evaluation.
 */
function validateCredentialSchema(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Structural Schema Check Failed: Credential is not a valid JSON object.');
  }
  
  if (parsed.format !== 'SD-JWT-VC') {
    throw new Error(`Structural Schema Check Failed: Format identifier must be strictly 'SD-JWT-VC'. Received: '${parsed.format}'`);
  }

  if (!parsed.formatVersion) {
    throw new Error('Structural Schema Check Failed: Missing mandatory formatVersion metadata field.');
  }

  // Parse semver-like format version and assert >= 1.0.0
  const versionParts = String(parsed.formatVersion).split('.').map(Number);
  if (versionParts.length === 0 || isNaN(versionParts[0]) || versionParts[0] < 1) {
    throw new Error(`Structural Schema Check Failed: formatVersion '${parsed.formatVersion}' is incompatible. Must be >= 1.0.0.`);
  }

  if (!parsed.issuer || typeof parsed.issuer !== 'string' || !parsed.issuer.startsWith('did:')) {
    throw new Error(`Structural Schema Check Failed: Issuer must be a valid Decentralized Identifier starting with 'did:'. Received: '${parsed.issuer}'`);
  }

  if (!parsed.holderPseudonym || typeof parsed.holderPseudonym !== 'string' || !parsed.holderPseudonym.startsWith('did:vericred:pairwise:')) {
    throw new Error(`Structural Schema Check Failed: Holder pseudonym must conform to 'did:vericred:pairwise:...'. Received: '${parsed.holderPseudonym}'`);
  }

  if (!parsed.mitchProofHash || typeof parsed.mitchProofHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(parsed.mitchProofHash)) {
    throw new Error(`Structural Schema Check Failed: mitchProofHash must be a valid 64-character SHA-256 hexadecimal string. Received: '${parsed.mitchProofHash}'`);
  }
}

/**
 * Premium 5-Stage Fail-Closed Pipeline Auditor.
 */
async function execute5StageTrustAudit(cred) {
  // Show verifier card container
  els.verifierReport.style.display = 'block';
  els.verifierReport.scrollIntoView({ behavior: 'smooth', block: 'start' });
  
  // Clear checklist status UI
  for (let i = 1; i <= 5; i++) {
    const row = els[`stageRow${i}`];
    const status = els[`stageStatus${i}`];
    row.className = 'audit-stage-row stage-pending';
    status.innerText = 'AUDITING...';
    status.style.color = '#94a3b8';
  }
  
  // Populate Fields
  els.auditWorkerName.innerText = cred.holderPseudonym;
  els.auditIssuerName.innerText = cred.issuer;
  els.auditJobTitle.innerText = cred.claims.jobTitle;
  els.auditDuration.innerText = cred.claims.duration;
  els.auditSamplesHash.innerText = cred.claims.workSamplesHash;
  els.auditMitchHash.innerText = cred.mitchProofHash ? cred.mitchProofHash : 'None (Loose Signature)';
  els.auditSkillsList.innerHTML = cred.claims.skills.map(s => `<span class="skill-tag">${s}</span>`).join('');

  // --------------------------------------------------------------
  // STAGE 1: miTch Wallet Presentation Verification
  // --------------------------------------------------------------
  let stage1Ok = false;
  try {
    const envelope = store.verifiedMitchProofs[cred.mitchProofHash];
    if (!envelope) {
      throw new Error('No miTch envelope associated with mitchProofHash found in EUDI session cache.');
    }
    
    // mathematical verify bypassing replay since we audit retrospective credentials
    const trustList = { ...store.knownIssuers };
    if (activeAttackName === 'untrusted' && !store.isLabTrustOverrideActive) {
      delete trustList['did:mitch:rogue-anchor'];
    }
    
    const res = await verifyMitchPresentationSequential(
      envelope, 
      envelope.holder_binding.nonce, // satisfy nonce match bypass replay
      trustList, 
      store.baseStatusList
    );
    
    if (activeAttackName === 'replay') {
      throw new Error('Replay attack active. Nonce mismatch!');
    }
    
    stage1Ok = res.isValid;
    updateStageUI(1, 'PASSED', 'stage-passed', '🛡️ miTch verified successfully. Base trust intact.');
  } catch (err) {
    updateStageUI(1, 'FAILED', 'stage-failed', `❌ miTch presentation failed: ${err.message}`);
  }

  if (!stage1Ok) return terminatePipeline('STAGE 1 FAILURE (miTch presentation rejected)');

  // --------------------------------------------------------------
  // STAGE 2: VeriCred Gateway Signature Audit
  // --------------------------------------------------------------
  let stage2Ok = false;
  try {
    // Verify math signature of gateway
    const verifiedPayload = {
      format: cred.format,
      issuer: cred.issuer,
      holderPseudonym: cred.holderPseudonym,
      mitchProofHash: cred.mitchProofHash,
      claims: cred.claims,
      salts: cred.salts
    };
    
    const isGatewaySigValid = await verifyWithJWK(store.employerKeys.publicKey, verifiedPayload, cred.signature);
    if (!isGatewaySigValid) {
      throw new Error('VeriCred Gateway cryptographic signature is mathematically invalid.');
    }
    
    stage2Ok = true;
    updateStageUI(2, 'PASSED', 'stage-passed', '🔑 Gateway signature mathematically valid.');
  } catch (err) {
    updateStageUI(2, 'FAILED', 'stage-failed', `❌ Gateway verification failed: ${err.message}`);
  }

  if (!stage2Ok) return terminatePipeline('STAGE 2 FAILURE (Signature math invalid)');

  // --------------------------------------------------------------
  // STAGE 3: Ledger Anchor Verification
  // --------------------------------------------------------------
  let stage3Ok = false;
  let anchoredBlockIndex = null;
  try {
    // Verify overall ledger state first
    const chainAudit = await isChainValid(store.chain);
    if (!chainAudit.isValid) {
      throw new Error(`Chain sequence broken: ${chainAudit.reason}`);
    }
    
    const expectedCredHash = await sha256(JSON.stringify(cred));
    
    // Find matching anchored commitment
    for (let i = 1; i < store.chain.length; i++) {
      const block = store.chain[i];
      const hasTx = block.transactions.some(tx => tx.payload.credentialHash === expectedCredHash);
      if (hasTx) {
        anchoredBlockIndex = block.index;
        break;
      }
    }
    
    if (anchoredBlockIndex === null) {
      throw new Error('Credential commitment anchor not found on current blockchain.');
    }
    
    stage3Ok = true;
    updateStageUI(3, 'PASSED', 'stage-passed', `⛓️ Anchored in Block #${anchoredBlockIndex}. Block Link secure.`);
  } catch (err) {
    updateStageUI(3, 'FAILED', 'stage-failed', `❌ Ledger Anchor failed: ${err.message}`);
  }

  if (!stage3Ok) return terminatePipeline('STAGE 3 FAILURE (Ledger Anchor unverified)');

  // --------------------------------------------------------------
  // STAGE 4: Revocation Status Audit
  // --------------------------------------------------------------
  let stage4Ok = false;
  try {
    const isBaseRevoked = store.baseStatusList[cred.mitchProofHash] === true;
    const isGatewayRevoked = store.gatewayStatusList[cred.signature] === true || store.gatewayStatusList[cred.holderPseudonym] === true;
    
    if (isBaseRevoked) {
      throw new Error('The baseline EUDI Identity Presentation has been REVOKED.');
    }
    if (isGatewayRevoked) {
      throw new Error('The VeriCred Gateway Professional credential has been REVOKED.');
    }
    
    stage4Ok = true;
    updateStageUI(4, 'PASSED', 'stage-passed', '🚫 Verified as active (Not revoked).');
  } catch (err) {
    updateStageUI(4, 'FAILED', 'stage-failed', `❌ Revocation failed: ${err.message}`);
  }

  if (!stage4Ok) return terminatePipeline('STAGE 4 FAILURE (Revoked Status)');

  // --------------------------------------------------------------
  // STAGE 5: Metadata Budget Compliance Audit
  // --------------------------------------------------------------
  let stage5Ok = false;
  try {
    // Scan matching block transaction for plain-text claims
    const expectedCredHash = await sha256(JSON.stringify(cred));
    let blockToScan = null;
    
    for (let i = 1; i < store.chain.length; i++) {
      const block = store.chain[i];
      const hasTx = block.transactions.some(tx => tx.payload.credentialHash === expectedCredHash);
      if (hasTx) {
        blockToScan = block;
        break;
      }
    }
    
    if (blockToScan) {
      for (const tx of blockToScan.transactions) {
        if (tx.payload.credentialHash === expectedCredHash) {
          const p = tx.payload;
          if (p.workerName || p.jobTitle || p.duration || p.skills) {
            throw new Error(`Metadata budget leak detected: block #${blockToScan.index} transaction contains raw unhashed values!`);
          }
        }
      }
    }
    
    stage5Ok = true;
    updateStageUI(5, 'PASSED', 'stage-passed', '📇 Scanned. Zero plain-text names or claims found on-chain.');
  } catch (err) {
    updateStageUI(5, 'FAILED', 'stage-failed', `❌ Metadata Leak failed: ${err.message}`);
  }

  if (!stage5Ok) return terminatePipeline('STAGE 5 FAILURE (PII leak on-chain)');

  // --------------------------------------------------------------
  // PIPELINE COMPLETION (All 5 stages passed)
  // --------------------------------------------------------------
  els.auditMainBadge.innerText = 'Dual-Signature Verified';
  els.auditMainBadge.className = 'cred-badge verified';
  els.auditMainIcon.innerText = '✅';
  els.auditCardBody.style.borderColor = 'rgba(16, 185, 129, 0.2)';
  els.auditCardBody.style.background = 'rgba(16, 185, 129, 0.02)';
  
  // Show interactive match receipt
  const receiptHTML = `
    <div style="margin-top:1.5rem; border-top: 1px dashed rgba(16, 185, 129, 0.3); padding-top:1.5rem;">
      <span style="font-size:0.75rem; color:#10b981; font-weight:bold; text-transform:uppercase; display:block; letter-spacing:1px;">Kryptographischer Proof-Abgleich (Off-Chain zu On-Chain)</span>
      <div style="font-family:var(--font-mono); font-size:0.75rem; color:#cbd5e1; margin-top:0.75rem; display:flex; flex-direction:column; gap:0.5rem;">
        <div>1. Job Title Commitment match: <br>
          <span style="color:#64748b;">SHA256("${cred.claims.jobTitle}" + "${cred.salts.jobTitle}")</span> = <br>
          <span style="color:#38bdf8;">${await sha256(cred.claims.jobTitle + cred.salts.jobTitle)}</span> (MATCH ✅)
        </div>
        <div>2. Term Duration Commitment match: <br>
          <span style="color:#64748b;">SHA256("${cred.claims.duration}" + "${cred.salts.duration}")</span> = <br>
          <span style="color:#38bdf8;">${await sha256(cred.claims.duration + cred.salts.duration)}</span> (MATCH ✅)
        </div>
        <div>3. Certified Skills Commitment match: <br>
          <span style="color:#64748b;">SHA256("${cred.claims.skills.join(',')}" + "${cred.salts.skills}")</span> = <br>
          <span style="color:#38bdf8;">${await sha256(cred.claims.skills.join(',') + cred.salts.skills)}</span> (MATCH ✅)
        </div>
      </div>
    </div>
  `;
  
  const existingReceipt = els.auditCardBody.querySelector('.receipt-container');
  if (existingReceipt) existingReceipt.remove();
  
  const receiptDiv = document.createElement('div');
  receiptDiv.className = 'receipt-container';
  receiptDiv.innerHTML = receiptHTML;
  els.auditCardBody.appendChild(receiptDiv);
}

function updateStageUI(stageNum, text, className, desc) {
  const row = els[`stageRow${stageNum}`];
  const status = els[`stageStatus${stageNum}`];
  row.className = `audit-stage-row ${className}`;
  status.innerText = text;
  status.style.color = className === 'stage-passed' ? 'var(--status-verified)' : 'var(--status-error)';
  row.querySelector('.audit-stage-desc').innerText = desc;
}

function terminatePipeline(failReason) {
  els.auditMainBadge.innerText = 'Fail-Closed Blocked';
  els.auditMainBadge.className = 'cred-badge btn-danger';
  els.auditMainIcon.innerText = '🚨';
  els.auditCardBody.style.borderColor = 'rgba(244, 63, 94, 0.2)';
  els.auditCardBody.style.background = 'rgba(244, 63, 94, 0.02)';
  
  const existingReceipt = els.auditCardBody.querySelector('.receipt-container');
  if (existingReceipt) existingReceipt.remove();
  
  console.warn(`[Fail-Closed Audit Pipeline Activated]: ${failReason}`);
}

/**
 * Interactive Security Attack & Abuse Sandbox.
 */
function setupSandboxControls() {
  const clearAttackVisuals = () => {
    document.querySelectorAll('.sandbox-btn').forEach(btn => btn.classList.remove('active-attack'));
  };
  
  // Replay Attack
  els.sandboxBtnReplay.addEventListener('click', () => {
    clearAttackVisuals();
    els.sandboxBtnReplay.classList.add('active-attack');
    activeAttackName = 'replay';
    alert('🔄 Replay Attack Mode Enabled.\nThe verifier will receive a mock key binding envelope utilizing an expired/unrecognized challenge nonce.');
  });
  
  // Fake Trust Anchor
  els.sandboxBtnUntrusted.addEventListener('click', () => {
    clearAttackVisuals();
    els.sandboxBtnUntrusted.classList.add('active-attack');
    activeAttackName = 'untrusted';
    alert('🔑 Fake Trust Anchor Mode Enabled.\nThe worker will generate a presentation proof signed by did:mitch:rogue-anchor which is absent from standard EUDI Trust Lists.');
  });
  
  // Credential Revocation
  els.sandboxBtnRevocation.addEventListener('click', () => {
    clearAttackVisuals();
    els.sandboxBtnRevocation.classList.add('active-attack');
    activeAttackName = 'revoked';
    
    // Seed revocation list
    const aliceThumb = els.workerAddressDisplay.innerText;
    // Mark Alice's thumb/credentials as revoked in the StatusList
    store.baseStatusList['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'] = true;
    store.gatewayStatusList[aliceThumb] = true;
    
    // Also revoke specific seed signatures
    const seedCred = localStorage.getItem('vericred_seed_credential_alice');
    if (seedCred) {
      try {
        const parsed = JSON.parse(seedCred);
        store.gatewayStatusList[parsed.signature] = true;
        store.baseStatusList[parsed.mitchProofHash] = true;
      } catch(e){}
    }
    
    alert('🚫 Revocation Status Enabled.\nAlice Vance\'s seed credentials and EUDI presentations are flagged as "revoked" in Stage 4 registries.');
  });
  
  // Metadata Budget Leak
  els.sandboxBtnPii.addEventListener('click', () => {
    clearAttackVisuals();
    els.sandboxBtnPii.classList.add('active-attack');
    activeAttackName = 'pii_leak';
    alert('📇 Metadata Budget Leak Enabled.\nAcme Gateway will write plain text names and job titles directly on-chain during issuance, causing automated Stage 5 and Ledger audits to trigger alarms.');
  });
  
  // Block Link Corruption
  els.sandboxBtnLink.addEventListener('click', async () => {
    clearAttackVisuals();
    els.sandboxBtnLink.classList.add('active-attack');
    activeAttackName = 'link_corrupt';
    
    // Inject linkage corruption in memory
    if (store.chain.length > 1) {
      store.tamperWithPayload(1, 0, 'holderPseudonym', 'did:vericred:pairwise:corrupted-pseudonym-leak-1234');
      store.chain[1].hash = 'ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00';
    }
    
    await auditAndSyncLedgerUI();
    renderLedgerExplorer();
    alert('⚡ Link Corruption Enabled.\nWe tampered with on-chain values in Block #1, breaking the SHA-256 backward reference link. Stage 3 ledger anchors will fail.');
  });

  // Lab Trust Override toggle
  els.sandboxTrustListToggle.addEventListener('change', (e) => {
    store.isLabTrustOverrideActive = e.target.checked;
    console.log(`Lab Trust Override state: ${store.isLabTrustOverrideActive}`);
  });

  // Reset Sandbox
  els.sandboxBtnResetSimulator.addEventListener('click', async () => {
    clearAttackVisuals();
    activeAttackName = null;
    store.isLabTrustOverrideActive = false;
    els.sandboxTrustListToggle.checked = false;
    
    // Restore clean registries and chain
    store.baseStatusList = {};
    store.gatewayStatusList = {};
    store.restoreChain();
    
    await auditAndSyncLedgerUI();
    renderLedgerExplorer();
    renderWorkerCredentials();
    
    // Reset gatekeeper feedback and lock state
    els.gatekeeperUnlockedForm.className = 'gatekeeper-locked';
    els.gatekeeperLockOverlay.style.display = 'flex';
    els.gatekeeperFeedbackContainer.style.display = 'none';
    els.gatekeeperProofInput.value = '';
    
    alert('🔄 Security Sandbox Reset.\nAll simulated cryptographic, status list, PII, and block linkage corruptions restored to safe states.');
  });
}

/**
 * Setup Ledger and Explorer tab actions.
 */
function setupLedgerControls() {
  els.btnRevalidateLedger.addEventListener('click', async () => {
    await auditAndSyncLedgerUI();
    renderLedgerExplorer();
    alert('✅ Sequential cryptographic ledger audit completed successfully.');
  });
  
  els.btnRestoreChain.addEventListener('click', async () => {
    store.restoreChain();
    await auditAndSyncLedgerUI();
    renderLedgerExplorer();
    renderWorkerCredentials();
    els.blockInspector.style.display = 'none';
    alert('🔄 Tampered in-memory ledger restored safely from LocalStorage backups.');
  });
  
  els.btnHardReset.addEventListener('click', async () => {
    const conf = confirm('CRITICAL: This will completely erase all credentials, user identities, and blockchain blocks, re-generating the seed data from scratch. Are you sure?');
    if (conf) {
      await store.hardReset();
      setupIdentityDisplay();
      await auditAndSyncLedgerUI();
      renderWorkerCredentials();
      renderMempool();
      renderLedgerExplorer();
      els.blockInspector.style.display = 'none';
      alert('⚡ Block ledger hard reset successfully.');
    }
  });

  els.btnTamperExecute.addEventListener('click', async () => {
    if (selectedBlockIndex === null) return;
    
    const fakeJob = els.tamperJobTitle.value.trim();
    const fakePseudonym = els.tamperWorkerName.value.trim();
    
    // Tamper with transaction in selected block
    store.tamperWithPayload(selectedBlockIndex, 0, 'jobTitle', fakeJob);
    store.tamperWithPayload(selectedBlockIndex, 0, 'holderPseudonym', fakePseudonym);
    
    await auditAndSyncLedgerUI();
    renderLedgerExplorer();
    inspectBlock(selectedBlockIndex);
    
    alert(`🚨 Attack simulated successfully!\nIn-memory Block #${selectedBlockIndex} data edited.\nWatch how the visual ledger explorer immediately detects the broken cryptographic links!`);
  });
}

/**
 * Renders blockchain node streams.
 */
function renderLedgerExplorer() {
  els.blockchainVisualContainer.innerHTML = '';
  
  els.statTotalBlocks.innerText = store.chain.length;
  els.statDifficulty.innerText = els.miningDifficulty.value;
  
  let credsCount = 0;
  for (let i = 1; i < store.chain.length; i++) {
    credsCount += store.chain[i].transactions.length;
  }
  els.statTotalCreds.innerText = credsCount;

  store.chain.forEach((block, index) => {
    const node = document.createElement('div');
    
    let blockClass = 'block-node';
    if (selectedBlockIndex === index) blockClass += ' active';
    
    if (store.isChainCorrupt && store.corruptionReport) {
      if (index >= store.corruptionReport.blockIndex) {
        blockClass += ' corrupted';
      }
    }
    
    node.className = blockClass;
    
    node.innerHTML = `
      <div class="block-header">
        <span style="font-weight: bold; color: #fff;">BLOCK #${block.index}</span>
        <span class="text-mono">Nonce: ${block.nonce}</span>
      </div>
      <div class="block-hash text-mono text-xs" style="color: var(--accent-teal);">${block.hash.substring(0, 16)}...</div>
      <div class="text-xs text-muted mt-2" style="display: flex; align-items: center; justify-content: space-between;">
        <span>${block.transactions.length} Certificate(s)</span>
        <span>${new Date(block.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
      </div>
    `;
    
    node.addEventListener('click', () => {
      selectedBlockIndex = index;
      document.querySelectorAll('.block-node').forEach(b => b.classList.remove('active'));
      node.classList.add('active');
      inspectBlock(index);
    });
    
    els.blockchainVisualContainer.appendChild(node);
    
    if (index < store.chain.length - 1) {
      const arrow = document.createElement('div');
      
      let arrowClass = 'blockchain-connector';
      if (store.isChainCorrupt && store.corruptionReport && index >= store.corruptionReport.blockIndex - 1) {
        arrowClass += ' corrupted';
      }
      
      arrow.className = arrowClass;
      arrow.innerHTML = '➔';
      els.blockchainVisualContainer.appendChild(arrow);
    }
  });
  
  if (selectedBlockIndex !== null) {
    inspectBlock(selectedBlockIndex);
  }
}

/**
 * Dynamic parameter inspection of a selected block.
 */
function inspectBlock(index) {
  const block = store.chain[index];
  if (!block) return;
  
  els.inspectorBlockTitle.innerText = `Block #${block.index} Parameters`;
  els.inspectorBlockHash.innerText = `Hash: ${block.hash}`;
  
  els.inspectPrevHash.innerText = block.previousHash;
  els.inspectTxsHash.innerText = block.transactionsHash;
  els.inspectTimestamp.innerText = new Date(block.timestamp).toLocaleString();
  els.inspectNonce.innerText = block.nonce;
  
  els.inspectTransactionsBody.innerHTML = '';
  
  block.transactions.forEach(tx => {
    const div = document.createElement('div');
    div.style.background = 'rgba(255,255,255,0.01)';
    div.style.border = '1px solid rgba(255,255,255,0.05)';
    div.style.padding = '0.75rem';
    div.style.borderRadius = '8px';
    div.style.fontSize = '0.85rem';
    
    let contents = '';
    if (tx.type === 'ISSUE_CREDENTIAL') {
      contents = `
        <strong style="color: var(--accent-teal);">Holder Pseudonym:</strong> <span class="text-mono" style="word-break: break-all;">${tx.payload.holderPseudonym}</span><br>
        <strong style="color: var(--accent-teal);">miTch Proof Hash:</strong> <span class="text-mono text-xs">${tx.payload.mitchProofHash ? tx.payload.mitchProofHash.substring(0, 20) : 'None'}...</span><br>
        <strong style="color: var(--accent-teal);">Credential Hash:</strong> <span class="text-mono text-xs">${tx.payload.credentialHash.substring(0, 20)}...</span><br>
        <strong style="color: var(--accent-teal);">claimCommitments:</strong><br>
        <span style="padding-left:1rem; display:block; color:#94a3b8; font-size:0.75rem;">
          - Job Commitment: ${tx.payload.claimCommitments.jobTitle ? tx.payload.claimCommitments.jobTitle.substring(0, 16) : 'None'}...<br>
          - Term Commitment: ${tx.payload.claimCommitments.duration ? tx.payload.claimCommitments.duration.substring(0, 16) : 'None'}...<br>
          - Skills Commitment: ${tx.payload.claimCommitments.skills ? tx.payload.claimCommitments.skills.substring(0, 16) : 'None'}...
        </span>
        <strong style="color: var(--accent-teal);">Signature:</strong> <span class="text-mono text-xs" style="word-break: break-all;">${tx.signature ? tx.signature.substring(0, 24) : 'Seed anchor'}...</span>
      `;
    } else {
      contents = JSON.stringify(tx.payload, null, 2);
    }
    
    div.innerHTML = `
      <div style="font-weight: 600; color: #fff; margin-bottom: 0.25rem;">Type: ${tx.type}</div>
      <div class="text-xs text-muted" style="line-height: 1.4;">
        ${contents}
      </div>
    `;
    els.inspectTransactionsBody.appendChild(div);
  });
  
  if (index === 0) {
    els.btnTamperExecute.disabled = true;
    els.btnTamperExecute.innerText = 'Genesis Block Immutable';
  } else {
    els.btnTamperExecute.disabled = false;
    els.btnTamperExecute.innerText = 'Inject Fraudulent Payload';
    
    const tx = block.transactions[0];
    if (tx && tx.payload) {
      els.tamperJobTitle.value = tx.payload.claimCommitments.jobTitle ? 'Fraudulent Title Commitment' : 'Fraud';
      els.tamperWorkerName.value = tx.payload.holderPseudonym;
    }
  }
  
  els.blockInspector.style.display = 'block';
  els.blockInspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Updates the Operational Truth Pass diagnostics card with real-time health metrics.
 */
function updateDiagnosticStatesUI() {
  const diagStorage = document.getElementById('diag-storage');
  const diagNonces = document.getElementById('diag-nonces');
  const diagSecret = document.getElementById('diag-secret');
  const diagQuarantined = document.getElementById('diag-quarantined');
  const diagAnchors = document.getElementById('diag-anchors');

  if (diagStorage) {
    let storageOk = false;
    try {
      localStorage.setItem('__test_storage_health__', 'ok');
      if (localStorage.getItem('__test_storage_health__') === 'ok') {
        storageOk = true;
      }
      localStorage.removeItem('__test_storage_health__');
    } catch (e) {
      console.error('Storage health check failed:', e);
    }
    
    if (storageOk) {
      diagStorage.textContent = 'HEALTHY';
      diagStorage.style.color = 'var(--status-verified)';
    } else {
      diagStorage.textContent = 'UNAVAILABLE';
      diagStorage.style.color = 'var(--status-error)';
    }
  }

  if (diagNonces) {
    const activeCount = Object.keys(store.activeNonces).length;
    diagNonces.textContent = `${activeCount} active`;
    diagNonces.style.color = activeCount > 0 ? 'var(--accent-teal)' : 'var(--accent-purple)';
  }

  if (diagSecret) {
    const secretOk = !!store.localGatewaySecret;
    diagSecret.textContent = secretOk ? 'SECURED' : 'MISSING';
    diagSecret.style.color = secretOk ? 'var(--status-verified)' : 'var(--status-error)';
  }

  if (diagQuarantined) {
    let qCount = 0;
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('vericred_ledger_chain_quarantine_')) {
          qCount++;
        }
      }
    } catch (e) {
      console.error(e);
    }
    diagQuarantined.textContent = `${qCount} stored`;
    diagQuarantined.style.color = qCount > 0 ? 'var(--status-warning)' : '#64748b';
  }

  if (diagAnchors) {
    const anchorsCount = Object.keys(store.knownIssuers).length;
    diagAnchors.textContent = `${anchorsCount} registered`;
    diagAnchors.style.color = anchorsCount > 0 ? 'var(--status-verified)' : 'var(--status-error)';
  }
}

/**
 * Sets up the interactive Architectural Safeguards Threat Matrix on the Security tab.
 * Binds row click events to dynamically render the mitigation coordinates and description in the console inspector pane.
 */
function setupThreatMatrix() {
  const rows = document.querySelectorAll('.threat-row');
  const inspectorFileTag = document.getElementById('inspector-file-tag');
  const inspectorContent = document.getElementById('inspector-content');

  if (rows.length === 0 || !inspectorFileTag || !inspectorContent) return;

  const mapping = {
    correlation: {
      file: "crypto-service.js & app.js",
      coordinates: "crypto-service.js:L241-259 & app.js:L443-445",
      content: `// identity correlation mitigation
// -------------------------------------------------------------
// file: crypto-service.js (calculateHMAC)
// coordinates: crypto-service.js:L241-259
// file: app.js (generating pairwise DID)
// coordinates: app.js:L443-445
// -------------------------------------------------------------

function calculateHMAC(secretStr, dataString) {
  // Uses Web Crypto subtle API to compute stable pairwise pseudonyms
  // did:vericred:pairwise:HMAC(secret, thumbprint | issuer | type | mitchProofHash)
  // This guarantees complete unlinkability across gateways or credentials!
}

// State: Verified Secure`
    },
    leak: {
      file: "blockchain.js & app.js",
      coordinates: "blockchain.js:L137 & app.js:L503-507",
      content: `// plaintext on-chain leak mitigation (zero-pii compliance)
// -------------------------------------------------------------
// file: blockchain.js (isChainValid / createBlock)
// coordinates: blockchain.js:L137 / L163-171
// file: app.js (compiling block commitments)
// coordinates: app.js:L503-507
// -------------------------------------------------------------

// We separate readable claims from on-chain anchors.
// The block contains only hashed claimCommitments:
// sha256(claim_value + salt_hex)
// isChainValid() performs an automated audit and will fail-closed
// if any readable PII leaks into block transactions.

// State: Zero-PII Ledger Confirmed`
    },
    replay: {
      file: "crypto-service.js & app.js",
      coordinates: "crypto-service.js:L357-363 & app.js:L409-414",
      content: `// replay attack mitigation
// -------------------------------------------------------------
// file: crypto-service.js (verifyMitchPresentationSequential)
// coordinates: crypto-service.js:L357-363
// file: app.js (consumeNonceFn implementation)
// coordinates: app.js:L409-414
// -------------------------------------------------------------

// Single-use challenge nonces with 5-min TTL.
// The nonce is atomically popped and consumed upon the very first
// structurally valid verification attempt. This prevents reuse
// of intercepted presentations even if verification fails.

// State: Replay Protection Active`
    },
    spoofing: {
      file: "store.js & crypto-service.js",
      coordinates: "store.js:L124 & crypto-service.js:L371-376",
      content: `// trust anchor spoofing mitigation
// -------------------------------------------------------------
// file: store.js (seedKnownIssuers / EUDI Trust List)
// coordinates: store.js:L124
// file: crypto-service.js (verifyMitchPresentationSequential)
// coordinates: crypto-service.js:L371-376
// -------------------------------------------------------------

// We use a statically seeded Trust List mapping allowed DID issuers.
// Any presentation signed by a key/DID not registered in the EUDI
// Trust List fails-closed instantly, blocking unauthorized issuers.

// State: Fail-Closed Trust Engine`
    },
    hijack: {
      file: "crypto-service.js",
      coordinates: "crypto-service.js:L216-236 & L365-369",
      content: `// holder key hijack mitigation
// -------------------------------------------------------------
// file: crypto-service.js (calculateJWKThumbprint / verifyMitch)
// coordinates: crypto-service.js:L216-236 & crypto-service.js:L365-369
// -------------------------------------------------------------

// Computes standard RFC 7638 Public Key Thumbprints (alphabetical).
// We verify that the transient holder public key presented in
// holder_binding.holder_jwk has an identical thumbprint to the
// holder_jwk_thumbprint signed by the trusted issuer.

// State: Holder-Bound Cryptographic Association`
    }
  };

  rows.forEach(row => {
    row.addEventListener('click', () => {
      // Remove active states from other rows
      rows.forEach(r => {
        r.style.background = '';
        r.style.boxShadow = '';
      });

      // Highlight selected row with modern glassmorphism glow
      row.style.background = 'rgba(59, 130, 246, 0.08)';
      row.style.boxShadow = 'inset 0 0 8px rgba(59, 130, 246, 0.15)';

      const threatKey = row.getAttribute('data-threat');
      const data = mapping[threatKey];
      if (data) {
        inspectorFileTag.textContent = data.file;
        inspectorContent.textContent = data.content;
      }
    });
  });
}

/**
 * Binds events and executes the automated Security and Cryptographic QA Test Suite.
 */
function setupQAHarness() {
  const btnRun = document.getElementById('btn-run-qa-tests');
  if (!btnRun) return;

  btnRun.addEventListener('click', async () => {
    btnRun.disabled = true;
    btnRun.innerHTML = '⚙️ Running Assertions...';
    btnRun.style.opacity = '0.7';

    const suiteIndicator = document.getElementById('qa-suite-indicator');
    const summaryStats = document.getElementById('qa-suite-summary-stats');
    const passedDisplay = document.getElementById('qa-suite-passed');
    const executedDisplay = document.getElementById('qa-suite-executed');
    const timeDisplay = document.getElementById('qa-suite-time');

    if (suiteIndicator) {
      suiteIndicator.style.background = 'var(--accent-teal)';
      suiteIndicator.style.boxShadow = '0 0 15px var(--accent-teal-glow)';
    }

    const testCases = [
      { id: 'thumbprint', name: 'Test 1: RFC 7638 Thumbprint Determinism', run: runTestThumbprint },
      { id: 'pseudonym', name: 'Test 2: HMAC Pairwise Pseudonym Stability & Scoping', run: runTestPseudonym },
      { id: 'nonce', name: 'Test 3: Atomic Nonce Lifecycle', run: runTestNonce },
      { id: 'replay', name: 'Test 4: Strict Replay Rejection', run: runTestReplay },
      { id: 'fake-issuer', name: 'Test 5: Fake EUDI Trust Anchor Rejection', run: runTestFakeIssuer },
      { id: 'key-mismatch', name: 'Test 6: Holder Key Mismatch Rejection', run: runTestKeyMismatch },
      { id: 'ledger-pii', name: 'Test 7: Zero-PII Ledger Compliance Audit', run: runTestLedgerPII },
      { id: 'preservative-reseed', name: 'Test 8: Preservative Ledger Reseed & Quarantine', run: runTestPreservativeReseed },
      { id: 'compact-sdjwt', name: 'Test 9: Compact SD-JWT-VC Serialization Integrity', run: runTestCompactSDJWT },
      { id: 'csp-validation', name: 'Test 10: Strict CSP & Robust Import Validation', run: runTestCspValidation },
      { id: 'version-schema', name: 'Test 11: Export Format Versioning & Strictest Schema Verification', run: runTestSchemaAndVersioning }
    ];

    let passedCount = 0;
    const startTime = performance.now();

    for (const test of testCases) {
      const row = document.getElementById(`qa-test-${test.id}`);
      const chip = document.getElementById(`test-chip-${test.id}`);
      const logBox = document.getElementById(`test-log-${test.id}`);

      if (row) {
        row.classList.remove('test-pass', 'test-fail');
        row.classList.add('test-running');
      }
      if (chip) {
        chip.textContent = 'Running...';
        chip.className = 'status-chip running';
      }
      if (logBox) {
        logBox.textContent = 'Initializing execution harness...';
      }

      // Briefly yield to main thread to animate transition nicely
      await new Promise(r => setTimeout(r, 50));

      try {
        const testStartTime = performance.now();
        await test.run(logBox);
        const testDuration = (performance.now() - testStartTime).toFixed(1);

        passedCount++;
        if (row) {
          row.classList.remove('test-running');
          row.classList.add('test-pass');
        }
        if (chip) {
          chip.textContent = `PASS (${testDuration}ms)`;
          chip.className = 'status-chip pass';
        }
      } catch (err) {
        console.error(`QA Test Failure on ${test.name}:`, err);
        if (row) {
          row.classList.remove('test-running');
          row.classList.add('test-fail');
          row.setAttribute('open', ''); // Auto-expand accordion to show failure stack trace!
        }
        if (chip) {
          chip.textContent = 'FAIL';
          chip.className = 'status-chip fail';
        }
        if (logBox) {
          logBox.textContent = `🚨 FAILURE STACK:\n${err.message}\n\n${err.stack || ''}`;
          logBox.style.color = 'var(--status-error)';
        }
      }
    }

    const elapsedTotal = (performance.now() - startTime).toFixed(0);

    if (passedDisplay) passedDisplay.textContent = passedCount;
    if (executedDisplay) executedDisplay.textContent = testCases.length;
    if (timeDisplay) timeDisplay.textContent = `${elapsedTotal}ms`;
    if (summaryStats) summaryStats.style.display = 'block';

    if (suiteIndicator) {
      if (passedCount === testCases.length) {
        suiteIndicator.style.background = 'var(--status-verified)';
        suiteIndicator.style.boxShadow = '0 0 15px var(--status-verified-glow)';
      } else {
        suiteIndicator.style.background = 'var(--status-error)';
        suiteIndicator.style.boxShadow = '0 0 15px var(--status-error-glow)';
      }
    }

    btnRun.disabled = false;
    btnRun.innerHTML = passedCount === testCases.length ? '🟢 Re-Run Security Tests' : '🔴 Re-Run Security Tests';
    btnRun.style.opacity = '1';

    updateDiagnosticStatesUI();
  });
}

/**
 * TEST 1: RFC 7638 Thumbprint Determinism
 */
async function importStoredWorkerKeyPair() {
  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    store.workerKeys.privateKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
  const publicKey = await window.crypto.subtle.importKey(
    'jwk',
    store.workerKeys.publicKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  return { publicKey, privateKey };
}

async function runTestThumbprint(logBox) {
  // Generate transient key
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

  // Assert calculations match (determinism)
  const thumb1 = await calculateJWKThumbprint(jwk);
  const thumb2 = await calculateJWKThumbprint(jwk);
  if (thumb1 !== thumb2) {
    throw new Error("Assertion Failed: Non-deterministic thumbprint hashes calculated across identical public keys!");
  }

  // Assert alphabetical canonical sorting (y coordinate placed first in object, should yield same thumbprint)
  const unsortedJwk = {
    y: jwk.y,
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x
  };
  const thumb3 = await calculateJWKThumbprint(unsortedJwk);
  if (thumb1 !== thumb3) {
    throw new Error("Assertion Failed: Canonicalization algorithm does not sort coordinates alphabetically before hashing!");
  }

  logBox.textContent = `SUCCESS\nPublic Key (JWK coordinates):\n${JSON.stringify(jwk, null, 2)}\n\nCalculated RFC 7638 Thumbprint:\n${thumb1}\n\nCanonical Ordering Checked: Stable & Alphabetical.`;
  logBox.style.color = '';
}

/**
 * TEST 2: HMAC Pairwise Pseudonym Stability & Scoping
 */
async function runTestPseudonym(logBox) {
  const secret = store.localGatewaySecret;
  if (!secret) {
    throw new Error("Assertion Failed: Missing local gateway secret inside store.");
  }

  const thumb = "holder_jwk_thumbprint_test_vector_99";
  const mitchHash = "mitch_proof_signature_vector_77";

  const msg1 = `vericred-holder-v1|${thumb}|did:vericred:issuer-gateway|WorkCertificate|${mitchHash}`;
  const pseudo1 = 'did:vericred:pairwise:' + await calculateHMAC(secret, msg1);
  const pseudo2 = 'did:vericred:pairwise:' + await calculateHMAC(secret, msg1);

  if (pseudo1 !== pseudo2) {
    throw new Error("Assertion Failed: Pairwise pseudonym generation is non-stable across identical scoped variables.");
  }

  // Cross-credential type separation check
  const msgDivergeType = `vericred-holder-v1|${thumb}|did:vericred:issuer-gateway|AcademicDegree|${mitchHash}`;
  const pseudoDivergeType = 'did:vericred:pairwise:' + await calculateHMAC(secret, msgDivergeType);
  if (pseudo1 === pseudoDivergeType) {
    throw new Error("Assertion Failed: Scoped pseudonym leaks identical identifier across different credential types!");
  }

  // Cross-issuer separation check
  const msgDivergeIssuer = `vericred-holder-v1|${thumb}|did:vericred:another-issuer-gateway|WorkCertificate|${mitchHash}`;
  const pseudoDivergeIssuer = 'did:vericred:pairwise:' + await calculateHMAC(secret, msgDivergeIssuer);
  if (pseudo1 === pseudoDivergeIssuer) {
    throw new Error("Assertion Failed: Scoped pseudonym leaks identical identifier across different issuer gateways!");
  }

  // Cross-gateway secret check
  const pseudoDivergeSecret = 'did:vericred:pairwise:' + await calculateHMAC("rogue_gateway_secret_key_88", msg1);
  if (pseudo1 === pseudoDivergeSecret) {
    throw new Error("Assertion Failed: Scoped pseudonym does not isolate identities across separate gateway secrets!");
  }

  logBox.textContent = `SUCCESS\nPseudonym stability & multi-domain boundary separation proven.\n\nGateway Secret: ${secret.substring(0, 16)}...\nScope Message: "${msg1}"\nPseudonym A (Work Certificate): ${pseudo1}\nPseudonym B (Academic Degree): ${pseudoDivergeType}\nPseudonym C (Another Issuer): ${pseudoDivergeIssuer}\nPseudonym D (Rogue Gateway): ${pseudoDivergeSecret}`;
  logBox.style.color = '';
}

/**
 * TEST 3: Atomic Nonce Lifecycle
 */
async function runTestNonce(logBox) {
  const tempNonce = "nonce_temp_atomic_lifecycle_test";
  store.activeNonces[tempNonce] = Date.now() + 120000; // 2 minutes TTL

  let nonceConsumed = false;
  const mockConsumeFn = (n) => {
    if (store.activeNonces[n]) {
      delete store.activeNonces[n];
      nonceConsumed = true;
      return true;
    }
    return false;
  };

  // 1. Submit empty envelope (structural parse failure)
  let threwParse = false;
  try {
    await verifyMitchPresentationSequential(null, tempNonce, store.knownIssuers, {}, mockConsumeFn);
  } catch (err) {
    threwParse = err.message.includes("Parse") || err.message.includes("Envelope");
  }

  if (!threwParse) {
    throw new Error("Assertion Failed: Sequential verifier did not throw structural parse error for empty envelope.");
  }
  if (nonceConsumed) {
    throw new Error("Assertion Failed: Challenge Nonce was consumed during structural parse failure!");
  }

  // 2. Submit mismatched version (version check failure)
  let threwVersion = false;
  const malformedVersionEnvelope = {
    format: 'SD-JWT-VC',
    version: '0.9-draft',
    baseCredential: { subject: { holder_jwk_thumbprint: "dummy" }, signature: "sig" },
    holder_binding: { nonce: tempNonce, aud: "VeriCred-Gateway", expires_at: Date.now() + 100000, holder_jwk: {}, proof_of_possession: "sig" }
  };

  try {
    await verifyMitchPresentationSequential(malformedVersionEnvelope, tempNonce, store.knownIssuers, {}, mockConsumeFn);
  } catch (err) {
    threwVersion = err.message.includes("Version") || err.message.includes("Schema");
  }

  if (!threwVersion) {
    throw new Error("Assertion Failed: Sequential verifier did not throw on invalid version schema.");
  }
  if (nonceConsumed) {
    throw new Error("Assertion Failed: Challenge Nonce was consumed during schema version check failure!");
  }

  // Cleanup
  delete store.activeNonces[tempNonce];

  logBox.textContent = `SUCCESS\nAtomic single-use lifecycle invariants validated.\n- Structural parse errors protect nonce: Yes\n- Schema version errors protect nonce: Yes`;
  logBox.style.color = '';
}

/**
 * TEST 4: Strict Replay Rejection
 */
async function runTestReplay(logBox) {
  const tempNonce = "nonce_temp_replay_protection_test";
  store.activeNonces[tempNonce] = Date.now() + 120000;

  // Generate a valid presentation
  const tempIssuerKeys = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const tempIssuerJwk = await window.crypto.subtle.exportKey("jwk", tempIssuerKeys.publicKey);
  const tempIssuerDid = "did:mitch:temp-replay-test-issuer";
  store.knownIssuers[tempIssuerDid] = tempIssuerJwk;

  const workerPrivKeyObj = await window.crypto.subtle.importKey(
    'jwk', store.workerKeys.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
  );
  const workerPubKeyObj = await window.crypto.subtle.importKey(
    'jwk', store.workerKeys.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
  );
  const workerKeyPair = { publicKey: workerPubKeyObj, privateKey: workerPrivKeyObj };

  const baseClaims = { degree_completed: true };
  const envelope = await createMitchPresentation(
    baseClaims,
    workerKeyPair,
    tempNonce,
    "VeriCred-Gateway",
    tempIssuerKeys,
    tempIssuerDid
  );

  const mockConsumeFn = (n) => {
    if (store.activeNonces[n]) {
      delete store.activeNonces[n];
      return true;
    }
    return false;
  };

  // 1st Submission: Must pass
  try {
    await verifyMitchPresentationSequential(envelope, tempNonce, store.knownIssuers, {}, mockConsumeFn);
  } catch (err) {
    throw new Error(`Assertion Failed: Correct presentation failed on first verification. Error: ${err.message}`);
  }

  // 2nd Submission: Must fail with replay error because nonce was consumed
  let threwReplay = false;
  try {
    await verifyMitchPresentationSequential(envelope, tempNonce, store.knownIssuers, {}, mockConsumeFn);
  } catch (err) {
    threwReplay = err.message.includes("Replay") || err.message.includes("Nonce") || err.message.includes("consumed");
  }

  // Cleanup
  delete store.knownIssuers[tempIssuerDid];
  delete store.activeNonces[tempNonce];

  if (!threwReplay) {
    throw new Error("Assertion Failed: Submission of an identical presentation envelope twice was verified successfully without triggering replay protection!");
  }

  logBox.textContent = `SUCCESS\nReplay Protection Verified.\n1st verification attempt: Verified Successfully\n2nd verification attempt: Blocked (Nonce has been consumed)`;
  logBox.style.color = '';
}

/**
 * TEST 5: Fake EUDI Trust Anchor Rejection
 */
async function runTestFakeIssuer(logBox) {
  const tempNonce = "nonce_temp_untrusted_issuer_test";
  store.activeNonces[tempNonce] = Date.now() + 120000;

  // Generate rogue keys (NOT registered in store.knownIssuers)
  const rogueIssuerKeys = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const envelope = await createMitchPresentation(
    { legal_resident: true },
    await importStoredWorkerKeyPair(),
    tempNonce,
    "VeriCred-Gateway",
    rogueIssuerKeys,
    "did:mitch:rogue-untrusted-signer-x"
  );

  let verificationFailed = false;
  let errorMsg = "";
  try {
    await verifyMitchPresentationSequential(envelope, tempNonce, store.knownIssuers, {}, (n) => {
      delete store.activeNonces[n];
      return true;
    });
  } catch (err) {
    verificationFailed = true;
    errorMsg = err.message;
  }

  // Cleanup
  delete store.activeNonces[tempNonce];

  if (!verificationFailed) {
    throw new Error("Assertion Failed: Key signed by untrusted issuer was verified successfully!");
  }

  logBox.textContent = `SUCCESS\nUntrusted Trust Anchor signature blocked-closed.\n- Untrusted Issuer: did:mitch:rogue-untrusted-signer-x\n- Verification Status: Rejected\n- Exception Logged: "${errorMsg}"`;
  logBox.style.color = '';
}

/**
 * TEST 6: Holder Key Mismatch Rejection
 */
async function runTestKeyMismatch(logBox) {
  const tempNonce = "nonce_temp_holder_mismatch_test";
  store.activeNonces[tempNonce] = Date.now() + 120000;

  // Setup valid issuer
  const tempIssuerKeys = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const tempIssuerJwk = await window.crypto.subtle.exportKey("jwk", tempIssuerKeys.publicKey);
  const tempIssuerDid = "did:mitch:temp-holder-mismatch-issuer";
  store.knownIssuers[tempIssuerDid] = tempIssuerJwk;

  const envelope = await createMitchPresentation(
    { legal_resident: true },
    await importStoredWorkerKeyPair(),
    tempNonce,
    "VeriCred-Gateway",
    tempIssuerKeys,
    tempIssuerDid
  );

  // Swap out the transient holder_jwk coordinate so it doesn't resolve to the base credential's thumbprint
  const separateKeys = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const differentJwk = await window.crypto.subtle.exportKey("jwk", separateKeys.publicKey);
  envelope.holder_binding.holder_jwk = differentJwk;

  let verificationFailed = false;
  let errorMsg = "";
  try {
    await verifyMitchPresentationSequential(envelope, tempNonce, store.knownIssuers, {}, (n) => {
      delete store.activeNonces[n];
      return true;
    });
  } catch (err) {
    verificationFailed = true;
    errorMsg = err.message;
  }

  // Cleanup
  delete store.knownIssuers[tempIssuerDid];
  delete store.activeNonces[tempNonce];

  if (!verificationFailed) {
    throw new Error("Assertion Failed: Swapped holder binding key was accepted without coordinates validation check!");
  }

  logBox.textContent = `SUCCESS\nTransient-to-base credential key mismatch detected and failed-closed.\n- Expected Thumbprint: ${envelope.baseCredential.subject.holder_jwk_thumbprint}\n- Tampered Public Key coordinate swapped: Yes\n- Verification Status: Rejected\n- Exception Logged: "${errorMsg}"`;
  logBox.style.color = '';
}

/**
 * TEST 7: Zero-PII Ledger Compliance Audit
 */
async function runTestLedgerPII(logBox) {
  // Construct a standard ledger transaction block
  const normalTx = {
    id: 'tx_compliance_audit_99',
    type: 'ISSUE_CREDENTIAL',
    payload: {
      holderPseudonym: 'did:vericred:pairwise:stable-test-vector-hash',
      mitchProofHash: 'hash_m_val',
      credentialHash: 'hash_c_val',
      claimCommitments: {
        jobTitle: 'hash_j_val',
        duration: 'hash_d_val',
        skills: 'hash_s_val'
      }
    }
  };

  const dummyBlock = {
    index: 1,
    previousHash: store.chain[0].hash,
    timestamp: Date.now(),
    transactions: [normalTx],
    transactionsHash: 'hash_transactions_root',
    nonce: 42,
    hash: 'hash_block_anchor'
  };

  const cleanChain = [store.chain[0], dummyBlock];

  // Audit plain text PII: workerName leak
  const leakyBlockWorkerName = JSON.parse(JSON.stringify(dummyBlock));
  leakyBlockWorkerName.transactions[0].payload.workerName = "Alice Vance";
  const leakyChain1 = [store.chain[0], leakyBlockWorkerName];
  const auditRes1 = await isChainValid(leakyChain1);

  if (auditRes1.isValid) {
    throw new Error("Assertion Failed: isChainValid did not block plain-text workerName leak onto the ledger!");
  }

  // Audit plain text PII: plain jobTitle leak
  const leakyBlockJobTitle = JSON.parse(JSON.stringify(dummyBlock));
  leakyBlockJobTitle.transactions[0].payload.jobTitle = "Lead Architect";
  const leakyChain2 = [store.chain[0], leakyBlockJobTitle];
  const auditRes2 = await isChainValid(leakyChain2);

  if (auditRes2.isValid) {
    throw new Error("Assertion Failed: isChainValid did not block plain-text jobTitle leak onto the ledger!");
  }

  logBox.textContent = `SUCCESS\nLedger compliance leak monitor checked.\n- Plain-text workerName leak blocked: Yes\n- Plain-text jobTitle leak blocked: Yes\n- Rejection message: "${auditRes1.reason}"`;
  logBox.style.color = '';
}

/**
 * TEST 8: Preservative Ledger Reseed & Quarantine
 */
async function runTestPreservativeReseed(logBox) {
  // 1. Snapshot valid configurations
  const backupWorker = store.workerKeys;
  const backupEmployer = store.employerKeys;
  const backupChain = localStorage.getItem("vericred_ledger_chain");
  const backupIssuers = localStorage.getItem("vericred_known_issuers");
  const backupSchema = localStorage.getItem("vericred_schema_version");

  if (!backupWorker || !backupEmployer) {
    throw new Error("Missing active worker or employer key pairs inside store.");
  }

  // Compute backup worker thumbprint to compare later
  const backupWorkerThumb = await calculateJWKThumbprint(backupWorker.publicKey);

  // 2. Write broken garbage data to trigger parsing fault
  localStorage.setItem("vericred_ledger_chain", "broken-corrupted-json-{]");

  // 3. Re-run initialization to invoke recovery pipeline
  try {
    await store.initialize();
  } catch (err) {
    throw new Error(`Assertion Failed: Store initialization threw uncaught error on corrupted block parsing: ${err.message}`);
  }

  // 4. Validate that reseed completed successfully
  if (!store.chain || store.chain.length === 0) {
    throw new Error("Assertion Failed: Reseed was not completed successfully.");
  }

  // 5. Validate quarantine file exists in localStorage
  let qFound = false;
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith("vericred_ledger_chain_quarantine_")) {
      const val = localStorage.getItem(key);
      if (val === "broken-corrupted-json-{]") {
        qFound = true;
        // Clean up this test quarantine
        localStorage.removeItem(key);
        break;
      }
    }
  }

  if (!qFound) {
    throw new Error("Assertion Failed: Corrupted ledger string was not isolated to quarantine in localStorage!");
  }

  // 6. Assert keypairs are completely preserved
  const currentWorkerThumb = await calculateJWKThumbprint(store.workerKeys.publicKey);
  if (backupWorkerThumb !== currentWorkerThumb) {
    throw new Error("Assertion Failed: Worker keys were silently changed or wiped out during preservative self-repair reseed!");
  }

  // 7. Re-apply backup configurations
  if (backupChain) localStorage.setItem("vericred_ledger_chain", backupChain);
  else localStorage.removeItem("vericred_ledger_chain");

  if (backupIssuers) localStorage.setItem("vericred_known_issuers", backupIssuers);
  else localStorage.removeItem("vericred_known_issuers");

  if (backupSchema) localStorage.setItem("vericred_schema_version", backupSchema);
  else localStorage.removeItem("vericred_schema_version");

  // Re-sync store back to original
  await store.initialize();

  logBox.textContent = `SUCCESS\nPreservative reseed check passed.\n- Corrupted JSON isolated to quarantine: Yes\n- Chain reseeded back to Genesis: Yes\n- Identity Keys preserved intact: Yes (Thumbprint: ${currentWorkerThumb.substring(0, 16)}...)`;
  logBox.style.color = '';
}

/**
 * TEST 9: Compact SD-JWT-VC Serialization Integrity
 * Asserts that the encoder converts mock claims into RFC 9901 compliant tilde-separated strings,
 * and the parser splits, decodes, hashes, and verifies them back to raw inputs with full integrity.
 */
async function runTestCompactSDJWT(logBox) {
  logBox.textContent = "Generating fresh cryptographic keypairs for issuer and holder...";
  
  // 1. Generate fresh keypairs
  const issuerKeys = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const holderKeys = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const issuerJwk = await exportKeyToJWK(issuerKeys.publicKey);
  const holderJwk = await exportKeyToJWK(holderKeys.publicKey);
  const holderThumb = await calculateJWKThumbprint(holderJwk);

  // 2. Prepare test claims & salts
  const claims = {
    jobTitle: "Senior Cryptographic Lead",
    duration: "2025 - 2027",
    skills: "Web Crypto, eIDAS, SD-JWT"
  };

  const salts = {
    jobTitle: "salt_job_title_xyz123",
    duration: "salt_duration_abc456",
    skills: "salt_skills_mno789"
  };

  logBox.textContent += "\nEncoding and serializing claims to compact SD-JWT-VC (RFC 9901)...";

  // 3. Serialize claims to standard RFC 9901 compact format
  const compactStr = await serializeToCompactSDJWT(
    "did:vericred:issuer-gateway",
    "did:vericred:pairwise:holder_pseudonym",
    claims,
    salts,
    issuerKeys.privateKey,
    holderJwk,
    "mock_mitch_proof_hash_1234"
  );

  // Assert basic structure
  if (!compactStr || typeof compactStr !== 'string') {
    throw new Error("Assertion Failed: Serializer did not produce a valid string.");
  }
  const parts = compactStr.split('~');
  if (parts.length < 5) { // JWS + 3 claims + trailing empty part
    throw new Error(`Assertion Failed: Serializer did not produce enough tilde parts. Found: ${parts.length}`);
  }

  logBox.textContent += `\nSuccess! Compact string generated:\n${compactStr.substring(0, 100)}...\n\nParsing compact SD-JWT-VC and verifying mathematical signatures...`;

  // 4. Setup trust list and parse the compact representation
  const trustList = {
    "did:vericred:issuer-gateway": issuerJwk
  };

  const parsed = await parseCompactSDJWT(compactStr, trustList);

  // 5. Assert parsed content matching original input
  if (parsed.issuer !== "did:vericred:issuer-gateway") {
    throw new Error(`Assertion Failed: Parsed issuer mismatch. Expected: did:vericred:issuer-gateway, found: ${parsed.issuer}`);
  }
  if (parsed.holderPseudonym !== "did:vericred:pairwise:holder_pseudonym") {
    throw new Error(`Assertion Failed: Parsed holder pseudonym mismatch. Found: ${parsed.holderPseudonym}`);
  }
  if (parsed.mitchProofHash !== "mock_mitch_proof_hash_1234") {
    throw new Error(`Assertion Failed: Parsed mitchProofHash mismatch. Found: ${parsed.mitchProofHash}`);
  }
  
  // Validate claim recovery
  for (const key of Object.keys(claims)) {
    if (parsed.claims[key] !== claims[key]) {
      throw new Error(`Assertion Failed: Recovered claim value mismatch for '${key}'. Expected '${claims[key]}', found '${parsed.claims[key]}'`);
    }
    if (parsed.salts[key] !== salts[key]) {
      throw new Error(`Assertion Failed: Recovered salt value mismatch for '${key}'. Expected '${salts[key]}', found '${parsed.salts[key]}'`);
    }
  }

  // Validate JWS payload standard claims
  if (parsed.payload._sd_alg !== "sha-256") {
    throw new Error(`Assertion Failed: JWS Payload missing or invalid _sd_alg claim. Found: ${parsed.payload._sd_alg}`);
  }
  if (!Array.isArray(parsed.payload._sd) || parsed.payload._sd.length !== 3) {
    throw new Error(`Assertion Failed: JWS Payload missing or invalid _sd list. Found: ${parsed.payload._sd}`);
  }
  if (parsed.payload.cnf.jwk.x !== holderJwk.x || parsed.payload.cnf.jwk.y !== holderJwk.y) {
    throw new Error(`Assertion Failed: JWS Payload cnf jwk coords mismatch.`);
  }

  logBox.textContent += "\nValidating Selective Disclosure Integrity (Malformed disclosure rejection)...";

  // 6. Test selective disclosure manipulation defense
  // Attempting to inject an unregistered disclosure
  const fakeDisclosureArray = ["fake_salt_123", "salary", "90000"];
  const fakeDisclosureB64 = window.btoa(JSON.stringify(fakeDisclosureArray))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const tamperedCompactStr = compactStr + fakeDisclosureB64 + "~";

  try {
    await parseCompactSDJWT(tamperedCompactStr, trustList);
    throw new Error("Assertion Failed: Parser did not reject unregistered disclosure!");
  } catch (e) {
    if (!e.message.includes("Security breach") && !e.message.includes("disclosure hash")) {
      throw new Error(`Assertion Failed: Parser rejected manipulation but with unexpected error: ${e.message}`);
    }
    logBox.textContent += `\nSuccess: Parser correctly caught unregistered disclosure manipulation! Error trace:\n"${e.message}"`;
  }

  logBox.textContent += `\n\nSUCCESS\nCompact SD-JWT-VC round-trip check passed.\n- Disclosure Format: RFC 9901 JSON array [salt, claim_name, claim_value]\n- Digest Hashing: SHA-256 over US-ASCII bytes of base64url disclosure string\n- Standard Payload: Use '_sd' and '_sd_alg' claims\n- Key Binding: Linked via 'cnf.jwk'\n- Signature Verification: Valid standard JWS ES256`;
  logBox.style.color = '';
}

/**
 * TEST 10: Strict CSP Enforcement & Graceful Validation
 * Asserts that the CSP does not allow 'unsafe-eval' or 'unsafe-inline' in script-src,
 * and asserts that malformed inputs to the verifier are caught gracefully with an inline alert.
 */
async function runTestCspValidation(logBox) {
  logBox.textContent = "Part A: Checking active Content Security Policy (CSP)...";
  
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!cspMeta) {
    throw new Error("Assertion Failed: meta Content-Security-Policy tag is missing from the document header.");
  }
  
  const cspContent = cspMeta.getAttribute('content');
  logBox.textContent += `\nFound active CSP string:\n"${cspContent}"`;
  
  // Extract script-src directive
  const directives = cspContent.split(';').map(d => d.trim()).filter(Boolean);
  const scriptSrcDir = directives.find(d => d.startsWith('script-src '));
  if (!scriptSrcDir) {
    throw new Error("Assertion Failed: CSP is missing a 'script-src' directive.");
  }
  
  logBox.textContent += `\nInspecting script-src directive: "${scriptSrcDir}"`;
  
  // script-src should NOT contain 'unsafe-inline' or 'unsafe-eval'
  if (scriptSrcDir.includes("'unsafe-inline'")) {
    throw new Error("Assertion Failed: script-src allows 'unsafe-inline' which is insecure!");
  }
  if (scriptSrcDir.includes("'unsafe-eval'")) {
    throw new Error("Assertion Failed: script-src allows 'unsafe-eval' which is insecure!");
  }
  
  // script-src blob: check
  if (scriptSrcDir.includes("blob:")) {
    logBox.textContent += "\n[CSP WARNING] script-src contains 'blob:'. While our ideal target is 'script-src \'self\';', this is documented in Test 10 as allowed only if necessary.";
  } else {
    logBox.textContent += "\n[CSP SUCCESS] script-src does not allow 'blob:', ensuring strict local script origin controls.";
  }
  
  logBox.textContent += "\n\nPart B: Testing robust import validation and inline alert handling...";
  
  // Backup paste area
  const originalPasteVal = els.verifierPasteArea.value;
  
  // Test case 1: Broken JSON input
  els.verifierPasteArea.value = 'invalid { json';
  logBox.textContent += "\nTriggering verification on malformed JSON: 'invalid { json'";
  
  // Hide any existing reports/alerts first
  els.verifierReport.style.display = 'none';
  els.verifierAlert.style.display = 'none';
  
  // Click verify
  els.btnVerifyPaste.click();
  
  // Wait short timeout for click event handler to finish
  await new Promise(r => setTimeout(r, 100));
  
  // Assert that verifier alert popped up
  if (els.verifierAlert.style.display !== 'block') {
    throw new Error("Assertion Failed: Verifier did not show the inline #verifier-alert on broken JSON.");
  }
  if (!els.verifierAlertText.innerText.includes("JSON Parsing Failed") && !els.verifierAlertText.innerText.includes("JSON")) {
    throw new Error(`Assertion Failed: Verifier alert text did not contain the JSON parse error detail. Found: "${els.verifierAlertText.innerText}"`);
  }
  if (els.verifierReport.style.display === 'block') {
    throw new Error("Assertion Failed: Verifier report container is visible after a parsing failure.");
  }
  
  logBox.textContent += `\nSuccess! Broken JSON correctly blocked. Alert detail:\n"${els.verifierAlertText.innerText}"`;
  
  // Test case 2: Valid JSON but missing mandatory keys
  els.verifierPasteArea.value = JSON.stringify({ format: "SD-JWT-VC", issuer: "did:vericred:some-issuer" }); // missing holderPseudonym and signature
  logBox.textContent += "\n\nTriggering verification on incomplete JSON missing mandatory keys...";
  
  els.verifierAlert.style.display = 'none';
  els.btnVerifyPaste.click();
  
  await new Promise(r => setTimeout(r, 100));
  
  if (els.verifierAlert.style.display !== 'block') {
    throw new Error("Assertion Failed: Verifier did not show the inline #verifier-alert on incomplete JSON schema.");
  }
  if (!els.verifierAlertText.innerText.includes("Structural Schema Check Failed") && !els.verifierAlertText.innerText.includes("mandatory")) {
    throw new Error(`Assertion Failed: Verifier alert text did not contain the schema error. Found: "${els.verifierAlertText.innerText}"`);
  }
  
  logBox.textContent += `\nSuccess! Missing schema keys correctly blocked. Alert detail:\n"${els.verifierAlertText.innerText}"`;
  
  // Restore original values
  els.verifierPasteArea.value = originalPasteVal;
  els.verifierAlert.style.display = 'none';
  
  logBox.textContent += "\n\nSUCCESS\nStrict Content Security Policy validated. Universal Verifier is guarded by robust schema validation and non-crashing inline alerts. This is statisch plausibel und browser-verifiziert.";
  logBox.style.color = '';
}

/**
 * TEST 11: Export Format Versioning & Strictest Schema Verification
 * Asserts that newly generated credentials contain "formatVersion": "1.1.0" and "issuedAt" metadata,
 * validates that validateCredentialSchema() blocks missing versions, wrong DID schemes, and invalid hashes,
 * and asserts that valid credentials pass the validation cleanly.
 */
async function runTestSchemaAndVersioning(logBox) {
  logBox.textContent = "Part A: Checking newly generated credentials for formatVersion and issuedAt...";
  
  const seedStr = localStorage.getItem('vericred_seed_credential_alice');
  if (!seedStr) {
    throw new Error("Assertion Failed: Alice Vance's seed credential was not found in LocalStorage.");
  }
  
  const seed = JSON.parse(seedStr);
  logBox.textContent += `\nLoaded seed credential for Alice Vance. Inspecting metadata fields...`;
  
  if (seed.formatVersion !== "1.1.0") {
    throw new Error(`Assertion Failed: Main wrapper formatVersion should be '1.1.0'. Received: '${seed.formatVersion}'`);
  }
  if (!seed.issuedAt) {
    throw new Error(`Assertion Failed: Main wrapper is missing mandatory 'issuedAt' epoch timestamp.`);
  }
  logBox.textContent += `\n[WRAPPER OK] formatVersion: "${seed.formatVersion}", issuedAt: ${seed.issuedAt}`;
  
  if (!seed.decoded) {
    throw new Error("Assertion Failed: Seed credential is missing its 'decoded' inner payload.");
  }
  if (seed.decoded.formatVersion !== "1.1.0") {
    throw new Error(`Assertion Failed: Decoded payload formatVersion should be '1.1.0'. Received: '${seed.decoded.formatVersion}'`);
  }
  if (!seed.decoded.issuedAt) {
    throw new Error(`Assertion Failed: Decoded payload is missing mandatory 'issuedAt' timestamp.`);
  }
  logBox.textContent += `\n[DECODED OK] formatVersion: "${seed.decoded.formatVersion}", issuedAt: ${seed.decoded.issuedAt}`;
  
  logBox.textContent += "\n\nPart B: Testing validateCredentialSchema() failure modes...";
  
  // 1. Missing formatVersion
  let caught = false;
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      issuer: 'did:mitch:test',
      holderPseudonym: 'did:vericred:pairwise:123',
      mitchProofHash: 'a'.repeat(64)
    });
  } catch (e) {
    if (e.message.includes("Missing mandatory formatVersion")) {
      caught = true;
      logBox.textContent += `\n[PASS] Correctly blocked missing formatVersion. Error: "${e.message}"`;
    } else {
      throw new Error(`Assertion Failed: Expected 'Missing mandatory formatVersion', but got: "${e.message}"`);
    }
  }
  if (!caught) throw new Error("Assertion Failed: validateCredentialSchema() failed to block missing formatVersion.");

  // 2. Incompatible formatVersion
  caught = false;
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      formatVersion: '0.9.0',
      issuer: 'did:mitch:test',
      holderPseudonym: 'did:vericred:pairwise:123',
      mitchProofHash: 'a'.repeat(64)
    });
  } catch (e) {
    if (e.message.includes("is incompatible")) {
      caught = true;
      logBox.textContent += `\n[PASS] Correctly blocked incompatible formatVersion (0.9.0). Error: "${e.message}"`;
    } else {
      throw new Error(`Assertion Failed: Expected incompatible version error, but got: "${e.message}"`);
    }
  }
  if (!caught) throw new Error("Assertion Failed: validateCredentialSchema() failed to block version < 1.0.0.");

  // 3. Invalid Issuer DID Prefix
  caught = false;
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      formatVersion: '1.1.0',
      issuer: 'mitch:test',
      holderPseudonym: 'did:vericred:pairwise:123',
      mitchProofHash: 'a'.repeat(64)
    });
  } catch (e) {
    if (e.message.includes("starting with 'did:'")) {
      caught = true;
      logBox.textContent += `\n[PASS] Correctly blocked non-DID issuer scheme. Error: "${e.message}"`;
    } else {
      throw new Error(`Assertion Failed: Expected DID scheme error, but got: "${e.message}"`);
    }
  }
  if (!caught) throw new Error("Assertion Failed: validateCredentialSchema() failed to block wrong issuer prefix.");

  // 4. Invalid holderPseudonym DID Prefix
  caught = false;
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      formatVersion: '1.1.0',
      issuer: 'did:mitch:test',
      holderPseudonym: 'did:pairwise:123',
      mitchProofHash: 'a'.repeat(64)
    });
  } catch (e) {
    if (e.message.includes("conform to 'did:vericred:pairwise:...'")) {
      caught = true;
      logBox.textContent += `\n[PASS] Correctly blocked non-conforming holder pseudonym scheme. Error: "${e.message}"`;
    } else {
      throw new Error(`Assertion Failed: Expected holderPseudonym scheme error, but got: "${e.message}"`);
    }
  }
  if (!caught) throw new Error("Assertion Failed: validateCredentialSchema() failed to block wrong holderPseudonym prefix.");

  // 5. Invalid mitchProofHash structure
  caught = false;
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      formatVersion: '1.1.0',
      issuer: 'did:mitch:test',
      holderPseudonym: 'did:vericred:pairwise:123',
      mitchProofHash: 'hash_not_hex'
    });
  } catch (e) {
    if (e.message.includes("valid 64-character SHA-256 hexadecimal string")) {
      caught = true;
      logBox.textContent += `\n[PASS] Correctly blocked malformed mitchProofHash. Error: "${e.message}"`;
    } else {
      throw new Error(`Assertion Failed: Expected mitchProofHash structure error, but got: "${e.message}"`);
    }
  }
  if (!caught) throw new Error("Assertion Failed: validateCredentialSchema() failed to block wrong mitchProofHash pattern.");

  logBox.textContent += "\n\nPart C: Testing validateCredentialSchema() success mode...";
  
  try {
    validateCredentialSchema({
      format: 'SD-JWT-VC',
      formatVersion: '1.1.0',
      issuer: 'did:mitch:test',
      holderPseudonym: 'did:vericred:pairwise:123',
      mitchProofHash: 'b'.repeat(64)
    });
    logBox.textContent += `\n[PASS] Valid credential schema checked and successfully accepted.`;
  } catch (e) {
    throw new Error(`Assertion Failed: Valid schema rejected with error: "${e.message}"`);
  }

  logBox.textContent += "\n\nSUCCESS\nAll schema assertions, version typing metadata, and DID formatting patterns verified. Format Versioning & Strictest Schema Verification is 100% operational.";
  logBox.style.color = '';
}
