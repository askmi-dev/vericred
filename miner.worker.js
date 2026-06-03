/**
 * VeriCred Proof of Work Miner (Web Worker)
 * 
 * Runs a background hashing loop using the Web Crypto API to solve the Proof of Work
 * puzzle for blocks, keeping the main UI thread at 60 FPS.
 */

// Helper to convert an ArrayBuffer to a hex string
function bufToHex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

self.onmessage = async function(e) {
  try {
    const { index, previousHash, transactionsHash, timestamp, difficulty } = e.data;
    
    // Difficulty represents the number of required leading zeroes in the hash hex representation
    const targetPrefix = '0'.repeat(difficulty);
    const encoder = new TextEncoder();
    
    // Base block header payload to stringify and hash alongside the nonce
    const baseHeader = `${index}${previousHash}${transactionsHash}${timestamp}`;
    
    let nonce = 0;
    const startTime = performance.now();
    let lastReportTime = startTime;
    let hashesCount = 0;
    
    while (true) {
      const dataString = baseHeader + nonce;
      const dataBuffer = encoder.encode(dataString);
      
      // Compute SHA-256 hash using native cryptographic engine
      const hashBuffer = await self.crypto.subtle.digest('SHA-256', dataBuffer);
      const hashHex = bufToHex(hashBuffer);
      
      hashesCount++;
      
      // Check if hash matches the target difficulty
      if (hashHex.substring(0, difficulty) === targetPrefix) {
        const elapsedMs = performance.now() - startTime;
        self.postMessage({
          type: 'success',
          data: {
            nonce,
            hash: hashHex,
            elapsedMs: Math.round(elapsedMs)
          }
        });
        break;
      }
      
      // Periodically send hash-rate and mining progress updates to the UI (e.g., every 1000 hashes and at least 250ms elapsed)
      if (nonce % 1000 === 0) {
        const now = performance.now();
        const intervalMs = now - lastReportTime;
        
        if (intervalMs >= 250) {
          const hashRate = Math.round((hashesCount / intervalMs) * 1000);
          self.postMessage({
            type: 'progress',
            data: {
              nonce,
              hash: hashHex,
              hashRate,
              elapsedMs: Math.round(now - startTime)
            }
          });
          hashesCount = 0;
          lastReportTime = now;
        }
      }
      
      nonce++;
    }
  } catch (error) {
    self.postMessage({
      type: 'error',
      data: {
        message: error.message || 'Unknown mining error'
      }
    });
  }
};
