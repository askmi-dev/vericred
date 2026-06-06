@echo off
cd /d D:\Mensch\VeriCred
del .git\index.lock 2>nul
git add src/connectors/generator.ts src/config/types.ts src/oid4vci/metadata.ts src/oid4vci/issuer.ts src/credentials/ src/sdjwt/ src/oid4vci/__tests__/
git commit -m "test: full OID4VCI wallet simulation — all 17 checks pass

atomicWrite fix (src/connectors/generator.ts):
- Use dirname(filePath) for temp file, not os.tmpdir()
- Prevents EXDEV cross-device rename error when target is on different filesystem
- Remove os.tmpdir import

Wallet simulation result (scripts/wallet_sim.mjs):
Metadata: AgeCredential in credential_configurations_supported   PASS
Metadata: proof_types_supported.jwt present                      PASS
Metadata: format identifier = dc+sd-jwt                          PASS
Offer: POST /offer                                               PASS
Token: POST /token, c_nonce present                              PASS
Proof: holder proof JWT built with thumbprint                    PASS
Credential: POST /credentials                                    PASS
Credential: Combined Format jwt~d1~d2~d3~d4~                    PASS
JWT payload: vct, iss, cnf.jkt, _sd_alg, _sd, credentialStatus  PASS
JWT payload: NO raw claim values                                  PASS
Disclosures: all 4 decode to [salt, name, value]                 PASS
Disclosures: all digests in _sd array                            PASS
Partial disclosure: age_over_18 without age_over_21              PASS
c_nonce rotated in response                                       PASS

81/81 unit tests still green"
git push
pause
