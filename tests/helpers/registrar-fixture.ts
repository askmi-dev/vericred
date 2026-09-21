export function registrarFixture(role: 'issuer' | 'verifier') {
  const common = {
    identifier: [{ type: 'https://registrar.example.invalid/identifier-type', identifier: 'SYNTHETIC-' + role }],
    srvDescription: [{ lang: 'en', content: 'Synthetic ' + role + ' service' }],
    registryURI: 'https://registrar.example.invalid/api',
  };
  return role === 'issuer' ? { ...common, providesAttestations: [{ format: 'dc+sd-jwt', type: 'urn:vericred:credential:AgeCredential:1' }] }
    : { ...common, intendedUseIdentifier: 'synthetic-age-check', purpose: [{ lang: 'en', content: 'Synthetic age check' }], policyURI: 'https://registrar.example.invalid/privacy',
        credential: [{ format: 'dc+sd-jwt', meta: { vct_values: ['urn:vericred:credential:AgeCredential:1'] }, claim: [{ path: ['age_over_18'] }] }] };
}
