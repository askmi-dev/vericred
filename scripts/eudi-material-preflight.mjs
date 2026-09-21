import { inspectEudiMaterials } from '../dist/wallet/provisioning.js';
if (process.argv.length !== 3 || process.argv[2] !== '--offline') {
  console.error('Usage: node scripts/eudi-material-preflight.mjs --offline (supply deployment settings through the environment)');
  process.exitCode = 2;
} else {
  try {
    const report = await inspectEudiMaterials();
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.status === 'PASS' ? 0 : 1;
  } catch {
    console.error('EUDI material preflight could not complete. Check the local build and provisioning settings.');
    process.exitCode = 1;
  }
}
