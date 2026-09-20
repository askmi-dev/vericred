import { backupData, restoreData } from '../dist/storage/recovery.js';
const [operation, source, destination, confirmation, ...extra] = process.argv.slice(2);
const usage = 'Usage: node scripts/backup-restore.mjs backup|restore <source-directory> <new-destination-directory> --offline';
if (!['backup', 'restore'].includes(operation) || !source || !destination || confirmation !== '--offline' || extra.length) {
  console.error(usage); process.exitCode = 1;
} else {
  try {
    if (!process.env.PSEUDO_SECRET) throw new Error('PSEUDO_SECRET must be supplied through the environment, never a command-line argument');
    const result = await (operation === 'backup' ? backupData : restoreData)(source, destination, process.env.PSEUDO_SECRET);
    console.log(JSON.stringify({ operation, result }, null, 2));
    if (operation === 'restore') console.log('Recovered offline. All pre-recovery lists are revoked and sessions/grants invalidated. Reissue credentials before resuming service.');
  } catch (error) {
    console.error('Offline recovery failed: ' + (error instanceof Error ? error.message : 'unknown error')); process.exitCode = 1;
  }
}