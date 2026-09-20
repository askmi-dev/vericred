import assert from 'node:assert/strict';
import { execFile, fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';

// No caller-supplied database URL is accepted. Only this run's temporary databases are used.
const exec = promisify(execFile);
const label = 'com.vericred.connector-acceptance';
const database = 'vericred_acceptance';
const user = 'vericred';
const timezone = 'Pacific/Kiritimati';
const fixture = [
  { id: 'internal-001', email: 'boundary@example.invalid', date_of_birth: '2008-01-01' },
  { id: 'internal-002', email: 'leap@example.invalid', date_of_birth: '2000-02-29' },
];
const engines = {
  postgres: { image: 'postgres:16-alpine', port: 5432, tmpfs: '/var/lib/postgresql/data:rw,nosuid,nodev,size=256m' },
  mysql: { image: 'mysql:8.4', port: 3306, tmpfs: '/var/lib/mysql:rw,nosuid,nodev,size=1g' },
};
async function docker(args, environment = {}, timeout = 60_000) {
  return (await exec('docker', args, {
    timeout, maxBuffer: 1024 * 1024, windowsHide: true, env: { ...process.env, ...environment },
  })).stdout.trim();
}
function redact(message, secrets = []) {
  let result = String(message);
  for (const secret of secrets) if (secret) result = result.replaceAll(secret, '[redacted]');
  return result.replace(/(?:postgres(?:ql)?|mysql):\/\/\S+/gi, '[redacted database URL]').slice(0, 4000);
}
async function assertOwner(name, runId) {
  const owner = await docker(['inspect', '--format', '{{ index .Config.Labels "' + label + '" }}', name]);
  assert.equal(owner, runId, 'Refusing to operate on a container owned by another run');
}
async function connectAndSeed(config) {
  const deadline = Date.now() + (config.engine === 'mysql' ? 180_000 : 90_000);
  let lastCode = 'not_ready';
  while (Date.now() < deadline) {
    let connection;
    try {
      if (config.engine === 'postgres') {
        const { default: pg } = await import('pg');
        connection = new pg.Client({ connectionString: config.connectionString, connectionTimeoutMillis: 3000, query_timeout: 5000 });
        await connection.connect();
        await connection.query('CREATE TABLE acceptance_holders (id VARCHAR(40) PRIMARY KEY, email VARCHAR(120) UNIQUE NOT NULL, date_of_birth DATE NOT NULL)');
        for (const row of fixture) await connection.query(
          'INSERT INTO acceptance_holders (id, email, date_of_birth) VALUES ($1, $2, $3)',
          [row.id, row.email, row.date_of_birth],
        );
      } else {
        const mysql = await import('mysql2/promise');
        connection = await mysql.createConnection({ uri: config.connectionString, connectTimeout: 3000 });
        await connection.execute('CREATE TABLE acceptance_holders (id VARCHAR(40) PRIMARY KEY, email VARCHAR(120) UNIQUE NOT NULL, date_of_birth DATE NOT NULL)');
        for (const row of fixture) await connection.execute(
          'INSERT INTO acceptance_holders (id, email, date_of_birth) VALUES (?, ?, ?)',
          [row.id, row.email, row.date_of_birth],
        );
      }
      return;
    } catch (error) {
      // Retry connection startup only; SQL/fixture failures fail acceptance immediately.
      lastCode = error.code ?? error.name;
      if (!['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'PROTOCOL_CONNECTION_LOST',
        'ER_ACCESS_DENIED_ERROR', 'ER_BAD_DB_ERROR', '57P03', '28P01', '3D000'].includes(lastCode)
        && !/Connection terminated|Connection lost|timeout expired/.test(error.message)) throw error;
    } finally {
      if (connection) await connection.end().catch(() => {});
    }
    await delay(1000);
  }
  throw new Error('Database startup deadline exceeded (' + lastCode + ')');
}
async function worker(config) {
  let connector;
  let stage = 'database readiness and fixtures';
  try {
    await connectAndSeed(config);
    stage = 'source connector initialization';
    const options = { connectionString: config.connectionString, table: 'acceptance_holders', identifierColumn: 'email' };
    connector = config.engine === 'postgres'
      ? (await import('../src/connectors/postgres.ts')).loadPostgresConnector(options, config.pseudonymSecret)
      : (await import('../src/connectors/mysql.ts')).loadMySQLConnector(options, config.pseudonymSecret);
    stage = 'health and schema';
    assert.equal(typeof connector.healthCheck, 'function');
    await connector.healthCheck();
    assert.deepEqual((await connector.getSchema()).sort(), ['date_of_birth', 'email', 'id']);
    stage = 'DATE preservation and independent lookup identifiers';
    for (const expected of fixture) {
      const holder = await connector.lookup(expected.email);
      assert.ok(holder, 'Fixture must be found using its configured email identifier');
      assert.equal(holder.id, expected.id, 'Source id must remain unchanged');
      assert.equal(holder._lookupIdentifier, expected.email, 'The configured identifier must be carried separately');
      assert.equal(holder.date_of_birth, expected.date_of_birth, 'SQL DATE must remain YYYY-MM-DD in UTC+14');
    }
    stage = 'list pagination and list-to-lookup roundtrip';
    assert.equal(typeof connector.list, 'function');
    const listed = await connector.list({ limit: 10, offset: 0 });
    assert.equal(listed.length, fixture.length);
    for (const holder of listed) {
      assert.equal(typeof holder._lookupIdentifier, 'string');
      assert.deepEqual(await connector.lookup(holder._lookupIdentifier), holder);
    }
    assert.deepEqual((await connector.list({ limit: 1, offset: 1 })).map(holder => holder.id), [fixture[1].id]);
    assert.deepEqual(await connector.list({ limit: 1, offset: 2 }), []);
    stage = 'missing holder';
    assert.equal(await connector.lookup('missing@example.invalid'), null);
    stage = 'service outage must reject health, lookup and listing';
    await assertOwner(config.container, config.runId);
    await docker(['stop', '-t', '10', config.container], {}, 30_000);
    await assert.rejects(async () => connector.healthCheck());
    await assert.rejects(async () => connector.lookup(fixture[0].email));
    await assert.rejects(async () => connector.list({ limit: 10, offset: 0 }));
    await connector.close?.();
    connector = undefined;
    process.send?.({ ok: true });
  } catch (error) {
    process.send?.({ ok: false, message: stage + ': ' + redact(error.message, config.secrets) });
    process.exitCode = 1;
  } finally {
    if (connector) await connector.close?.();
    process.disconnect?.();
  }
}
async function runWorker(config) {
  // A driver-level crash must not skip the supervisor's container cleanup.
  await new Promise((resolve, reject) => {
    const child = fork(fileURLToPath(import.meta.url), ['--worker'], {
      execArgv: ['--import', 'tsx'],
      env: { ...process.env, NODE_ENV: 'test', TZ: timezone },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      windowsHide: true,
    });
    let result;
    let diagnostics = '';
    let timedOut = false;
    const capture = chunk => { diagnostics = (diagnostics + chunk).slice(-16_384); };
    child.stdout.on('data', capture);
    child.stderr.on('data', capture);
    child.on('message', message => { result = message; });
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, 240_000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      if (code === 0 && result?.ok) resolve();
      else reject(new Error(result?.message ?? (timedOut ? 'Connector worker timed out' :
        'Connector worker exited (' + (code ?? signal) + '): ' + redact(diagnostics, config.secrets))));
    });
    child.send(config);
  });
}
async function main() {
  const runId = randomUUID();
  const names = [];
  let failed = false;
  const secrets = [];
  try {
    // Fail before creating resources if the daemon is unavailable. Never start Docker here.
    assert.equal(await docker(['info', '--format', '{{.OSType}}']), 'linux', 'Linux Docker containers are required');
    for (const [engine, settings] of Object.entries(engines)) {
      const container = 'vericred-connector-' + runId + '-' + engine;
      names.push(container);
      const password = randomBytes(32).toString('hex');
      const rootPassword = randomBytes(32).toString('hex');
      const pseudonymSecret = randomBytes(32).toString('hex');
      secrets.push(password, rootPassword, pseudonymSecret);
      const environment = engine === 'postgres'
        ? { POSTGRES_USER: user, POSTGRES_PASSWORD: password, POSTGRES_DB: database }
        : { MYSQL_USER: user, MYSQL_PASSWORD: password, MYSQL_ROOT_PASSWORD: rootPassword, MYSQL_DATABASE: database };
      console.log('Connector acceptance: ' + engine + ', ' + settings.image + ', TZ=' + timezone);
      await docker(['run', '-d', '--name', container, '--label', label + '=' + runId,
        '--tmpfs', settings.tmpfs, '-p', '127.0.0.1::' + settings.port,
        ...Object.keys(environment).flatMap(name => ['-e', name]), settings.image], environment, 180_000);
      await assertOwner(container, runId);
      const binding = await docker(['port', container, settings.port + '/tcp']);
      assert.match(binding, /^127\.0\.0\.1:\d+$/, 'Expected only a random loopback binding');
      const scheme = engine === 'postgres' ? 'postgresql' : 'mysql';
      const connectionString = scheme + '://' + user + ':' + password + '@' + binding + '/' + database;
      const imageId = await docker(['inspect', '--format', '{{.Image}}', container]);
      console.log('  image=' + imageId);
      await runWorker({ engine, container, runId, connectionString, pseudonymSecret, secrets });
      console.log('  PASS: health, schema, DATE, identifiers, listing, missing record and service outage');
      await assertOwner(container, runId);
      await docker(['rm', container]);
      names.pop();
    }
  } catch (error) {
    failed = true;
    console.error('Connector acceptance FAIL: ' + redact(error.message, secrets));
  } finally {
    for (const name of names) {
      try {
        await assertOwner(name, runId);
        await docker(['rm', '-f', name]);
      } catch (error) {
        if (!/No such (?:object|container)/i.test(String(error.stderr ?? error.message))) {
          failed = true;
          console.error('Cleanup requires attention for generated container ' + name + ': ' + redact(error.message, secrets));
        }
      }
    }
  }
  if (failed) process.exitCode = 1;
  else console.log('Connector acceptance PASS: both live database engines; generated containers removed');
}
if (process.argv[2] === '--worker') {
  process.once('message', config => { void worker(config); });
} else {
  await main();
}