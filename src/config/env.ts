// Must be imported before modules that capture deployment settings.
if (process.env.NODE_ENV !== 'test') {
  const explicit = { ...process.env };
  try { process.loadEnvFile(); } catch { /* An environment file is optional. */ }
  Object.assign(process.env, explicit);
}
