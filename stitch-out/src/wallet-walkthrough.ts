import { adminMutation } from './admin-client';
import { element, formatTime, readJson, runtimeReadiness, type RuntimeReadiness } from './admin-runtime';

const node = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const selectHolder = node<HTMLSelectElement>('select-holder');
const identifier = node<HTMLInputElement>('input-holder-identifier');
const offerType = node<HTMLSelectElement>('select-template');
const presentationType = node<HTMLSelectElement>('presentation-type');
const fields: Record<string, string[]> = { AgeCredential: ['age_over_18'], EmployeeCredential: ['given_name', 'family_name', 'organization', 'role'], MembershipCredential: ['organization', 'membership_type'] };
interface Credential { credentialId: string; holderEmail: string; credentialType?: string; issuedAt: string; expiresAt?: string; revoked: boolean; listId: string; statusIndex: number }
interface Template { id: string; displayName: string; requiredFields: string[]; optionalFields: string[] }
interface Config { type: string; fieldMappings: Record<string, string>; templateMappings: Record<string, Record<string, string>>; templateOptionsByType: Record<string, Record<string, unknown>> }
let readiness: RuntimeReadiness | undefined;
let templates: Template[] = [];
let config: Config | undefined;
let credentials: Credential[] = [];
let selectedId = '';
let offerUri = '';
let presentationUri = '';
let offerTimer: ReturnType<typeof setTimeout> | undefined;
let recordTimer: ReturnType<typeof setTimeout> | undefined;
let pollTimer: ReturnType<typeof setTimeout> | undefined;
let pollVersion = 0;
let recordPending = false;
let recordRefreshUntil = 0;
let resultClaims: Record<string, unknown> | null = null;
let verifiedType = '';
let actionPending = false;
const showError = (id: string, error: unknown) => { node(id).textContent = error instanceof Error ? error.message : 'The request could not be completed.'; };

function option(value: string, label: string) { const result = element('option', label); result.value = value; return result; }
function recordedStatus(record: Credential) { return record.revoked ? 'Revoked' : !record.expiresAt ? 'Expiry unknown' : Date.parse(record.expiresAt) <= Date.now() ? 'Expired' : 'Active'; }
function safeLink(uri: unknown, prefix: string): string { if (typeof uri !== 'string' || !uri.startsWith(prefix) || uri.length > 100000) throw new Error('The gateway returned an invalid wallet link.'); return uri; }
function showQr(id: string, data: unknown, description: string) {
    if (typeof data !== 'string' || !/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(data) || data.length > 2000000) throw new Error('The gateway returned an invalid QR image.');
    const img = element('img'); img.src = data; img.alt = description; node(id).replaceChildren(img); node(id).hidden = false;
}
function clearOffer(message = 'No offer created.') {
    clearTimeout(offerTimer); offerUri = ''; node('offer-qr').replaceChildren(); node('offer-qr').hidden = true; node('offer-actions').hidden = true; node('open-offer').removeAttribute('href'); node('offer-status').textContent = message;
}
function stopPresentation(message = 'Stopped waiting. An already shared request may remain valid until it expires.') {
    ++pollVersion; clearTimeout(pollTimer); presentationUri = ''; node('presentation-qr').replaceChildren(); node('presentation-qr').hidden = true; node('presentation-actions').hidden = true; node('open-presentation').removeAttribute('href'); node('presentation-status').textContent = message;
}
async function copyLink(value: string, statusId: string) {
    if (!value) return;
    try { await navigator.clipboard.writeText(value); node(statusId).textContent = 'Wallet link copied. Share it only with the intended holder.'; }
    catch { node(statusId).textContent = 'Clipboard access is unavailable. Scan the QR or use Open wallet on this device.'; }
}
async function writeJson(url: string, body: unknown, admin = false) {
    const init = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) };
    const response = admin ? await adminMutation(url, init) : await fetch(url, { ...init, credentials: 'same-origin', cache: 'no-store' });
    if (response.status === 401 || response.status === 403 || response.redirected) throw new Error('Your session has expired. Sign in again before continuing.');
    if (!response.ok) {
        const messages: Record<number, string> = { 400: 'Check the selected type, source identifier and schema mapping.', 404: 'The holder or record was not found. Check its source identifier.', 409: 'The configuration changed. Refresh this page before creating another request.', 429: 'Too many requests. Wait before trying again.', 503: 'This service is unavailable. Check the runtime readiness and source connection.' };
        throw new Error(messages[response.status] ?? `The gateway could not complete the action (${response.status}).`);
    }
    return response.json();
}
function describeMapping() {
    const template = templates.find(t => t.id === offerType.value);
    if (!template) { node('mapping-summary').textContent = 'Choose a credential type.'; return; }
    const mappings = config?.templateMappings?.[template.id] ?? (config?.type === template.id ? config.fieldMappings : {});
    const parts = [element('p', 'Only mapped source fields are used. Source values are not displayed here.', 'mb-2')];
    for (const field of template.requiredFields) parts.push(element('p', (mappings[field] ?? 'Mapping required') + ' → ' + field, 'font-mono mb-1'));
    parts.push(element('p', template.id === 'AgeCredential' ? 'Age predicates are derived from date of birth. The date of birth is not issued.' : 'The selected template turns mapped fields into credential claims.', 'mt-2'));
    parts.push(element('p', 'Verifier requests: ' + (fields[template.id] ?? []).join(', ') + (template.id === 'AgeCredential' ? ' = true' : ''), 'mt-2'));
    node('mapping-summary').replaceChildren(...parts);
}
function describePresentation() { node('requested-claims').textContent = 'Requested disclosure: ' + (fields[presentationType.value] ?? []).join(', ') + (presentationType.value === 'AgeCredential' ? '. age_over_18 must be true.' : '.'); }
async function loadConfiguration() {
    try {
        const [catalog, current] = await Promise.all([readJson<{ templates: Template[] }>('/admin/templates'), readJson<Config>('/admin/api/config')]);
        templates = catalog.templates; config = current;
        for (const select of [offerType, presentationType]) select.replaceChildren(option('', 'Choose a credential type'), ...templates.filter(t => fields[t.id]).map(t => option(t.id, t.displayName)));
        offerType.value = current.type; presentationType.value = current.type;
        node<HTMLButtonElement>('create-offer').disabled = false; node<HTMLButtonElement>('create-presentation').disabled = false;
        describeMapping(); describePresentation();
    } catch (error) { showError('offer-status', error); showError('presentation-status', error); }
}
async function loadHolders() {
    try {
        const holders = await readJson<Record<string, unknown>[]>('/admin/api/holders?limit=100');
        selectHolder.replaceChildren(option('', 'Select a holder or enter an identifier'), ...holders.map(holder => option(String(holder._lookupIdentifier ?? holder.id ?? ''), [holder.firstName, holder.lastName, holder.email].filter(Boolean).join(' ') || String(holder.id ?? 'Holder'))).filter(item => item.value));
        node('holder-source-note').textContent = holders.length ? `Showing up to 100 holders. Details follow the gateway’s privacy settings.` : 'No holders listed. Add a test holder or enter a known source identifier.';
    } catch { selectHolder.replaceChildren(option('', 'Listing unavailable — enter an identifier')); node('holder-source-note').textContent = 'This source could not be listed. A direct lookup may still work.'; }
}
async function loadRuntime(refresh = false) {
    try {
        readiness = await runtimeReadiness(refresh);
        node('flow-runtime').textContent = readiness.walletProfile === 'eudi-android' ? 'EUDI Android candidate · shared miTch protocol contract' : 'Custom profile · local / integration walkthrough';
        node('flow-runtime-detail').textContent = `Issuer: ${readiness.issuer.url} · Source: ${readiness.source.type}. ` + (readiness.configurationReady ? 'Local configuration checks passed. ' : 'Some local configuration needs attention; inspect Gateway overview. ') + 'Wallet acceptance remains unverified.';
    } catch (error) { showError('flow-runtime', error); node('flow-runtime-detail').textContent = 'Readiness could not be checked. Refresh the page to retry.'; }
}
node('offer-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (actionPending) return;
    const holder = identifier.value.trim() || selectHolder.value;
    if (!holder || !offerType.value) { node('offer-status').textContent = 'Select a holder or enter a source identifier, then choose a credential type.'; return; }
    actionPending = true; clearOffer('Reading the holder and creating the offer…');
    const controls = [selectHolder, identifier, offerType, node<HTMLButtonElement>('create-offer')]; controls.forEach(control => control.disabled = true);
    try {
        const result = await writeJson('/offer', { identifier: holder, credentialType: offerType.value }, true);
        const uri = safeLink(result.offer_uri, 'openid-credential-offer://');
        showQr('offer-qr', result.qr_code, 'Scan this credential offer using the intended wallet');
        offerUri = uri; node<HTMLAnchorElement>('open-offer').href = uri; node('offer-actions').hidden = false;
        node('offer-status').textContent = 'Offer ready. Scan it and accept issuance in the wallet within 10 minutes. A generated offer is not an issued credential.';
        offerTimer = setTimeout(() => clearOffer('This offer has expired. Create a new offer if issuance was not completed.'), 10 * 60_000);
        recordRefreshUntil = Date.now() + 10 * 60_000; scheduleRecordRefresh();
    } catch (error) { clearOffer(); showError('offer-status', error); }
    finally { actionPending = false; controls.forEach(control => control.disabled = false); }
});
identifier.addEventListener('input', () => { selectHolder.value = ''; clearOffer('Selection changed. Create a new offer for this holder.'); });
selectHolder.addEventListener('change', () => { identifier.value = ''; clearOffer('Selection changed. Create a new offer for this holder.'); });
offerType.addEventListener('change', () => { clearOffer('Credential type changed. Create a new offer.'); describeMapping(); presentationType.value = offerType.value; stopPresentation('Credential type changed. Create a new presentation request.'); clearResults(); describePresentation(); });
node('copy-offer').addEventListener('click', () => void copyLink(offerUri, 'offer-status'));
node('hide-offer').addEventListener('click', () => clearOffer('Offer hidden from this page. An already shared offer remains valid until used or expired.'));

function clearResults() { resultClaims = null; verifiedType = ''; node('presentation-result').hidden = true; node('verified-claims').replaceChildren(); node<HTMLInputElement>('show-claim-values').checked = false; }
function renderClaims() {
    const visible = node<HTMLInputElement>('show-claim-values').checked;
    const entries = (fields[verifiedType] ?? []).filter(name => Object.hasOwn(resultClaims ?? {}, name));
    node('verified-claims').replaceChildren(...entries.map(name => {
        const item = element('div', '', 'flex flex-wrap gap-2 justify-between border-b border-slate-800 pb-2');
        const value = resultClaims?.[name];
        const display = !visible ? 'Disclosed · value hidden' : typeof value === 'string' ? value.slice(0, 160) : typeof value === 'boolean' || typeof value === 'number' ? String(value) : 'Structured value hidden';
        item.append(element('dt', name, 'font-mono text-xs'), element('dd', display, 'text-sm break-all')); return item;
    }));
    const extras = Object.keys(resultClaims ?? {}).filter(name => !entries.includes(name)).length;
    node('extra-claims').textContent = extras ? `${extras} additional disclosed field(s) are not displayed. Review wallet disclosure settings.` : 'Only the requested disclosed fields are shown. No credential or proof tokens are displayed.';
}
async function pollPresentation(sessionId: string, readToken: string, type: string, version: number, expiresAt: number) {
    if (version !== pollVersion) return;
    if (Date.now() >= expiresAt) { stopPresentation('Request expired. Create a new presentation request.'); return; }
    try {
        const result = await readJson<{ status: string; claims: Record<string, unknown> | null }>('/api/oid4vp/session/' + encodeURIComponent(sessionId), { headers: { Authorization: 'Bearer ' + readToken } });
        if (version !== pollVersion) return;
        if (result.status === 'verified' && result.claims) {
            stopPresentation('A valid presentation was received. This is an observed result for this request.');
            resultClaims = result.claims; verifiedType = type; renderClaims(); node('verified-at').textContent = 'Observed at ' + new Date().toLocaleString() + '. This result is historical.'; node('presentation-result').hidden = false; await loadRecords(); return;
        }
        if (result.status !== 'initiated') throw new Error('Unexpected session state. Create a new request.');
        pollTimer = setTimeout(() => void pollPresentation(sessionId, readToken, type, version, expiresAt), 2500);
    } catch (error) { if (version === pollVersion) { stopPresentation('Polling stopped. The request may still be valid; create a new request to continue.'); showError('presentation-status', error); } }
}
node('presentation-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!presentationType.value) return;
    const button = node<HTMLButtonElement>('create-presentation'); if (button.disabled) return;
    stopPresentation('Creating a presentation request…'); clearResults(); button.disabled = true; presentationType.disabled = true;
    const type = presentationType.value; const version = pollVersion;
    try {
        const result = await writeJson('/api/oid4vp/initiate', { credentialType: type, protocol: 'openid4vp-1.0' });
        if (version !== pollVersion) return;
        const uri = safeLink(result.requestUri, 'openid4vp://');
        if (typeof result.sessionId !== 'string' || !/^sess-[a-f0-9]{64}$/.test(result.sessionId) || typeof result.readToken !== 'string' || !result.readToken) throw new Error('The gateway returned an invalid session.');
        showQr('presentation-qr', result.qrCodeDataUrl, 'Scan this presentation request with the wallet that holds the credential');
        presentationUri = uri; node<HTMLAnchorElement>('open-presentation').href = uri; node('presentation-actions').hidden = false;
        node('presentation-status').textContent = 'Waiting for wallet consent and a valid presentation. This request expires within 30 minutes. No response does not prove acceptance or rejection.';
        void pollPresentation(result.sessionId, result.readToken, type, version, Date.now() + 30 * 60_000);
    } catch (error) { stopPresentation(); showError('presentation-status', error); }
    finally { button.disabled = false; presentationType.disabled = false; }
});
presentationType.addEventListener('change', () => { stopPresentation('Credential type changed. Create a new request.'); clearResults(); describePresentation(); });
node('copy-presentation').addEventListener('click', () => void copyLink(presentationUri, 'presentation-status'));
node('stop-presentation').addEventListener('click', () => stopPresentation());
node('show-claim-values').addEventListener('change', renderClaims);

function renderRecords() {
    const query = node<HTMLInputElement>('record-filter').value.toLowerCase().trim();
    const filtered = credentials.filter(record => [record.credentialId, record.holderEmail, record.credentialType, recordedStatus(record)].some(value => String(value ?? '').toLowerCase().includes(query))).slice().reverse();
    if (!filtered.length) { const row = element('tr'); const cell = element('td', credentials.length ? 'No matching records.' : 'No credentials issued yet. Complete an offer in a wallet to create a record.', 'p-4 text-slate-500'); cell.colSpan = 5; row.append(cell); node('credentials-tbody').replaceChildren(row); return; }
    node('credentials-tbody').replaceChildren(...filtered.map(record => {
        const row = element('tr', '', 'border-b border-slate-800');
        for (const value of [formatTime(record.issuedAt), record.holderEmail ?? 'Unknown', record.credentialType ?? 'Unknown (legacy)', recordedStatus(record)]) row.append(element('td', value, 'p-3'));
        const action = element('td', '', 'p-3'); const button = element('button', 'Inspect', 'text-emerald-500 font-semibold'); button.type = 'button'; button.setAttribute('aria-label', 'Inspect credential ' + record.credentialId); button.addEventListener('click', () => { selectedId = record.credentialId; showRecord(); node('record-detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }); action.append(button); row.append(action); return row;
    }));
}
function showRecord() {
    const record = credentials.find(item => item.credentialId === selectedId); node('record-detail').hidden = !record; if (!record) return;
    const fields: [string, string][] = [['Credential ID', record.credentialId], ['Subject', record.holderEmail ?? 'Unknown'], ['Type', record.credentialType ?? 'Unknown'], ['Recorded state', recordedStatus(record)], ['Issued', formatTime(record.issuedAt)], ['Expires', record.expiresAt ? formatTime(record.expiresAt) : 'Unknown'], ['Status list', record.listId], ['Status index', String(record.statusIndex)]];
    node('record-fields').replaceChildren(...fields.map(([key, value]) => { const group = element('div'); group.append(element('dt', key, 'text-xs text-slate-500'), element('dd', value, 'break-all font-mono text-xs mt-1')); return group; }));
    node<HTMLButtonElement>('revoke-record').disabled = record.revoked;
    node('revoke-record').textContent = record.revoked ? 'Already revoked' : 'Revoke this credential';
    node('record-action-status').textContent = '';
}
async function loadRecords() {
    if (recordPending) return;
    recordPending = true; node<HTMLButtonElement>('refresh-records').disabled = true;
    try { const result = await readJson<Credential[]>('/admin/api/credentials'); if (!Array.isArray(result)) throw new Error('Invalid credential records.'); credentials = result; renderRecords(); showRecord(); node('records-status').textContent = `${result.length} recorded credential(s). Updated ${new Date().toLocaleTimeString()}. Match the subject and type to your test; other operators may issue credentials too.`; }
    catch (error) { showError('records-status', error); }
    finally { recordPending = false; node<HTMLButtonElement>('refresh-records').disabled = false; }
}
function scheduleRecordRefresh() { clearTimeout(recordTimer); if (Date.now() < recordRefreshUntil) recordTimer = setTimeout(async () => { if (!document.hidden) await loadRecords(); scheduleRecordRefresh(); }, 5000); }
node('refresh-records').addEventListener('click', () => void loadRecords());
node('record-filter').addEventListener('input', renderRecords);
node('revoke-record').addEventListener('click', async () => {
    const record = credentials.find(item => item.credentialId === selectedId); if (!record || record.revoked) return;
    if (!window.confirm(`Permanently revoke ${record.credentialId}? The holder will need a new credential. This cannot be undone.`)) return;
    const button = node<HTMLButtonElement>('revoke-record'); button.disabled = true;
    try { const result = await writeJson('/admin/revoke', { credentialId: record.credentialId }, true); await loadRecords(); node('record-action-status').textContent = result.success ? 'Credential revoked. Create a new presentation request to observe refusal; the earlier verified result stays historical.' : 'The record was already revoked or could not be found. Review the refreshed records.'; }
    catch (error) { showError('record-action-status', error); button.disabled = false; }
});
node('check-status').addEventListener('click', async () => {
    const record = credentials.find(item => item.credentialId === selectedId); if (!record) return;
    if (!readiness) { node('record-action-status').textContent = 'Readiness is unavailable. Refresh the page before checking the status endpoint.'; return; }
    const button = node<HTMLButtonElement>('check-status'); button.disabled = true;
    const endpoint = (readiness.walletProfile === 'eudi-android' ? '/status/token/' : '/status/') + encodeURIComponent(record.listId);
    try { const response = await fetch(endpoint, { cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(15000) }); const type = response.headers.get('content-type') ?? ''; await response.body?.cancel(); if (!response.ok) throw new Error(`Status endpoint unavailable (${response.status}).`); if (!type.includes('application/statuslist+jwt') && !type.includes('application/jwt')) throw new Error('The status endpoint returned an unexpected format.'); node('record-action-status').textContent = 'Status endpoint responded successfully (' + type.split(';')[0] + '). This reachability check does not verify its signature or replace the wallet’s status validation.'; }
    catch (error) { showError('record-action-status', error); } finally { button.disabled = false; }
});
async function loadAlerts() {
    const button = node<HTMLButtonElement>('refresh-alerts'); button.disabled = true;
    try { const logs = await readJson<{ category: string; type: string; message: string; timestamp: string }[]>('/admin/api/interop-logs'); node('protocol-alerts').replaceChildren(...(logs.length ? logs.slice(0, 10).map(log => { const item = element('li', '', 'border border-slate-800 rounded-xl p-3'); item.append(element('p', `${log.category} · ${formatTime(log.timestamp)}`, 'text-xs font-semibold'), element('p', log.message, 'text-sm text-slate-500 mt-1')); return item; }) : [element('li', 'No issuance protocol alerts recorded.', 'text-sm text-slate-500')])); }
    catch (error) { node('protocol-alerts').replaceChildren(element('li', error instanceof Error ? error.message : 'Alerts unavailable.', 'text-sm text-slate-500')); } finally { button.disabled = false; }
}
node('refresh-alerts').addEventListener('click', () => void loadAlerts());
window.addEventListener('pagehide', () => { clearOffer(); stopPresentation(); clearResults(); clearTimeout(recordTimer); credentials = []; });
window.addEventListener('pageshow', event => { if (event.persisted) { void loadRuntime(true); void loadConfiguration(); void loadHolders(); void loadRecords(); void loadAlerts(); } });
void loadRuntime(); void loadConfiguration(); void loadHolders(); void loadRecords(); void loadAlerts();
