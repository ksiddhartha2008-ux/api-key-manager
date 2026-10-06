import http from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createHash, randomBytes, timingSafeEqual, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const ROOT = resolve(import.meta.dirname);
const port = Number(process.env.PORT || 4173);
const databasePath = resolve(ROOT, process.env.DATABASE_URL || './data/api-control-center.db');
await mkdir(dirname(databasePath), { recursive: true });
const db = new DatabaseSync(databasePath);
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');

const now = () => new Date().toISOString();
const id = () => randomUUID();
const hash = (value) => createHash('sha256').update(value).digest('hex');
const json = (res, status, body) => res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(JSON.stringify(body));
const error = (res, status, message, code = 'REQUEST_FAILED') => json(res, status, { error: { code, message } });

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL, environment TEXT NOT NULL CHECK(environment IN ('development','staging','production')),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL CHECK(status IN ('active','revoked','expired','rotating')) DEFAULT 'active',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT, last_used_at TEXT,
      revoked_at TEXT, rate_limit INTEGER NOT NULL, quota_limit INTEGER, rotation_parent_id TEXT,
      grace_expires_at TEXT, FOREIGN KEY(rotation_parent_id) REFERENCES api_keys(id)
    );
    CREATE TABLE IF NOT EXISTS api_key_scopes (id TEXT PRIMARY KEY, api_key_id TEXT NOT NULL, scope TEXT NOT NULL, UNIQUE(api_key_id, scope), FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS usage_events (id TEXT PRIMARY KEY, api_key_id TEXT NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL, status_code INTEGER NOT NULL, response_time_ms INTEGER NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(api_key_id) REFERENCES api_keys(id));
    CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT, metadata TEXT NOT NULL DEFAULT '{}', ip_address TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, type TEXT NOT NULL, severity TEXT NOT NULL, resource_id TEXT, message TEXT NOT NULL, threshold INTEGER, current_value INTEGER, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL, resolved_at TEXT);
    CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, provider TEXT NOT NULL UNIQUE, name TEXT NOT NULL, status TEXT NOT NULL, configured_budget REAL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS provider_usage (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, reported_cost REAL, estimated_cost REAL, remaining_budget REAL, source_type TEXT NOT NULL CHECK(source_type IN ('REPORTED','CALCULATED','USER_CONFIGURED','UNAVAILABLE')), fetched_at TEXT NOT NULL, FOREIGN KEY(provider_id) REFERENCES providers(id));
    CREATE INDEX IF NOT EXISTS idx_keys_status ON api_keys(status); CREATE INDEX IF NOT EXISTS idx_keys_expiry ON api_keys(expires_at);
    CREATE INDEX IF NOT EXISTS idx_usage_key_time ON usage_events(api_key_id, created_at); CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at);
  `);
}
function audit(action, resourceType, resourceId, metadata = {}) {
  db.prepare('INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id(), 'local-demo-user', action, resourceType, resourceId, JSON.stringify(metadata), null, now());
}
function seed() {
  if (db.prepare('SELECT COUNT(*) AS count FROM providers').get().count === 0) {
    const insert = db.prepare('INSERT INTO providers VALUES (?, ?, ?, ?, ?, ?, ?)');
    const stamp = now();
    for (const [provider, name, budget] of [['openai','OpenAI',250], ['anthropic','Anthropic',180], ['openrouter','OpenRouter',120]]) insert.run(id(), provider, name, 'not_connected', budget, stamp, stamp);
  }
}
migrate(); seed();

function publicKey(row) {
  return { id: row.id, name: row.name, prefix: row.key_prefix, environment: row.environment, description: row.description, status: effectiveStatus(row), createdAt: row.created_at, expiresAt: row.expires_at, lastUsedAt: row.last_used_at, revokedAt: row.revoked_at, rateLimit: row.rate_limit, quotaLimit: row.quota_limit, graceExpiresAt: row.grace_expires_at, rotationParentId: row.rotation_parent_id, scopes: db.prepare('SELECT scope FROM api_key_scopes WHERE api_key_id = ? ORDER BY scope').all(row.id).map(x => x.scope) };
}
function effectiveStatus(key) {
  if (key.status === 'revoked') return 'revoked';
  if (key.expires_at && new Date(key.expires_at) <= new Date()) return 'expired';
  if (key.grace_expires_at && new Date(key.grace_expires_at) <= new Date()) return 'expired';
  return key.status;
}
function cleanText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function createKey(payload) {
  const name = cleanText(payload.name, 70), description = cleanText(payload.description, 240);
  const environment = ['development','staging','production'].includes(payload.environment) ? payload.environment : 'development';
  const rateLimit = Number(payload.rateLimit);
  const quotaLimit = payload.quotaLimit === '' || payload.quotaLimit == null ? null : Number(payload.quotaLimit);
  const expiresAt = payload.expiresAt ? new Date(payload.expiresAt).toISOString() : null;
  const scopes = Array.isArray(payload.scopes) ? [...new Set(payload.scopes.filter(s => ['read','write','demo:read','analytics:read'].includes(s)))].slice(0, 4) : [];
  if (name.length < 2) throw new Error('A key name of at least two characters is required.');
  if (!Number.isInteger(rateLimit) || rateLimit < 1 || rateLimit > 10000) throw new Error('Rate limit must be an integer from 1 to 10,000.');
  if (quotaLimit !== null && (!Number.isInteger(quotaLimit) || quotaLimit < 1 || quotaLimit > 10000000)) throw new Error('Quota must be a positive whole number.');
  if (payload.expiresAt && Number.isNaN(new Date(payload.expiresAt).valueOf())) throw new Error('Expiration date is invalid.');
  if (!scopes.length) throw new Error('Choose at least one scope.');
  const secret = `sk_${environment === 'production' ? 'live' : 'test'}_${randomBytes(32).toString('base64url')}`;
  const record = { id: id(), name, keyHash: hash(secret), prefix: secret.slice(0, 15) + '…', environment, description, createdAt: now(), expiresAt, rateLimit, quotaLimit };
  db.prepare('INSERT INTO api_keys (id,name,key_hash,key_prefix,environment,description,status,created_at,updated_at,expires_at,rate_limit,quota_limit) VALUES (?,?,?,?,?,?,\'active\',?,?,?,?,?)').run(record.id, record.name, record.keyHash, record.prefix, record.environment, record.description, record.createdAt, record.createdAt, record.expiresAt, record.rateLimit, record.quotaLimit);
  const addScope = db.prepare('INSERT INTO api_key_scopes VALUES (?, ?, ?)'); for (const scope of scopes) addScope.run(id(), record.id, scope);
  audit('key.created', 'api_key', record.id, { prefix: record.prefix, environment, scopes });
  return { key: publicKey(db.prepare('SELECT * FROM api_keys WHERE id=?').get(record.id)), secret };
}
function authenticate(rawKey, requiredScope) {
  if (typeof rawKey !== 'string' || !/^sk_(live|test)_[A-Za-z0-9_-]{20,}$/.test(rawKey)) return { ok: false, status: 401, message: 'A valid API key is required.' };
  const candidate = hash(rawKey); const key = db.prepare('SELECT * FROM api_keys WHERE key_hash=?').get(candidate);
  if (!key || !timingSafeEqual(Buffer.from(candidate), Buffer.from(key.key_hash))) return { ok: false, status: 401, message: 'API key is not recognized.' };
  const status = effectiveStatus(key); if (status !== 'active' && status !== 'rotating') return { ok: false, status: 403, message: `This API key is ${status}.` };
  if (requiredScope && !db.prepare('SELECT 1 FROM api_key_scopes WHERE api_key_id=? AND scope IN (?,?)').get(key.id, requiredScope, 'admin')) return { ok: false, status: 403, message: 'This key lacks the required scope.' };
  const since = new Date(Date.now() - 60_000).toISOString(); const requests = db.prepare('SELECT COUNT(*) AS count FROM usage_events WHERE api_key_id=? AND created_at >= ?').get(key.id, since).count;
  if (requests >= key.rate_limit) return { ok: false, status: 429, message: 'Rate limit exceeded. Retry after 60 seconds.', key };
  if (key.quota_limit !== null && db.prepare('SELECT COUNT(*) AS count FROM usage_events WHERE api_key_id=?').get(key.id).count >= key.quota_limit) return { ok: false, status: 429, message: 'Configured quota has been exhausted.', key };
  return { ok: true, key };
}
function recordUsage(key, statusCode, responseTime = 0) {
  db.prepare('INSERT INTO usage_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id(), key.id, '/api/demo/data', 'GET', statusCode, responseTime, 'try-it-console', now());
  db.prepare('UPDATE api_keys SET last_used_at=?, updated_at=? WHERE id=?').run(now(), now(), key.id);
}
async function body(req) { let text=''; for await (const part of req) { text += part; if (text.length > 50_000) throw new Error('Request body is too large.'); } try { return text ? JSON.parse(text) : {}; } catch { throw new Error('Request body must be valid JSON.'); } }
function dashboard() {
  const keys = db.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all().map(publicKey);
  const usage = db.prepare("SELECT substr(created_at,1,10) day, COUNT(*) requests FROM usage_events WHERE created_at >= ? GROUP BY day ORDER BY day").all(new Date(Date.now()-6*86400000).toISOString());
  return { keys, totals: { keys: keys.length, active: keys.filter(x => x.status === 'active').length, requests: db.prepare('SELECT COUNT(*) count FROM usage_events').get().count, alerts: db.prepare("SELECT COUNT(*) count FROM alerts WHERE status='open'").get().count }, usage, alerts: db.prepare("SELECT * FROM alerts WHERE status='open' ORDER BY created_at DESC LIMIT 5").all(), providers: db.prepare('SELECT provider,name,status,configured_budget AS configuredBudget,updated_at AS updatedAt FROM providers ORDER BY name').all(), recentActivity: db.prepare('SELECT action,resource_type AS resourceType,resource_id AS resourceId,metadata,created_at AS createdAt FROM audit_logs ORDER BY created_at DESC LIMIT 8').all() };
}
const routes = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`); const path = url.pathname;
  if (req.method === 'GET' && path === '/api/health') return json(res, 200, { status: 'healthy', database: 'connected', simulationEngine: process.env.SIMULATION_LAB_ENABLED === 'true' ? 'unverified' : 'disabled', providers: 'partial' });
  if (req.method === 'GET' && path === '/api/dashboard') return json(res, 200, dashboard());
  if (req.method === 'GET' && path === '/api/keys') return json(res, 200, { data: db.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all().map(publicKey) });
  if (req.method === 'POST' && path === '/api/keys') { try { const result = createKey(await body(req)); return json(res, 201, result); } catch (e) { return error(res, 422, e.message, 'VALIDATION_FAILED'); } }
  const revokeMatch = path.match(/^\/api\/keys\/([^/]+)\/revoke$/);
  if (req.method === 'POST' && revokeMatch) { const key = db.prepare('SELECT * FROM api_keys WHERE id=?').get(revokeMatch[1]); if (!key) return error(res, 404, 'Key not found.', 'NOT_FOUND'); db.prepare("UPDATE api_keys SET status='revoked', revoked_at=?, updated_at=? WHERE id=?").run(now(),now(),key.id); audit('key.revoked','api_key',key.id,{prefix:key.key_prefix}); return json(res,200,{key:publicKey(db.prepare('SELECT * FROM api_keys WHERE id=?').get(key.id))}); }
  const rotateMatch = path.match(/^\/api\/keys\/([^/]+)\/rotate$/);
  if (req.method === 'POST' && rotateMatch) { const old = db.prepare('SELECT * FROM api_keys WHERE id=?').get(rotateMatch[1]); if (!old) return error(res,404,'Key not found.','NOT_FOUND'); if (effectiveStatus(old) !== 'active') return error(res,409,'Only active keys can be rotated.','INVALID_STATE'); const p=await body(req); const graceDays=Math.max(1,Math.min(30,Number(p.graceDays)||7)); const newKey=createKey({ name:`${old.name} (rotated)`,description:old.description,environment:old.environment,rateLimit:old.rate_limit,quotaLimit:old.quota_limit,expiresAt:old.expires_at,scopes:db.prepare('SELECT scope FROM api_key_scopes WHERE api_key_id=?').all(old.id).map(x=>x.scope) }); const grace=new Date(Date.now()+graceDays*86400000).toISOString(); db.prepare("UPDATE api_keys SET status='rotating', grace_expires_at=?, updated_at=? WHERE id=?").run(grace,now(),old.id); db.prepare('UPDATE api_keys SET rotation_parent_id=? WHERE id=?').run(old.id,newKey.key.id); audit('key.rotated','api_key',old.id,{oldPrefix:old.key_prefix,newKeyId:newKey.key.id,graceDays}); return json(res,201,{...newKey,previousKey:{id:old.id,prefix:old.key_prefix,graceExpiresAt:grace}}); }
  if (req.method === 'GET' && path === '/api/audit') return json(res,200,{data:db.prepare('SELECT action,resource_type AS resourceType,resource_id AS resourceId,metadata,created_at AS createdAt FROM audit_logs ORDER BY created_at DESC LIMIT 100').all()});
  if (req.method === 'GET' && path === '/api/providers') return json(res,200,{data:db.prepare('SELECT provider,name,status,configured_budget AS configuredBudget,updated_at AS updatedAt FROM providers ORDER BY name').all().map(p=>({...p,metrics:[{label:'Provider balance',value:'Unavailable',sourceType:'UNAVAILABLE'},{label:'Budget',value:p.configuredBudget===null?'Not configured':`$${p.configuredBudget.toFixed(2)}`,sourceType:p.configuredBudget===null?'UNAVAILABLE':'USER_CONFIGURED'}]}))});
  if (req.method === 'GET' && path === '/api/demo/data') { const started=Date.now(); const access=authenticate(req.headers['x-api-key'],'demo:read'); if (!access.ok) return error(res,access.status,access.message,access.status===429?'RATE_LIMITED':'UNAUTHORIZED'); recordUsage(access.key,200,Date.now()-started); return json(res,200,{message:'Protected demo data delivered.',data:{environment:'demo',generatedAt:now(),requestId:id().slice(0,8)}}); }
  if (path.startsWith('/api/simulations')) return error(res,503,'Simulation Lab is disabled until a pinned, private MiroFish service is configured.','SIMULATION_UNAVAILABLE');
  return serveStatic(path,res);
};
async function serveStatic(path,res) { const safe=path === '/' ? 'index.html' : path.replace(/^\/+/, ''); if (safe.includes('..')) return error(res,404,'Not found.','NOT_FOUND'); try { const file=await readFile(join(ROOT,'public',safe)); const type=safe.endsWith('.css')?'text/css':safe.endsWith('.js')?'text/javascript':safe.endsWith('.svg')?'image/svg+xml':'text/html'; res.writeHead(200,{'Content-Type':`${type}; charset=utf-8`,'X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",'Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Permissions-Policy':'camera=(), microphone=(), geolocation=()'}).end(file); } catch { error(res,404,'Not found.','NOT_FOUND'); } }
const server=http.createServer((req,res)=>routes(req,res).catch(e=>{ if (!res.headersSent) error(res,400,e.message,'BAD_REQUEST'); }));
if (process.argv.includes('--migrate')) { console.log('Database migrated successfully.'); process.exit(0); }
server.listen(port, () => console.log(`API Control Center listening on http://localhost:${port}`));
