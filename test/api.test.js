import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let server, base, temp;
async function request(path, options = {}) { const response = await fetch(base + path, { headers: { 'Content-Type':'application/json', ...(options.headers || {}) }, ...options }); return { status:response.status, body:await response.json() }; }
test.before(async () => { temp=await mkdtemp(join(tmpdir(),'acc-test-')); const port=4399 + Math.floor(Math.random()*300); base=`http://127.0.0.1:${port}`; server=spawn(process.execPath,['server.js'],{cwd:new URL('..',import.meta.url),env:{...process.env,PORT:String(port),DATABASE_URL:join(temp,'test.db')}}); await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Server did not start')),5000);server.stdout.on('data',data=>{if(data.toString().includes('listening')){clearTimeout(timer);resolve()}});server.on('error',reject)}); });
test.after(async()=>{server.kill();await rm(temp,{recursive:true,force:true})});
test('create → call → rate-limit → revoke lifecycle is enforced',async()=>{
  const created=await request('/api/keys',{method:'POST',body:JSON.stringify({name:'Lifecycle test',environment:'development',rateLimit:1,quotaLimit:10,scopes:['demo:read']})});
  assert.equal(created.status,201);assert.match(created.body.secret,/^sk_test_/);assert.equal(created.body.key.prefix.includes(created.body.secret.slice(-10)),false);
  const key=created.body.secret;
  const first=await request('/api/demo/data',{headers:{'X-API-Key':key}});assert.equal(first.status,200);
  const limited=await request('/api/demo/data',{headers:{'X-API-Key':key}});assert.equal(limited.status,429);
  const revoked=await request(`/api/keys/${created.body.key.id}/revoke`,{method:'POST',body:'{}'});assert.equal(revoked.status,200);
  const blocked=await request('/api/demo/data',{headers:{'X-API-Key':key}});assert.equal(blocked.status,403);
});
test('unscoped keys cannot access the protected demo endpoint',async()=>{
  const created=await request('/api/keys',{method:'POST',body:JSON.stringify({name:'No demo',environment:'development',rateLimit:10,scopes:['read']})});
  const response=await request('/api/demo/data',{headers:{'X-API-Key':created.body.secret}});assert.equal(response.status,403);
});
