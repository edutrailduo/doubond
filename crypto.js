// DuoBond device-only encryption v1.
// Static P-256 ECDH + HKDF-SHA-256 + AES-256-GCM.
// This is not a Signal-protocol ratchet and does not provide forward secrecy.
const DB_NAME = 'duobond-device-keys';
const STORE = 'keys';
const KEY_ID = 'primary-device-key';
const enc = new TextEncoder();
const dec = new TextDecoder();

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}
async function dbSet(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}
function b64(bytes) {
  let s = '';
  new Uint8Array(bytes).forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}
function unb64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function fingerprint(jwk) {
  const canonical = JSON.stringify({crv:jwk.crv,kty:jwk.kty,x:jwk.x,y:jwk.y});
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(canonical));
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2,'0')).join('').match(/.{1,4}/g).join(' ').toUpperCase();
}
export async function getOrCreateDeviceKey() {
  let pair = await dbGet(KEY_ID);
  if (!pair) {
    pair = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, false, ['deriveBits']);
    await dbSet(KEY_ID, pair);
  }
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { pair, publicJwk, fingerprint: await fingerprint(publicJwk) };
}
export async function deriveChatKey(privateKey, peerPublicJwk) {
  const peer = await crypto.subtle.importKey('jwk', peerPublicJwk, {name:'ECDH',namedCurve:'P-256'}, false, []);
  const bits = await crypto.subtle.deriveBits({name:'ECDH',public:peer}, privateKey, 256);
  const material = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'HKDF',hash:'SHA-256',salt:enc.encode('DuoBond E2EE v1'),info:enc.encode('two-person-chat')},
    material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']
  );
}
export async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, enc.encode(text));
  return JSON.stringify({v:1,alg:'A256GCM',iv:b64(iv),ct:b64(ciphertext)});
}
export async function decryptText(key, body) {
  const packet = JSON.parse(body);
  if (packet.v !== 1 || packet.alg !== 'A256GCM') throw new Error('Unsupported encrypted message format');
  const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(packet.iv)},key,unb64(packet.ct));
  return dec.decode(plaintext);
}
