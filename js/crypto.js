// Criptografía del chat (Web Crypto API).
//
// Modelo:
//  - Cada sala se identifica con un SECRETO aleatorio de 128 bits (el "código").
//  - Del secreto se derivan con HKDF, de forma independiente:
//      * roomId      -> nombre público de la sala en Trystero (no revela el secreto)
//      * signaling   -> contraseña de Trystero (cifra el SDP que pasa por los relays)
//      * binding     -> sal para derivar las claves por par (sin el secreto no hay claves)
//  - Cada pestaña genera un par ECDH P-256 efímero (la clave privada no es exportable
//    y desaparece al cerrar la pestaña => secreto hacia adelante a nivel de sesión).
//  - Con cada par se acuerda una clave ECDH y se derivan DOS claves AES-GCM-256,
//    una por dirección, ligadas a ambas claves públicas.
//  - Cada mensaje lleva un contador estrictamente creciente autenticado (AAD) => anti-replay.
//  - El "número de seguridad" permite verificar fuera de banda que no hay MITM.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const PROTOCOL = 'secure-chat/v2';
export const SECRET_BYTES = 16; // 128 bits
export const MAX_TEXT_CHARS = 2000;
// Tope de un mensaje cifrado (texto o anuncio de archivo, serializado en JSON).
export const MAX_CIPHERTEXT_BYTES = 16 * 1024;
const IV_BYTES = 12;

// ---------- utilidades de codificación ----------

export const toHex = bytes =>
  Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

export const fromHex = hex => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

export const toB64 = bytes => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};

export const fromB64 = str => {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
};

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const decodeB64Strict = (value, maxBytes) => {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 + 4) return null;
  if (!B64_RE.test(value)) return null;
  try {
    return fromB64(value);
  } catch {
    return null;
  }
};

// ---------- código de sala ----------

export const generateSecret = () =>
  globalThis.crypto.getRandomValues(new Uint8Array(SECRET_BYTES));

// Formato legible: 8 grupos de 4 hex -> "1a2b-3c4d-..."
export const formatCode = secret => toHex(secret).match(/.{4}/g).join('-');

// Acepta el código con o sin guiones/espacios; devuelve el secreto o null si es inválido.
export const parseCode = input => {
  if (typeof input !== 'string') return null;
  const hex = input.toLowerCase().replace(/[\s-]/g, '');
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  return fromHex(hex);
};

const hkdfBits = async (ikm, salt, info, bits) => {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits', 'deriveKey']);
  return new Uint8Array(
    await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, base, bits)
  );
};

export async function deriveRoomMaterial(secret) {
  const salt = enc.encode(PROTOCOL);
  const [roomId, signaling, binding] = await Promise.all([
    hkdfBits(secret, salt, `${PROTOCOL}/room-id`, 128),
    hkdfBits(secret, salt, `${PROTOCOL}/signaling`, 256),
    hkdfBits(secret, salt, `${PROTOCOL}/pair-binding`, 256)
  ]);
  return { roomId: toHex(roomId), signalingPassword: toHex(signaling), binding };
}

// ---------- identidad efímera ----------

export async function createIdentity() {
  const keyPair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey));
  return { privateKey: keyPair.privateKey, publicRaw, publicB64: toB64(publicRaw) };
}

// Valida e importa una clave pública P-256 sin comprimir (65 bytes, prefijo 0x04).
export async function importPeerPublicKey(b64) {
  const raw = decodeB64Strict(b64, 65);
  if (!raw || raw.length !== 65 || raw[0] !== 0x04) throw new Error('clave pública inválida');
  // importKey verifica que el punto pertenezca a la curva.
  const key = await subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return { key, raw };
}

const compareBytes = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

// Deriva las claves de sesión con un par concreto.
export async function derivePairKeys(identity, peerPublic, binding, roomId) {
  const shared = new Uint8Array(
    await subtle.deriveBits({ name: 'ECDH', public: peerPublic.key }, identity.privateKey, 256)
  );
  const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const dirKey = (from, to) =>
    subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: binding,
        info: concat(enc.encode(`${PROTOCOL}/msg/${roomId}/`), from, to)
      },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

  const [sendKey, recvKey] = await Promise.all([
    dirKey(identity.publicRaw, peerPublic.raw),
    dirKey(peerPublic.raw, identity.publicRaw)
  ]);

  // Número de seguridad: idéntico en ambos lados (claves públicas ordenadas).
  const [lo, hi] =
    compareBytes(identity.publicRaw, peerPublic.raw) < 0
      ? [identity.publicRaw, peerPublic.raw]
      : [peerPublic.raw, identity.publicRaw];
  const digest = new Uint8Array(
    await subtle.digest('SHA-256', concat(enc.encode(`${PROTOCOL}/safety/${roomId}/`), lo, hi))
  );
  const groups = [];
  for (let i = 0; i < 6; i++) {
    const n = ((digest[i * 4] << 24) | (digest[i * 4 + 1] << 16) | (digest[i * 4 + 2] << 8) | digest[i * 4 + 3]) >>> 0;
    groups.push(String(n % 100000).padStart(5, '0'));
  }

  const peerDigest = new Uint8Array(await subtle.digest('SHA-256', peerPublic.raw));

  return {
    sendKey,
    recvKey,
    safetyNumber: groups.join(' '),
    // Etiqueta derivada de la clave (no del peerId). 4 bytes: falsificarla exigiría
    // generar del orden de 2^32 claves; además la app avisa si dos coinciden.
    label: toHex(peerDigest.slice(0, 4))
  };
}

// ---------- cifrado de mensajes ----------

const aad = (kind, seq) => enc.encode(`${PROTOCOL}/${kind}/${seq}`);

export async function sealMessage(key, kind, seq, text) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kind, seq) }, key, enc.encode(text))
  );
  return { v: 2, n: seq, iv: toB64(iv), ct: toB64(ct) };
}

// Valida el formato del sobre recibido. Devuelve null si es inválido.
export function parseEnvelope(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const { v, n, iv, ct } = payload;
  if (v !== 2 || !Number.isSafeInteger(n) || n < 1) return null;
  const ivBytes = decodeB64Strict(iv, IV_BYTES);
  const ctBytes = decodeB64Strict(ct, MAX_CIPHERTEXT_BYTES);
  if (!ivBytes || ivBytes.length !== IV_BYTES) return null;
  if (!ctBytes || ctBytes.length < 17 || ctBytes.length > MAX_CIPHERTEXT_BYTES) return null;
  return { seq: n, iv: ivBytes, ct: ctBytes };
}

export async function openMessage(key, kind, envelope) {
  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: envelope.iv, additionalData: aad(kind, envelope.seq) },
    key,
    envelope.ct
  );
  return dec.decode(plain);
}

// ---------- trozos de archivo (binario) ----------
//
// Formato del marco: [id 16 B][índice u32 BE][iv 12 B][ciphertext + tag 16 B]
// El AAD liga cada trozo a su archivo, a su posición y al número total de trozos:
// no se pueden reordenar, mezclar entre archivos ni truncar sin que falle.

export const FILE_ID_BYTES = 16;
const FRAME_HEADER = FILE_ID_BYTES + 4 + IV_BYTES;

const u32 = n => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

const chunkAad = (fileId, index, total) => concat(enc.encode(`${PROTOCOL}/chunk/`), fileId, u32(index), u32(total));

export const newFileId = () => globalThis.crypto.getRandomValues(new Uint8Array(FILE_ID_BYTES));

export async function sealChunk(key, fileId, index, total, data) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: chunkAad(fileId, index, total) }, key, data)
  );
  return concat(fileId, u32(index), iv, ct);
}

// Valida el marco recibido. Devuelve null si no tiene un formato posible.
export function parseChunkFrame(data, maxPlainBytes) {
  let bytes = null;
  if (data instanceof Uint8Array) bytes = data;
  else if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
  if (!bytes || bytes.length < FRAME_HEADER + 17 || bytes.length > FRAME_HEADER + maxPlainBytes + 16) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fileId = bytes.slice(0, FILE_ID_BYTES);
  return {
    fileId,
    fileIdHex: toHex(fileId),
    index: view.getUint32(FILE_ID_BYTES),
    iv: bytes.slice(FILE_ID_BYTES + 4, FRAME_HEADER),
    ct: bytes.slice(FRAME_HEADER)
  };
}

export async function openChunk(key, frame, total) {
  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv: frame.iv, additionalData: chunkAad(frame.fileId, frame.index, total) },
      key,
      frame.ct
    )
  );
}

export const sha256Hex = async data => toHex(new Uint8Array(await subtle.digest('SHA-256', data)));
