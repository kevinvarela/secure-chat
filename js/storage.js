// Chats guardados en este dispositivo (localStorage).
//
// Se guarda el código de cada sala y su historial para poder volver sin
// compartirlo de nuevo. Quedan en el navegador SIN cifrar: quien tenga acceso
// a este dispositivo/perfil puede verlos. El usuario los borra cuando quiera.

const INDEX_KEY = 'securechat.chats.v1';
const HISTORY_PREFIX = 'securechat.history.v1.';
const MAX_HISTORY = 500;

const read = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
};

const write = (key, value) => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false; // modo privado, cuota llena o almacenamiento bloqueado
  }
};

const isChat = c =>
  c && typeof c.id === 'string' && typeof c.code === 'string' && typeof c.name === 'string';

export function listChats() {
  const chats = read(INDEX_KEY, []);
  return (Array.isArray(chats) ? chats.filter(isChat) : []).sort(
    (a, b) => (b.lastOpened || 0) - (a.lastOpened || 0)
  );
}

const saveIndex = chats => write(INDEX_KEY, chats);

export function getChat(id) {
  return listChats().find(c => c.id === id) || null;
}

// Devuelve el chat con ese código, creándolo si no existe.
export function upsertChat({ code, role }) {
  const chats = listChats();
  let chat = chats.find(c => c.code === code);
  const now = Date.now();
  if (chat) {
    chat.lastOpened = now;
  } else {
    const id = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
    chat = { id, code, role, name: `Chat ${code.slice(0, 4).toUpperCase()}`, created: now, lastOpened: now };
    chats.push(chat);
  }
  saveIndex(chats);
  return chat;
}

export function renameChat(id, name) {
  const clean = String(name).trim().slice(0, 40);
  if (!clean) return;
  const chats = listChats();
  const chat = chats.find(c => c.id === id);
  if (!chat) return;
  chat.name = clean;
  saveIndex(chats);
}

export function deleteChat(id) {
  saveIndex(listChats().filter(c => c.id !== id));
  try {
    localStorage.removeItem(HISTORY_PREFIX + id);
  } catch {
    /* sin almacenamiento */
  }
}

// ---------- historial ----------

const isEntry = m =>
  m && typeof m.text === 'string' && typeof m.ts === 'number' && typeof m.mine === 'boolean';

export function loadHistory(id) {
  const list = read(HISTORY_PREFIX + id, []);
  return Array.isArray(list) ? list.filter(isEntry) : [];
}

export function appendHistory(id, entry) {
  const list = loadHistory(id);
  list.push(entry);
  write(HISTORY_PREFIX + id, list.slice(-MAX_HISTORY));
  const chats = listChats();
  const chat = chats.find(c => c.id === id);
  if (chat) {
    chat.lastMessage = entry.ts;
    saveIndex(chats);
  }
}
