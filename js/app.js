// Lógica principal: roles host / invitado sobre Trystero (WebRTC + señalización Nostr).
import { joinRoom } from '../vendor/trystero.js';
import {
  MAX_TEXT_CHARS,
  createIdentity,
  deriveRoomMaterial,
  derivePairKeys,
  formatCode,
  generateSecret,
  importPeerPublicKey,
  openMessage,
  parseCode,
  parseEnvelope,
  sealMessage
} from './crypto.js';
import * as ui from './ui.js';
import * as store from './storage.js';

const { el } = ui;

const APP_ID = 'p2p-securechat-v2';
const ACTION = 'msg';
const MAX_RECEIVE_BYTES = 64 * 1024;
const HANDSHAKE_TIMEOUT_MS = 20000;
const CONFIRM_TEXT = 'secure-chat-key-confirm';

// Par de claves efímero de esta pestaña (nunca sale del navegador).
const identityPromise = createIdentity();

// Sesión activa. `token` invalida callbacks de sesiones anteriores (evita carreras).
let session = null;
let sessionCounter = 0;

// ---------------------------------------------------------------------------
// Entrar / salir de una sala
// ---------------------------------------------------------------------------

async function startSession(role, secret) {
  const token = ++sessionCounter;
  ui.setBusy(true);
  await leaveSession({ silent: true });

  let material, identity;
  try {
    [material, identity] = await Promise.all([deriveRoomMaterial(secret), identityPromise]);
  } catch (err) {
    console.error(err);
    ui.toast('Tu navegador no soporta la criptografía necesaria', 'error');
    ui.setBusy(false);
    return;
  }
  if (token !== sessionCounter) return; // se inició otra sesión mientras derivábamos

  const code = formatCode(secret);
  // Se guarda en "Tus chats" para poder volver sin compartir el código de nuevo.
  const chat = store.upsertChat({ code, role });
  const history = store.loadHistory(chat.id);
  role = chat.role;

  const s = {
    token,
    role,
    chat,
    code,
    material,
    identity,
    peers: new Map(), // peerId -> estado criptográfico del par
    room: null,
    action: null
  };
  session = s;

  ui.showChat({ role, code: s.code, name: chat.name, history });
  ui.appendSystem(
    history.length
      ? 'Chat reabierto. Esperando a que la otra persona lo abra también…'
      : role === 'host'
        ? 'Sala creada. Comparte el código y espera a que la otra persona se conecte.'
        : 'Buscando al host de la sala…'
  );

  try {
    s.room = joinRoom(
      { appId: APP_ID, password: material.signalingPassword, maxReceiveBytes: MAX_RECEIVE_BYTES },
      material.roomId,
      {
        handshakeTimeoutMs: HANDSHAKE_TIMEOUT_MS,
        onPeerHandshake: (peerId, send, receive, isInitiator) =>
          peerHandshake(s, peerId, send, receive, isInitiator),
        onJoinError: details => {
          if (s !== session) return;
          console.warn('Error de unión', details);
          ui.toast('Un participante no superó la verificación y fue rechazado', 'error');
        }
      }
    );
  } catch (err) {
    console.error(err);
    ui.setConnection({ state: 'error', role, error: 'No se pudo iniciar la conexión P2P.' });
    return;
  }

  s.action = s.room.makeAction(ACTION, {
    onMessage: (data, ctx) => {
      if (s !== session) return;
      const peer = s.peers.get(ctx.peerId);
      if (!peer) return; // sin handshake válido no se acepta nada
      // Procesado en serie por par: el orden importa para el contador anti-replay.
      peer.queue = peer.queue.then(() => receiveMessage(s, peer, data)).catch(err => console.warn(err));
    }
  });

  s.room.onPeerJoin = peerId => {
    if (s !== session) return;
    const peer = s.peers.get(peerId);
    if (!peer) return;
    peer.joined = true;
    ui.toast(`Participante ${peer.label} conectado`, 'success');
    ui.appendSystem(`Participante ${peer.label} se unió. Número de seguridad: ${peer.safetyNumber}`);
    refreshPeers();
  };

  s.room.onPeerLeave = peerId => {
    if (s !== session) return;
    const peer = s.peers.get(peerId);
    s.peers.delete(peerId);
    if (peer?.joined) {
      ui.toast(`Participante ${peer.label} desconectado`);
      ui.appendSystem(`Participante ${peer.label} salió de la sala.`);
    }
    refreshPeers();
  };

  ui.setBusy(false);
  if (role === 'host') el.btnCopy.focus();
}

async function leaveSession({ silent = false } = {}) {
  const s = session;
  session = null;
  if (!s) return;
  s.peers.clear();
  if (!silent) {
    ui.showStart(); // la interfaz responde al instante; la desconexión sigue en segundo plano
    renderChats();
  }
  try {
    await s.room?.leave();
  } catch (err) {
    console.warn('Error al salir', err);
  }
}

// ---------------------------------------------------------------------------
// Handshake por par: ECDH efímero + confirmación de clave.
// Se ejecuta DESPUÉS de la verificación de contraseña de Trystero y ANTES de
// que el par cuente como conectado. Si lanza, Trystero descarta la conexión.
// ---------------------------------------------------------------------------

async function peerHandshake(s, peerId, send, receive, isInitiator) {
  const { identity, material } = s;
  const hello = { t: 'hello', pub: identity.publicB64 };

  const readHello = async () => {
    const { data } = await receive();
    if (!data || data.t !== 'hello' || typeof data.pub !== 'string') throw new Error('handshake inválido');
    return data.pub;
  };

  let theirPubB64;
  if (isInitiator) {
    await send(hello);
    theirPubB64 = await readHello();
  } else {
    theirPubB64 = await readHello();
    await send(hello);
  }
  if (theirPubB64 === identity.publicB64) throw new Error('conexión consigo mismo');

  const peerPublic = await importPeerPublicKey(theirPubB64);
  const keys = await derivePairKeys(identity, peerPublic, material.binding, material.roomId);

  // Confirmación: cada lado demuestra que derivó las mismas claves.
  const myConfirm = { t: 'confirm', ...(await sealMessage(keys.sendKey, 'confirm', 1, CONFIRM_TEXT)) };
  const checkConfirm = async () => {
    const { data } = await receive();
    const env = data?.t === 'confirm' ? parseEnvelope(data) : null;
    if (!env || env.seq !== 1) throw new Error('confirmación inválida');
    if ((await openMessage(keys.recvKey, 'confirm', env)) !== CONFIRM_TEXT) throw new Error('confirmación inválida');
  };
  if (isInitiator) {
    await send(myConfirm);
    await checkConfirm();
  } else {
    await checkConfirm();
    await send(myConfirm);
  }

  if (s !== session) throw new Error('sesión cerrada');

  const previous = s.peers.get(peerId);
  if (previous && previous.safetyNumber !== keys.safetyNumber) {
    ui.appendSystem(`⚠ La clave del participante ${previous.label} ha cambiado. Volved a comparar el número de seguridad.`);
  }

  s.peers.set(peerId, {
    id: peerId,
    ...keys,
    sendSeq: 0,
    recvSeq: 0,
    verified: false,
    joined: previous?.joined ?? false,
    queue: Promise.resolve()
  });
}

// ---------------------------------------------------------------------------
// Mensajes
// ---------------------------------------------------------------------------

async function receiveMessage(s, peer, data) {
  const env = parseEnvelope(data);
  if (!env) {
    console.warn('Mensaje con formato inválido descartado');
    return;
  }
  if (env.seq <= peer.recvSeq) {
    console.warn('Mensaje repetido o fuera de orden descartado (posible replay)');
    return;
  }
  let text;
  try {
    text = await openMessage(peer.recvKey, 'msg', env);
  } catch {
    ui.toast('Se descartó un mensaje que no pasó la verificación', 'error');
    return;
  }
  if (s !== session || s.peers.get(peer.id) !== peer) return;
  if (env.seq <= peer.recvSeq) return;
  peer.recvSeq = env.seq;
  if (text.length > MAX_TEXT_CHARS) return;
  const entry = { text, from: peer.label, mine: false, ts: Date.now() };
  store.appendHistory(s.chat.id, entry);
  ui.appendMessage(entry);
}

async function sendMessage(text) {
  const s = session;
  if (!s?.action) return;
  const targets = [...s.peers.values()].filter(p => p.joined);
  if (!targets.length) {
    ui.toast('No hay nadie conectado', 'error');
    return;
  }

  const entry = { text, mine: true, ts: Date.now() };
  store.appendHistory(s.chat.id, entry);
  const bubble = ui.appendMessage(entry);
  const results = await Promise.allSettled(
    targets.map(async peer => {
      const env = await sealMessage(peer.sendKey, 'msg', ++peer.sendSeq, text);
      await s.action.send(env, { target: peer.id });
    })
  );
  const failed = results.filter(r => r.status === 'rejected');
  if (failed.length) {
    failed.forEach(r => console.warn('Fallo al enviar', r.reason));
    bubble.markFailed(failed.length === targets.length ? 'no enviado' : 'no llegó a todos');
  }
}

// ---------------------------------------------------------------------------
// Interfaz
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Navegación en móvil: vista "panel" (código, participantes) <-> vista "chat".
// La vista de chat añade una entrada al historial para que el botón "atrás"
// del teléfono vuelva al panel en vez de salir de la página.
// ---------------------------------------------------------------------------

function openChat() {
  if (ui.getView() === 'chat') return;
  if (ui.isMobile() && history.state?.view !== 'chat') history.pushState({ view: 'chat' }, '');
  ui.setView('chat');
}

function openPanel() {
  if (history.state?.view === 'chat') history.back(); // popstate cambia la vista
  else ui.setView('panel');
}

window.addEventListener('popstate', () => {
  if (session && ui.getView() === 'chat') ui.setView('panel');
});

function refreshPeers() {
  const s = session;
  if (!s) return;
  const joined = [...s.peers.values()].filter(p => p.joined);
  // Al llegar el primer participante, el chat pasa a pantalla completa.
  if (joined.length > 0 && !s.hadPeers) openChat();
  s.hadPeers = joined.length > 0;
  ui.renderPeers(joined, peerId => {
    const peer = s.peers.get(peerId);
    if (!peer) return;
    peer.verified = true;
    ui.appendSystem(`Has verificado al participante ${peer.label}.`);
    refreshPeers();
  });
  ui.setConnection({ state: joined.length ? 'ready' : 'waiting', role: s.role, count: joined.length });
}

// ---------------------------------------------------------------------------
// Chats guardados
// ---------------------------------------------------------------------------

function renderChats() {
  ui.renderChatList(store.listChats(), {
    onOpen: id => {
      const chat = store.getChat(id);
      const secret = chat && parseCode(chat.code);
      if (!secret) {
        ui.toast('Este chat guardado está dañado', 'error');
        return;
      }
      startSession(chat.role, secret);
    },
    onRename: (id, name) => {
      store.renameChat(id, name);
      renderChats();
    },
    onDelete: id => {
      const chat = store.getChat(id);
      if (!chat) return;
      if (!confirm(`¿Borrar "${chat.name}"?\n\nSe eliminarán el código y el historial de este dispositivo. Para volver a hablar necesitarás que te compartan el código otra vez.`)) return;
      store.deleteChat(id);
      renderChats();
      ui.toast('Chat borrado');
    }
  });
}

renderChats();

el.btnHost.addEventListener('click', () => startSession('host', generateSecret()));

el.formJoin.addEventListener('submit', e => {
  e.preventDefault();
  const secret = parseCode(el.joinCode.value);
  if (!secret) {
    el.joinCode.classList.add('invalid');
    ui.toast('Código inválido: deben ser 32 caracteres hexadecimales', 'error');
    el.joinCode.focus();
    return;
  }
  el.joinCode.classList.remove('invalid');
  startSession('guest', secret);
});

el.joinCode.addEventListener('input', () => el.joinCode.classList.remove('invalid'));

el.btnCopy.addEventListener('click', async () => {
  if (!session) return;
  const ok = await ui.copyText(session.code, el.hostCode);
  ui.toast(ok ? 'Código copiado al portapapeles' : 'Pulsa Ctrl+C para copiar el código', ok ? 'success' : 'info');
});

el.btnLeave.addEventListener('click', () => {
  sessionCounter++; // cancela cualquier unión en curso
  if (history.state?.view === 'chat') history.replaceState(null, '');
  leaveSession();
});

el.btnBack.addEventListener('click', openPanel);
el.btnOpenChat.addEventListener('click', openChat);

// En móvil, tocar "Enviar" movería el foco al botón y cerraría el teclado.
// Evitamos que el botón tome el foco: si el teclado estaba abierto, sigue abierto
// hasta que el usuario lo cierre.
let keepKeyboard = false;
el.btnSend.addEventListener('pointerdown', e => {
  keepKeyboard = document.activeElement === el.messageInput;
  e.preventDefault();
});

el.formSend.addEventListener('submit', e => {
  e.preventDefault();
  if (keepKeyboard && document.activeElement !== el.messageInput) {
    el.messageInput.focus({ preventScroll: true });
  }
  keepKeyboard = false;
  const text = el.messageInput.value.trim();
  if (!text) return;
  if (text.length > MAX_TEXT_CHARS) {
    ui.toast(`Máximo ${MAX_TEXT_CHARS} caracteres`, 'error');
    return;
  }
  el.messageInput.value = '';
  sendMessage(text);
});

window.addEventListener('pagehide', () => session?.room?.leave());

// Permite enlaces de invitación con el código en el fragmento (#código):
// el fragmento nunca se envía a ningún servidor.
const fromHash = parseCode(decodeURIComponent(location.hash.slice(1)));
if (fromHash) {
  history.replaceState(null, '', location.pathname + location.search);
  el.joinCode.value = formatCode(fromHash);
}
