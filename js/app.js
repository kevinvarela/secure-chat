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
  sealMessage,
  newFileId,
  sealChunk,
  parseChunkFrame,
  openChunk,
  sha256Hex,
  toHex
} from './crypto.js';
import * as files from './files.js';
import * as ui from './ui.js';
import * as store from './storage.js';

const { el } = ui;

const APP_ID = 'p2p-securechat-v2';
const ACTION = 'msg';
const CHUNK_ACTION = 'chunk';
// Un trozo de archivo cifrado (64 KB + cabecera) es el payload más grande permitido.
const MAX_RECEIVE_BYTES = files.CHUNK_BYTES + 1024;
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
    action: null,
    chunkAction: null,
    incomingBytes: 0, // memoria reservada por recepciones en curso (todas las personas)
    fileQueue: Promise.resolve() // los archivos salientes se envían de uno en uno
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

  s.chunkAction = s.room.makeAction(CHUNK_ACTION, {
    onMessage: (data, ctx) => {
      if (s !== session) return;
      const peer = s.peers.get(ctx.peerId);
      if (!peer) return;
      // Misma cola que los mensajes: el anuncio del archivo siempre se procesa antes que sus trozos.
      peer.queue = peer.queue.then(() => receiveChunk(s, peer, data)).catch(err => console.warn(err));
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
    if (peer) abortIncoming(s, peer, 'Transferencia interrumpida: el participante se desconectó.');
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
  for (const peer of s.peers.values()) abortIncoming(s, peer);
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
    queue: Promise.resolve(), // procesado en serie de lo recibido
    sendChain: Promise.resolve(), // envíos cifrados en orden (el contador debe llegar creciente)
    incoming: new Map() // fileId -> transferencia en curso
  });
}

// ---------------------------------------------------------------------------
// Mensajes
// ---------------------------------------------------------------------------

// Contenido de un mensaje cifrado: JSON {k:'text', text} o {k:'file', ...anuncio}.
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
  let plain;
  try {
    plain = await openMessage(peer.recvKey, 'msg', env);
  } catch {
    ui.toast('Se descartó un mensaje que no pasó la verificación', 'error');
    return;
  }
  if (s !== session || s.peers.get(peer.id) !== peer) return;
  if (env.seq <= peer.recvSeq) return;
  peer.recvSeq = env.seq;

  let body;
  try {
    body = JSON.parse(plain);
  } catch {
    body = null;
  }
  if (body?.k === 'text' && typeof body.text === 'string') {
    if (body.text.length > MAX_TEXT_CHARS) return;
    const id = typeof body.id === 'string' && ENTRY_ID_RE.test(body.id) ? body.id : newEntryId();
    const entry = { id, text: body.text, from: peer.label, mine: false, ts: Date.now() };
    store.appendHistory(s.chat.id, entry);
    ui.appendMessage(entry);
  } else if (body?.k === 'file') {
    acceptOffer(s, peer, body);
  } else {
    console.warn('Tipo de mensaje desconocido descartado');
  }
}

// Envía un objeto cifrado a un par. Encadenado por par para que los contadores
// salgan en orden aunque se envíen varios mensajes a la vez.
function sendSecure(s, peer, body) {
  const run = peer.sendChain.then(async () => {
    const env = await sealMessage(peer.sendKey, 'msg', ++peer.sendSeq, JSON.stringify(body));
    await s.action.send(env, { target: peer.id });
  });
  peer.sendChain = run.catch(() => {});
  return run;
}

const connectedPeers = s => [...s.peers.values()].filter(p => p.joined);

// Identificador aleatorio de 128 bits para cada mensaje/archivo. Viaja dentro del
// mensaje cifrado y evita duplicar entradas en el historial compartido por pestañas.
const newEntryId = () => toHex(newFileId());
const ENTRY_ID_RE = /^[0-9a-f]{32}$/;

async function sendMessage(text) {
  const s = session;
  if (!s?.action) return;
  const targets = connectedPeers(s);
  if (!targets.length) {
    ui.toast('No hay nadie conectado', 'error');
    return;
  }

  const id = newEntryId();
  const entry = { id, text, mine: true, ts: Date.now() };
  store.appendHistory(s.chat.id, entry);
  const bubble = ui.appendMessage(entry);
  const results = await Promise.allSettled(targets.map(peer => sendSecure(s, peer, { k: 'text', id, text })));
  const failed = results.filter(r => r.status === 'rejected');
  if (failed.length) {
    failed.forEach(r => console.warn('Fallo al enviar', r.reason));
    bubble.markFailed(failed.length === targets.length ? 'no enviado' : 'no llegó a todos');
  }
}

// ---------------------------------------------------------------------------
// Archivos
//
//  1. Anuncio {id, nombre, tamaño, nº de trozos, SHA-256} por el canal de mensajes
//     (cifrado, autenticado y con contador anti-replay).
//  2. Trozos binarios de 64 KB, cada uno cifrado con AES-GCM y ligado por AAD a
//     (id, índice, total).
//  3. El receptor exige tamaños exactos, no acepta trozos duplicados ni de archivos
//     no anunciados, limita memoria y transferencias simultáneas, y al final
//     comprueba el SHA-256 del archivo completo antes de mostrarlo.
// ---------------------------------------------------------------------------

const fileEntry = (name, size, mine, from) => ({
  text: '',
  mine,
  from,
  ts: Date.now(),
  file: { name, size, sizeLabel: files.formatSize(size) }
});

function sendFiles(fileList) {
  const s = session;
  if (!s) return;
  for (const file of fileList) {
    if (!file.size) {
      ui.toast(`"${files.sanitizeFileName(file.name)}" está vacío`, 'error');
      continue;
    }
    if (file.size > files.MAX_FILE_BYTES) {
      ui.toast(`"${files.sanitizeFileName(file.name)}" supera el límite de ${files.formatSize(files.MAX_FILE_BYTES)}`, 'error');
      continue;
    }
    // Se envían de uno en uno para no saturar la conexión ni la memoria.
    const name = files.sanitizeFileName(file.name);
    const entry = fileEntry(name, file.size, true);
    const card = ui.appendFile({ ...entry, ...entry.file });
    s.fileQueue = s.fileQueue.then(() => sendFile(s, file, name, card, entry)).catch(err => {
      console.warn('Fallo al enviar archivo', err);
      card.fail('No se pudo enviar el archivo.');
    });
  }
}

async function sendFile(s, file, name, card, entry) {
  if (s !== session) return card.fail('Envío cancelado.');
  const targets = connectedPeers(s);
  if (!targets.length) return card.fail('No enviado: no hay nadie conectado.');

  card.setProgress(0, 'Preparando…');
  const bytes = new Uint8Array(await file.arrayBuffer());
  const hash = await sha256Hex(bytes);
  const fileId = newFileId();
  const total = files.chunkCount(bytes.length);
  const offer = { k: 'file', id: toHex(fileId), name, size: bytes.length, chunks: total, hash };
  entry.id = offer.id;

  const sent = new Map(targets.map(p => [p.id, 0]));
  const updateProgress = () => {
    const min = Math.min(...sent.values());
    card.setProgress(min / total, `Enviando… ${Math.round((min / total) * 100)}%`);
  };

  const results = await Promise.allSettled(
    targets.map(async peer => {
      await sendSecure(s, peer, offer);
      for (let i = 0; i < total; i++) {
        if (s !== session || s.peers.get(peer.id) !== peer) throw new Error('participante desconectado');
        const start = i * files.CHUNK_BYTES;
        const frame = await sealChunk(peer.sendKey, fileId, i, total, bytes.subarray(start, start + files.CHUNK_BYTES));
        await s.chunkAction.send(frame, { target: peer.id }); // Trystero aplica control de flujo
        sent.set(peer.id, i + 1);
        updateProgress();
      }
    })
  );

  const failed = results.filter(r => r.status === 'rejected').length;
  if (failed === targets.length) return card.fail('No se pudo enviar el archivo.');
  store.appendHistory(s.chat.id, entry);
  const imageType = files.sniffImageType(bytes);
  card.complete({
    blob: file.slice(0, file.size, imageType || 'application/octet-stream'),
    imageType,
    risky: files.isRiskyName(name),
    label: failed ? 'No llegó a todos los participantes.' : 'Enviado ✓'
  });
}

function acceptOffer(s, peer, body) {
  const offer = files.parseOffer(body);
  if (!offer) {
    console.warn('Anuncio de archivo inválido descartado');
    return;
  }
  if (peer.incoming.has(offer.id)) return; // id repetido: se ignora
  if (peer.incoming.size >= files.MAX_INCOMING_PER_PEER || s.incomingBytes + offer.size > files.MAX_INCOMING_TOTAL_BYTES) {
    ui.appendSystem(`Se rechazó "${offer.name}" de ${peer.label}: demasiadas transferencias simultáneas.`);
    return;
  }

  const entry = { ...fileEntry(offer.name, offer.size, false, peer.label), id: offer.id };
  const transfer = {
    ...offer,
    parts: new Array(offer.chunks),
    received: 0,
    entry,
    card: ui.appendFile({ ...entry, ...entry.file }),
    timer: null
  };
  s.incomingBytes += offer.size;
  peer.incoming.set(offer.id, transfer);
  armTimeout(s, peer, transfer);
}

function armTimeout(s, peer, transfer) {
  clearTimeout(transfer.timer);
  transfer.timer = setTimeout(
    () => dropTransfer(s, peer, transfer, 'Transferencia cancelada: no llegaron datos durante 60 s.'),
    files.TRANSFER_TIMEOUT_MS
  );
}

function dropTransfer(s, peer, transfer, reason) {
  if (peer.incoming.get(transfer.id) !== transfer) return;
  clearTimeout(transfer.timer);
  peer.incoming.delete(transfer.id);
  s.incomingBytes -= transfer.size;
  transfer.parts = null; // libera la memoria
  if (reason) transfer.card.fail(reason);
}

function abortIncoming(s, peer, reason) {
  for (const transfer of [...peer.incoming.values()]) dropTransfer(s, peer, transfer, reason);
}

async function receiveChunk(s, peer, data) {
  const frame = parseChunkFrame(data, files.CHUNK_BYTES);
  if (!frame) return;
  const transfer = peer.incoming.get(frame.fileIdHex);
  if (!transfer) return; // archivo no anunciado o ya terminado
  if (frame.index >= transfer.chunks || transfer.parts[frame.index]) return; // fuera de rango o duplicado

  let plain;
  try {
    plain = await openChunk(peer.recvKey, frame, transfer.chunks);
  } catch {
    return dropTransfer(s, peer, transfer, 'Archivo descartado: un fragmento no pasó la verificación.');
  }
  if (s !== session || peer.incoming.get(transfer.id) !== transfer) return;
  if (plain.length !== files.expectedChunkSize(transfer.size, frame.index, transfer.chunks)) {
    return dropTransfer(s, peer, transfer, 'Archivo descartado: tamaño de fragmento incorrecto.');
  }

  transfer.parts[frame.index] = plain;
  transfer.received++;
  transfer.card.setProgress(
    transfer.received / transfer.chunks,
    `Recibiendo… ${Math.round((transfer.received / transfer.chunks) * 100)}%`
  );
  armTimeout(s, peer, transfer);
  if (transfer.received < transfer.chunks) return;

  // Completo: verificar el hash del archivo entero antes de mostrar nada.
  const imageType = files.sniffImageType(transfer.parts[0]);
  const blob = new Blob(transfer.parts);
  const ok = (await sha256Hex(await blob.arrayBuffer())) === transfer.hash;
  if (peer.incoming.get(transfer.id) !== transfer) return;
  if (!ok) return dropTransfer(s, peer, transfer, 'Archivo descartado: la huella SHA-256 no coincide.');

  dropTransfer(s, peer, transfer); // libera la reserva; la tarjeta se completa abajo
  store.appendHistory(s.chat.id, transfer.entry);
  transfer.card.complete({
    // slice() solo reetiqueta el tipo, sin copiar. Lo que no es imagen verificada se
    // marca como octet-stream para que el navegador nunca lo interprete (HTML, SVG...).
    blob: blob.slice(0, blob.size, imageType || 'application/octet-stream'),
    imageType,
    risky: files.isRiskyName(transfer.name)
  });
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

// Adjuntar archivos: botón, arrastrar y soltar, o pegar (Ctrl+V)
el.btnAttach.addEventListener('click', () => el.fileInput.click());
el.fileInput.addEventListener('change', () => {
  sendFiles([...el.fileInput.files]);
  el.fileInput.value = '';
});

const chatArea = el.messages.parentElement;
let dragDepth = 0;
const canDrop = e => session && !el.btnAttach.disabled && [...(e.dataTransfer?.types || [])].includes('Files');
chatArea.addEventListener('dragenter', e => {
  if (!canDrop(e)) return;
  e.preventDefault();
  dragDepth++;
  el.dropZone.hidden = false;
});
chatArea.addEventListener('dragover', e => {
  if (canDrop(e)) e.preventDefault();
});
chatArea.addEventListener('dragleave', () => {
  if (--dragDepth <= 0) {
    dragDepth = 0;
    el.dropZone.hidden = true;
  }
});
chatArea.addEventListener('drop', e => {
  dragDepth = 0;
  el.dropZone.hidden = true;
  if (!canDrop(e)) return;
  e.preventDefault();
  sendFiles([...e.dataTransfer.files]);
});
el.messageInput.addEventListener('paste', e => {
  const pasted = [...(e.clipboardData?.files || [])];
  if (!pasted.length) return;
  e.preventDefault();
  sendFiles(pasted);
});
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
