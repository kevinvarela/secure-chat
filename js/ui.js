// Capa de interfaz: todo el DOM se construye con textContent (nunca innerHTML),
// así que ningún dato recibido de la red puede inyectar HTML.

const $ = id => document.getElementById(id);

export const el = {
  screenStart: $('screen-start'),
  screenChat: $('screen-chat'),
  btnHost: $('btn-host'),
  formJoin: $('form-join'),
  joinCode: $('join-code'),
  btnJoin: $('btn-join'),
  roleBadge: $('role-badge'),
  hostCodeCard: $('host-code-card'),
  hostCode: $('host-code'),
  btnCopy: $('btn-copy'),
  peerList: $('peer-list'),
  peerEmpty: $('peer-empty'),
  statusDot: $('status-dot'),
  statusText: $('status-text'),
  btnLeave: $('btn-leave'),
  roomTitle: $('room-title'),
  chatName: $('chat-name'),
  savedChats: $('saved-chats'),
  chatList: $('chat-list'),
  e2eeBadge: $('e2ee-badge'),
  overlay: $('chat-overlay'),
  overlayTitle: $('overlay-title'),
  overlayText: $('overlay-text'),
  messages: $('messages'),
  formSend: $('form-send'),
  messageInput: $('message-input'),
  btnSend: $('btn-send'),
  btnBack: $('btn-back'),
  btnAttach: $('btn-attach'),
  fileInput: $('file-input'),
  dropZone: $('drop-zone'),
  btnOpenChat: $('btn-open-chat'),
  unreadBadge: $('unread-badge'),
  toasts: $('toast-container')
};

// ---------- vistas en móvil ----------

const mobileQuery = window.matchMedia('(max-width: 767px)');
export const isMobile = () => mobileQuery.matches;

let unread = 0;

export function getView() {
  return el.screenChat.dataset.view;
}

export function setView(view) {
  el.screenChat.dataset.view = view;
  if (view === 'chat') {
    unread = 0;
    el.unreadBadge.hidden = true;
    el.messages.scrollTop = el.messages.scrollHeight;
    if (isMobile() && !el.messageInput.disabled) el.messageInput.focus({ preventScroll: true });
  }
}

function countUnread() {
  if (!isMobile() || getView() === 'chat') return;
  unread++;
  el.unreadBadge.textContent = unread > 99 ? '99+' : String(unread);
  el.unreadBadge.hidden = false;
}

const h = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

// ---------- toasts ----------

export function toast(message, type = 'info') {
  const node = h('div', `toast toast-${type}`, message);
  el.toasts.appendChild(node);
  requestAnimationFrame(() => node.classList.add('show'));
  setTimeout(() => {
    node.classList.remove('show');
    setTimeout(() => node.remove(), 300);
  }, 3200);
}

// ---------- pantallas ----------

export function showStart() {
  revokeObjectUrls();
  el.screenChat.hidden = true;
  el.screenStart.hidden = false;
  el.messages.replaceChildren();
  el.peerList.replaceChildren();
  el.joinCode.value = '';
  el.joinCode.classList.remove('invalid');
  el.messageInput.value = '';
  setBusy(false);
}

// Con historial previo el overlay no tapa los mensajes: el estado se ve en el pie.
let hasHistory = false;

export function showChat({ role, code, name, history = [] }) {
  el.screenStart.hidden = true;
  el.screenChat.hidden = false;
  el.roleBadge.textContent = role === 'host' ? 'Host' : 'Invitado';
  el.chatName.textContent = name;
  el.roomTitle.textContent = name;
  el.hostCode.value = code;
  revokeObjectUrls();
  el.messages.replaceChildren();
  for (const m of history) {
    if (m.file) appendFile({ ...m, ...m.file, restored: true });
    else appendMessage({ ...m, restored: true });
  }
  hasHistory = history.length > 0;
  renderPeers([]);
  setConnection({ state: 'waiting', role });
  setView('panel');
}

export function setBusy(busy) {
  el.btnHost.disabled = busy;
  el.btnJoin.disabled = busy;
}

// ---------- estado de conexión ----------

export function setConnection({ state, role, count = 0, error }) {
  const ready = state === 'ready';
  el.statusDot.className = `dot ${ready ? 'dot-ok' : state === 'error' ? 'dot-err' : 'dot-wait'}`;
  el.statusText.className = ready ? 'status-ok' : state === 'error' ? 'status-err' : 'status-wait';
  el.statusText.textContent = ready
    ? `${count} ${count === 1 ? 'participante conectado' : 'participantes conectados'}`
    : state === 'error'
      ? 'Error de conexión'
      : role === 'host'
        ? 'Esperando invitados…'
        : 'Buscando al host…';

  el.e2eeBadge.className = `badge ${ready ? 'badge-on' : 'badge-off'}`;
  el.e2eeBadge.textContent = ready ? 'Cifrado E2E activo' : 'Sin conexión cifrada';

  el.messageInput.disabled = !ready;
  el.btnSend.disabled = !ready;
  el.btnAttach.disabled = !ready;

  el.overlay.classList.toggle('is-hidden', ready || (hasHistory && state !== 'error'));
  el.overlay.classList.toggle('is-error', state === 'error');
  if (state === 'error') {
    el.overlayTitle.textContent = 'No se pudo conectar';
    el.overlayText.textContent = error || '';
  } else if (role === 'host') {
    el.overlayTitle.textContent = 'Esperando a la otra persona…';
    el.overlayText.textContent = 'Comparte el código de la sala. En cuanto alguien entre, se establecerá una clave cifrada solo para ustedes.';
  } else {
    el.overlayTitle.textContent = 'Conectando con el host…';
    el.overlayText.textContent = 'El host debe tener la sala abierta. Puede tardar unos segundos.';
  }
}

// ---------- participantes ----------

export function renderPeers(peers, onVerify) {
  el.peerList.replaceChildren(
    ...peers.map(peer => {
      const li = h('li', 'peer');
      const head = h('div', 'peer-head');
      head.appendChild(h('span', '', `Participante ${peer.label}`));
      if (peer.verified) {
        head.appendChild(h('span', 'peer-verified', '✔ Verificado'));
      } else {
        const btn = h('button', 'btn btn-ghost btn-small', 'Marcar verificado');
        btn.type = 'button';
        btn.addEventListener('click', () => onVerify?.(peer.id));
        head.appendChild(btn);
      }
      li.appendChild(head);
      li.appendChild(h('span', 'hint', 'Número de seguridad'));
      li.appendChild(h('span', 'peer-safety', peer.safetyNumber));
      return li;
    })
  );
  el.peerEmpty.hidden = peers.length > 0;
}

// ---------- mensajes ----------

const formatTime = ts => {
  const d = new Date(ts);
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toDateString() === new Date().toDateString()
    ? time
    : `${d.toLocaleDateString([], { day: '2-digit', month: '2-digit' })} ${time}`;
};

export function appendMessage({ text, from, mine, ts = Date.now(), restored = false }) {
  const wrap = h('div', `msg ${mine ? 'msg-me' : 'msg-peer'}`);
  const inner = h('div', 'msg-inner');
  inner.appendChild(h('span', 'msg-meta', mine ? 'Tú' : `Participante ${from}`));
  inner.appendChild(h('p', 'msg-bubble', text));
  const meta = h('span', 'msg-meta', formatTime(ts));
  inner.appendChild(meta);
  wrap.appendChild(inner);
  if (restored) wrap.classList.add('msg-restored');
  pushMessage(wrap);
  if (!mine && !restored) countUnread();
  return {
    markFailed(reason) {
      wrap.classList.add('msg-failed');
      meta.textContent = `${meta.textContent} · ${reason}`;
    }
  };
}

// ---------- archivos ----------

// URLs blob: creadas en esta sesión; se liberan al cambiar de chat.
const objectUrls = new Set();
function revokeObjectUrls() {
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls.clear();
}

const extLabel = name => {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i + 1, i + 5) : 'file';
};

// Tarjeta de archivo. Devuelve un controlador para actualizar el progreso y el resultado.
export function appendFile({ name, size, sizeLabel, mine, from, ts = Date.now(), restored = false }) {
  const wrap = h('div', `msg ${mine ? 'msg-me' : 'msg-peer'}`);
  if (restored) wrap.classList.add('msg-restored');
  const inner = h('div', 'msg-inner');
  inner.appendChild(h('span', 'msg-meta', mine ? 'Tú' : `Participante ${from}`));

  const card = h('div', 'msg-bubble file-card');
  const row = h('div', 'file-row');
  const info = h('div', 'file-info');
  const nameEl = h('span', 'file-name', name);
  nameEl.title = name;
  info.append(nameEl, h('span', 'file-size', sizeLabel));
  row.append(h('span', 'file-icon', extLabel(name)), info);
  card.appendChild(row);

  const bar = h('div', 'file-progress');
  const fill = h('span');
  bar.appendChild(fill);
  const status = h('span', 'file-status');

  if (restored) {
    status.textContent = 'Archivo no disponible: los archivos no se guardan en el historial.';
    card.appendChild(status);
  } else {
    card.append(bar, status);
    status.textContent = mine ? 'Enviando…' : 'Recibiendo…';
  }

  inner.appendChild(card);
  inner.appendChild(h('span', 'msg-meta', formatTime(ts)));
  wrap.appendChild(inner);
  pushMessage(wrap);
  if (!mine && !restored) countUnread();

  return {
    setProgress(fraction, label) {
      fill.style.width = `${Math.round(Math.min(1, Math.max(0, fraction)) * 100)}%`;
      if (label) status.textContent = label;
    },
    // blob: contenido final; imageType solo si se verificó por magic bytes
    complete({ blob, imageType, risky, label }) {
      bar.remove();
      const url = URL.createObjectURL(blob);
      objectUrls.add(url);
      if (imageType) {
        const img = h('img', 'file-thumb');
        img.alt = name;
        img.decoding = 'async';
        img.src = url;
        img.addEventListener('load', () => {
          const box = el.messages;
          if (box.scrollHeight - box.scrollTop - box.clientHeight < 300) box.scrollTop = box.scrollHeight;
        });
        card.insertBefore(img, row);
      }
      if (risky) {
        card.appendChild(h('span', 'file-warn', '⚠ Tipo de archivo que puede ejecutar código. Ábrelo solo si confías plenamente en quien lo envía.'));
      }
      const a = h('a', 'file-download', 'Descargar');
      a.href = url;
      a.download = name; // fuerza la descarga: nunca se renderiza dentro de la app
      a.rel = 'noopener';
      card.appendChild(a);
      status.textContent = label || '';
      if (!label) status.remove();
    },
    fail(reason) {
      wrap.classList.add('file-failed');
      bar.remove();
      status.textContent = reason;
    }
  };
}

export function appendSystem(text) {
  const wrap = h('div', 'msg msg-system');
  wrap.appendChild(h('p', 'msg-bubble', text));
  pushMessage(wrap);
}

function pushMessage(node) {
  const box = el.messages;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  box.appendChild(node);
  if (nearBottom || node.classList.contains('msg-me')) box.scrollTop = box.scrollHeight;
}

// ---------- portapapeles ----------

export async function copyText(text, inputFallback) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Sin permiso de portapapeles: dejamos el texto seleccionado para Ctrl+C.
    inputFallback?.focus();
    inputFallback?.select();
    return false;
  }
}

// ---------- lista de chats guardados ----------

const formatDate = ts =>
  ts ? new Date(ts).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';

export function renderChatList(chats, { onOpen, onRename, onDelete }) {
  el.savedChats.hidden = chats.length === 0;
  el.chatList.replaceChildren(
    ...chats.map(chat => {
      const li = h('li', 'chat-item');
      const main = h('div', 'chat-item-main');
      const name = h('span', 'chat-item-name', chat.name);
      const role = chat.role === 'host' ? 'Host' : 'Invitado';
      const last = chat.lastMessage || chat.lastOpened;
      main.append(name, h('span', 'chat-item-meta', `${role} · ${formatDate(last)} · ${chat.code.slice(0, 9)}…`));

      const actions = h('div', 'chat-item-actions');
      const btnOpen = h('button', 'btn btn-primary btn-small', 'Abrir');
      const btnRename = h('button', 'btn btn-ghost btn-small', '✎');
      const btnDelete = h('button', 'btn btn-ghost btn-small btn-danger', 'Borrar');
      btnRename.title = 'Renombrar';
      btnRename.setAttribute('aria-label', `Renombrar ${chat.name}`);
      btnDelete.setAttribute('aria-label', `Borrar ${chat.name}`);
      for (const b of [btnOpen, btnRename, btnDelete]) b.type = 'button';
      btnOpen.addEventListener('click', () => onOpen(chat.id));
      btnDelete.addEventListener('click', () => onDelete(chat.id));
      btnRename.addEventListener('click', () => {
        // Edición en línea: Intro o perder el foco guarda, Escape cancela.
        const input = h('input', 'input');
        input.value = chat.name;
        input.maxLength = 40;
        input.setAttribute('aria-label', 'Nuevo nombre');
        let done = false;
        const finish = save => {
          if (done) return;
          done = true;
          if (save) onRename(chat.id, input.value);
          else input.replaceWith(name);
        };
        input.addEventListener('keydown', e => {
          if (e.key === 'Enter') finish(true);
          if (e.key === 'Escape') finish(false);
        });
        input.addEventListener('blur', () => finish(true));
        name.replaceWith(input);
        input.focus();
        input.select();
      });
      actions.append(btnOpen, btnRename, btnDelete);
      li.append(main, actions);
      return li;
    })
  );
}
