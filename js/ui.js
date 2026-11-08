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
  roomLabel: $('room-label'),
  e2eeBadge: $('e2ee-badge'),
  overlay: $('chat-overlay'),
  overlayTitle: $('overlay-title'),
  overlayText: $('overlay-text'),
  messages: $('messages'),
  formSend: $('form-send'),
  messageInput: $('message-input'),
  btnSend: $('btn-send'),
  btnBack: $('btn-back'),
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
  el.screenChat.hidden = true;
  el.screenStart.hidden = false;
  el.messages.replaceChildren();
  el.peerList.replaceChildren();
  el.joinCode.value = '';
  el.joinCode.classList.remove('invalid');
  el.messageInput.value = '';
  setBusy(false);
}

export function showChat({ role, code, roomId }) {
  el.screenStart.hidden = true;
  el.screenChat.hidden = false;
  el.roleBadge.textContent = role === 'host' ? 'Host' : 'Invitado';
  el.hostCodeCard.hidden = role !== 'host';
  el.hostCode.value = role === 'host' ? code : '';
  el.roomLabel.textContent = `#${roomId.slice(0, 8)}`;
  el.messages.replaceChildren();
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

  el.overlay.classList.toggle('is-hidden', ready);
  el.overlay.classList.toggle('is-error', state === 'error');
  if (state === 'error') {
    el.overlayTitle.textContent = 'No se pudo conectar';
    el.overlayText.textContent = error || '';
  } else if (role === 'host') {
    el.overlayTitle.textContent = 'Esperando a la otra persona…';
    el.overlayText.textContent = 'Comparte el código de la sala. En cuanto alguien entre, se establecerá una clave cifrada solo para vosotros.';
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

const timeNow = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function appendMessage({ text, from, mine }) {
  const wrap = h('div', `msg ${mine ? 'msg-me' : 'msg-peer'}`);
  const inner = h('div', 'msg-inner');
  inner.appendChild(h('span', 'msg-meta', mine ? 'Tú' : `Participante ${from}`));
  inner.appendChild(h('p', 'msg-bubble', text));
  const meta = h('span', 'msg-meta', timeNow());
  inner.appendChild(meta);
  wrap.appendChild(inner);
  pushMessage(wrap);
  if (!mine) countUnread();
  return {
    markFailed(reason) {
      wrap.classList.add('msg-failed');
      meta.textContent = `${meta.textContent} · ${reason}`;
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
