// Reglas de seguridad para archivos: límites, validación del anuncio,
// detección del tipo real por contenido y saneado de nombres.

export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MB por archivo
export const CHUNK_BYTES = 64 * 1024; // texto plano por trozo
export const MAX_INCOMING_PER_PEER = 3; // transferencias simultáneas por participante
export const MAX_INCOMING_TOTAL_BYTES = 150 * 1024 * 1024; // memoria total reservada para recepciones
export const TRANSFER_TIMEOUT_MS = 60 * 1000; // sin progreso => se cancela
export const AUTO_ACCEPT_BYTES = 10 * 1024 * 1024; // más grandes => el receptor debe aceptar
export const ACCEPT_TIMEOUT_MS = 2 * 60 * 1000; // tiempo para aceptar/rechazar
export const MAX_PENDING_OFFERS_PER_PEER = 3; // ofertas esperando respuesta por participante
export const MAX_SESSION_RECEIVED_BYTES = 500 * 1024 * 1024; // total recibido por sesión (los archivos quedan en memoria)
export const needsAcceptance = size => size > AUTO_ACCEPT_BYTES;

export const chunkCount = size => Math.ceil(size / CHUNK_BYTES);
export const expectedChunkSize = (size, index, total) =>
  index < total - 1 ? CHUNK_BYTES : size - CHUNK_BYTES * (total - 1);

// ---------- nombres ----------

const extOf = name => {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i) : '';
};

// Quita todo lo que pueda engañar o romper una ruta:
//  - caracteres de control
//  - marcas bidi y de ancho cero (el truco "factura‮fdp.exe" que se ve como "factura.exe.pdf")
//  - separadores de ruta y caracteres reservados de Windows
export function sanitizeFileName(name) {
  let n = String(name ?? '')
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .replace(/[؜​-‏‪-‮⁠-⁩﻿]/g, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .trim()
    .replace(/^\.+/, '')
    .replace(/[. ]+$/, '');
  if (!n) n = 'archivo';
  if (n.length > 120) {
    const ext = extOf(n).slice(0, 16);
    n = n.slice(0, 120 - ext.length) + ext;
  }
  return n;
}

// Extensiones que pueden ejecutar código o abrir algo activo al hacer doble clic.
const RISKY_EXT = new Set([
  'exe', 'msi', 'msix', 'bat', 'cmd', 'com', 'scr', 'pif', 'cpl', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'mjs',
  'wsf', 'wsh', 'hta', 'jar', 'apk', 'aab', 'app', 'dmg', 'pkg', 'sh', 'bash', 'command', 'run', 'bin', 'deb', 'rpm',
  'html', 'htm', 'xhtml', 'shtml', 'mht', 'svg', 'xml', 'lnk', 'url', 'reg', 'inf', 'iso', 'img', 'vhd', 'dll', 'sys',
  'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'chm', 'py', 'pyw', 'php', 'pl', 'rb', 'appimage',
  'scf', 'msc', 'msp', 'mst', 'gadget', 'ws', 'jnlp', 'xll', 'ppam', 'sldm', 'potm', 'library-ms', 'search-ms',
  'settingcontent-ms', 'appref-ms', 'application', 'cab', 'diagcab', 'desktop', 'terminal', 'webloc', 'workflow',
  'scpt', 'action', 'csh', 'ksh', 'zsh', 'fish', 'ps1xml', 'psc1', 'vb', 'hta', 'mhtml', 'xht', 'xsl', 'svgz'
]);

export const isRiskyName = name => RISKY_EXT.has(extOf(name).slice(1).toLowerCase());

// ---------- tipo real por contenido (magic bytes) ----------
// Nunca se confía en el tipo que declara el emisor. Solo estos formatos raster
// se muestran como imagen; SVG queda excluido porque puede contener scripts.

const startsWith = (b, sig, offset = 0) => sig.every((v, i) => b[offset + i] === v);

function sniffImageType(bytes) {
  if (!bytes || bytes.length < 12) return null;
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes, [0x57, 0x45, 0x42, 0x50], 8)) return 'image/webp';
  return null;
}

// ---------- dimensiones (protección contra "bombas" de descompresión) ----------
// Una imagen de pocos KB puede declarar 50.000 x 50.000 píxeles: al decodificarla
// el navegador reservaría gigas de memoria. Se leen las dimensiones de la cabecera
// y solo se previsualiza si están dentro de límites razonables.

export const MAX_PREVIEW_PIXELS = 40_000_000;
export const MAX_PREVIEW_SIDE = 16384;

const be16 = (b, i) => (b[i] << 8) | b[i + 1];
const be32 = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
const le16 = (b, i) => b[i] | (b[i + 1] << 8);
const le24 = (b, i) => b[i] | (b[i + 1] << 8) | (b[i + 2] << 16);

function imageDimensions(bytes, type) {
  try {
    if (type === 'image/png') {
      // IHDR justo tras la firma: ancho y alto en los bytes 16..23
      if (bytes.length < 24 || String.fromCharCode(...bytes.subarray(12, 16)) !== 'IHDR') return null;
      return { w: be32(bytes, 16), h: be32(bytes, 20) };
    }
    if (type === 'image/gif') return { w: le16(bytes, 6), h: le16(bytes, 8) };
    if (type === 'image/webp') {
      const chunk = String.fromCharCode(...bytes.subarray(12, 16));
      if (chunk === 'VP8X' && bytes.length >= 30) return { w: le24(bytes, 24) + 1, h: le24(bytes, 27) + 1 };
      if (chunk === 'VP8 ' && bytes.length >= 30) return { w: le16(bytes, 26) & 0x3fff, h: le16(bytes, 28) & 0x3fff };
      if (chunk === 'VP8L' && bytes.length >= 25) {
        const b = bytes;
        return { w: 1 + (((b[22] & 0x3f) << 8) | b[21]), h: 1 + (((b[24] & 0x0f) << 10) | (b[23] << 2) | ((b[22] & 0xc0) >> 6)) };
      }
      return null;
    }
    if (type === 'image/jpeg') {
      // Recorre los segmentos hasta el SOFn (puede no estar en el primer fragmento)
      let i = 2;
      while (i + 9 < bytes.length) {
        if (bytes[i] !== 0xff) return null;
        const marker = bytes[i + 1];
        if (marker === 0xff) { i++; continue; }
        if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { i += 2; continue; }
        const len = be16(bytes, i + 2);
        if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
          return { w: be16(bytes, i + 7), h: be16(bytes, i + 5) };
        }
        if (len < 2) return null;
        i += 2 + len;
      }
      return null;
    }
  } catch {
    return null;
  }
  return null;
}

// Devuelve el tipo de imagen si es seguro previsualizarla; si no, null.
// Se mira el contenido real (magic bytes), nunca el tipo declarado, y nunca SVG.
export function previewableImageType(bytes) {
  const type = sniffImageType(bytes);
  if (!type) return null;
  const dim = imageDimensions(bytes, type);
  if (!dim || !dim.w || !dim.h) return null;
  if (dim.w > MAX_PREVIEW_SIDE || dim.h > MAX_PREVIEW_SIDE || dim.w * dim.h > MAX_PREVIEW_PIXELS) return null;
  return type;
}

// ---------- anuncio de archivo ----------

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

// Valida el anuncio recibido de un participante. Devuelve null si algo no cuadra.
export function parseOffer(o) {
  if (!o || typeof o !== 'object') return null;
  const { id, name, size, chunks, hash } = o;
  if (typeof id !== 'string' || !HEX32.test(id)) return null;
  if (typeof hash !== 'string' || !HEX64.test(hash)) return null;
  if (typeof name !== 'string' || name.length > 1024) return null;
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_FILE_BYTES) return null;
  if (chunks !== chunkCount(size)) return null;
  return { id, name: sanitizeFileName(name), size, chunks, hash };
}

// ---------- formato ----------

export function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
