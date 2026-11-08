// Reglas de seguridad para archivos: límites, validación del anuncio,
// detección del tipo real por contenido y saneado de nombres.

export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MB por archivo
export const CHUNK_BYTES = 64 * 1024; // texto plano por trozo
export const MAX_INCOMING_PER_PEER = 3; // transferencias simultáneas por participante
export const MAX_INCOMING_TOTAL_BYTES = 150 * 1024 * 1024; // memoria total reservada para recepciones
export const TRANSFER_TIMEOUT_MS = 60 * 1000; // sin progreso => se cancela

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
  'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'chm', 'py', 'pyw', 'php', 'pl', 'rb', 'appimage'
]);

export const isRiskyName = name => RISKY_EXT.has(extOf(name).slice(1).toLowerCase());

// ---------- tipo real por contenido (magic bytes) ----------
// Nunca se confía en el tipo que declara el emisor. Solo estos formatos raster
// se muestran como imagen; SVG queda excluido porque puede contener scripts.

const startsWith = (b, sig, offset = 0) => sig.every((v, i) => b[offset + i] === v);

export function sniffImageType(bytes) {
  if (!bytes || bytes.length < 12) return null;
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes, [0x57, 0x45, 0x42, 0x50], 8)) return 'image/webp';
  return null;
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
