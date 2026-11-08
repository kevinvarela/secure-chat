# P2P SecureChat

Chat cifrado de extremo a extremo que funciona **directamente entre navegadores** (WebRTC), sin servidor propio y sin cuentas.

## Uso

1. **Host:** pulsa **Crear sala**. Se genera un código de 128 bits (`xxxx-xxxx-…`). Cópialo y compártelo por un canal de confianza.
2. **Invitado:** pega el código en **Tengo un código** y pulsa **Conectar**.
3. Cuando os conectéis, comparad el **número de seguridad** por otro medio (llamada, en persona). Si coincide, nadie está interceptando la conversación.

### Tus chats

Cada sala que creas o a la que te unes se guarda en **Tus chats**, en la pantalla inicial, con un nombre editable y su historial. Para volver a una sala pulsa **Abrir**: se reconecta con el mismo código, sin tener que compartirlo otra vez. La otra persona también tiene que tener ese chat abierto, porque los mensajes viajan directamente entre los dos navegadores. Los chats solo se eliminan cuando pulsas **Borrar**.

### Archivos

Para enviar archivos de hasta **50 MB** usa el botón 📎, arrastra y suelta, o pega con Ctrl+V. Las imágenes PNG, JPEG, GIF y WebP se muestran con una pequeña vista previa. El resto aparece como una tarjeta con su nombre, tamaño y un botón **Descargar**. Los archivos no se guardan en el historial.

También se puede abrir `https://…/index.html#<código>` para precargar el código. El fragmento `#` nunca se envía a ningún servidor.

## Ejecutar

Son archivos estáticos, así que basta con publicarlos en GitHub Pages o en cualquier hosting estático. En local:

```bash
python3 -m http.server 8000
```

Después abre `http://localhost:8000`. Desde `file://` no funciona, porque los módulos ES requieren HTTP.

## Estructura

```
index.html            marcado (sin scripts ni estilos inline, con CSP estricta)
css/styles.css        estilos
js/app.js             roles host/invitado, salas Trystero, handshake y mensajes
js/crypto.js          derivación de claves, ECDH, AES-GCM, números de seguridad
js/ui.js              DOM (solo textContent, nunca innerHTML)
js/storage.js         chats guardados e historial (localStorage)
js/files.js           límites, validación, detección de tipo y saneado de nombres de archivo
vendor/trystero.js    Trystero 0.26.0 empaquetado localmente (sin CDN)
```

## Modelo de seguridad

- **Código de sala:** secreto aleatorio de 128 bits. Con HKDF se derivan por separado el ID público de la sala, la contraseña de señalización y la sal de las claves por par. El código nunca viaja por la red.
- **Señalización:** usa relays públicos de Nostr solo para el emparejamiento inicial. El SDP va cifrado con la contraseña derivada (opción `password` de Trystero).
- **Claves por par:** cada pestaña genera un par ECDH P-256 efímero. Con cada participante se derivan dos claves AES-GCM-256, una por dirección, ligadas al secreto de la sala, y se confirman antes de aceptar la conexión.
- **Mensajes:** AES-GCM con IV aleatorio y un contador autenticado para impedir repeticiones (replay). Las entradas se validan en formato y tamaño.
- **Archivos:**
  - El anuncio (nombre, tamaño, número de trozos, SHA-256) va por el canal de mensajes, cifrado y con anti-replay.
  - El contenido viaja en trozos binarios de 64 KB, cada uno cifrado con AES-GCM y ligado por AAD a su archivo, su posición y el total. No se pueden reordenar, mezclar ni truncar.
  - El receptor exige el tamaño exacto de cada trozo, ignora los duplicados y los que pertenecen a archivos no anunciados, y verifica el SHA-256 del archivo completo antes de mostrarlo.
  - Límites contra abusos: 50 MB por archivo, 3 transferencias simultáneas por participante, 150 MB en memoria en total y 60 s sin progreso cancelan la transferencia.
  - La vista previa solo se muestra si los bytes son realmente PNG, JPEG, GIF o WebP: no se confía en el tipo que declara el emisor. **SVG nunca se previsualiza**, porque puede contener scripts.
  - Todo lo demás se entrega como `application/octet-stream` y con descarga forzada, así que nunca se interpreta dentro de la app.
  - Los nombres se sanean: sin caracteres de control, sin rutas y sin marcas bidi, para evitar trucos como `factura‮fdp.exe`. Las extensiones ejecutables o activas llevan una advertencia.
- **Secreto hacia adelante por sesión:** las claves privadas no son exportables y desaparecen al cerrar la pestaña. No hay ratchet: dentro de una misma sesión se usa la misma clave.

### Limitaciones

- Quien tenga el código puede entrar a la sala. Compártelo solo con quien corresponda.
- No hay servidor TURN, así que algunas redes muy restrictivas (NAT simétrico, redes corporativas) pueden impedir la conexión directa.
- Los relays de Nostr y el otro participante ven tu dirección IP (inherente a WebRTC).
- Los chats guardados (código e historial) quedan **sin cifrar** en el `localStorage` del navegador. Quien tenga acceso a ese dispositivo o perfil puede leerlos o reabrir la sala. Bórralos si usas un equipo compartido.
- Las claves por par se generan de nuevo en cada sesión, así que al reabrir un chat cambia el número de seguridad y hay que volver a verificarlo.
- Lo que se descarga queda fuera de la app. Un archivo malicioso puede seguir siendo peligroso si lo abres, así que ábrelo solo si confías en quien lo envía.
- No hay mensajes diferidos: si la otra persona no tiene el chat abierto, el mensaje no se envía.

## Actualizar Trystero

```bash
npm i trystero@<versión> esbuild
echo "export { joinRoom, selfId } from 'trystero';" > entry.js
npx esbuild entry.js --bundle --format=esm --minify --legal-comments=inline --outfile=vendor/trystero.js
```
