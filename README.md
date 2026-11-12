# P2P SecureChat

Chat cifrado de extremo a extremo que funciona **directamente entre navegadores** (WebRTC), sin servidor propio y sin cuentas.

## Uso

1. **Host:** presiona **Crear sala**. Se genera un código de 128 bits (`xxxx-xxxx-…`). Cópialo y compártelo por un canal de confianza.
2. **Invitado:** pega el código en **Tengo un código** y presiona **Conectar**.
3. Cuando se conecten, comparen el **número de seguridad** por otro medio (una llamada o en persona). Si coincide, nadie está interceptando la conversación.

### Tus chats

Cada sala que creas o a la que te unes se guarda en **Tus chats**, en la pantalla inicial, con un nombre editable y su historial. Para volver a una sala presiona **Abrir**: se reconecta con el mismo código, sin tener que compartirlo otra vez. La otra persona también tiene que tener ese chat abierto, porque los mensajes viajan directamente entre los dos navegadores. Los chats solo se eliminan cuando presionas **Borrar**.

### Archivos

Para enviar archivos de hasta **50 MB** usa el botón 📎, arrástralos al chat o pégalos con Ctrl+V. Los archivos de más de 10 MB solo se envían si quien los recibe presiona **Aceptar**. Las imágenes PNG, JPEG, GIF y WebP se muestran con una pequeña vista previa. El resto aparece como una tarjeta con su nombre, tamaño y un botón **Descargar**. Los archivos no se guardan en el historial.

También se puede abrir `https://…/index.html#<código>` para precargar el código. El fragmento `#` nunca se envía a ningún servidor.

## Ejecutar

Son archivos estáticos, así que alcanza con publicarlos en GitHub Pages o en cualquier hosting estático. Para probarlo en tu computadora:

```bash
python3 -m http.server 8000
```

Luego abre `http://localhost:8000`. Desde `file://` no funciona, porque los módulos ES requieren HTTP.

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
  - El anuncio (nombre, tamaño, cantidad de fragmentos, SHA-256) va por el canal de mensajes, cifrado y con anti-replay.
  - El contenido viaja en fragmentos binarios de 64 KB, cada uno cifrado con AES-GCM y ligado por AAD a su archivo, su posición y el total. No se pueden reordenar, mezclar ni truncar.
  - El receptor exige el tamaño exacto de cada fragmento, ignora los duplicados y los que pertenecen a archivos no anunciados, y verifica el SHA-256 del archivo completo antes de mostrarlo.
  - Límites contra abusos: 50 MB por archivo, 3 transferencias simultáneas por participante, 150 MB en memoria en curso, 500 MB recibidos por sesión, y 60 s sin progreso cancelan la transferencia. Los archivos de más de 10 MB requieren que el receptor los acepte.
  - La vista previa solo se muestra si los bytes son realmente PNG, JPEG, GIF o WebP: no se confía en el tipo que declara el emisor. **SVG nunca se previsualiza**, porque puede contener scripts. Antes de mostrarla se leen las dimensiones de la cabecera, y no hay vista previa para imágenes de más de 40 megapíxeles o 16.384 px de lado (protección contra "bombas" de descompresión).
  - Todo lo demás se entrega como `application/octet-stream` y con descarga forzada, así que nunca se interpreta dentro de la app.
  - Los nombres se sanean: sin caracteres de control, sin rutas y sin marcas bidi, para evitar trucos como `factura‮fdp.exe`. Las extensiones ejecutables o activas llevan una advertencia.
- **Identificación de participantes:** la etiqueta "Participante xxxxxxxx" son 4 bytes del hash de su clave pública. Si dos participantes tienen la misma etiqueta, la app avisa. Los mensajes de participantes verificados llevan ✔.
- **Clickjacking:** la app no se inicia si se carga dentro de un iframe.
- **Secreto hacia adelante por sesión:** las claves privadas no son exportables y desaparecen al cerrar la pestaña. No hay ratchet: dentro de una misma sesión se usa la misma clave.

### Limitaciones

- **Publícala en un origen propio.** En GitHub Pages todos tus proyectos comparten el origen `usuario.github.io`, y cualquier script de otro proyecto tuyo (o de un CDN que use) podría leer los chats guardados o controlar la app. Usa un dominio o subdominio propio, Cloudflare Pages, Netlify o una cuenta u organización dedicada.
- Quien tenga el código puede entrar a la sala. Compártelo solo con quien corresponda.
- No hay servidor TURN, así que algunas redes muy restrictivas (NAT simétrico, redes corporativas) pueden impedir la conexión directa.
- Los relays de Nostr y el otro participante ven tu dirección IP (inherente a WebRTC).
- Los chats guardados (código e historial) quedan **sin cifrar** en el `localStorage` del navegador. Quien tenga acceso a ese dispositivo o perfil puede leerlos o reabrir la sala. Bórralos si usas una computadora compartida.
- Las claves por par se generan de nuevo en cada sesión, así que al reabrir un chat cambia el número de seguridad y hay que volver a verificarlo.
- Lo que se descarga queda fuera de la app. Un archivo malicioso puede seguir siendo peligroso si lo abres, así que ábrelo solo si confías en quien lo envía.
- No hay mensajes diferidos: si la otra persona no tiene el chat abierto, el mensaje no se envía.

## Actualizar Trystero

```bash
npm i trystero@<versión> esbuild
echo "export { joinRoom, selfId } from 'trystero';" > entry.js
npx esbuild entry.js --bundle --format=esm --minify --legal-comments=inline --outfile=vendor/trystero.js
```
