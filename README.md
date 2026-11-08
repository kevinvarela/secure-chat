# P2P SecureChat

Chat cifrado de extremo a extremo que funciona **directamente entre navegadores** (WebRTC), sin servidor propio, sin cuentas y sin historial.

## Uso

1. **Host:** pulsa **Crear sala**. Se genera un código de 128 bits (`xxxx-xxxx-…`). Cópialo y compártelo por un canal de confianza.
2. **Invitado:** pega el código en **Tengo un código** y pulsa **Conectar**.
3. Cuando os conectéis, comparad el **número de seguridad** por otro medio (llamada, en persona). Si coincide, nadie está interceptando la conversación.

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
vendor/trystero.js    Trystero 0.26.0 empaquetado localmente (sin CDN)
```

## Modelo de seguridad

- **Código de sala:** secreto aleatorio de 128 bits. Con HKDF se derivan por separado el ID público de la sala, la contraseña de señalización y la sal de las claves por par. El código nunca viaja por la red.
- **Señalización:** usa relays públicos de Nostr solo para el emparejamiento inicial. El SDP va cifrado con la contraseña derivada (opción `password` de Trystero).
- **Claves por par:** cada pestaña genera un par ECDH P-256 efímero. Con cada participante se derivan dos claves AES-GCM-256, una por dirección, ligadas al secreto de la sala, y se confirman antes de aceptar la conexión.
- **Mensajes:** AES-GCM con IV aleatorio y un contador autenticado para impedir repeticiones (replay). Las entradas se validan en formato y tamaño.
- **Secreto hacia adelante por sesión:** las claves privadas no son exportables y desaparecen al cerrar la pestaña. No hay ratchet: dentro de una misma sesión se usa la misma clave.

### Limitaciones

- Quien tenga el código puede entrar a la sala. Compártelo solo con quien corresponda.
- No hay servidor TURN, así que algunas redes muy restrictivas (NAT simétrico, redes corporativas) pueden impedir la conexión directa.
- Los relays de Nostr y el otro participante ven tu dirección IP (inherente a WebRTC).
- Los mensajes no se guardan: al recargar se pierden.

## Actualizar Trystero

```bash
npm i trystero@<versión> esbuild
echo "export { joinRoom, selfId } from 'trystero';" > entry.js
npx esbuild entry.js --bundle --format=esm --minify --legal-comments=inline --outfile=vendor/trystero.js
```
