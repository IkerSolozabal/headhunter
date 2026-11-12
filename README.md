# headhunter

Extractor de **IOC** (Indicators of Compromise) para correos `.eml`. Web estática, pensada para GitHub Pages, que procesa el archivo **íntegramente en tu navegador**: el correo nunca se sube a ningún servidor.

Arrastras un `.eml` y obtienes, clasificados y seleccionables:

| Categoría | Qué incluye |
|---|---|
| **Direcciones IP** | IPv4 e IPv6 de todas las cabeceras (`Received`, `X-Originating-IP`, `Authentication-Results`, `Received-SPF`…) y del cuerpo. Marca IPs privadas/reservadas, el número de salto `Received` y, con IPinfo, ASN, organización y país. |
| **Dominios** | Dominio registrable (eTLD+1) de remitentes, destinatarios, URLs, hostnames, `DKIM d=`, `smtp.mailfrom`, `header.from`, Message-ID… |
| **Hostnames** | FQDN completos (`mail-sor-f41.google.com`) y nombres HELO sin dominio (`WIN-8K2JD7`). |
| **URLs** | Del cuerpo de texto y HTML (`href`, `src`, `action`), cabeceras (`List-Unsubscribe`), adjuntos HTML/texto y cadenas de adjuntos binarios (p. ej. `/URI` de PDFs). Revierte defang (`hxxp`, `[.]`). |
| **Emails** | `From`, `To`, `Cc`, `Reply-To`, `Return-Path`, `Sender`, `Delivered-To`, `X-Original-To`, `envelope-from`, `mailto:`, cuerpo… |
| **Hashes** | MD5, SHA1 y SHA256 de cada adjunto (y del propio `.eml`). |
| **Ficheros adjuntos** | Nombre, tipo MIME y tamaño. |
| **Otros** | `Message-ID`, `In-Reply-To`, `References`, `X-Mailer`, `User-Agent`… |

Además muestra un resumen con asunto, remitente, resultados **SPF / DKIM / DMARC** y avisos de discrepancias `Reply-To ≠ From` / `Return-Path ≠ From`.

## Uso

1. Abre la web y arrastra un `.eml` (o haz clic para elegirlo, o pégalo con `Ctrl+V`).
2. Filtra por categoría o texto, y selecciona IOC individualmente, por grupo o todos.
3. Pulsa **Copiar**: se copian al portapapeles **uno por línea**.
   - Activa **Defang** para copiarlos neutralizados (`hxxps://evil[.]com`, `1[.]2[.]3[.]4`).
   - **Solo IPs públicas** (activado por defecto) oculta privadas, loopback, CGNAT, etc.

Hay un botón **Probar con un ejemplo** que carga [`samples/ejemplo-phishing.eml`](samples/ejemplo-phishing.eml).

## Enriquecimiento de IPs con IPinfo

Las IPs públicas se consultan en [IPinfo Lite](https://ipinfo.io/developers/lite-api), que es gratuito, y se muestra **ASN, organización (`as_name`) y país** junto a cada IP.

1. Crea una cuenta gratuita en <https://ipinfo.io/signup> y copia tu token.
2. En la web, pulsa el engranaje ⚙ (arriba a la derecha) y pega el token.

El token **se guarda solo en el `localStorage` de tu navegador**; no está en el código ni en el repositorio. Las respuestas se cachean 7 días en el navegador para no gastar peticiones (botón *Vaciar caché* en ajustes).

Petición equivalente:

```bash
curl -H "Authorization: Bearer $IPINFO_TOKEN" https://api.ipinfo.io/lite/8.8.8.8
```

```json
{
  "ip": "8.8.8.8",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "as_domain": "google.com",
  "country_code": "US",
  "country": "United States",
  "continent_code": "NA",
  "continent": "North America"
}
```

Desde el navegador se usa `?token=` en lugar de la cabecera `Authorization` para evitar la petición *preflight* de CORS.

## Privacidad

- El `.eml` se lee con la File API y se analiza en JavaScript local. No hay backend.
- Lo único que sale del navegador son las **IPs públicas** hacia `api.ipinfo.io`, y solo si has configurado un token. Puedes desactivar la consulta automática en ajustes y lanzarla a mano con *Consultar IPinfo*.

## Despliegue en GitHub Pages

No hay paso de build. En el repositorio: **Settings → Pages → Build and deployment → Source: Deploy from a branch**, rama `main`, carpeta `/ (root)`. Quedará en `https://<usuario>.github.io/headhunter/`.

El fichero `.nojekyll` evita que Jekyll procese el sitio.

## Desarrollo local

Los módulos ES necesitan servirse por HTTP (no funcionan con `file://`). Cualquier servidor estático vale:

```bash
npx serve .
```

```bash
python -m http.server 8000
```

## Estructura

```
index.html        Página única
css/styles.css    Estilos (tema oscuro, glassmorphism)
js/app.js         Interfaz: carga, render, selección, portapapeles, ajustes
js/eml.js         Parser MIME/EML (multipart, base64, quoted-printable, RFC 2047/2231, message/rfc822)
js/ioc.js         Extracción y clasificación de IOC, defang/refang, ámbito de IPs, dominio registrable
js/hash.js        MD5 (implementación propia) + SHA1/SHA256 (Web Crypto)
js/ipinfo.js      Cliente de IPinfo Lite con caché y concurrencia limitada
samples/          Correo de ejemplo
```

## Limitaciones conocidas

- La detección de dominios en **texto libre** usa una lista de TLDs habituales y descarta TLDs que coinciden con extensiones de fichero (`.zip`, `.mov`, `.sh`…). En contextos estructurados (URLs, emails, `Received`, DKIM…) se acepta cualquier TLD.
- El dominio registrable se calcula con una lista reducida de sufijos públicos multinivel (`co.uk`, `com.br`, `github.io`…), no con la Public Suffix List completa.
- No se descomprimen adjuntos (`.zip`, `winmail.dat`): se hashea el contenedor.
