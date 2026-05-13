'use strict';

/* =============================================================
   ja3-lab.js — Laboratorio Interactivo TLS / JA3 Fingerprinting
   Cryptography for SOC Analysts

   Este módulo calcula huellas JA3 en el browser de forma
   completamente estática — sin backend, sin dependencias.

   Estructura:
     1. MD5 puro en JS    → computeMd5()
     2. Motor JA3         → parseJa3Fields(), buildJa3String(), computeJa3Hash()
     3. Datos de presets  → JA3_PRESETS (Chrome, Firefox, curl, Meterpreter, CS)
     4. Base de firmas    → JA3_SIGNATURES (threat intel conocido)
     5. Tab navigation    → initTabs()
     6. Tab Anatomía      → initAnatomyTab()
     7. Tab Calculadora   → initCalculatorTab()
     8. Tab Firmas        → initSignaturesTab()
     9. Tab SOC           → initSocTab()
    10. Init principal    → DOMContentLoaded
   ============================================================= */


/* ─────────────────────────────────────────────────────────────
   1. MD5 PURO EN JAVASCRIPT (RFC 1321)
   Implementación basada en Paul Johnston (paj@pajhome.org.uk)
   Sin dependencias externas — todos los datos permanecen en el
   browser del analista, nunca se envían al servidor.
   ───────────────────────────────────────────────────────────── */

/**
 * computeMd5(str) → string hex de 32 chars
 *
 * Calcula el hash MD5 de una cadena de texto.
 * JA3 usa MD5 porque fue diseñado en 2017 priorizando velocidad
 * de cálculo en herramientas de red, no seguridad criptográfica.
 */
function computeMd5(str) {
  // Suma de 32 bits con manejo de desbordamiento
  function safeAdd(x, y) {
    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }

  // Rotación circular a la izquierda
  function bitRol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
  }

  // Función genérica de ronda MD5
  function md5Cmn(q, a, b, x, s, t) {
    return safeAdd(bitRol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }

  // Las cuatro funciones de ronda (F, G, H, I) del RFC 1321
  function md5Ff(a, b, c, d, x, s, t) { return md5Cmn((b & c) | (~b & d), a, b, x, s, t); }
  function md5Gg(a, b, c, d, x, s, t) { return md5Cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function md5Hh(a, b, c, d, x, s, t) { return md5Cmn(b ^ c ^ d,          a, b, x, s, t); }
  function md5Ii(a, b, c, d, x, s, t) { return md5Cmn(c ^ (b | ~d),        a, b, x, s, t); }

  // Procesamiento de bloque de 512 bits (16 words de 32 bits)
  function coreMd5(x, len) {
    // Padding según RFC 1321 §3.1
    x[len >> 5] |= 0x80 << (len % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;

    // Vector de inicialización (IV) del RFC 1321
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;

    // Procesar cada bloque de 16 words
    for (let i = 0; i < x.length; i += 16) {
      const oa = a, ob = b, oc = c, od = d;

      // Ronda 1 — F(b,c,d) = (b AND c) OR (NOT b AND d)
      a = md5Ff(a,b,c,d, x[i+ 0], 7, -680876936);    d = md5Ff(d,a,b,c, x[i+ 1],12, -389564586);
      c = md5Ff(c,d,a,b, x[i+ 2],17,  606105819);     b = md5Ff(b,c,d,a, x[i+ 3],22,-1044525330);
      a = md5Ff(a,b,c,d, x[i+ 4], 7, -176418897);    d = md5Ff(d,a,b,c, x[i+ 5],12, 1200080426);
      c = md5Ff(c,d,a,b, x[i+ 6],17,-1473231341);     b = md5Ff(b,c,d,a, x[i+ 7],22,  -45705983);
      a = md5Ff(a,b,c,d, x[i+ 8], 7, 1770035416);    d = md5Ff(d,a,b,c, x[i+ 9],12,-1958414417);
      c = md5Ff(c,d,a,b, x[i+10],17,    -42063);      b = md5Ff(b,c,d,a, x[i+11],22,-1990404162);
      a = md5Ff(a,b,c,d, x[i+12], 7, 1804603682);    d = md5Ff(d,a,b,c, x[i+13],12,  -40341101);
      c = md5Ff(c,d,a,b, x[i+14],17,-1502002290);     b = md5Ff(b,c,d,a, x[i+15],22, 1236535329);

      // Ronda 2 — G(b,c,d) = (b AND d) OR (c AND NOT d)
      a = md5Gg(a,b,c,d, x[i+ 1], 5, -165796510);    d = md5Gg(d,a,b,c, x[i+ 6], 9,-1069501632);
      c = md5Gg(c,d,a,b, x[i+11],14,  643717713);     b = md5Gg(b,c,d,a, x[i+ 0],20, -373897302);
      a = md5Gg(a,b,c,d, x[i+ 5], 5, -701558691);    d = md5Gg(d,a,b,c, x[i+10], 9,   38016083);
      c = md5Gg(c,d,a,b, x[i+15],14, -660478335);     b = md5Gg(b,c,d,a, x[i+ 4],20, -405537848);
      a = md5Gg(a,b,c,d, x[i+ 9], 5,  568446438);    d = md5Gg(d,a,b,c, x[i+14], 9,-1019803690);
      c = md5Gg(c,d,a,b, x[i+ 3],14, -187363961);     b = md5Gg(b,c,d,a, x[i+ 8],20, 1163531501);
      a = md5Gg(a,b,c,d, x[i+13], 5,-1444681467);    d = md5Gg(d,a,b,c, x[i+ 2], 9,  -51403784);
      c = md5Gg(c,d,a,b, x[i+ 7],14, 1735328473);     b = md5Gg(b,c,d,a, x[i+12],20,-1926607734);

      // Ronda 3 — H(b,c,d) = b XOR c XOR d
      a = md5Hh(a,b,c,d, x[i+ 5], 4,    -378558);    d = md5Hh(d,a,b,c, x[i+ 8],11,-2022574463);
      c = md5Hh(c,d,a,b, x[i+11],16, 1839030562);     b = md5Hh(b,c,d,a, x[i+14],23,  -35309556);
      a = md5Hh(a,b,c,d, x[i+ 1], 4,-1530992060);    d = md5Hh(d,a,b,c, x[i+ 4],11, 1272893353);
      c = md5Hh(c,d,a,b, x[i+ 7],16, -155497632);     b = md5Hh(b,c,d,a, x[i+10],23,-1094730640);
      a = md5Hh(a,b,c,d, x[i+13], 4,  681279174);    d = md5Hh(d,a,b,c, x[i+ 0],11, -358537222);
      c = md5Hh(c,d,a,b, x[i+ 3],16, -722521979);     b = md5Hh(b,c,d,a, x[i+ 6],23,   76029189);
      a = md5Hh(a,b,c,d, x[i+ 9], 4, -640364487);    d = md5Hh(d,a,b,c, x[i+12],11, -421815835);
      c = md5Hh(c,d,a,b, x[i+15],16,  530742520);     b = md5Hh(b,c,d,a, x[i+ 2],23, -995338651);

      // Ronda 4 — I(b,c,d) = c XOR (b OR NOT d)
      a = md5Ii(a,b,c,d, x[i+ 0], 6, -198630844);    d = md5Ii(d,a,b,c, x[i+ 7],10, 1126891415);
      c = md5Ii(c,d,a,b, x[i+14],15,-1416354905);     b = md5Ii(b,c,d,a, x[i+ 5],21,  -57434055);
      a = md5Ii(a,b,c,d, x[i+12], 6, 1700485571);    d = md5Ii(d,a,b,c, x[i+ 3],10,-1894986606);
      c = md5Ii(c,d,a,b, x[i+10],15,   -1051523);     b = md5Ii(b,c,d,a, x[i+ 1],21,-2054922799);
      a = md5Ii(a,b,c,d, x[i+ 8], 6, 1873313359);    d = md5Ii(d,a,b,c, x[i+15],10,  -30611744);
      c = md5Ii(c,d,a,b, x[i+ 6],15,-1560198380);     b = md5Ii(b,c,d,a, x[i+13],21, 1309151649);
      a = md5Ii(a,b,c,d, x[i+ 4], 6, -145523070);    d = md5Ii(d,a,b,c, x[i+11],10,-1120210379);
      c = md5Ii(c,d,a,b, x[i+ 2],15,  718787259);     b = md5Ii(b,c,d,a, x[i+ 9],21, -343485551);

      a = safeAdd(a, oa);
      b = safeAdd(b, ob);
      c = safeAdd(c, oc);
      d = safeAdd(d, od);
    }
    return [a, b, c, d];
  }

  // Convierte string a array de words de 32 bits (little-endian)
  function str2binl(str) {
    const bin  = [];
    const mask = (1 << 8) - 1;
    for (let i = 0; i < str.length * 8; i += 8)
      bin[i >> 5] |= (str.charCodeAt(i / 8) & mask) << (i % 32);
    return bin;
  }

  // Convierte array de words a hexadecimal lowercase
  function binl2hex(binarray) {
    const hx = '0123456789abcdef';
    let out = '';
    for (let i = 0; i < binarray.length * 4; i++) {
      out += hx.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
             hx.charAt((binarray[i >> 2] >> ((i % 4) * 8))     & 0xF);
    }
    return out;
  }

  return binl2hex(coreMd5(str2binl(str), str.length * 8));
}


/* ─────────────────────────────────────────────────────────────
   2. MOTOR JA3
   JA3 fue creado por John Althouse, Jeff Atkinson y Josh Atkins
   (Salesforce Engineering) en 2017. Publicado en:
   https://github.com/salesforce/ja3

   FÓRMULA JA3:
     SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
     └─ cada lista: valores separados por '-'
     └─ campos:     separados por ','
     └─ hash final: MD5 del string concatenado
   ───────────────────────────────────────────────────────────── */

/**
 * Valores GREASE (RFC 8701) que se excluyen del cálculo JA3.
 * GREASE = Generate Random Extensions And Sustain Extensibility.
 * Los browsers modernos envían GREASE para forzar que los servidores
 * ignoren valores desconocidos. JA3 los filtra para consistencia.
 */
const GREASE_VALUES = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
  0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

/**
 * parseIntList(str) → number[]
 * Convierte "769,47,53" → [769, 47, 53]
 * Acepta comas o guiones como separadores.
 */
function parseIntList(str) {
  if (!str || !str.trim()) return [];
  return str.trim()
    .split(/[\s,\-]+/)
    .map(s => parseInt(s.trim(), 10))
    .filter(n => !isNaN(n));
}

/**
 * filterGrease(nums) → number[]
 * Elimina valores GREASE de la lista.
 */
function filterGrease(nums) {
  return nums.filter(n => !GREASE_VALUES.has(n));
}

/**
 * buildJa3String(fields) → string
 * Construye el string de concatenación JA3 sin hashear.
 *
 * @param fields {version, ciphers, extensions, curves, ecFormats}
 *   - ciphers, extensions, curves, ecFormats son arrays de números
 */
function buildJa3String(fields) {
  const { version, ciphers, extensions, curves, ecFormats } = fields;

  // Filtrar GREASE de cada lista
  const filtCiphers    = filterGrease(ciphers);
  const filtExtensions = filterGrease(extensions);
  const filtCurves     = filterGrease(curves);
  const filtEcFormats  = ecFormats; // EC point formats no tienen GREASE

  // Construir el string: listas con '-', campos con ','
  const parts = [
    String(version),
    filtCiphers.join('-'),
    filtExtensions.join('-'),
    filtCurves.join('-'),
    filtEcFormats.join('-'),
  ];

  return parts.join(',');
}

/**
 * computeJa3Hash(ja3String) → string
 * Hashea el string JA3 con MD5.
 */
function computeJa3Hash(ja3String) {
  return computeMd5(ja3String);
}


/* ─────────────────────────────────────────────────────────────
   3. DATOS DE PRESETS — CLIENTES TLS REALES
   Cada preset define los campos del Client Hello capturados con
   Wireshark o tshark. Los valores están en decimal (como JA3).
   ───────────────────────────────────────────────────────────── */

/**
 * Los 5 campos del Client Hello que JA3 usa:
 *   version     → Versión TLS del handshake (ej: 771 = TLS 1.2)
 *   ciphers     → Lista de cipher suites ofrecidas (decimal)
 *   extensions  → Lista de tipos de extensión TLS
 *   curves      → Extensión supported_groups (curvas elípticas)
 *   ecFormats   → Extensión ec_point_formats
 */
const JA3_PRESETS = {
  chrome: {
    label: 'Chrome 96+ (Windows)',
    category: 'benign',
    description: 'Cliente web estándar. Incluye TLS 1.3 ciphers (4865-4867) y GREASE para compatibilidad.',
    version:    771,
    ciphers:    [0xaaaa, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
    extensions: [0xaaaa, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0xaaaa],
    curves:     [0xaaaa, 29, 23, 24],
    ecFormats:  [0],
  },
  firefox: {
    label: 'Firefox 95+ (Linux)',
    category: 'benign',
    description: 'Browser Mozilla. Diferente selección de cipher suites y extensiones que Chrome.',
    version:    771,
    ciphers:    [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49172, 49171, 51, 57, 47, 53],
    extensions: [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
    curves:     [29, 23, 24, 25, 256, 257],
    ecFormats:  [0],
  },
  curl: {
    label: 'curl 7.x / libcurl (OpenSSL)',
    category: 'tool',
    description: 'Cliente HTTP de línea de comandos. Huella muy específica, distinguible de browsers fácilmente.',
    version:    771,
    ciphers:    [49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47, 255],
    extensions: [11, 10, 35, 16, 22, 23, 13],
    curves:     [29, 23, 24],
    ecFormats:  [0],
  },
  metasploit: {
    label: 'Metasploit Meterpreter',
    category: 'malware',
    description: '⚠️ Framework de explotación. Client Hello muy básico: pocas ciphers, sin extensiones comunes.',
    version:    769,
    ciphers:    [4,5,10,9,100,98,3,6,19,18,99],
    extensions: [15],
    curves:     [],
    ecFormats:  [],
  },
  cobaltstrike: {
    label: 'Cobalt Strike 4.x (default)',
    category: 'malware',
    description: '⚠️ Framework C2 post-explotación. Huella similar a Java estándar — a veces difícil de detectar.',
    version:    771,
    ciphers:    [49162, 49161, 49172, 49171, 53, 47, 10, 5, 4, 57, 51, 22, 19, 16, 13, 9, 8, 7, 3, 2, 1],
    extensions: [0, 10, 11, 35],
    curves:     [23, 24, 25],
    ecFormats:  [0],
  },
};


/* ─────────────────────────────────────────────────────────────
   4. BASE DE FIRMAS JA3 CONOCIDAS (THREAT INTEL)
   Hashes documentados públicamente en threat intel.
   Fuentes: Salesforce JA3 repo, abuse.ch, VirusTotal, CISA.
   NOTA: Los hashes cambian con versiones de software.
   ───────────────────────────────────────────────────────────── */
const JA3_SIGNATURES = [
  // ── Malware / C2 ──────────────────────────────────────────
  {
    hash:     'e7d705a3286e19ea42f587b344ee6865',
    name:     'Metasploit Meterpreter',
    type:     'malware',
    detail:   'Framework de explotación Rapid7. SSL/TLS muy básico, sin extensiones modernas.',
    severity: 'critical',
  },
  {
    hash:     'de350869b8c85de67a350c8d186f11e6',
    name:     'Cobalt Strike (pre-4.x)',
    type:     'c2',
    detail:   'Beacon por defecto de CS < 4. Malleable C2 puede alterar la huella en versiones modernas.',
    severity: 'critical',
  },
  {
    hash:     '8bab54f22de07d88e90f5e8e5edb5a69',
    name:     'Emotet C2 Communication',
    type:     'malware',
    detail:   'Banking trojan / botnet. JA3 usado en campañas 2020-2022 antes del takedown.',
    severity: 'critical',
  },
  {
    hash:     '19e29534fd49dd27d09234e7b95b86c1',
    name:     'Dridex / BitPaymer',
    type:     'malware',
    detail:   'Troyano bancario. Mismo JA3 observado en fases de exfiltración.',
    severity: 'critical',
  },
  {
    hash:     'a0e9f5d64349fb13191bc781f81f42e1',
    name:     'Tor Browser / Cobalt Strike 4.x',
    type:     'tool',
    detail:   'Compartido por Tor Browser y algunas configs de CS. Requiere contexto adicional.',
    severity: 'high',
  },
  {
    hash:     '6d1a47b7b9e7d98e1c7c9d82da2bf1a6',
    name:     'AsyncRAT / QuasarRAT',
    type:     'malware',
    detail:   'RATs escritos en .NET. C# TLS default sin configuración custom produce esta huella.',
    severity: 'critical',
  },
  // ── Herramientas de pentest / dual-use ────────────────────
  {
    hash:     'cd08e31494f9531f560d64c695473da9',
    name:     'curl 7.x (OpenSSL)',
    type:     'tool',
    detail:   'Herramienta HTTP legítima, también usada en scripts de ataque y exfiltración.',
    severity: 'medium',
  },
  {
    hash:     'b386946a5a44d1ddcc843bc75336dfce',
    name:     'Python requests (urllib3)',
    type:     'tool',
    detail:   'Librería HTTP de Python. Legítima pero muy usada en tooling de ataque automatizado.',
    severity: 'medium',
  },
  {
    hash:     '51c64c77e60f3980eea90869b68c58a8',
    name:     'Go / Golang default TLS',
    type:     'tool',
    detail:   'TLS por defecto del runtime de Go. Muchas herramientas de ataque están escritas en Go.',
    severity: 'medium',
  },
  {
    hash:     'd27bce09bbd6e1f96baa48516c11c8cc',
    name:     'Nmap SSL Scanning',
    type:     'tool',
    detail:   'Escaneos SSL con nmap. Debería verse solo en IPs de tu red o en ventanas de mantenimiento.',
    severity: 'medium',
  },
  // ── Browsers legítimos ────────────────────────────────────
  {
    hash:     '773906b0efdefa24a7f2b8eb6985bf37',
    name:     'Chrome 83-96 (Windows)',
    type:     'benign',
    detail:   'Huella de Chrome con TLS 1.3. Normal en tráfico corporativo y usuarios finales.',
    severity: 'info',
  },
  {
    hash:     '53b7c45e93f5d2f5765a1cf5e61c1e26',
    name:     'Firefox 95+ (Linux)',
    type:     'benign',
    detail:   'Mozilla Firefox versiones recientes. Diferencia principal: curvas x25519 primero.',
    severity: 'info',
  },
  {
    hash:     '07f3d598e197f6255e17ef9b0c6cd22a',
    name:     'Safari / iOS 15+',
    type:     'benign',
    detail:   'Apple Safari y WebKit. Extensiones propias de Apple (ALPS) generan una huella distinta.',
    severity: 'info',
  },
];


/* ─────────────────────────────────────────────────────────────
   5. TAB NAVIGATION
   Mismo patrón que john-lab.js — reutilizable en todos los labs.
   ───────────────────────────────────────────────────────────── */
function initTabs() {
  const buttons  = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      buttons.forEach(b  => b.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const el = document.getElementById('tab-' + target);
      if (!el) return;
      el.classList.add('active');

      // Inicializar tab específico al activar
      if (target === 'calculator') activateAllSteps(false); // reset
    });
  });
}


/* ─────────────────────────────────────────────────────────────
   6. TAB 1 — ANATOMÍA: interacción hover en campos del paquete
   ───────────────────────────────────────────────────────────── */
function initAnatomyTab() {
  // Al hacer click en un campo JA3, se explica en el panel inferior
  const fields  = document.querySelectorAll('.tls-field.ja3-field');
  const explain = document.getElementById('field-explain');

  if (!explain) return;

  const EXPLANATIONS = {
    version: {
      title: 'SSLVersion (Campo 1)',
      text:  'La versión TLS del ClientHello handshake. Valor decimal de la capa Record. ' +
             '<code>769</code> = TLS 1.0, <code>770</code> = TLS 1.1, <code>771</code> = TLS 1.2, ' +
             '<code>772</code> = TLS 1.3. Nota: en TLS 1.3 el campo legacy_version sigue siendo 0x0303 (771) — ' +
             'la versión real se negocia en la extensión supported_versions.',
    },
    ciphers: {
      title: 'Ciphers (Campo 2)',
      text:  'Lista de cipher suites que el cliente ofrece, en orden de preferencia. ' +
             'Cada valor es un identificador IANA de 16 bits (decimal). Se excluyen valores GREASE. ' +
             'Los primeros valores revelan preferencias: ej. <code>4865</code> = TLS_AES_128_GCM_SHA256 (TLS 1.3).',
    },
    extensions: {
      title: 'Extensions (Campo 3)',
      text:  'Tipos de extensiones TLS incluidas en el Client Hello. El orden importa — browsers ' +
             'diferentes priorizan extensiones de forma distinta. Valores GREASE excluidos. ' +
             'Ej: <code>0</code> = SNI, <code>16</code> = ALPN, <code>43</code> = supported_versions, ' +
             '<code>51</code> = key_share.',
    },
    curves: {
      title: 'EllipticCurves (Campo 4)',
      text:  'Extensión supported_groups (formerly elliptic_curves). Grupos criptográficos que el cliente soporta. ' +
             '<code>29</code> = x25519 (muy común en TLS 1.3), <code>23</code> = secp256r1, ' +
             '<code>24</code> = secp384r1. El orden revela la implementación TLS del cliente.',
    },
    ecformats: {
      title: 'ECPointFormats (Campo 5)',
      text:  'Extensión ec_point_formats. Formatos de puntos de curva elíptica soportados. ' +
             'Casi siempre es <code>[0]</code> (uncompressed). En TLS 1.3 esta extensión ya no aplica, ' +
             'pero clients la incluyen por compatibilidad con TLS 1.2.',
    },
  };

  fields.forEach(field => {
    field.addEventListener('click', () => {
      const key = field.dataset.explain;
      const info = EXPLANATIONS[key];
      if (!info || !explain) return;

      fields.forEach(f => f.style.background = '');
      field.style.background = 'rgba(0, 212, 255, 0.1)';

      explain.innerHTML = `
        <strong style="color:var(--accent)">${info.title}</strong><br>
        <span style="font-size:0.82rem; line-height:1.65">${info.text}</span>
      `;
      explain.classList.add('visible');
    });
  });
}


/* ─────────────────────────────────────────────────────────────
   7. TAB 2 — CALCULADORA JA3 INTERACTIVA
   ───────────────────────────────────────────────────────────── */

/**
 * activateAllSteps(on)
 * Activa/desactiva los indicadores visuales de los pasos.
 */
function activateAllSteps(on) {
  document.querySelectorAll('.ja3-step').forEach(s => {
    s.classList.toggle('active', on);
  });
}

/**
 * setStepOutput(stepId, text)
 * Actualiza el texto del output de un paso.
 */
function setStepOutput(stepId, text) {
  const el = document.getElementById(stepId);
  if (el) el.textContent = text;
}

/**
 * loadPreset(key)
 * Carga los campos del preset en los inputs del calculador.
 */
function loadPreset(key) {
  const p = JA3_PRESETS[key];
  if (!p) return;

  const get = id => document.getElementById(id);

  if (get('calc-version'))    get('calc-version').value    = p.version;
  if (get('calc-ciphers'))    get('calc-ciphers').value    = p.ciphers.join(',');
  if (get('calc-extensions')) get('calc-extensions').value = p.extensions.join(',');
  if (get('calc-curves'))     get('calc-curves').value     = p.curves.join(',');
  if (get('calc-ecformats'))  get('calc-ecformats').value  = p.ecFormats.join(',');

  // Mostrar descripción del preset
  const descEl = document.getElementById('preset-description');
  if (descEl) {
    descEl.textContent = p.description;
    descEl.classList.add('visible');
  }

  // Resetear resultado anterior
  resetCalculator();
}

/**
 * resetCalculator()
 * Limpia los resultados del calculador.
 */
function resetCalculator() {
  activateAllSteps(false);
  ['step-extract', 'step-grease', 'step-concat', 'step-hash'].forEach(id => {
    setStepOutput(id, '—');
  });
  const resultEl = document.getElementById('ja3-result');
  if (resultEl) resultEl.textContent = '—';

  const threatEl = document.getElementById('calc-threat');
  if (threatEl) {
    threatEl.className = 'threat-indicator';
    threatEl.innerHTML = '';
  }
}

/**
 * runCalculator()
 * Lee los campos del formulario, calcula el JA3 paso a paso,
 * y muestra cada etapa animada.
 */
function runCalculator() {
  const get = id => document.getElementById(id);

  // Leer inputs
  const version    = parseInt(get('calc-version')?.value || '771', 10);
  const ciphers    = parseIntList(get('calc-ciphers')?.value    || '');
  const extensions = parseIntList(get('calc-extensions')?.value || '');
  const curves     = parseIntList(get('calc-curves')?.value     || '');
  const ecFormats  = parseIntList(get('calc-ecformats')?.value  || '0');

  if (!version || ciphers.length === 0) {
    alert('Ingresá al menos la versión y las cipher suites.');
    return;
  }

  // ── Paso 1: Extracción de campos ──────────────────────────
  setTimeout(() => {
    const step1 = document.getElementById('ja3-step-1');
    if (step1) step1.classList.add('active');

    const extract = [
      `version     = ${version}`,
      `ciphers     = [${ciphers.join(', ')}]`,
      `extensions  = [${extensions.join(', ')}]`,
      `curves      = [${curves.join(', ')}]`,
      `ecFormats   = [${ecFormats.join(', ')}]`,
    ].join('\n');
    setStepOutput('step-extract', extract);
  }, 100);

  // ── Paso 2: Filtrar GREASE ────────────────────────────────
  setTimeout(() => {
    const step2 = document.getElementById('ja3-step-2');
    if (step2) step2.classList.add('active');

    const fc = filterGrease(ciphers);
    const fe = filterGrease(extensions);
    const fk = filterGrease(curves);

    const greaseFound  = [...ciphers, ...extensions, ...curves].filter(n => GREASE_VALUES.has(n));
    const greaseUnique = [...new Set(greaseFound)];

    const greaseLine = greaseUnique.length > 0
      ? `GREASE eliminados: [${greaseUnique.map(n => '0x' + n.toString(16).toUpperCase()).join(', ')}]`
      : 'GREASE eliminados: ninguno';

    setStepOutput('step-grease',
      `${greaseLine}\nciphers     → [${fc.join(', ')}]\nextensions  → [${fe.join(', ')}]\ncurves      → [${fk.join(', ')}]`
    );
  }, 500);

  // ── Paso 3: Concatenación JA3 ─────────────────────────────
  setTimeout(() => {
    const step3 = document.getElementById('ja3-step-3');
    if (step3) step3.classList.add('active');

    const ja3str = buildJa3String({ version, ciphers, extensions, curves, ecFormats });
    setStepOutput('step-concat', ja3str);
    // Guardar para el siguiente paso
    window._lastJa3String = ja3str;
  }, 1000);

  // ── Paso 4: Hash MD5 ─────────────────────────────────────
  setTimeout(() => {
    const step4 = document.getElementById('ja3-step-4');
    if (step4) step4.classList.add('active');

    const ja3str  = window._lastJa3String || buildJa3String({ version, ciphers, extensions, curves, ecFormats });
    const ja3hash = computeJa3Hash(ja3str);

    setStepOutput('step-hash', ja3hash);

    // Mostrar en el display grande
    const resultEl = document.getElementById('ja3-result');
    if (resultEl) resultEl.textContent = ja3hash;

    // Lookup en base de firmas
    showThreatResult(ja3hash);
  }, 1600);
}

/**
 * showThreatResult(hash)
 * Busca el hash en JA3_SIGNATURES y muestra el indicador de amenaza.
 */
function showThreatResult(hash) {
  const threatEl = document.getElementById('calc-threat');
  if (!threatEl) return;

  const sig = JA3_SIGNATURES.find(s => s.hash === hash);

  if (sig) {
    const typeClass = {
      malware: 'threat-malware', c2: 'threat-malware',
      tool:    'threat-tool',
      benign:  'threat-benign',
    }[sig.type] || 'threat-unknown';

    const icon = { malware: '🔴', c2: '🔴', tool: '🟡', benign: '🟢' }[sig.type] || '⚪';

    threatEl.className = `threat-indicator ${typeClass} visible`;
    threatEl.innerHTML = `
      <strong>${icon} ${sig.name}</strong> — ${sig.detail}
    `;
  } else {
    threatEl.className = 'threat-indicator threat-unknown visible';
    threatEl.innerHTML = `
      <strong>⚪ Hash no encontrado en la base de firmas local</strong> —
      Verificar en: <code>ja3er.com</code>, <code>sslbl.abuse.ch/ja3-fingerprints</code>,
      <code>intel.google.com/GCTI</code>. La ausencia no implica benignidad.
    `;
  }
}

function initCalculatorTab() {
  // Botones de preset
  document.querySelectorAll('.calc-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      // Marcar activo
      document.querySelectorAll('.calc-preset-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      loadPreset(btn.dataset.preset);
    });
  });

  // Botón calcular
  const calcBtn = document.getElementById('calc-run-btn');
  if (calcBtn) calcBtn.addEventListener('click', runCalculator);

  // Botón limpiar
  const clearBtn = document.getElementById('calc-clear-btn');
  if (clearBtn) clearBtn.addEventListener('click', resetCalculator);

  // Cargar Chrome por defecto
  loadPreset('chrome');
  if (document.querySelector('.calc-preset-btn[data-preset="chrome"]')) {
    document.querySelector('.calc-preset-btn[data-preset="chrome"]').classList.add('active');
  }
}


/* ─────────────────────────────────────────────────────────────
   8. TAB 3 — FIRMAS CONOCIDAS
   ───────────────────────────────────────────────────────────── */
function renderSignatures() {
  const container = document.getElementById('sig-container');
  if (!container) return;

  container.innerHTML = '';

  JA3_SIGNATURES.forEach(sig => {
    const typeClass  = { malware: 'malware', c2: 'c2', tool: 'tool', benign: 'benign' }[sig.type] || 'tool';
    const badgeClass = { malware: 'badge-malware', c2: 'badge-c2', tool: 'badge-tool', benign: 'badge-benign' }[sig.type] || 'badge-tool';
    const badgeText  = { malware: '⚠ MALWARE', c2: '⚠ C2', tool: 'DUAL-USE', benign: '✓ LEGÍTIMO' }[sig.type] || 'TOOL';
    const sevColor   = { critical: '#ff2d55', high: '#ff6a00', medium: '#ffcc00', info: '#39ff14' }[sig.severity] || '#7a8ea8';

    const card = document.createElement('div');
    card.className = `sig-card ${typeClass}`;
    card.innerHTML = `
      <div class="sig-hash">${sig.hash}</div>
      <div class="sig-info">
        <div class="sig-name">${sig.name}</div>
        <div class="sig-detail">${sig.detail}</div>
      </div>
      <span class="sig-badge ${badgeClass}">${badgeText}</span>
    `;
    container.appendChild(card);
  });
}

function initSignaturesTab() {
  renderSignatures();

  // Lookup rápido
  const lookupInput = document.getElementById('sig-lookup-input');
  const lookupBtn   = document.getElementById('sig-lookup-btn');
  const lookupRes   = document.getElementById('lookup-result');

  function doLookup() {
    if (!lookupInput || !lookupRes) return;
    const hash = lookupInput.value.trim().toLowerCase();

    if (!/^[a-f0-9]{32}$/.test(hash)) {
      lookupRes.className    = 'lookup-result visible not-found';
      lookupRes.textContent  = 'Hash inválido. Un hash MD5 tiene exactamente 32 caracteres hexadecimales.';
      return;
    }

    const sig = JA3_SIGNATURES.find(s => s.hash === hash);
    if (sig) {
      const foundClass = { malware: 'found-malware', c2: 'found-malware', tool: 'found-tool', benign: 'found-benign' }[sig.type] || 'found-tool';
      lookupRes.className = `lookup-result visible ${foundClass}`;
      lookupRes.innerHTML = `
        <strong>${sig.name}</strong><br>
        <span style="font-size:0.8rem">${sig.detail}</span>
      `;
    } else {
      lookupRes.className   = 'lookup-result visible not-found';
      lookupRes.textContent = 'No encontrado en base local. Consultá: ja3er.com · sslbl.abuse.ch · VirusTotal.';
    }
  }

  if (lookupBtn) lookupBtn.addEventListener('click', doLookup);
  if (lookupInput) lookupInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLookup(); });

  // Filtrado por tipo
  document.querySelectorAll('.sig-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sig-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const filter = btn.dataset.filter;
      document.querySelectorAll('.sig-card').forEach(card => {
        if (filter === 'all') {
          card.style.display = '';
        } else {
          card.style.display = card.classList.contains(filter) ? '' : 'none';
        }
      });
    });
  });
}


/* ─────────────────────────────────────────────────────────────
   9. TAB 4 — RESPUESTA SOC (estático, sin lógica JS adicional)
   ───────────────────────────────────────────────────────────── */
function initSocTab() {
  // Los pasos SOC son HTML estático — solo activamos animación
  const steps = document.querySelectorAll('.soc-step');
  if (!steps.length) return;

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.animation = 'tabFadeIn 0.35s ease forwards';
      }
    });
  }, { threshold: 0.15 });

  steps.forEach(s => observer.observe(s));
}


/* ─────────────────────────────────────────────────────────────
   10. INIT — Punto de entrada principal
   ───────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initAnatomyTab();
  initCalculatorTab();
  initSignaturesTab();
  initSocTab();
});
