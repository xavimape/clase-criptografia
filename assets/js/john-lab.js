'use strict';

/* =============================================================
   john-lab.js — Laboratorio Interactivo John the Ripper
   Cryptography for SOC Analysts — clase-cripto-soc.netlify.app

   AVISO LEGAL: Todo lo que ocurre aquí es SIMULADO.
   No se ejecuta ningún cracking real. Solo uso educativo.
   ============================================================= */

/* ─────────────────────────────────────────────────────────────
   DATOS DE DEMOSTRACIÓN
   Hashes MD5 pre-computados públicamente conocidos.
   Estas contraseñas son intencionalmente débiles y se usan
   exclusivamente para ilustrar por qué MD5 es inseguro.
   ───────────────────────────────────────────────────────────── */
const KNOWN_HASHES = {
  '21232f297a57a5a743894a0e4a801fc3': 'admin',
  '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
  'd8578edf8458ce06fbc5bb76a58c5ca4': 'qwerty',
  '482c811da5d5b4bc6d497ffa98491e38': 'password123',
  '0d107d09f5bbe40cade3de5c71e9e9b7': 'letmein',
  'fcea920f7412b5da7be0cf42b8c93759': '111111',
  '7c6a180b36896a0a8c02787eeafb0e4c': 'password1',
  'f25a2fc72690b780b2a14e140ef6a9e0': 'iloveyou',
  'e10adc3949ba59abbe56e057f20f883e': '123456',
  '25d55ad283aa400af464c76d713c07ad': '12345678',
};

const ROCKYOU_MINI = [
  'admin', 'password', 'password123', '123456', 'qwerty',
  'letmein', 'welcome', 'monkey', 'dragon', 'master',
  'abc123', '111111', 'baseball', 'iloveyou', 'trustno1',
  'sunshine', 'princess', 'shadow', 'superman', 'michael',
  'football', 'mustang', 'access', 'batman', 'passw0rd',
  'password1', '1234567', '12345678', '123456789', 'qwerty123',
];

/* ─────────────────────────────────────────────────────────────
   1. TAB NAVIGATION
   ───────────────────────────────────────────────────────────── */
function initTabs() {
  const buttons  = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      // Deactivate all
      buttons.forEach(b  => b.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));

      // Activate selected
      btn.classList.add('active');
      const targetEl = document.getElementById('tab-' + target);
      if (!targetEl) return;
      targetEl.classList.add('active');

      // Trigger tab-specific initialisation
      if (target === 'hashes')     animateHashBars();
      if (target === 'bruteforce') updateBruteForce();
    });
  });
}

/* ─────────────────────────────────────────────────────────────
   2. TAB 1 — DICTIONARY ATTACK SIMULATION
   ───────────────────────────────────────────────────────────── */
let dictRunning = false;
let dictTimers  = [];

function clearAllTimers() {
  dictTimers.forEach(id => clearTimeout(id));
  dictTimers = [];
}

function scheduleTimeout(fn, delay) {
  const id = setTimeout(fn, delay);
  dictTimers.push(id);
  return id;
}

function clearTerminal() {
  const body = document.getElementById('terminal-body');
  if (body) body.innerHTML = '';
}

function addLine(text, cssClass) {
  const body = document.getElementById('terminal-body');
  if (!body) return;
  const span = document.createElement('span');
  span.className = 'terminal-line' + (cssClass ? ' ' + cssClass : '');
  span.textContent = text;
  body.appendChild(span);
  body.scrollTop = body.scrollHeight;
}

function setRunBtn(label, handler) {
  const btn = document.getElementById('dict-run-btn');
  if (!btn) return;
  btn.textContent = label;
  btn.disabled    = false;
  btn.onclick     = handler;
}

function stopDictionary() {
  clearAllTimers();
  dictRunning = false;
  setRunBtn('▶ Iniciar auditoría', runDictionaryAttack);
}

function runDictionaryAttack() {
  const hashInput = document.getElementById('dict-hash-input');
  const hash = hashInput ? hashInput.value.trim().toLowerCase() : '';

  if (!hash) {
    addLine('[ERROR] Ingresá un hash MD5 para auditar.', 't-error');
    return;
  }
  if (!/^[a-f0-9]{32}$/.test(hash)) {
    addLine('[ERROR] Formato inválido. Un hash MD5 tiene 32 caracteres hexadecimales (0-9, a-f).', 't-error');
    return;
  }

  clearTerminal();
  dictRunning  = true;
  const runBtn = document.getElementById('dict-run-btn');
  if (runBtn) {
    runBtn.textContent = '⏹ Detener';
    runBtn.onclick     = () => { stopDictionary(); addLine('[ABORTED] Auditoría detenida por el usuario.', 't-warn'); };
  }

  const matchedPlain = KNOWN_HASHES[hash] || null;
  const matchIndex   = matchedPlain ? ROCKYOU_MINI.indexOf(matchedPlain) : -1;
  const totalWords   = ROCKYOU_MINI.length;
  const startTime    = Date.now();

  // ── Header lines ──
  const headers = [
    { text: 'john (v1.9.0-jumbo-1) — Cryptography for SOC Analysts Lab',  cls: 't-info' },
    { text: '───────────────────────────────────────────────────────────', cls: 't-prompt' },
    { text: `[CMD]  john --format=raw-md5 --wordlist=rockyou-mini.txt hash.txt`, cls: 't-cmd' },
    { text: `[INFO] Target hash : ${hash}`,                                cls: 't-info' },
    { text: `[INFO] Format      : Raw-MD5`,                                cls: 't-info' },
    { text: `[INFO] Loading wordlist: rockyou-mini.txt (${totalWords} words) ...`, cls: 't-info' },
    { text: `[INFO] Wordlist loaded. Starting dictionary attack...`,       cls: 't-info' },
    { text: '───────────────────────────────────────────────────────────', cls: 't-prompt' },
  ];

  let cumulativeDelay = 0;
  headers.forEach((line, i) => {
    scheduleTimeout(() => {
      if (!dictRunning) return;
      addLine(line.text, line.cls);
    }, cumulativeDelay + i * 75);
  });

  cumulativeDelay += headers.length * 75 + 120;

  // ── Try each word ──
  // Show every word at index < 5, then 1 in 4, always show the match.
  const STEP_MS    = 110;   // ms between batches of 4
  const WITHIN_MS  = 18;    // ms between lines in same batch

  ROCKYOU_MINI.forEach((word, idx) => {
    const batchDelay = cumulativeDelay + Math.floor(idx / 4) * STEP_MS + (idx % 4) * WITHIN_MS;

    const shouldShow = idx < 5 || idx % 4 === 0 || idx === matchIndex;

    if (!shouldShow) return;

    scheduleTimeout(() => {
      if (!dictRunning) return;

      if (idx === matchIndex) {
        // ── MATCH FOUND ──
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        addLine('───────────────────────────────────────────────────────────', 't-prompt');
        addLine(`[MATCH] ${word.padEnd(20)} → HASH CRACKEADO`, 't-match');
        addLine(`[FOUND] ${word}:${hash}`, 't-match');
        addLine('───────────────────────────────────────────────────────────', 't-prompt');
        addLine(`[STATS] 1 password hash crackeado en ${elapsed}s`, 't-match');
        addLine(`[STATS] ${matchIndex + 1} / ${totalWords} palabras probadas`, 't-info');
        addLine(`[WARN]  Hash MD5 roto en ${elapsed}s → MD5 es INSEGURO para passwords`, 't-warn');
        addLine(`[HINT]  Solución: bcrypt o Argon2id + salt`, 't-info');
        stopDictionary();
      } else {
        addLine(`[TRY]  ${word.padEnd(20)} → no match`, 't-try');
      }
    }, batchDelay);
  });

  // ── If no match ──
  if (matchIndex === -1) {
    const finalDelay = cumulativeDelay + Math.ceil(totalWords / 4) * STEP_MS + 300;
    scheduleTimeout(() => {
      if (!dictRunning) return;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      addLine('───────────────────────────────────────────────────────────', 't-prompt');
      addLine(`[INFO] Wordlist agotada. ${totalWords} contraseñas probadas (${elapsed}s)`, 't-info');
      addLine(`[INFO] Sin match en rockyou-mini.txt`, 't-warn');
      addLine(`[HINT] Intentos siguientes: --incremental (fuerza bruta) o wordlist más grande`, 't-info');
      addLine(`[NOTE] La contraseña puede ser compleja o no estar en esta wordlist.`, 't-info');
      stopDictionary();
    }, finalDelay);
  }
}

function initDictionaryTab() {
  const runBtn   = document.getElementById('dict-run-btn');
  const clearBtn = document.getElementById('dict-clear-btn');
  const hashInput = document.getElementById('dict-hash-input');

  // Preset hash buttons
  document.querySelectorAll('.preset-btn[data-hash]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (hashInput) hashInput.value = btn.dataset.hash;
    });
  });

  if (runBtn)   runBtn.addEventListener('click', runDictionaryAttack);
  if (clearBtn) clearBtn.addEventListener('click', () => { stopDictionary(); clearTerminal(); });
}

/* ─────────────────────────────────────────────────────────────
   3. TAB 2 — BRUTE FORCE CALCULATOR
   ───────────────────────────────────────────────────────────── */
const CHARSETS = {
  digits:      { size: 10,  label: 'Números (0-9)' },
  lower:       { size: 26,  label: 'Minúsculas (a-z)' },
  upper:       { size: 26,  label: 'Mayúsculas (A-Z)' },
  lower_upper: { size: 52,  label: 'a-z + A-Z' },
  alphanumeric:{ size: 62,  label: 'a-zA-Z + 0-9' },
  full:        { size: 95,  label: 'Full ASCII imprimible' },
};

const CRACK_SPEEDS = [
  { label: 'MD5 (GPU RTX 3090)',      speed: 10e9,   note: '~10B/seg',    style: 'danger-cell' },
  { label: 'SHA1 (GPU)',              speed: 3.3e9,  note: '~3.3B/seg',   style: 'danger-cell' },
  { label: 'SHA256 (GPU)',            speed: 1.2e9,  note: '~1.2B/seg',   style: 'danger-cell' },
  { label: 'bcrypt $12 (GPU)',        speed: 15000,  note: '~15K/seg',    style: null },
  { label: 'Argon2id (GPU)',          speed: 800,    note: '~800/seg',    style: null },
];

function fmtNum(n) {
  if (n >= 1e18) return (n / 1e18).toFixed(1) + ' ×10¹⁸';
  if (n >= 1e15) return (n / 1e15).toFixed(1) + ' ×10¹⁵';
  if (n >= 1e12) return (n / 1e12).toFixed(1) + ' billones';
  if (n >= 1e9)  return (n / 1e9).toFixed(1)  + ' mil millones';
  if (n >= 1e6)  return (n / 1e6).toFixed(1)  + ' millones';
  if (n >= 1e3)  return Math.round(n / 1e3)    + ' mil';
  return Math.round(n).toString();
}

function fmtTime(sec) {
  if (sec < 0.001)         return '< 1 ms';
  if (sec < 1)             return (sec * 1000).toFixed(0) + ' ms';
  if (sec < 60)            return sec.toFixed(2) + ' seg';
  if (sec < 3600)          return (sec / 60).toFixed(1) + ' min';
  if (sec < 86400)         return (sec / 3600).toFixed(1) + ' horas';
  if (sec < 86400 * 365)   return (sec / 86400).toFixed(0) + ' días';
  if (sec < 86400 * 365 * 1000) return (sec / (86400 * 365)).toFixed(0) + ' años';
  return '> 1.000 años';
}

function timeClass(sec) {
  if (sec < 3600)          return 'danger-cell';   // < 1 hora
  if (sec < 86400 * 365)   return 'warn-cell';     // < 1 año
  return 'ok-cell';
}

function updateBruteForce() {
  const lengthEl  = document.getElementById('bf-length');
  const charsetEl = document.getElementById('bf-charset');
  if (!lengthEl || !charsetEl) return;

  const length  = parseInt(lengthEl.value) || 8;
  const csKey   = charsetEl.value;
  const charset = CHARSETS[csKey] || CHARSETS.full;

  // combinations = charsetSize ^ length (use logarithms to avoid Infinity)
  const logComb   = length * Math.log10(charset.size);
  const combBig   = Math.pow(10, logComb);
  const entropy   = length * Math.log2(charset.size);

  // Update display
  const combEl = document.getElementById('bf-combinations');
  if (combEl) combEl.textContent = fmtNum(combBig);

  const csInfoEl = document.getElementById('bf-charset-info');
  if (csInfoEl) csInfoEl.textContent = `${charset.size} caracteres posibles · ${charset.label}`;

  const entropyEl = document.getElementById('bf-entropy');
  if (entropyEl) entropyEl.textContent = entropy.toFixed(1) + ' bits';

  // Build speed table
  const tbody = document.getElementById('bf-speed-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  CRACK_SPEEDS.forEach(({ label, speed, note, style }) => {
    const sec    = combBig / speed;
    const tCls   = style || timeClass(sec);
    const row    = document.createElement('tr');
    row.innerHTML = `
      <td style="font-size:0.85rem">${label}</td>
      <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted)">${note}</td>
      <td class="${tCls}" style="font-size:0.82rem">${fmtTime(sec)}</td>
    `;
    tbody.appendChild(row);
  });
}

function initBruteForceTab() {
  const lengthEl      = document.getElementById('bf-length');
  const charsetEl     = document.getElementById('bf-charset');
  const lengthDisplay = document.getElementById('bf-length-display');

  if (lengthEl) {
    lengthEl.addEventListener('input', () => {
      if (lengthDisplay) lengthDisplay.textContent = lengthEl.value;
      updateBruteForce();
    });
  }
  if (charsetEl) {
    charsetEl.addEventListener('change', updateBruteForce);
  }

  // Quick preset buttons
  document.querySelectorAll('.bf-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      if (lengthEl) {
        lengthEl.value = btn.dataset.length;
        if (lengthDisplay) lengthDisplay.textContent = btn.dataset.length;
      }
      if (charsetEl) charsetEl.value = btn.dataset.charset;
      updateBruteForce();
    });
  });

  updateBruteForce();
}

/* ─────────────────────────────────────────────────────────────
   4. TAB 3 — HASH COMPARATOR
   ───────────────────────────────────────────────────────────── */
const HASH_DATA = [
  {
    name: 'MD5', year: '1992',
    card_class: 'insecure', verdict: 'INSEGURO', verdict_class: 'verdict-danger',
    metrics: [
      { label: 'Seguridad para passwords', pct: 4,  bar: 'bar-red' },
      { label: 'Velocidad del atacante',   pct: 98, bar: 'bar-red' },
      { label: 'Resistencia colisiones',   pct: 5,  bar: 'bar-red' },
    ],
    note: '~10B hash/seg en GPU. Colisiones demostradas desde 2004. Nunca usar para passwords.',
  },
  {
    name: 'SHA1', year: '1995',
    card_class: 'weak', verdict: 'DÉBIL', verdict_class: 'verdict-warn',
    metrics: [
      { label: 'Seguridad para passwords', pct: 18, bar: 'bar-yellow' },
      { label: 'Velocidad del atacante',   pct: 90, bar: 'bar-red' },
      { label: 'Resistencia colisiones',   pct: 20, bar: 'bar-yellow' },
    ],
    note: '~3.3B hash/seg en GPU. SHAttered collision (2017). Deprecated por NIST.',
  },
  {
    name: 'bcrypt', year: '1999',
    card_class: 'strong', verdict: 'SEGURO', verdict_class: 'verdict-ok',
    metrics: [
      { label: 'Seguridad para passwords', pct: 82, bar: 'bar-green' },
      { label: 'Velocidad del atacante',   pct: 7,  bar: 'bar-green' },
      { label: 'Resistencia colisiones',   pct: 80, bar: 'bar-green' },
    ],
    note: '~15K hash/seg máx. Salt automático. Work factor ajustable. Estándar ampliamente adoptado.',
  },
  {
    name: 'Argon2id', year: '2015',
    card_class: 'best', verdict: 'ÓPTIMO', verdict_class: 'verdict-best',
    metrics: [
      { label: 'Seguridad para passwords', pct: 97, bar: 'bar-blue' },
      { label: 'Velocidad del atacante',   pct: 2,  bar: 'bar-blue' },
      { label: 'Resistencia colisiones',   pct: 97, bar: 'bar-blue' },
    ],
    note: 'PHC winner. Memory-hard. Resistente a GPU/ASIC. Ajuste de mem/iter/threads. OWASP recomendado.',
  },
];

function renderHashCards() {
  const container = document.getElementById('hash-cards-container');
  if (!container) return;

  container.innerHTML = '';

  HASH_DATA.forEach(h => {
    const metricsHTML = h.metrics.map(m => `
      <div class="hash-metric">
        <div class="hash-metric-label">
          <span>${m.label}</span>
          <span>${m.pct}%</span>
        </div>
        <div class="hash-bar-track">
          <div class="hash-bar-fill ${m.bar}" data-width="${m.pct}" style="width:0%"></div>
        </div>
      </div>
    `).join('');

    const card = document.createElement('div');
    card.className = `hash-card ${h.card_class}`;
    card.innerHTML = `
      <div class="hash-card-name">${h.name}</div>
      <div class="hash-card-year">Diseñado ${h.year}</div>
      ${metricsHTML}
      <span class="hash-verdict ${h.verdict_class}">${h.verdict}</span>
      <p class="hash-card-note">${h.note}</p>
    `;
    container.appendChild(card);
  });
}

function animateHashBars() {
  // Brief delay so the tab is visible before animating
  setTimeout(() => {
    document.querySelectorAll('.hash-bar-fill[data-width]').forEach(el => {
      el.style.width = '0%';
      // Force a reflow to restart the CSS transition
      void el.getBoundingClientRect();
      requestAnimationFrame(() => {
        el.style.width = el.dataset.width + '%';
      });
    });
  }, 60);
}

/* ─────────────────────────────────────────────────────────────
   5. TAB 4 — MITIGATION CHECKLIST
   ───────────────────────────────────────────────────────────── */
const CHECKLIST_ITEMS = [
  {
    id: 'mfa',
    title: 'Activar MFA (Multi-Factor Authentication)',
    desc: 'Control más efectivo contra credential stuffing y brute force online. Incluso con la contraseña comprometida, el atacante no puede acceder sin el segundo factor.',
  },
  {
    id: 'length',
    title: 'Contraseñas de 16+ caracteres',
    desc: '16 chars con full ASCII = ~10²⁸ combinaciones. Fuerza bruta se vuelve computacionalmente inviable incluso con hardware especializado.',
  },
  {
    id: 'complexity',
    title: 'Mezclar tipos de caracteres',
    desc: 'Combinar mayúsculas, minúsculas, números y símbolos expande exponencialmente el espacio de búsqueda y resiste ataques de diccionario.',
  },
  {
    id: 'manager',
    title: 'Usar un gestor de contraseñas',
    desc: 'Genera y almacena contraseñas únicas por servicio. Elimina la reutilización de contraseñas, principal vector de credential stuffing.',
  },
  {
    id: 'salt',
    title: 'Salt aleatorio único por usuario (backend)',
    desc: 'Invalida rainbow tables y garantiza que dos usuarios con la misma contraseña tengan hashes distintos. bcrypt y Argon2 lo hacen automáticamente.',
  },
  {
    id: 'bcrypt',
    title: 'Almacenar con bcrypt (cost≥12) o Argon2id',
    desc: 'Reemplazar MD5/SHA1 por funciones lentas por diseño. bcrypt cost 12 ≈ 150ms por hash. Hashear 10B contraseñas tomaría décadas.',
  },
  {
    id: 'lockout',
    title: 'Account lockout y rate limiting',
    desc: 'Bloquear cuenta tras N intentos fallidos. Limitar requests por IP/usuario. Detiene ataques online automatizados sin importar la wordlist.',
  },
  {
    id: 'monitor',
    title: 'Monitorear en SIEM: failed logins + correlación',
    desc: 'Alerta ante >10 login fallidos en 60s por IP. Correlacionar con threat intel (IPs conocidas de credential stuffing). Event ID 4625/4740 en Windows.',
  },
];

function renderChecklist() {
  const list = document.getElementById('mitigation-checklist');
  if (!list || list.children.length > 0) { updateProgress(); return; }

  CHECKLIST_ITEMS.forEach(item => {
    const li = document.createElement('li');
    li.className    = 'check-item';
    li.dataset.id   = item.id;
    li.innerHTML = `
      <div class="check-box">✓</div>
      <div class="check-info">
        <div class="check-title">${item.title}</div>
        <p class="check-desc">${item.desc}</p>
      </div>
    `;
    li.addEventListener('click', () => {
      li.classList.toggle('checked');
      updateProgress();
    });
    list.appendChild(li);
  });

  updateProgress();
}

function updateProgress() {
  const total   = document.querySelectorAll('.check-item').length;
  const checked = document.querySelectorAll('.check-item.checked').length;
  const pct     = total > 0 ? Math.round((checked / total) * 100) : 0;

  const fill  = document.getElementById('checklist-progress-fill');
  const label = document.getElementById('checklist-progress-label');
  if (fill)  fill.style.width = pct + '%';
  if (label) label.textContent = `${checked} / ${total} controles`;
}

/* ─────────────────────────────────────────────────────────────
   INIT — punto de entrada
   ───────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDictionaryTab();
  initBruteForceTab();
  renderHashCards();
  renderChecklist();

  // If hash tab is default-active on load, run bars immediately
  if (document.getElementById('tab-hashes')?.classList.contains('active')) {
    animateHashBars();
  }
});
