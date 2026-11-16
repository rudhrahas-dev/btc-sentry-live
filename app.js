/* ======================================================== */
/* BITCOIN SENTRY MOBILE COCKPIT CLIENT ENGINE             */
/* WebCrypto PBKDF2 + AES-GCM-256 Authenticated Decryption  */
/* ======================================================== */

(function () {
  'use strict';

  // State
  let currentPin = '';
  let activePin = '';
  let pollIntervalId = null;
  let elapsedTimerId = null;
  let blockStartTimestamp = Date.now();
  let lastUpdatedEpoch = 0;
  let cachedPayload = null;

  // DOM Elements - Lock Screen
  const lockScreen = document.getElementById('lockScreen');
  const cockpit = document.getElementById('cockpit');
  const pinDots = [
    document.getElementById('dot0'),
    document.getElementById('dot1'),
    document.getElementById('dot2'),
    document.getElementById('dot3'),
    document.getElementById('dot4'),
    document.getElementById('dot5')
  ];
  const pinStatus = document.getElementById('pinErrorMsg');
  const rememberMe = document.getElementById('rememberMe');
  const keypad = document.querySelector('.keypad');

  // DOM Elements - Cockpit
  const currentBlockEl = document.getElementById('currentBlock');
  const blockElapsedEl = document.getElementById('blockElapsed');
  const networkDiffEl = document.getElementById('networkDiff');
  const blkZeroesBadge = document.getElementById('blkZeroesBadge');
  const sessionRecordBadge = document.getElementById('sessionRecordBadge');
  const trophyDiffEl = document.getElementById('trophyDiff');
  const bestHashPreview = document.getElementById('bestHashPreview');

  const speedValEl = document.getElementById('speedVal');
  const speedEfficiencyEl = document.getElementById('speedEfficiency');
  const peakSpeedEl = document.getElementById('peakSpeed');
  const tachoFill = document.getElementById('tachoFill');
  const totalNoncesEl = document.getElementById('totalNonces');
  const batchSizeEl = document.getElementById('batchSize');

  const gpuTempEl = document.getElementById('gpuTemp');
  const gpuWattsEl = document.getElementById('gpuWatts');
  const gpuFanEl = document.getElementById('gpuFan');
  const gpuClockEl = document.getElementById('gpuClock');
  const cpuTempLoadEl = document.getElementById('cpuTempLoad');
  const feedContainer = document.getElementById('feedContainer');
  const lastUpdatedText = document.getElementById('lastUpdatedText');
  const telemetryStatus = document.getElementById('telemetryStatus');
  const walletAddrEl = document.getElementById('walletAddr');
  const walletPill = document.getElementById('walletPill');

  const btnRefresh = document.getElementById('btnRefresh');
  const btnLock = document.getElementById('btnLock');

  // ========================================================
  // UTILITIES: HEX & WEBCRYPTO
  // ========================================================
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  async function decryptTelemetry(pin, encryptedObj) {
    if (!encryptedObj || !encryptedObj.salt || !encryptedObj.iv || !encryptedObj.ct) {
      throw new Error('Malformed encrypted payload');
    }

    const salt = hexToBytes(encryptedObj.salt);
    const iv = hexToBytes(encryptedObj.iv);
    const ciphertext = hexToBytes(encryptedObj.ct);

    const encoder = new TextEncoder();
    const pinBytes = encoder.encode(pin);

    // 1. Import raw PIN as key material
    const baseKey = await crypto.subtle.importKey(
      'raw',
      pinBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // 2. Derive 256-bit AES-GCM key via PBKDF2 (100,000 iterations)
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // 3. Decrypt ciphertext (includes 16-byte GCM authentication tag)
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      aesKey,
      ciphertext
    );

    const decodedStr = new TextDecoder().decode(decryptedBuffer);
    return JSON.parse(decodedStr);
  }

  // ========================================================
  // PIN KEYPAD LOGIC
  // ========================================================
  function updatePinDisplay() {
    pinDots.forEach((dot, index) => {
      if (index < currentPin.length) {
        dot.classList.add('filled');
      } else {
        dot.classList.remove('filled');
      }
    });
  }

  function handleKeyInput(key) {
    if (key === 'clear') {
      currentPin = '';
      updatePinDisplay();
      pinStatus.textContent = 'ENTER 6-DIGIT PIN';
      pinStatus.classList.remove('error');
      return;
    }

    if (key === 'backspace') {
      currentPin = currentPin.slice(0, -1);
      updatePinDisplay();
      pinStatus.textContent = 'ENTER 6-DIGIT PIN';
      pinStatus.classList.remove('error');
      return;
    }

    if (currentPin.length < 6 && /^[0-9]$/.test(key)) {
      currentPin += key;
      updatePinDisplay();

      if (currentPin.length === 6) {
        attemptUnlock(currentPin);
      }
    }
  }

  // Keyboard support for desktop testing
  window.addEventListener('keydown', (e) => {
    if (cockpit.classList.contains('hidden')) {
      if (e.key >= '0' && e.key <= '9') {
        handleKeyInput(e.key);
      } else if (e.key === 'Backspace') {
        handleKeyInput('backspace');
      } else if (e.key === 'Escape') {
        handleKeyInput('clear');
      }
    }
  });

  // Touch keypad clicks
  keypad.addEventListener('click', (e) => {
    const btn = e.target.closest('.key-btn');
    if (!btn) return;
    const key = btn.getAttribute('data-key');
    handleKeyInput(key);
  });

  // Telemetry URL endpoints (Raw GitHub CDN bypasses Jekyll build delay & Fastly edge cache)
  const RAW_TELEMETRY_URL = 'https://raw.githubusercontent.com/rudhrahas-dev/btc-sentry-live/main/telemetry.json';
  const LOCAL_TELEMETRY_URL = 'telemetry.json';

  async function fetchTelemetryPayload() {
    const bust = Date.now();
    // 1. Prioritize raw.githubusercontent.com for instant real-time telemetry
    try {
      const respRaw = await fetch(`${RAW_TELEMETRY_URL}?t=${bust}`, { cache: 'no-store' });
      if (respRaw.ok) {
        return await respRaw.json();
      }
    } catch (rawErr) {
      console.warn('Raw GitHub fetch failed, falling back to local Pages url:', rawErr);
    }

    // 2. Fallback to GitHub Pages local asset
    const respLocal = await fetch(`${LOCAL_TELEMETRY_URL}?t=${bust}`, { cache: 'no-store' });
    if (!respLocal.ok) {
      throw new Error(`HTTP ${respLocal.status}: Telemetry offline`);
    }
    return await respLocal.json();
  }

  async function attemptUnlock(pinCandidate) {
    pinStatus.textContent = 'VERIFYING KEY...';
    pinStatus.classList.remove('error');

    try {
      // 1. Fetch latest telemetry payload (zero-latency raw endpoint)
      const encryptedData = await fetchTelemetryPayload();

      // 2. Decrypt with PIN
      const payload = await decryptTelemetry(pinCandidate, encryptedData);

      // Success!
      activePin = pinCandidate;
      cachedPayload = payload;

      if (rememberMe.checked) {
        localStorage.setItem('sentry_saved_pin', pinCandidate);
      } else {
        sessionStorage.setItem('sentry_session_pin', pinCandidate);
      }

      // Smooth transition
      lockScreen.classList.add('fade-out');
      setTimeout(() => {
        lockScreen.style.display = 'none';
        cockpit.classList.remove('hidden');
        renderTelemetry(payload);
        startPolling();
      }, 300);

    } catch (err) {
      console.warn('Unlock failure:', err);
      pinStatus.textContent = 'INVALID OPERATOR PIN';
      pinStatus.classList.add('error');
      keypad.classList.add('shake');
      setTimeout(() => {
        keypad.classList.remove('shake');
        currentPin = '';
        updatePinDisplay();
      }, 500);
    }
  }

  function lockCockpit() {
    stopPolling();
    activePin = '';
    currentPin = '';
    updatePinDisplay();
    localStorage.removeItem('sentry_saved_pin');
    sessionStorage.removeItem('sentry_session_pin');
    cockpit.classList.add('hidden');
    lockScreen.style.display = 'flex';
    lockScreen.classList.remove('fade-out');
    pinStatus.textContent = 'ENTER 6-DIGIT PIN';
    pinStatus.classList.remove('error');
  }

  btnLock.addEventListener('click', lockCockpit);

  // ========================================================
  // TELEMETRY RENDERING ENGINE
  // ========================================================
  function getZeroesBadgeClass(z) {
    if (z >= 11) return 'badge-magenta';
    if (z === 10) return 'badge-green';
    if (z === 9) return 'badge-cyan';
    return 'badge-gold';
  }

  function renderTelemetry(data) {
    lastUpdatedEpoch = data.updated_at || Math.floor(Date.now() / 1000);
    updateRelativeTime();

    // 1. Target Block Card
    if (data.current_block) {
      currentBlockEl.textContent = '#' + data.current_block;
    }
    if (data.target_diff) {
      networkDiffEl.textContent = data.target_diff;
    }

    // Active block best zeroes
    const blkZ = data.current_block_zeroes || 0;
    blkZeroesBadge.textContent = blkZ > 0 ? `${blkZ} zeroes` : '--';
    blkZeroesBadge.className = 'zeroes-badge ' + getZeroesBadgeClass(blkZ);

    // Session record trophy
    const sessZ = data.highest_zeroes || 12;
    sessionRecordBadge.textContent = `${sessZ} ZEROES`;
    if (data.highest_diff) {
      const dStr = data.highest_diff >= 1000 ? Math.round(data.highest_diff).toLocaleString() : data.highest_diff.toFixed(1);
      trophyDiffEl.textContent = `Diff: ${dStr}`;
    }
    if (data.highest_hash) {
      const h = data.highest_hash;
      bestHashPreview.textContent = `${h.substr(0, 14)}...${h.substr(-8)}`;
      bestHashPreview.title = `Full Hash: ${h} (from ${data.highest_source || 'GPU Search'})`;
    }

    // Elapsed block time calculation (exact epoch sync)
    if (data.block_start_epoch) {
      blockStartTimestamp = data.block_start_epoch * 1000;
      updateElapsedTimer();
    } else if (data.block_elapsed_sec !== undefined) {
      blockStartTimestamp = Date.now() - (data.block_elapsed_sec * 1000);
      updateElapsedTimer();
    }

    // 2. Hash Engine Speed & Nonces
    const speed = data.hashrate || 0.0;
    speedValEl.innerHTML = `${speed.toFixed(1)} <span class="unit">${data.hashrate_unit || 'MH/s'}</span>`;
    if (data.efficiency_khw) {
      speedEfficiencyEl.textContent = `Efficiency: ${Math.round(data.efficiency_khw).toLocaleString()} kH/W`;
    }
    if (data.peak_hashrate) {
      peakSpeedEl.textContent = `Peak: ${data.peak_hashrate.toFixed(1)} MH/s`;
    }

    // Tachometer fill (0 to 160 MH/s scale)
    const pct = Math.min(100, Math.max(5, (speed / 160) * 100));
    tachoFill.style.width = pct + '%';

    if (data.total_nonces_trillion) {
      totalNoncesEl.textContent = `${data.total_nonces_trillion.toFixed(2)} TRILLION`;
    }
    if (data.threads && data.intensity) {
      batchSizeEl.textContent = `${Math.round(data.threads / 1000)}k (I${data.intensity})`;
    }

    // 3. Silicon Hardware Vitals
    if (data.gpu_temp !== undefined) {
      gpuTempEl.textContent = `${Math.round(data.gpu_temp)}°C`;
      gpuTempEl.style.color = data.gpu_temp > 70 ? 'var(--neon-orange)' : 'var(--neon-green)';
    }
    if (data.gpu_power !== undefined) {
      gpuWattsEl.textContent = `${data.gpu_power.toFixed(1)}W`;
    }
    if (data.gpu_fan !== undefined) {
      gpuFanEl.textContent = `${data.gpu_fan}%`;
    }
    if (data.gpu_clock !== undefined) {
      gpuClockEl.textContent = `${data.gpu_clock}M`;
    }
    if (data.cpu_temp !== undefined && data.cpu_load !== undefined) {
      cpuTempLoadEl.textContent = `${Math.round(data.cpu_temp)}°C · ${data.cpu_load.toFixed(1)}L`;
    }

    // Payout Wallet & Pool
    if (data.wallet) {
      const w = data.wallet;
      walletAddrEl.textContent = `${w.substr(0, 8)}...${w.substr(-6)}`;
      walletPill.onclick = () => {
        navigator.clipboard.writeText(w).then(() => {
          const old = walletAddrEl.textContent;
          walletAddrEl.textContent = 'COPIED!';
          setTimeout(() => { walletAddrEl.textContent = old; }, 1200);
        });
      };
    }
    if (data.pool) {
      document.getElementById('poolName').textContent = data.pool.split(':')[0];
    }

    // 4. Live Event Feed
    if (Array.isArray(data.recent_events) && data.recent_events.length > 0) {
      renderEventFeed(data.recent_events);
    }
  }

  function renderEventFeed(events) {
    feedContainer.innerHTML = '';
    events.forEach(ev => {
      const row = document.createElement('div');
      row.className = 'feed-row ' + (ev.type === 'best_hash' ? 'feed-magenta' : (ev.type === 'milestone' ? 'feed-gold' : 'feed-cyan'));

      const tSpan = document.createElement('span');
      tSpan.className = 'f-time';
      tSpan.textContent = ev.time || '--:--';

      const txtSpan = document.createElement('span');
      txtSpan.className = 'f-text';
      txtSpan.innerHTML = ev.text || '';

      row.appendChild(tSpan);
      row.appendChild(txtSpan);
      feedContainer.appendChild(row);
    });
  }

  // ========================================================
  // CLOCK & TIMERS
  // ========================================================
  function updateElapsedTimer() {
    const sec = Math.max(0, Math.floor((Date.now() - blockStartTimestamp) / 1000));
    const mins = Math.floor(sec / 60);
    const secs = sec % 60;
    blockElapsedEl.textContent = `⏱️ ${String(mins).padStart(2, '0')}m ${String(secs).padStart(2, '0')}s`;
  }

  function updateRelativeTime() {
    if (!lastUpdatedEpoch) return;
    const diffSec = Math.max(0, Math.floor(Date.now() / 1000 - lastUpdatedEpoch));
    if (diffSec < 5) {
      lastUpdatedText.textContent = 'Synced just now';
    } else if (diffSec < 60) {
      lastUpdatedText.textContent = `Synced ${diffSec}s ago`;
    } else {
      const mins = Math.floor(diffSec / 60);
      lastUpdatedText.textContent = `Synced ${mins}m ago`;
    }
  }

  // ========================================================
  // BACKGROUND POLLING LOOP
  // ========================================================
  async function fetchLatest() {
    if (!activePin) return;
    try {
      const enc = await fetchTelemetryPayload();
      const payload = await decryptTelemetry(activePin, enc);
      cachedPayload = payload;
      renderTelemetry(payload);
      telemetryStatus.textContent = 'LIVE SYNC';
      telemetryStatus.style.color = 'var(--neon-green)';
    } catch (err) {
      console.warn('Sync poll error:', err);
      telemetryStatus.textContent = 'PAUSED';
      telemetryStatus.style.color = 'var(--text-dim)';
    }
  }

  function startPolling() {
    stopPolling();
    // Poll telemetry every 10s for real-time mobile sync
    pollIntervalId = setInterval(fetchLatest, 10000);
    // Tick timers every 1s
    elapsedTimerId = setInterval(() => {
      updateElapsedTimer();
      updateRelativeTime();
    }, 1000);
  }

  function stopPolling() {
    if (pollIntervalId) clearInterval(pollIntervalId);
    if (elapsedTimerId) clearInterval(elapsedTimerId);
    pollIntervalId = null;
    elapsedTimerId = null;
  }

  btnRefresh.addEventListener('click', () => {
    btnRefresh.style.transform = 'rotate(180deg)';
    setTimeout(() => { btnRefresh.style.transform = 'none'; }, 300);
    fetchLatest();
  });

  // ========================================================
  // AUTO-LOGIN ON INIT (IF REMEMBERED)
  // ========================================================
  window.addEventListener('DOMContentLoaded', () => {
    const savedPin = localStorage.getItem('sentry_saved_pin') || sessionStorage.getItem('sentry_session_pin');
    if (savedPin && savedPin.length === 6) {
      currentPin = savedPin;
      updatePinDisplay();
      attemptUnlock(savedPin);
    }
  });

})();
