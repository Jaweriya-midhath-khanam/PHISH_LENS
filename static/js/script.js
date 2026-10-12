/**
 * PhisLens — Frontend Application Logic
 * Handles interactive particle starfield, theme toggling, URL scanning,
 * API integration, results rendering, and scan history persistence.
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- 1. Starfield Particle Background Animation ---
  initStarfield();

  // --- 2. Theme Toggle Controller ---
  initThemeToggle();

  // --- 3. Navigation & Section Scrolling ---
  initNavigation();

  // --- 4. Live Model Health & Stats Polling ---
  fetchModelHealth();
  fetchModelStats();

  // --- 5. URL Scanner & Results Handling ---
  initUrlScanner();

  // --- 6. Recent Scan History Controller ---
  renderHistory();
});


/* ==========================================================================
   1. Interactive Starfield Canvas Animation
   ========================================================================== */
function initStarfield() {
  const canvas = document.getElementById('starfield-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  const starCount = Math.floor((width * height) / 9000);
  const stars = [];

  for (let i = 0; i < starCount; i++) {
    stars.push({
      x: Math.random() * width,
      y: Math.random() * height,
      radius: Math.random() * 1.4 + 0.4,
      alpha: Math.random() * 0.8 + 0.2,
      velocity: Math.random() * 0.3 + 0.05,
      twinkleSpeed: Math.random() * 0.02 + 0.005,
      twinkleDirection: Math.random() > 0.5 ? 1 : -1,
      color: Math.random() > 0.8 ? '#c084fc' : '#ffffff',
    });
  }

  function resizeCanvas() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }

  window.addEventListener('resize', resizeCanvas);

  function animate() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < stars.length; i++) {
      const star = stars[i];

      // Update position
      star.y -= star.velocity;
      if (star.y < 0) {
        star.y = height;
        star.x = Math.random() * width;
      }

      // Update twinkle
      star.alpha += star.twinkleSpeed * star.twinkleDirection;
      if (star.alpha > 0.95) {
        star.alpha = 0.95;
        star.twinkleDirection = -1;
      } else if (star.alpha < 0.2) {
        star.alpha = 0.2;
        star.twinkleDirection = 1;
      }

      // Draw star
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
      ctx.fillStyle = star.color;
      ctx.globalAlpha = star.alpha;
      ctx.fill();
    }

    ctx.globalAlpha = 1.0;
    requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);
}


/* ==========================================================================
   2. Theme Toggle Controller (Dark / Light)
   ========================================================================== */
function initThemeToggle() {
  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  const savedTheme = localStorage.getItem('phislens-theme') || 'dark';

  document.documentElement.setAttribute('data-theme', savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('phislens-theme', newTheme);
    });
  }
}


/* ==========================================================================
   3. Navigation & Section Scrolling
   ========================================================================== */
function initNavigation() {
  const navLinks = document.querySelectorAll('.nav-item');
  const sections = document.querySelectorAll('.page-section');
  const mobileToggle = document.getElementById('mobile-menu-toggle');
  const mainNav = document.getElementById('main-nav');

  // Mobile menu toggle
  if (mobileToggle && mainNav) {
    mobileToggle.addEventListener('click', () => {
      mainNav.classList.toggle('open');
    });

    // Close mobile nav when link is clicked
    navLinks.forEach((link) => {
      link.addEventListener('click', () => {
        mainNav.classList.remove('open');
      });
    });
  }

  // Active state on scroll
  window.addEventListener('scroll', () => {
    let currentId = '';
    const scrollPosition = window.scrollY + 180;

    sections.forEach((section) => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      if (scrollPosition >= top && scrollPosition < top + height) {
        currentId = section.getAttribute('id');
      }
    });

    if (currentId) {
      navLinks.forEach((link) => {
        link.classList.toggle('active', link.getAttribute('href') === `#${currentId}`);
      });
    }
  });
}


/* ==========================================================================
   4. Health & Stats Polling
   ========================================================================== */
async function fetchModelHealth() {
  const badgeText = document.getElementById('model-status-text');
  const badgeWrap = document.getElementById('model-status-badge');

  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.model_loaded) {
      badgeText.textContent = 'AI Model: Active (91.5% Acc)';
      badgeWrap.style.borderColor = 'rgba(16, 185, 129, 0.4)';
    } else {
      badgeText.textContent = 'Model: Offline';
      badgeWrap.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    }
  } catch (err) {
    badgeText.textContent = 'API Connection Error';
    badgeWrap.style.borderColor = 'rgba(239, 68, 68, 0.4)';
  }
}

async function fetchModelStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    if (data.status === 'success' && data.metrics) {
      const m = data.metrics;
      const accElem = document.getElementById('metric-accuracy');
      const precElem = document.getElementById('metric-precision');
      const recElem = document.getElementById('metric-recall');
      const f1Elem = document.getElementById('metric-f1');

      if (accElem) accElem.textContent = `${(m.accuracy * 100).toFixed(2)}%`;
      if (precElem) precElem.textContent = `${(m.precision * 100).toFixed(2)}%`;
      if (recElem) recElem.textContent = `${(m.recall * 100).toFixed(2)}%`;
      if (f1Elem) f1Elem.textContent = `${(m.f1_score * 100).toFixed(2)}%`;

      if (m.confusion_matrix) {
        const cm = m.confusion_matrix;
        const tnElem = document.getElementById('cm-tn');
        const fpElem = document.getElementById('cm-fp');
        const fnElem = document.getElementById('cm-fn');
        const tpElem = document.getElementById('cm-tp');

        if (tnElem) tnElem.textContent = cm.true_negatives.toLocaleString();
        if (fpElem) fpElem.textContent = cm.false_positives.toLocaleString();
        if (fnElem) fnElem.textContent = cm.false_negatives.toLocaleString();
        if (tpElem) tpElem.textContent = cm.true_positives.toLocaleString();
      }
    }
  } catch (e) {
    // Graceful fallback to static defaults already in HTML
  }
}


/* ==========================================================================
   5. URL Scanner & Results Handling
   ========================================================================== */
function initUrlScanner() {
  const form = document.getElementById('url-scan-form');
  const input = document.getElementById('url-input');
  const clearBtn = document.getElementById('clear-input-btn');
  const submitBtn = document.getElementById('scan-submit-btn');
  const btnSpinner = document.getElementById('btn-spinner');
  const btnIcon = document.getElementById('btn-icon');
  const btnText = document.getElementById('btn-text');
  const alertBox = document.getElementById('input-alert');
  const progressBox = document.getElementById('scanning-progress-box');
  const resultsContainer = document.getElementById('results-container');
  const sampleChips = document.querySelectorAll('.sample-chip');

  // Input typing listener to show/hide clear button
  input.addEventListener('input', () => {
    clearBtn.style.display = input.value.trim().length > 0 ? 'block' : 'none';
    hideAlert();
  });

  // Clear input button
  clearBtn.addEventListener('click', () => {
    input.value = '';
    clearBtn.style.display = 'none';
    input.focus();
    hideAlert();
  });

  // Sample Chips quick click
  sampleChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const sampleUrl = chip.getAttribute('data-sample');
      if (sampleUrl) {
        input.value = sampleUrl;
        clearBtn.style.display = 'block';
        hideAlert();
        executeScan(sampleUrl);
      }
    });
  });

  // Form submit
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const targetUrl = input.value.trim();
    if (!targetUrl) {
      showAlert('Please enter a URL to inspect.');
      input.focus();
      return;
    }
    executeScan(targetUrl);
  });

  function showAlert(msg) {
    alertBox.textContent = msg;
    alertBox.className = 'input-alert alert-error';
    alertBox.style.display = 'block';
  }

  function hideAlert() {
    alertBox.style.display = 'none';
  }

  async function executeScan(urlToScan) {
    hideAlert();
    setScanningState(true);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToScan }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to complete URL forensic scan.');
      }

      renderScanResults(data);
      saveToHistory(data);
    } catch (err) {
      showAlert(err.message || 'Network error encountered during URL scanning.');
      resultsContainer.classList.remove('visible');
    } finally {
      setScanningState(false);
    }
  }

  function setScanningState(isScanning) {
    if (isScanning) {
      submitBtn.disabled = true;
      btnSpinner.style.display = 'inline-block';
      btnIcon.style.display = 'none';
      btnText.textContent = 'Forensics Active...';
      progressBox.classList.add('active');
      resultsContainer.classList.remove('visible');
    } else {
      submitBtn.disabled = false;
      btnSpinner.style.display = 'none';
      btnIcon.style.display = 'inline-block';
      btnText.textContent = 'Analyze URL';
      progressBox.classList.remove('active');
    }
  }
}

function renderScanResults(data) {
  const container = document.getElementById('results-container');
  if (!container) return;

  const pred = data.prediction;
  const urlInfo = data.url;
  const summary = data.features_summary;
  const explanations = data.explanations || [];

  // Determine icon & verdict classes
  let iconHtml = '';
  if (pred.color === 'green') {
    iconHtml = `
      <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <polyline points="9 12 11 14 15 10"></polyline>
      </svg>
    `;
  } else if (pred.color === 'yellow') {
    iconHtml = `
      <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    `;
  } else {
    iconHtml = `
      <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <line x1="15" y1="9" x2="9" y2="15"></line>
        <line x1="9" y1="9" x2="15" y2="15"></line>
      </svg>
    `;
  }

  const explanationsHtml = explanations
    .map(
      (obs) => `
      <li class="observation-item">
        <span class="obs-bullet">✦</span>
        <span>${escapeHtml(obs)}</span>
      </li>
    `
    )
    .join('');

  container.innerHTML = `
    <div class="result-card glass-panel verdict-${pred.class}">
      
      <!-- Primary Verdict Banner -->
      <div class="verdict-banner">
        <div class="verdict-main">
          <div class="verdict-icon-badge" aria-hidden="true">
            ${iconHtml}
          </div>
          <div>
            <h3 class="verdict-title">${escapeHtml(pred.label)}</h3>
            <p class="verdict-summary-url">${escapeHtml(urlInfo.normalized)}</p>
          </div>
        </div>

        <div class="confidence-box">
          <div class="confidence-val-row">
            <span class="confidence-number">${pred.confidence_percent}%</span>
            <span class="confidence-lbl">Model Confidence</span>
          </div>
          <div class="prob-breakdown">
            <span>Legitimate: <strong class="prob-val prob-legit">${(pred.probability_legitimate * 100).toFixed(1)}%</strong></span>
            <span>Phishing: <strong class="prob-val prob-phish">${(pred.probability_phishing * 100).toFixed(1)}%</strong></span>
          </div>
        </div>
      </div>

      <!-- Result Details Grid -->
      <div class="result-details-grid">
        <!-- Forensic Signals & Explanations -->
        <div class="detail-block">
          <h4 class="detail-block-title">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
            Forensic Signals & Threat Explanation
          </h4>
          <ul class="observations-list">
            ${explanationsHtml}
          </ul>
        </div>

        <!-- URL Structure Decomposition -->
        <div class="detail-block">
          <h4 class="detail-block-title">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="4 7 4 4 20 4 20 7"></polyline>
              <line x1="9" y1="20" x2="15" y2="20"></line>
              <line x1="12" y1="4" x2="12" y2="20"></line>
            </svg>
            Lexical & Structural Telemetry
          </h4>
          <table class="metrics-table">
            <tbody>
              <tr>
                <td class="metric-key">Protocol Scheme</td>
                <td class="metric-data">${escapeHtml(urlInfo.scheme.toUpperCase())} ${summary.is_https ? '🔒' : '⚠️'}</td>
              </tr>
              <tr>
                <td class="metric-key">Hostname / Domain</td>
                <td class="metric-data">${escapeHtml(urlInfo.hostname)}</td>
              </tr>
              <tr>
                <td class="metric-key">Total Character Length</td>
                <td class="metric-data">${summary.length_url} chars</td>
              </tr>
              <tr>
                <td class="metric-key">Subdomain Count</td>
                <td class="metric-data">${summary.subdomain_count}</td>
              </tr>
              <tr>
                <td class="metric-key">Raw IP Host Detection</td>
                <td class="metric-data">${summary.has_ip_address ? '<span style="color:#f87171">YES (Direct IP)</span>' : 'NO (Domain Host)'}</td>
              </tr>
              <tr>
                <td class="metric-key">Suspicious Brand Keywords</td>
                <td class="metric-data">${summary.has_sensitive_keywords > 0 ? `<span style="color:#fbbf24">${summary.has_sensitive_keywords} Detected</span>` : '0 Detected'}</td>
              </tr>
              <tr>
                <td class="metric-key">Hostname Shannon Entropy</td>
                <td class="metric-data">${summary.entropy_hostname} bits</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Safety Disclaimer Alert Box -->
      <div class="safety-warning-banner" role="alert">
        <span class="warning-icon" aria-hidden="true">⚠️</span>
        <div>
          <strong>Safety Advisory:</strong> ${escapeHtml(data.safety_warning)}
        </div>
      </div>

    </div>
  `;

  container.classList.add('visible');
  container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


/* ==========================================================================
   6. Recent Scan History Controller (Persisted in localStorage)
   ========================================================================== */
const HISTORY_KEY = 'phislens_scan_history';

function getHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveToHistory(scanData) {
  try {
    const list = getHistory();
    const entry = {
      id: Date.now(),
      url: scanData.url.normalized,
      class: scanData.prediction.class,
      label: scanData.prediction.label,
      confidence: scanData.prediction.confidence_percent,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    // Filter out duplicate identical URL if already at the top
    const filtered = list.filter((item) => item.url !== entry.url);
    filtered.unshift(entry);

    // Keep max 8 entries
    const truncated = filtered.slice(0, 8);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(truncated));
    renderHistory();
  } catch (e) {
    console.error('Failed to save scan history:', e);
  }
}

function renderHistory() {
  const historyList = document.getElementById('history-list');
  const clearBtn = document.getElementById('clear-history-btn');
  if (!historyList) return;

  const items = getHistory();

  if (items.length === 0) {
    historyList.innerHTML = `
      <div class="history-empty">
        <span>No recent scans recorded. Enter a URL above to perform your first forensic inspection.</span>
      </div>
    `;
    if (clearBtn) clearBtn.style.display = 'none';
    return;
  }

  if (clearBtn) {
    clearBtn.style.display = 'block';
    clearBtn.onclick = () => {
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
    };
  }

  historyList.innerHTML = items
    .map(
      (item) => `
      <div class="history-item">
        <div class="history-item-left">
          <span class="history-badge ${item.class}">${item.class}</span>
          <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span>
        </div>
        <div class="history-item-right">
          <span class="history-confidence">${item.confidence}%</span>
          <button type="button" class="history-rescan-btn" data-url="${escapeHtml(item.url)}">
            Re-scan
          </button>
        </div>
      </div>
    `
    )
    .join('');

  // Attach re-scan button handlers
  const rescanButtons = historyList.querySelectorAll('.history-rescan-btn');
  rescanButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const urlToRescan = btn.getAttribute('data-url');
      const input = document.getElementById('url-input');
      if (input && urlToRescan) {
        input.value = urlToRescan;
        const form = document.getElementById('url-scan-form');
        if (form) form.dispatchEvent(new Event('submit'));
      }
    });
  });
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
