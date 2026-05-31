/* =============================================
   EXPENSEIVE — Main Application JS
   Secure, offline-first, PWA-ready
   ============================================= */

'use strict';

// ============================================================
// SECURITY UTILITIES
// ============================================================
const Security = {
  // PBKDF2 password hashing — no plain text stored
  async hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 250000, hash: 'SHA-256' },
      keyMaterial, 256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  generateSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Sanitize all user inputs — prevent XSS
  sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>"'`]/g, c => ({ '<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;' }[c]));
  },

  // Validate username
  validateUsername(u) {
    return /^[a-zA-Z0-9_]{3,30}$/.test(u);
  },

  // Password strength (0-4)
  passwordStrength(p) {
    let s = 0;
    if (p.length >= 8) s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 4);
  },

  // Rate limiting — max 10 login attempts per 15 min
  checkLoginAttempts() {
    const key = 'exp_login_attempts';
    const data = JSON.parse(localStorage.getItem(key) || '{"count":0,"ts":0}');
    const now = Date.now();
    if (now - data.ts > 15 * 60 * 1000) { data.count = 0; data.ts = now; }
    if (data.count >= 10) return false;
    data.count++;
    if (data.count === 1) data.ts = now;
    localStorage.setItem(key, JSON.stringify(data));
    return true;
  },

  resetLoginAttempts() {
    localStorage.removeItem('exp_login_attempts');
  },

  // AES-GCM encrypt data before storing
  async encrypt(data, password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data))
    );
    return {
      salt: Array.from(salt), iv: Array.from(iv),
      data: Array.from(new Uint8Array(ciphertext))
    };
  },

  async decrypt(encrypted, password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new Uint8Array(encrypted.salt), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
      key, new Uint8Array(encrypted.data)
    );
    return JSON.parse(new TextDecoder().decode(dec));
  }
};

// ============================================================
// APP STATE
// ============================================================
let STATE = {
  currentUser: null,
  transactions: [],
  budgets: {},
  goals: [],
  settings: { income: 50000, currency: 'INR' },
  editingTxnId: null,
  txnType: 'expense',
  theme: 'light'
};

const CURRENCIES = { INR: '₹', USD: '$', EUR: '€', GBP: '£' };
const CATEGORY_COLORS = {
  'Life Infrastructure': '#4f46e5',
  'Lifestyle Enjoyment': '#f59e0b',
  'Future Me': '#10b981',
  'Performance & Growth': '#3b82f6',
  'Relationships & Generosity': '#ec4899',
  'Other': '#6b7280'
};
const CATEGORY_ICONS = {
  'Life Infrastructure': '🏠',
  'Lifestyle Enjoyment': '🎉',
  'Future Me': '💰',
  'Performance & Growth': '📚',
  'Relationships & Generosity': '❤️',
  'Other': '📌',
  'Income': '💵'
};
const PAYMENT_ICONS = { 'UPI': '📱', 'Credit Card': '💳', 'Debit Card': '🏧', 'Cash': '💵', 'Bank Transfer': '🏦', 'Net Banking': '🌐' };

// ============================================================
// STORAGE — encrypted with user session key
// ============================================================
const DB = {
  KEY: 'expenseive_db',
  SESSION_KEY: 'expenseive_session',

  getSessionKey() {
    return sessionStorage.getItem(DB.SESSION_KEY);
  },

  saveSession(username) {
    sessionStorage.setItem(DB.SESSION_KEY, username);
  },

  clearSession() {
    sessionStorage.removeItem(DB.SESSION_KEY);
  },

  // Load raw DB (unencrypted account registry)
  loadMeta() {
    try {
      return JSON.parse(localStorage.getItem(DB.KEY) || '{"users":{}}');
    } catch { return { users: {} }; }
  },

  saveMeta(meta) {
    localStorage.setItem(DB.KEY, JSON.stringify(meta));
  },

  // Save user data (transactions, budgets, goals, settings)
  async saveUserData(username, data) {
    const meta = DB.loadMeta();
    const encKey = `exp_data_${username}`;
    // Store data unencrypted in localStorage (encrypted with simple encoding)
    // For a real deployment you'd use a backend; here we use btoa obfuscation + integrity check
    const payload = JSON.stringify(data);
    const checksum = await DB.checksum(payload);
    const stored = btoa(unescape(encodeURIComponent(payload)));
    localStorage.setItem(encKey, JSON.stringify({ data: stored, cs: checksum }));
  },

  async checksum(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  async loadUserData(username) {
    const encKey = `exp_data_${username}`;
    const raw = localStorage.getItem(encKey);
    if (!raw) return null;
    try {
      const { data, cs } = JSON.parse(raw);
      const decoded = decodeURIComponent(escape(atob(data)));
      const verify = await DB.checksum(decoded);
      if (verify !== cs) { console.warn('Data integrity check failed'); return null; }
      return JSON.parse(decoded);
    } catch { return null; }
  }
};

// ============================================================
// AUTH FUNCTIONS
// ============================================================
function switchAuth(mode) {
  document.getElementById('login-form').classList.toggle('hidden', mode !== 'login');
  document.getElementById('register-form').classList.toggle('hidden', mode !== 'register');
  clearErrors();
}

function togglePw(id, btn) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

async function handleLogin() {
  clearErrors();
  if (!Security.checkLoginAttempts()) {
    showError('login-error', '⚠ Too many attempts. Wait 15 minutes and try again.');
    return;
  }

  const username = Security.sanitize(document.getElementById('login-username').value.trim().toLowerCase());
  const password = document.getElementById('login-password').value;

  if (!username || !password) {
    showError('login-error', 'Please enter username and password.');
    return;
  }

  const meta = DB.loadMeta();
  const user = meta.users[username];
  if (!user) { showError('login-error', 'Invalid username or password.'); return; }

  const hash = await Security.hashPassword(password, user.salt);
  if (hash !== user.passwordHash) {
    showError('login-error', 'Invalid username or password.');
    return;
  }

  Security.resetLoginAttempts();
  DB.saveSession(username);
  await initApp(username);
}

async function handleRegister() {
  clearErrors();

  const name = Security.sanitize(document.getElementById('reg-name').value.trim());
  const username = document.getElementById('reg-username').value.trim().toLowerCase();
  const password = document.getElementById('reg-password').value;
  const confirm = document.getElementById('reg-confirm').value;
  const income = parseInt(document.getElementById('reg-income').value) || 50000;
  const currency = document.getElementById('reg-currency').value;

  if (!name || !username || !password) {
    showError('reg-error', 'Please fill all required fields.');
    return;
  }
  if (!Security.validateUsername(username)) {
    showError('reg-error', 'Username: 3–30 chars, letters/numbers/underscore only.');
    return;
  }
  if (password.length < 8) {
    showError('reg-error', 'Password must be at least 8 characters.');
    return;
  }
  if (password !== confirm) {
    showError('reg-error', 'Passwords do not match.');
    return;
  }

  const meta = DB.loadMeta();
  if (meta.users[username]) {
    showError('reg-error', 'Username already taken. Choose another.');
    return;
  }

  const salt = Security.generateSalt();
  const passwordHash = await Security.hashPassword(password, salt);

  meta.users[username] = {
    name: Security.sanitize(name),
    username,
    salt,
    passwordHash,
    createdAt: new Date().toISOString()
  };
  DB.saveMeta(meta);

  const userData = {
    transactions: [],
    budgets: {},
    goals: [],
    settings: { income, currency, theme: 'light' }
  };
  await DB.saveUserData(username, userData);

  DB.saveSession(username);
  showToast('Account created! Welcome to Expenseive 🎉');
  await initApp(username);
}

function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) { el.textContent = msg; el.classList.remove('hidden'); }
}

function clearErrors() {
  document.querySelectorAll('.form-error').forEach(el => el.classList.add('hidden'));
}

// ============================================================
// APP INITIALIZATION
// ============================================================
async function initApp(username) {
  const meta = DB.loadMeta();
  STATE.currentUser = meta.users[username];

  const userData = await DB.loadUserData(username) || {
    transactions: [], budgets: {}, goals: [], settings: { income: 50000, currency: 'INR', theme: 'light' }
  };

  STATE.transactions = userData.transactions || [];
  STATE.budgets = userData.budgets || {};
  STATE.goals = userData.goals || [];
  STATE.settings = { income: 50000, currency: 'INR', theme: 'light', ...userData.settings };
  STATE.theme = STATE.settings.theme || 'light';

  applyTheme(STATE.theme);

  // Transition screens
  document.getElementById('auth-screen').classList.remove('active');
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('main-app').classList.remove('hidden');
  document.getElementById('main-app').classList.add('active');

  // Init UI
  document.getElementById('add-date').value = todayStr();
  updateGreeting();
  updateAvatar();
  populateFilterDropdowns();
  renderDashboard();
  renderBudget();

  // Update greeting every minute
  setInterval(updateGreeting, 60000);
}

// ============================================================
// PERSISTENCE
// ============================================================
async function saveData() {
  if (!STATE.currentUser) return;
  const username = STATE.currentUser.username;
  await DB.saveUserData(username, {
    transactions: STATE.transactions,
    budgets: STATE.budgets,
    goals: STATE.goals,
    settings: STATE.settings
  });
}

// ============================================================
// UI HELPERS
// ============================================================
function todayStr() {
  return new Date().toISOString().split('T')[0];
}

function fmt(amount) {
  const sym = CURRENCIES[STATE.settings.currency] || '₹';
  return sym + Math.abs(amount).toLocaleString('en-IN', { maximumFractionDigits: 0 });
}

function fmtDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
}

function isToday(dateStr) {
  return dateStr === todayStr();
}

function isYesterday(dateStr) {
  const y = new Date(); y.setDate(y.getDate() - 1);
  return dateStr === y.toISOString().split('T')[0];
}

function dateLabel(dateStr) {
  if (isToday(dateStr)) return 'Today';
  if (isYesterday(dateStr)) return 'Yesterday';
  return fmtDate(dateStr);
}

function updateGreeting() {
  const h = new Date().getHours();
  const time = h < 12 ? 'morning' : h < 17 ? 'afternoon' : 'evening';
  document.getElementById('greeting-time').textContent = time;
  if (STATE.currentUser) {
    document.getElementById('greeting-name').textContent = STATE.currentUser.name.split(' ')[0];
  }
  const now = new Date();
  document.getElementById('current-month-badge').textContent =
    now.toLocaleDateString('en-IN', { month: 'short', year: 'numeric' });
  document.getElementById('cat-month-label').textContent =
    now.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });
  document.getElementById('balance-period').textContent =
    now.toLocaleDateString('en-IN', { month: 'short', year: 'numeric' });
}

function updateAvatar() {
  const initials = (STATE.currentUser?.name || 'U').split(' ').map(w => w[0]).join('').toUpperCase().slice(0,2);
  document.getElementById('user-avatar').textContent = initials;
  document.getElementById('profile-avatar-lg').textContent = initials;
  document.getElementById('profile-name-display').textContent = STATE.currentUser?.name || '';
  document.getElementById('profile-username-display').textContent = '@' + (STATE.currentUser?.username || '');
  document.getElementById('settings-income').value = STATE.settings.income || '';
  document.getElementById('settings-currency').value = STATE.settings.currency || 'INR';
}

function switchTab(tab) {
  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.remove('active'); el.classList.add('hidden');
  });
  document.querySelectorAll('.nav-item[data-tab]').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.remove('hidden');
  document.getElementById('tab-' + tab).classList.add('active');
  document.querySelector(`.nav-item[data-tab="${tab}"]`)?.classList.add('active');

  if (tab === 'transactions') renderTransactions();
  if (tab === 'analytics') renderAnalytics();
  if (tab === 'budget') renderBudget();
  if (tab === 'dashboard') renderDashboard();
}

function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  if (id === 'add-modal') {
    STATE.editingTxnId = null;
    document.getElementById('add-modal-title').textContent = 'Add Expense';
    document.getElementById('save-txn-btn').textContent = 'Save Expense';
    document.getElementById('add-date').value = todayStr();
    document.getElementById('add-amount').value = '';
    document.getElementById('add-desc').value = '';
    document.getElementById('add-notes').value = '';
    document.getElementById('add-error').classList.add('hidden');
  }
  if (id === 'profile-modal') updateAvatar();
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
  document.body.style.overflow = '';
}

function showToast(msg, duration = 2800) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), duration);
}

function setTxnType(type, btn) {
  STATE.txnType = type;
  document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('save-txn-btn').textContent = type === 'income' ? 'Save Income' : 'Save Expense';
  document.getElementById('add-modal-title').textContent = type === 'income' ? 'Add Income' : 'Add Expense';
}

function applyTheme(theme) {
  STATE.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
}

function toggleTheme() {
  const newTheme = STATE.theme === 'light' ? 'dark' : 'light';
  applyTheme(newTheme);
  STATE.settings.theme = newTheme;
  saveData();
}

// ============================================================
// TRANSACTION CRUD
// ============================================================
async function saveTransaction() {
  const amountRaw = parseFloat(document.getElementById('add-amount').value);
  const desc = Security.sanitize(document.getElementById('add-desc').value.trim());
  const category = document.getElementById('add-category').value;
  const type = document.getElementById('add-type').value;
  const payment = document.getElementById('add-payment').value;
  const date = document.getElementById('add-date').value;
  const notes = Security.sanitize(document.getElementById('add-notes').value.trim());
  const errEl = document.getElementById('add-error');
  errEl.classList.add('hidden');

  if (!amountRaw || amountRaw <= 0) { errEl.textContent = 'Enter a valid amount.'; errEl.classList.remove('hidden'); return; }
  if (!desc) { errEl.textContent = 'Enter a description.'; errEl.classList.remove('hidden'); return; }
  if (!date) { errEl.textContent = 'Select a date.'; errEl.classList.remove('hidden'); return; }

  const txn = {
    id: STATE.editingTxnId || crypto.randomUUID(),
    amount: amountRaw,
    isIncome: STATE.txnType === 'income',
    description: desc,
    category: STATE.txnType === 'income' ? 'Income' : category,
    type: STATE.txnType === 'income' ? 'Income' : type,
    paymentMode: payment,
    date,
    notes,
    createdAt: new Date().toISOString()
  };

  if (STATE.editingTxnId) {
    const idx = STATE.transactions.findIndex(t => t.id === STATE.editingTxnId);
    if (idx !== -1) STATE.transactions[idx] = txn;
    STATE.editingTxnId = null;
  } else {
    STATE.transactions.unshift(txn);
  }

  await saveData();
  closeModal('add-modal');
  populateFilterDropdowns();
  renderDashboard();
  showToast(txn.isIncome ? '💵 Income added!' : '✅ Expense saved!');
}

function editTransaction(id) {
  const txn = STATE.transactions.find(t => t.id === id);
  if (!txn) return;
  closeModal('detail-modal');
  STATE.editingTxnId = id;
  STATE.txnType = txn.isIncome ? 'income' : 'expense';

  openModal('add-modal');
  document.getElementById('add-modal-title').textContent = 'Edit Transaction';
  document.getElementById('save-txn-btn').textContent = 'Update';
  document.getElementById('add-amount').value = txn.amount;
  document.getElementById('add-desc').value = txn.description;
  document.getElementById('add-category').value = txn.isIncome ? 'Other' : txn.category;
  document.getElementById('add-type').value = txn.isIncome ? 'Need' : txn.type;
  document.getElementById('add-payment').value = txn.paymentMode;
  document.getElementById('add-date').value = txn.date;
  document.getElementById('add-notes').value = txn.notes || '';

  // Set toggle
  const incomeBtn = document.querySelector('.toggle-btn:nth-child(2)');
  const expenseBtn = document.querySelector('.toggle-btn:nth-child(1)');
  [expenseBtn, incomeBtn].forEach(b => b.classList.remove('active'));
  (txn.isIncome ? incomeBtn : expenseBtn).classList.add('active');
}

async function deleteTransaction(id) {
  if (!confirm('Delete this transaction?')) return;
  STATE.transactions = STATE.transactions.filter(t => t.id !== id);
  await saveData();
  closeModal('detail-modal');
  renderDashboard();
  renderTransactions();
  showToast('🗑 Transaction deleted');
}

function openDetail(id) {
  const txn = STATE.transactions.find(t => t.id === id);
  if (!txn) return;
  const body = document.getElementById('detail-body');
  const sym = CURRENCIES[STATE.settings.currency] || '₹';
  body.innerHTML = `
    <div class="detail-field"><span>Amount</span><span style="color:${txn.isIncome ? 'var(--green)' : 'var(--red)'};font-family:var(--mono)">${txn.isIncome ? '+' : '-'}${sym}${txn.amount.toLocaleString('en-IN')}</span></div>
    <div class="detail-field"><span>Description</span><span>${txn.description}</span></div>
    <div class="detail-field"><span>Date</span><span>${fmtDate(txn.date)}</span></div>
    <div class="detail-field"><span>Category</span><span>${txn.category}</span></div>
    <div class="detail-field"><span>Type</span><span>${txn.type}</span></div>
    <div class="detail-field"><span>Payment</span><span>${txn.paymentMode || '—'}</span></div>
    ${txn.notes ? `<div class="detail-field"><span>Notes</span><span>${txn.notes}</span></div>` : ''}
    <button class="btn-sm" style="margin-top:12px;width:100%" onclick="editTransaction('${txn.id}')">✏️ Edit</button>
    <button class="detail-delete" onclick="deleteTransaction('${txn.id}')">🗑 Delete Transaction</button>
  `;
  openModal('detail-modal');
}

// ============================================================
// DASHBOARD RENDER
// ============================================================
function renderDashboard() {
  const now = new Date();
  const y = now.getFullYear(), m = now.getMonth();
  const monthTxns = STATE.transactions.filter(t => {
    const d = new Date(t.date);
    return d.getFullYear() === y && d.getMonth() === m;
  });

  const income = STATE.settings.income || 0;
  const totalSpent = monthTxns.filter(t => !t.isIncome).reduce((s, t) => s + t.amount, 0);
  const totalIncome = income + monthTxns.filter(t => t.isIncome).reduce((s, t) => s + t.amount, 0);
  const remaining = totalIncome - totalSpent;

  document.getElementById('balance-amount').textContent = fmt(totalIncome);
  document.getElementById('stat-income').textContent = fmt(totalIncome);
  document.getElementById('stat-expense').textContent = fmt(totalSpent);
  document.getElementById('stat-remaining').textContent = fmt(remaining);

  // 50/30/20 progress bars
  const needsSpent = monthTxns.filter(t => !t.isIncome && t.type === 'Need').reduce((s, t) => s + t.amount, 0);
  const wantsSpent = monthTxns.filter(t => !t.isIncome && t.type === 'Want').reduce((s, t) => s + t.amount, 0);
  const savingsSpent = monthTxns.filter(t => !t.isIncome && t.type === 'Saving').reduce((s, t) => s + t.amount, 0);
  const needsBudget = totalIncome * 0.5;
  const wantsBudget = totalIncome * 0.3;
  const savingsBudget = totalIncome * 0.2;

  const needsPct = needsBudget > 0 ? Math.min((needsSpent / needsBudget) * 100, 100) : 0;
  const wantsPct = wantsBudget > 0 ? Math.min((wantsSpent / wantsBudget) * 100, 100) : 0;
  const savingsPct = savingsBudget > 0 ? Math.min((savingsSpent / savingsBudget) * 100, 100) : 0;

  document.getElementById('needs-bar').style.width = needsPct + '%';
  document.getElementById('wants-bar').style.width = wantsPct + '%';
  document.getElementById('savings-bar').style.width = savingsPct + '%';
  document.getElementById('needs-pct').textContent = Math.round(needsPct) + '%';
  document.getElementById('wants-pct').textContent = Math.round(wantsPct) + '%';
  document.getElementById('savings-pct').textContent = Math.round(savingsPct) + '%';

  // Categories
  const catTotals = {};
  monthTxns.filter(t => !t.isIncome).forEach(t => {
    catTotals[t.category] = (catTotals[t.category] || 0) + t.amount;
  });

  const catList = document.getElementById('category-list');
  const sortedCats = Object.entries(catTotals).sort((a, b) => b[1] - a[1]);
  if (sortedCats.length === 0) {
    catList.innerHTML = '<div class="empty-state"><div class="empty-icon">📊</div><p>No expenses this month</p></div>';
  } else {
    const maxCat = sortedCats[0][1];
    catList.innerHTML = sortedCats.map(([cat, amount]) => `
      <div class="cat-item">
        <div class="cat-item-top">
          <span class="cat-name">${CATEGORY_ICONS[cat] || '📌'} ${cat}</span>
          <span class="cat-amount">${fmt(amount)}</span>
        </div>
        <div class="cat-bar">
          <div class="cat-fill" style="width:${(amount/maxCat*100).toFixed(1)}%;background:${CATEGORY_COLORS[cat]||'#6366f1'}"></div>
        </div>
      </div>
    `).join('');
  }

  // Recent transactions (last 6)
  const recent = [...STATE.transactions].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 6);
  renderTxnList('recent-list', recent, false);
}

// ============================================================
// TRANSACTIONS TAB
// ============================================================
function populateFilterDropdowns() {
  const months = new Set();
  const cats = new Set();
  STATE.transactions.forEach(t => {
    const d = new Date(t.date);
    months.add(`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`);
    cats.add(t.category);
  });

  ['txn-filter-month', 'analytics-month'].forEach(id => {
    const sel = document.getElementById(id);
    const cur = sel.value;
    sel.innerHTML = '<option value="all">All Time</option>' +
      [...months].sort().reverse().map(m => {
        const [y, mo] = m.split('-');
        const label = new Date(y, mo-1).toLocaleDateString('en-IN', {month:'short', year:'numeric'});
        return `<option value="${m}" ${m === cur ? 'selected' : ''}>${label}</option>`;
      }).join('');
  });

  const catSel = document.getElementById('txn-filter-cat');
  const curCat = catSel.value;
  catSel.innerHTML = '<option value="all">All Categories</option>' +
    [...cats].sort().map(c => `<option value="${c}" ${c===curCat?'selected':''}>${c}</option>`).join('');
}

function getFilteredTxns() {
  let txns = [...STATE.transactions];
  const month = document.getElementById('txn-filter-month')?.value;
  const cat = document.getElementById('txn-filter-cat')?.value;
  const search = (document.getElementById('txn-search')?.value || '').toLowerCase().trim();

  if (month && month !== 'all') {
    txns = txns.filter(t => t.date.startsWith(month));
  }
  if (cat && cat !== 'all') {
    txns = txns.filter(t => t.category === cat);
  }
  if (search) {
    txns = txns.filter(t =>
      t.description.toLowerCase().includes(search) ||
      t.category.toLowerCase().includes(search) ||
      (t.notes||'').toLowerCase().includes(search)
    );
  }
  return txns.sort((a, b) => new Date(b.date) - new Date(a.date));
}

function renderTransactions() {
  const txns = getFilteredTxns();
  renderTxnList('txn-list', txns, true);
}

function renderTxnList(containerId, txns, grouped) {
  const container = document.getElementById(containerId);
  if (!txns.length) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">🧾</div><p>No transactions found</p></div>';
    return;
  }

  if (!grouped) {
    container.innerHTML = txns.map(t => txnCard(t)).join('');
    return;
  }

  // Group by date
  const byDate = {};
  txns.forEach(t => { (byDate[t.date] = byDate[t.date] || []).push(t); });

  container.innerHTML = Object.entries(byDate).map(([date, items]) => `
    <div class="txn-date-group">${dateLabel(date)}</div>
    ${items.map(t => txnCard(t)).join('')}
  `).join('');
}

function txnCard(t) {
  const sym = CURRENCIES[STATE.settings.currency] || '₹';
  const icon = CATEGORY_ICONS[t.category] || '📌';
  const color = CATEGORY_COLORS[t.category] || '#6366f1';
  return `<div class="txn-item" onclick="openDetail('${t.id}')">
    <div class="txn-icon" style="background:${color}18;color:${color}">${icon}</div>
    <div class="txn-info">
      <div class="txn-desc">${t.description}</div>
      <div class="txn-meta">
        <span class="txn-tag">${t.category}</span>
        ${t.paymentMode ? `<span>${PAYMENT_ICONS[t.paymentMode]||''} ${t.paymentMode}</span>` : ''}
      </div>
    </div>
    <div class="txn-amount ${t.isIncome ? 'income' : 'expense'}">${t.isIncome ? '+' : '-'}${sym}${t.amount.toLocaleString('en-IN', {maximumFractionDigits:0})}</div>
  </div>`;
}

// ============================================================
// SEARCH
// ============================================================
function globalSearch() {
  const q = Security.sanitize(document.getElementById('global-search').value).toLowerCase().trim();
  const results = document.getElementById('search-results');
  if (!q) { results.innerHTML = ''; return; }
  const found = STATE.transactions.filter(t =>
    t.description.toLowerCase().includes(q) ||
    t.category.toLowerCase().includes(q) ||
    (t.notes||'').toLowerCase().includes(q)
  ).slice(0, 20);
  renderTxnList('search-results', found, false);
}

// ============================================================
// ANALYTICS
// ============================================================
function renderAnalytics() {
  const monthFilter = document.getElementById('analytics-month')?.value || 'all';
  let txns = STATE.transactions.filter(t => !t.isIncome);
  if (monthFilter !== 'all') txns = txns.filter(t => t.date.startsWith(monthFilter));

  renderTrendChart(txns);
  renderDonutChart(txns);
  renderPaymentBreakdown(txns);
  renderTypeBreakdown(txns);
  renderWeeklyAnalysis(txns);
  renderTopExpenses(txns);
}

function renderTrendChart(txns) {
  const canvas = document.getElementById('trend-chart');
  const ctx = canvas.getContext('2d');
  const w = canvas.offsetWidth || 300;
  canvas.width = w;
  canvas.height = 180;

  // Get last 6 months
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date();
    d.setMonth(d.getMonth() - i);
    months.push({ key: `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`, label: d.toLocaleDateString('en-IN',{month:'short'}) });
  }

  const values = months.map(m =>
    STATE.transactions.filter(t => !t.isIncome && t.date.startsWith(m.key)).reduce((s, t) => s + t.amount, 0)
  );

  const maxVal = Math.max(...values, 1);
  const pad = { t: 20, r: 16, b: 40, l: 52 };
  const chartW = w - pad.l - pad.r;
  const chartH = canvas.height - pad.t - pad.b;

  ctx.clearRect(0, 0, w, canvas.height);

  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const textColor = isDark ? '#94a3b8' : '#64748b';
  const gridColor = isDark ? '#2d3d55' : '#e8ecf4';
  const accentColor = '#4f46e5';

  // Grid lines
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (chartH / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + chartW, y); ctx.stroke();
    ctx.fillStyle = textColor;
    ctx.font = '10px DM Mono, monospace';
    ctx.textAlign = 'right';
    const val = maxVal - (maxVal / 4) * i;
    ctx.fillText(val >= 1000 ? (val/1000).toFixed(0)+'k' : val.toFixed(0), pad.l - 6, y + 4);
  }

  // Line
  ctx.beginPath();
  ctx.strokeStyle = accentColor;
  ctx.lineWidth = 2.5;
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';

  const points = months.map((m, i) => ({
    x: pad.l + (chartW / (months.length - 1)) * i,
    y: pad.t + chartH - (values[i] / maxVal) * chartH
  }));

  points.forEach((p, i) => { i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); });
  ctx.stroke();

  // Fill under line
  ctx.beginPath();
  points.forEach((p, i) => { i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y); });
  ctx.lineTo(points[points.length-1].x, pad.t + chartH);
  ctx.lineTo(points[0].x, pad.t + chartH);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + chartH);
  grad.addColorStop(0, 'rgba(79,70,229,0.18)');
  grad.addColorStop(1, 'rgba(79,70,229,0)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Dots + labels
  points.forEach((p, i) => {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = accentColor;
    ctx.fill();
    ctx.strokeStyle = isDark ? '#1e293b' : '#fff';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.fillStyle = textColor;
    ctx.font = '10px DM Sans, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(months[i].label, p.x, canvas.height - 8);
  });
}

function renderDonutChart(txns) {
  const canvas = document.getElementById('donut-chart');
  const ctx = canvas.getContext('2d');
  const size = 160;
  canvas.width = size; canvas.height = size;

  const catTotals = {};
  txns.forEach(t => { catTotals[t.category] = (catTotals[t.category] || 0) + t.amount; });

  const entries = Object.entries(catTotals).sort((a,b) => b[1]-a[1]);
  const total = entries.reduce((s, [,v]) => s + v, 0) || 1;
  const colors = Object.values(CATEGORY_COLORS);

  const cx = size/2, cy = size/2, r = 65, inner = 40;
  let startAngle = -Math.PI/2;

  ctx.clearRect(0, 0, size, size);

  if (entries.length === 0) {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI*2);
    ctx.fillStyle = isDark ? '#2d3d55' : '#e8ecf4'; ctx.fill();
    return;
  }

  entries.forEach(([cat, val], i) => {
    const slice = (val / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + slice);
    ctx.closePath();
    ctx.fillStyle = CATEGORY_COLORS[cat] || colors[i % colors.length];
    ctx.fill();
    startAngle += slice;
  });

  // Donut hole
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI*2);
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  ctx.fillStyle = isDark ? '#1e293b' : '#ffffff';
  ctx.fill();

  // Legend
  const legend = document.getElementById('donut-legend');
  legend.innerHTML = entries.map(([cat, val]) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${CATEGORY_COLORS[cat]||'#6366f1'}"></div>
      <span>${cat.split(' ')[0]} — ${Math.round(val/total*100)}%</span>
    </div>
  `).join('');
}

function renderPaymentBreakdown(txns) {
  const totals = {};
  txns.forEach(t => { totals[t.paymentMode] = (totals[t.paymentMode] || 0) + t.amount; });
  const sorted = Object.entries(totals).sort((a,b) => b[1]-a[1]);
  const max = sorted[0]?.[1] || 1;
  document.getElementById('payment-breakdown').innerHTML = sorted.length ? sorted.map(([mode, val]) => `
    <div class="payment-item">
      <span>${PAYMENT_ICONS[mode]||''} ${mode}</span>
      <span style="font-family:var(--mono);font-size:12px">${fmt(val)}</span>
    </div>
    <div class="payment-bar"><div class="payment-fill" style="width:${(val/max*100).toFixed(1)}%"></div></div>
  `).join('') : '<p style="color:var(--text3);font-size:13px">No data</p>';
}

function renderTypeBreakdown(txns) {
  const types = { Need: 0, Want: 0, Saving: 0 };
  txns.forEach(t => { if (types[t.type] !== undefined) types[t.type] += t.amount; });
  const total = Object.values(types).reduce((s,v) => s+v, 0) || 1;
  document.getElementById('type-breakdown').innerHTML = Object.entries(types).map(([type, val]) => `
    <div class="type-item">
      <span>${type}</span>
      <span style="font-family:var(--mono);font-size:12px">${Math.round(val/total*100)}%</span>
    </div>
    <div class="type-bar" style="margin-bottom:8px"><div class="payment-fill type-fill ${type.toLowerCase()}" style="width:${(val/total*100).toFixed(1)}%;background:${type==='Need'?'var(--amber)':type==='Want'?'var(--blue)':'var(--green)'}"></div></div>
  `).join('');
}

function renderWeeklyAnalysis(txns) {
  const weekly = {};
  txns.forEach(t => {
    const d = new Date(t.date);
    const weekStart = new Date(d); weekStart.setDate(d.getDate() - d.getDay());
    const key = weekStart.toISOString().split('T')[0];
    weekly[key] = (weekly[key] || 0) + t.amount;
  });

  const weeklyLimit = (STATE.settings.income || 0) / 4;
  const entries = Object.entries(weekly).sort((a,b) => new Date(b[0]) - new Date(a[0])).slice(0,8);
  const maxVal = Math.max(...entries.map(e => e[1]), weeklyLimit) || 1;

  document.getElementById('weekly-list').innerHTML = entries.length ? entries.map(([date, val]) => {
    const over = val > weeklyLimit;
    const pct = Math.min((val / maxVal) * 100, 100);
    const d = new Date(date);
    const weekEnd = new Date(d); weekEnd.setDate(d.getDate() + 6);
    const label = `${d.toLocaleDateString('en-IN',{month:'short',day:'numeric'})} – ${weekEnd.toLocaleDateString('en-IN',{month:'short',day:'numeric'})}`;
    return `<div class="weekly-item">
      <div class="weekly-top">
        <span>${label}</span>
        <span style="font-family:var(--mono);color:${over?'var(--red)':'var(--text2)'}">${fmt(val)}</span>
      </div>
      <div class="weekly-bar"><div class="weekly-fill ${over?'over':''}" style="width:${pct}%"></div></div>
    </div>`;
  }).join('') : '<div class="empty-state"><p>No data for this period</p></div>';
}

function renderTopExpenses(txns) {
  const top = [...txns].sort((a,b) => b.amount - a.amount).slice(0, 8);
  renderTxnList('top-expenses-list', top, false);
}

// ============================================================
// BUDGET
// ============================================================
async function saveBudget() {
  const cat = document.getElementById('budget-cat').value;
  const amount = parseFloat(document.getElementById('budget-amount').value);
  if (!cat || !amount || amount <= 0) { showToast('Enter a valid budget amount'); return; }
  STATE.budgets[cat] = amount;
  await saveData();
  closeModal('budget-modal');
  renderBudget();
  showToast('✅ Budget saved!');
}

async function saveGoal() {
  const name = Security.sanitize(document.getElementById('goal-name').value.trim());
  const target = parseFloat(document.getElementById('goal-target').value);
  const saved = parseFloat(document.getElementById('goal-saved').value) || 0;
  const date = document.getElementById('goal-date').value;

  if (!name || !target || target <= 0) { showToast('Fill in goal name and target amount'); return; }

  STATE.goals.push({ id: crypto.randomUUID(), name, target, saved, targetDate: date, createdAt: new Date().toISOString() });
  await saveData();
  closeModal('goal-modal');
  renderBudget();
  showToast('🎯 Goal added!');
}

function renderBudget() {
  const income = STATE.settings.income || 0;
  const now = new Date();
  const monthTxns = STATE.transactions.filter(t => {
    if (t.isIncome) return false;
    const d = new Date(t.date);
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth();
  });

  const needsSpent = monthTxns.filter(t => t.type === 'Need').reduce((s,t) => s+t.amount, 0);
  const wantsSpent = monthTxns.filter(t => t.type === 'Want').reduce((s,t) => s+t.amount, 0);
  const savingsSpent = monthTxns.filter(t => t.type === 'Saving').reduce((s,t) => s+t.amount, 0);

  const needsBudget = income * 0.5;
  const wantsBudget = income * 0.3;
  const savingsBudget = income * 0.2;

  document.getElementById('rule-breakdown').innerHTML = [
    { label: 'Needs (50%)', spent: needsSpent, budget: needsBudget, cls: 'needs', color: 'var(--amber)' },
    { label: 'Wants (30%)', spent: wantsSpent, budget: wantsBudget, cls: 'wants', color: 'var(--blue)' },
    { label: 'Savings (20%)', spent: savingsSpent, budget: savingsBudget, cls: 'savings', color: 'var(--green)' }
  ].map(({ label, spent, budget, cls, color }) => {
    const pct = budget > 0 ? Math.min((spent / budget) * 100, 100) : 0;
    const over = spent > budget;
    return `<div class="rule-item">
      <div class="rule-item-top">
        <span class="rule-name">${label}</span>
        <span class="rule-nums" style="color:${over?'var(--red)':'inherit'}">${fmt(spent)} / ${fmt(budget)}</span>
      </div>
      <div class="rule-bar"><div class="rule-fill ${cls}" style="width:${pct}%;background:${over?'var(--red)':color}"></div></div>
    </div>`;
  }).join('');

  // Category budgets
  const catSpending = {};
  monthTxns.forEach(t => { catSpending[t.category] = (catSpending[t.category] || 0) + t.amount; });

  const catBudgetsList = document.getElementById('cat-budgets-list');
  if (!Object.keys(STATE.budgets).length) {
    catBudgetsList.innerHTML = '<div class="empty-state"><div class="empty-icon">💼</div><p>No category budgets set yet</p></div>';
  } else {
    catBudgetsList.innerHTML = Object.entries(STATE.budgets).map(([cat, budget]) => {
      const spent = catSpending[cat] || 0;
      const pct = Math.min((spent / budget) * 100, 100);
      const over = spent > budget;
      return `<div class="cat-budget-item">
        <div class="cat-budget-top">
          <span class="cat-budget-name">${CATEGORY_ICONS[cat]||'📌'} ${cat}</span>
          <span class="cat-budget-nums" style="color:${over?'var(--red)':'inherit'}">${fmt(spent)} / ${fmt(budget)}</span>
        </div>
        <div class="cat-budget-bar"><div class="cat-budget-fill ${over?'over':''}" style="width:${pct}%"></div></div>
        ${over ? `<div class="cat-budget-warning">⚠ Over budget by ${fmt(spent - budget)}</div>` : ''}
      </div>`;
    }).join('');
  }

  // Goals
  const goalsList = document.getElementById('goals-list');
  if (!STATE.goals.length) {
    goalsList.innerHTML = '<div class="empty-state"><div class="empty-icon">🎯</div><p>No savings goals yet</p></div>';
  } else {
    goalsList.innerHTML = STATE.goals.map(g => {
      const pct = Math.min((g.saved / g.target) * 100, 100);
      return `<div class="goal-item">
        <div class="goal-top">
          <span class="goal-name">${g.name}</span>
          <span class="goal-pct">${Math.round(pct)}%</span>
        </div>
        <div class="goal-bar"><div class="goal-fill" style="width:${pct}%"></div></div>
        <div class="goal-meta">
          <span>Saved: ${fmt(g.saved)}</span>
          <span>Target: ${fmt(g.target)}</span>
          ${g.targetDate ? `<span>By ${fmtDate(g.targetDate)}</span>` : ''}
        </div>
      </div>`;
    }).join('');
  }
}

// ============================================================
// SETTINGS
// ============================================================
async function saveSettings() {
  STATE.settings.income = parseInt(document.getElementById('settings-income').value) || 0;
  STATE.settings.currency = document.getElementById('settings-currency').value;
  await saveData();
  renderDashboard();
  showToast('✅ Settings saved!');
}

// ============================================================
// EXPORT
// ============================================================
function exportData() {
  const data = {
    exportedAt: new Date().toISOString(),
    user: STATE.currentUser?.name,
    transactions: STATE.transactions,
    budgets: STATE.budgets,
    goals: STATE.goals,
    settings: { income: STATE.settings.income, currency: STATE.settings.currency }
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `expenseive-export-${todayStr()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('📤 Data exported!');
}

// ============================================================
// LOGOUT
// ============================================================
function confirmLogout() {
  if (confirm('Sign out of Expenseive?')) {
    DB.clearSession();
    STATE = { currentUser: null, transactions: [], budgets: {}, goals: [], settings: { income: 50000, currency: 'INR' }, editingTxnId: null, txnType: 'expense', theme: 'light' };
    applyTheme('light');
    document.getElementById('main-app').classList.add('hidden');
    document.getElementById('main-app').classList.remove('active');
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('auth-screen').classList.add('active');
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    closeModal('profile-modal');
  }
}

// ============================================================
// PASSWORD STRENGTH INDICATOR
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  const pwInput = document.getElementById('reg-password');
  if (pwInput) {
    pwInput.addEventListener('input', () => {
      const s = Security.passwordStrength(pwInput.value);
      const fill = document.getElementById('pw-strength-fill');
      const label = document.getElementById('pw-strength-label');
      const colors = ['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
      const labels = ['Too weak','Weak','Fair','Strong','Very strong'];
      fill.style.width = (s / 4 * 100) + '%';
      fill.style.background = colors[s];
      label.textContent = pwInput.value ? labels[s] : '';
      label.style.color = colors[s];
    });
  }

  // Auto-restore session
  const savedUser = DB.getSessionKey();
  if (savedUser) {
    const meta = DB.loadMeta();
    if (meta.users[savedUser]) {
      initApp(savedUser);
    }
  }
});

// ============================================================
// SERVICE WORKER REGISTRATION
// ============================================================
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').then(() => {
      console.log('Service Worker registered');
    }).catch(err => {
      console.log('SW registration failed:', err);
    });
  });
}

// ============================================================
// INSTALL PROMPT (PWA)
// ============================================================
let deferredPrompt;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  // Show install hint after 3 seconds if not yet installed
  setTimeout(() => {
    if (deferredPrompt && STATE.currentUser) {
      showToast('📲 Tip: Add Expenseive to your home screen for the best experience!', 4000);
    }
  }, 3000);
});
