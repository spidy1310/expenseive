/* =============================================
   EXPENSEIVE — Main Application JS
   Secure, offline-first, PWA-ready
   v2 — hardened security
   ============================================= */

'use strict';

// ============================================================
// SECURITY UTILITIES
// ============================================================
const Security = {

  // ── Password hashing: PBKDF2 SHA-256, 310,000 iterations ──
  // (OWASP 2023 recommended minimum for PBKDF2-SHA256)
  async hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 310000, hash: 'SHA-256' },
      keyMaterial, 256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  generateSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // ── AES-GCM 256-bit encryption of all financial data ──
  // Key is derived fresh from the user's password every session.
  // Without the correct password, the ciphertext is unreadable.
  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 310000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },

  async encryptData(plainObject, password) {
    const enc = new TextEncoder();
    const salt = Array.from(crypto.getRandomValues(new Uint8Array(32)));
    const iv   = Array.from(crypto.getRandomValues(new Uint8Array(12)));
    const key  = await Security.deriveKey(password, salt);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      enc.encode(JSON.stringify(plainObject))
    );
    return { v: 2, salt, iv, ct: Array.from(new Uint8Array(ciphertext)) };
  },

  async decryptData(blob, password) {
    const key = await Security.deriveKey(password, blob.salt);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(blob.iv) },
      key,
      new Uint8Array(blob.ct)
    );
    return JSON.parse(new TextDecoder().decode(plain));
  },

  // ── Input sanitisation — blocks XSS ──
  sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>"'`]/g, c =>
      ({ '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;', '`':'&#96;' }[c])
    );
  },

  validateUsername(u) {
    return /^[a-zA-Z0-9_]{3,30}$/.test(u);
  },

  passwordStrength(p) {
    let s = 0;
    if (p.length >= 8)  s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 4);
  },

  // ── Brute-force protection ──
  // Stored in localStorage so it SURVIVES page reloads and restarts.
  // Strategy: exponential lockout — each failed attempt doubles wait time.
  //   Attempts 1-3  : no lockout
  //   Attempt  4    : 30 s lockout
  //   Attempt  5    : 1 min
  //   Attempt  6    : 2 min
  //   Attempt  7    : 4 min
  //   Attempt  8+   : 15 min (hard cap)
  // After 15 consecutive failures the account is locked for 1 hour.
  LOCKOUT_KEY: 'exp_lockout_v2',
  MAX_BEFORE_HARDLOCK: 15,
  HARDLOCK_MS: 60 * 60 * 1000,    // 1 hour

  _getLockout() {
    try { return JSON.parse(localStorage.getItem(Security.LOCKOUT_KEY) || 'null') || { count: 0, lockedUntil: 0 }; }
    catch { return { count: 0, lockedUntil: 0 }; }
  },
  _saveLockout(obj) {
    localStorage.setItem(Security.LOCKOUT_KEY, JSON.stringify(obj));
  },

  // Returns { allowed: bool, waitSecs: number, locked: bool }
  checkLoginAttempts() {
    const lo   = Security._getLockout();
    const now  = Date.now();
    if (lo.lockedUntil && now < lo.lockedUntil) {
      return { allowed: false, waitSecs: Math.ceil((lo.lockedUntil - now) / 1000), locked: true };
    }
    // Lockout expired — reset if it was a timed lockout (not hardlock)
    if (lo.lockedUntil && now >= lo.lockedUntil && lo.count < Security.MAX_BEFORE_HARDLOCK) {
      lo.lockedUntil = 0;
    }
    return { allowed: true, waitSecs: 0, locked: false };
  },

  recordFailedAttempt() {
    const lo  = Security._getLockout();
    lo.count  = (lo.count || 0) + 1;
    if (lo.count >= Security.MAX_BEFORE_HARDLOCK) {
      lo.lockedUntil = Date.now() + Security.HARDLOCK_MS;
    } else if (lo.count >= 4) {
      const exp = Math.min(Math.pow(2, lo.count - 4) * 30 * 1000, 15 * 60 * 1000);
      lo.lockedUntil = Date.now() + exp;
    }
    Security._saveLockout(lo);
    return lo;
  },

  resetLoginAttempts() {
    localStorage.removeItem(Security.LOCKOUT_KEY);
  },

  // ── Validate hex color — blocks CSS injection via color picker ──
  // Only allows #RRGGBB format. Rejects any javascript:, url(), etc.
  validateHexColor(color) {
    return /^#[0-9A-Fa-f]{6}$/.test(color);
  },

  // ── Sanitize emoji/icon input — only allow actual emoji + basic chars ──
  // Strips anything that could be HTML/JS. Max 4 chars (one emoji).
  sanitizeIcon(raw) {
    if (typeof raw !== 'string') return '🏷️';
    // Strip all HTML tags and dangerous chars
    const stripped = raw.replace(/<[^>]*>/g, '').replace(/[<>"'`;&]/g, '').trim();
    // Take only first grapheme cluster (one emoji worth)
    const chars = [...stripped];
    return chars.slice(0, 2).join('') || '🏷️';
  },

  // ── Re-sanitize a value loaded from storage before rendering to DOM ──
  // Defence-in-depth: sanitize on both write AND read
  sanitizeLoaded(val) {
    if (typeof val !== 'string') return '';
    return val.replace(/[<>"'`]/g, c =>
      ({ '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;', '`':'&#96;' }[c])
    );
  },

  // ── Recovery phrase — BIP-39 standard wordlist (2048 words, 128-bit entropy) ──
  // 12 words chosen randomly → shown to user once → never stored plain text.
  // A PBKDF2 hash of the phrase is stored so we can verify it on recovery.
  // The phrase is also used as an alternative encryption key source so we can
  // re-encrypt data under a new password without losing the original data.

  BIP39: ("abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby balance bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone book boost border boring borrow boss bottom bounce box boy bracket brain brand brave breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp canal cancel candy cannon canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle cause cave ceiling celery cement census chair chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chunk cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster coarse coat coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact endless endorse enemy engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip erase erosion escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expire explain expose express extend extra eye fable face faculty fade faint faith fall false fame family famous fan fancy fantasy far fashion fat fatal father fatigue fault favorite feature february federal fee feed feel feet fellow felt fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grasp grass gravity great green grid grief grit grocery group grow grunt guard guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn hospital host hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon ignore ill illegal image imitate immense immune impact impose improve impulse inbox include income index indicate indoor industry infant inflict inform inhale inject inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab ladder lady lake lamp language laptop large later laugh laundry lava law lawn lawsuit layer lazy leader learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud loyal lucky luggage lumber lunar lunch luxury lyrics magnet maid main major make mammal mango mansion manual maple marble march margin marine market marriage mask master match maze meadow mean medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor miracle miss mixed mixture mobile model modify mom monitor monkey monster month moon moral more morning mosquito mother motion mound mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery naive name napkin narrow nasty nature near neck need negative neglect neither nephew nerve network news next nice night noble noise nominee noodle normal notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure obtain ocean october odor off offer office often oil okay old olive olympic omit once onion open opera oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outside oval over own oxygen oyster ozone pain paint pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patrol pause pave payment peace peanut peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play plaza pledge pluck plug plunge poem poet point polar pole police pond pony popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punish pupil puppy purchase purity purpose push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rage rail rain raise rally ramp ranch random range rapid rare rate rather raven reach ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm ribbon rice rich ride rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie rotate rough round route royal rubber rude rug rule run runway rural saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme scissors scorpion scout scrap screen script scrub search season seat second secret section security seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling siege sight sign silent silk silly silver similar simple since sing siren sister situate six size sketch skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock solar soldier solid solution solve someone song soon sorry soul sound soup source south space spare spatial spawn speak special speed sphere spice spider spike spin spirit split spoil sponsor spoon spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stop store storm story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise sustain swallow swamp swap swear sweet swift swim swing switch sword symbol symptom syrup table tackle tag tail talent tamper tank tape target task tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tilt timber time tiny tip tired title toast tobacco today together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck truly trumpet trust truth tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel wedding weekend weird welcome west wet whale wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo"),

  // Generate a random 12-word recovery phrase
  generatePhrase() {
    const words = Security.BIP39.split(' ');
    const indices = crypto.getRandomValues(new Uint32Array(12));
    return Array.from(indices).map(n => words[n % words.length]).join(' ');
  },

  // Hash the phrase for storage verification (separate PBKDF2 derivation)
  async hashPhrase(phrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(phrase.toLowerCase().trim()), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 310000, hash: 'SHA-256' },
      keyMaterial, 256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  // Derive an AES-GCM key from the recovery phrase (used to re-encrypt data on reset)
  async deriveKeyFromPhrase(phrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(phrase.toLowerCase().trim()), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 310000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },

  // Validate phrase input — must be exactly 12 words, all in BIP-39 list
  validatePhrase(phrase) {
    const words    = Security.BIP39.split(' ');
    const wordSet  = new Set(words);
    const entered  = phrase.toLowerCase().trim().split(/\s+/);
    if (entered.length !== 12) return { valid: false, reason: 'Must be exactly 12 words.' };
    const bad = entered.filter(w => !wordSet.has(w));
    if (bad.length > 0) return { valid: false, reason: `Unknown word${bad.length > 1 ? 's' : ''}: ${bad.slice(0,3).join(', ')}` };
    return { valid: true };
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

// ── Default categories every new account starts with ──
// Stored per-user in settings.categories — fully editable.
const DEFAULT_CATEGORIES = [
  { name: 'Life Infrastructure',       icon: '🏠', color: '#4f46e5', builtIn: true  },
  { name: 'Lifestyle Enjoyment',       icon: '🎉', color: '#f59e0b', builtIn: true  },
  { name: 'Future Me',                 icon: '💰', color: '#10b981', builtIn: true  },
  { name: 'Performance & Growth',      icon: '📚', color: '#3b82f6', builtIn: true  },
  { name: 'Relationships & Generosity',icon: '❤️', color: '#ec4899', builtIn: true  },
  { name: 'Other',                     icon: '📌', color: '#6b7280', builtIn: true  },
];

// ── Dynamic helpers — always read from current user's category list ──
function getUserCategories() {
  return STATE.settings.categories || DEFAULT_CATEGORIES;
}

function getCategoryMeta(name) {
  const cats = getUserCategories();
  return cats.find(c => c.name === name) || { name, icon: '📌', color: '#6b7280' };
}

function getCategoryColor(name) { return getCategoryMeta(name).color; }
function getCategoryIcon(name)  { return getCategoryMeta(name).icon;  }

// Keep legacy constants as thin wrappers (used in a few chart spots)
const CATEGORY_COLORS = new Proxy({}, { get: (_, k) => getCategoryColor(k) });
const CATEGORY_ICONS  = new Proxy({}, { get: (_, k) => getCategoryIcon(k)  });
const PAYMENT_ICONS = { 'UPI': '📱', 'Credit Card': '💳', 'Debit Card': '🏧', 'Cash': '💵', 'Bank Transfer': '🏦', 'Net Banking': '🌐' };

// ============================================================
// STORAGE — true AES-GCM 256-bit encryption at rest
// ============================================================
// The user's password is the only key. Data stored in localStorage
// is ciphertext — without the correct password it is unreadable,
// even with direct device/file access.
// ============================================================
const DB = {
  KEY: 'expenseive_db',
  SESSION_KEY: 'expenseive_session',

  // In-memory session — never written to disk
  _sessionPassword: null,
  _sessionPhrase: null,

  getSession() {
    return {
      username: sessionStorage.getItem(DB.SESSION_KEY),
      password: DB._sessionPassword,
      phrase:   DB._sessionPhrase
    };
  },

  saveSession(username, password, phrase = null) {
    sessionStorage.setItem(DB.SESSION_KEY, username);
    DB._sessionPassword = password;
    DB._sessionPhrase   = phrase;
  },

  clearSession() {
    sessionStorage.removeItem(DB.SESSION_KEY);
    DB._sessionPassword = null;
    DB._sessionPhrase   = null;
  },

  // ── Account registry (stores only hashed credentials) ──
  loadMeta() {
    try { return JSON.parse(localStorage.getItem(DB.KEY) || '{"users":{}}'); }
    catch { return { users: {} }; }
  },
  saveMeta(meta) {
    localStorage.setItem(DB.KEY, JSON.stringify(meta));
  },

  // ── Save user data — AES-GCM encrypted with their password ──
  async saveUserData(username, data, password) {
    const encKey = `exp_data_${username}`;
    const blob   = await Security.encryptData(data, password);
    localStorage.setItem(encKey, JSON.stringify(blob));
  },

  // ── Load and decrypt — fails loudly on wrong password ──
  async loadUserData(username, password) {
    const encKey = `exp_data_${username}`;
    const raw    = localStorage.getItem(encKey);
    if (!raw) return null;
    try {
      const blob = JSON.parse(raw);
      // Legacy v1 (plain btoa) — migrate on first login
      if (!blob.v || blob.v < 2) {
        console.warn('Migrating legacy unencrypted data to AES-GCM...');
        return DB._migrateLegacy(raw, username, password);
      }
      return await Security.decryptData(blob, password);
    } catch (e) {
      console.error('Decryption failed — wrong password or corrupted data', e);
      return null;
    }
  },

  // ── Re-encrypt all user data under a new password (used on password reset) ──
  // Decrypts with oldSecret (phrase or old password), re-encrypts with newPassword.
  async reEncryptUserData(username, oldSecret, newPassword, usePhrase = false) {
    const encKey = `exp_data_${username}`;
    const raw    = localStorage.getItem(encKey);
    if (!raw) return false;
    try {
      let data;
      if (usePhrase) {
        // Decrypt using phrase-derived key
        const blob = JSON.parse(raw);
        // We stored a phrase-encrypted copy alongside the password-encrypted copy
        const phraseBlob = JSON.parse(localStorage.getItem(`exp_phrase_data_${username}`) || 'null');
        if (!phraseBlob) return false;
        data = await Security.decryptData(phraseBlob, oldSecret);
      } else {
        const blob = JSON.parse(raw);
        data = await Security.decryptData(blob, oldSecret);
      }
      if (!data) return false;
      // Re-encrypt under new password
      await DB.saveUserData(username, data, newPassword);
      // Update the phrase-encrypted backup copy too (using existing phrase)
      const meta = DB.loadMeta();
      const user = meta.users[username];
      if (user && user.phraseBackupSalt) {
        // Re-encrypt backup with the same phrase (phrase hasn't changed)
        // We can't re-derive phrase here — just mark backup as needing refresh on next full login
        // The backup will be refreshed when user logs in with new password
      }
      return true;
    } catch (e) {
      console.error('Re-encryption failed:', e);
      return false;
    }
  },

  // ── Save a phrase-encrypted backup copy of user data ──
  // This is decryptable with the recovery phrase, independently of the password.
  async savePhraseBackup(username, data, phrase) {
    const blob = await Security.encryptData(data, phrase.toLowerCase().trim());
    localStorage.setItem(`exp_phrase_data_${username}`, JSON.stringify(blob));
  },

  async _migrateLegacy(raw, username, password) {
    try {
      const { data } = JSON.parse(raw);
      const decoded  = JSON.parse(decodeURIComponent(escape(atob(data))));
      // Re-save as properly encrypted
      await DB.saveUserData(username, decoded, password);
      return decoded;
    } catch { return null; }
  }
};

// ============================================================
// AUTO-LOCK — locks the app after 10 minutes of inactivity
// ============================================================
const AutoLock = {
  TIMEOUT_MS: 10 * 60 * 1000,
  _timer: null,

  reset() {
    clearTimeout(AutoLock._timer);
    AutoLock._timer = setTimeout(AutoLock.trigger, AutoLock.TIMEOUT_MS);
  },

  start() {
    ['touchstart', 'touchmove', 'click', 'keydown', 'scroll'].forEach(ev =>
      document.addEventListener(ev, AutoLock.reset, { passive: true })
    );
    AutoLock.reset();
  },

  stop() {
    clearTimeout(AutoLock._timer);
    ['touchstart', 'touchmove', 'click', 'keydown', 'scroll'].forEach(ev =>
      document.removeEventListener(ev, AutoLock.reset)
    );
  },

  trigger() {
    AutoLock.stop();
    DB.clearSession();
    // Wipe in-memory state
    STATE.currentUser = null;
    STATE.transactions = [];
    STATE.budgets = {};
    STATE.goals = [];
    // Show lock screen
    document.getElementById('main-app').classList.add('hidden');
    document.getElementById('main-app').classList.remove('active');
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('auth-screen').classList.add('active');
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';
    // Show locked message
    setTimeout(() => showError('login-error', '🔒 Session locked after 10 min of inactivity. Please sign in again.'), 100);
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

  // ── Check persistent lockout (survives page reloads & restarts) ──
  const lockStatus = Security.checkLoginAttempts();
  if (!lockStatus.allowed) {
    const mins = Math.ceil(lockStatus.waitSecs / 60);
    const msg  = lockStatus.waitSecs > 90
      ? `🔒 Account locked. Try again in ${mins} minute${mins > 1 ? 's' : ''}.`
      : `🔒 Too many attempts. Wait ${lockStatus.waitSecs} seconds.`;
    showError('login-error', msg);
    return;
  }

  const username = Security.sanitize(document.getElementById('login-username').value.trim().toLowerCase());
  const password = document.getElementById('login-password').value;

  if (!username || !password) {
    showError('login-error', 'Please enter username and password.');
    return;
  }

  // Artificial delay to slow automated attacks (even if lockout bypassed)
  await new Promise(r => setTimeout(r, 400));

  const meta = DB.loadMeta();
  const user = meta.users[username];

  // Always hash before comparing — constant-time-ish (avoids early exit timing leak)
  const hash = user ? await Security.hashPassword(password, user.salt) : await Security.hashPassword(password, 'dummy_salt_constant');

  if (!user || hash !== user.passwordHash) {
    const lo = Security.recordFailedAttempt();
    const remaining = Security.MAX_BEFORE_HARDLOCK - lo.count;
    if (lo.lockedUntil) {
      const waitSecs = Math.ceil((lo.lockedUntil - Date.now()) / 1000);
      const mins = Math.ceil(waitSecs / 60);
      showError('login-error', `🔒 Too many failed attempts. Locked for ${mins > 1 ? mins + ' minutes' : waitSecs + ' seconds'}.`);
    } else {
      showError('login-error', `Invalid username or password. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`);
    }
    return;
  }

  Security.resetLoginAttempts();
  DB.saveSession(username, password);   // password cached in memory only
  await initApp(username, password);
}

async function handleRegister() {
  clearErrors();

  const name     = Security.sanitize(document.getElementById('reg-name').value.trim());
  const username = document.getElementById('reg-username').value.trim().toLowerCase();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;
  const income   = parseInt(document.getElementById('reg-income').value) || 50000;
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

  // ── Generate recovery phrase ──
  const phrase     = Security.generatePhrase();
  const phraseSalt = Security.generateSalt();
  const phraseHash = await Security.hashPhrase(phrase, phraseSalt);

  const salt         = Security.generateSalt();
  const passwordHash = await Security.hashPassword(password, salt);

  meta.users[username] = {
    name: Security.sanitize(name),
    username,
    salt,
    passwordHash,
    phraseSalt,
    phraseHash,
    createdAt: new Date().toISOString()
  };
  DB.saveMeta(meta);

  const userData = {
    transactions: [],
    budgets: {},
    goals: [],
    settings: { income, currency, theme: 'light', categories: DEFAULT_CATEGORIES }
  };
  await DB.saveUserData(username, userData, password);

  // Save phrase-encrypted backup so recovery can decrypt data
  await DB.savePhraseBackup(username, userData, phrase);

  DB.saveSession(username, password);

  // Show the recovery phrase to the user before entering the app
  showPhraseModal(phrase, username, password);
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
async function initApp(username, password) {
  const meta = DB.loadMeta();
  STATE.currentUser = meta.users[username];

  // password is required for AES-GCM decryption
  const userData = await DB.loadUserData(username, password) || {
    transactions: [], budgets: {}, goals: [], settings: { income: 50000, currency: 'INR', theme: 'light', categories: DEFAULT_CATEGORIES }
  };

  STATE.transactions = userData.transactions || [];
  STATE.budgets      = userData.budgets      || {};
  STATE.goals        = userData.goals        || [];
  STATE.settings     = { income: 50000, currency: 'INR', theme: 'light', categories: DEFAULT_CATEGORIES, ...userData.settings };

  // Migration: accounts that existed before categories feature get defaults seeded
  if (!STATE.settings.categories || STATE.settings.categories.length === 0) {
    STATE.settings.categories = DEFAULT_CATEGORIES;
  }
  STATE.theme        = STATE.settings.theme  || 'light';
  STATE._password    = password;
  STATE._phrase      = DB._sessionPhrase || null;  // in-memory only

  applyTheme(STATE.theme);

  // Transition screens
  document.body.classList.add('app-active');
  document.getElementById('auth-screen').classList.remove('active');
  document.getElementById('auth-screen').classList.add('hidden');
  document.getElementById('main-app').classList.remove('hidden');
  document.getElementById('main-app').classList.add('active');

  // Init UI
  document.getElementById('add-date').value = todayStr();
  updateGreeting();
  updateAvatar();
  populateFilterDropdowns();
  populateCategoryDropdowns();
  renderDashboard();
  renderBudget();

  // Start auto-lock timer (locks after 10 min inactivity)
  AutoLock.start();

  // Update greeting every minute
  setInterval(updateGreeting, 60000);
}

// ============================================================
// PERSISTENCE
// ============================================================
async function saveData() {
  if (!STATE.currentUser || !STATE._password) return;
  const username = STATE.currentUser.username;
  const data = {
    transactions: STATE.transactions,
    budgets:      STATE.budgets,
    goals:        STATE.goals,
    settings:     STATE.settings
  };
  await DB.saveUserData(username, data, STATE._password);
  // Keep phrase backup in sync so recovery always has latest data
  if (STATE._phrase) {
    await DB.savePhraseBackup(username, data, STATE._phrase);
  }
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
  const sym  = CURRENCIES[STATE.settings.currency] || '₹';
  // Re-sanitize all user-supplied fields on render
  const desc = Security.sanitizeLoaded(txn.description);
  const cat  = Security.sanitizeLoaded(txn.category);
  const type = Security.sanitizeLoaded(txn.type || '');
  const pm   = Security.sanitizeLoaded(txn.paymentMode || '—');
  const notes= Security.sanitizeLoaded(txn.notes || '');
  body.innerHTML = `
    <div class="detail-field"><span>Amount</span><span style="color:${txn.isIncome ? 'var(--green)' : 'var(--red)'};font-family:var(--mono)">${txn.isIncome ? '+' : '-'}${sym}${Number(txn.amount).toLocaleString('en-IN')}</span></div>
    <div class="detail-field"><span>Description</span><span>${desc}</span></div>
    <div class="detail-field"><span>Date</span><span>${fmtDate(txn.date)}</span></div>
    <div class="detail-field"><span>Category</span><span>${cat}</span></div>
    <div class="detail-field"><span>Type</span><span>${type}</span></div>
    <div class="detail-field"><span>Payment</span><span>${pm}</span></div>
    ${notes ? `<div class="detail-field"><span>Notes</span><span>${notes}</span></div>` : ''}
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
// ── Populate all category <select> dropdowns from user's own list ──
function populateCategoryDropdowns() {
  const cats = getUserCategories();
  const options = cats.map(c =>
    `<option value="${Security.sanitize(c.name)}">${c.icon} ${Security.sanitize(c.name)}</option>`
  ).join('');

  const addSel    = document.getElementById('add-category');
  const budgetSel = document.getElementById('budget-cat');
  const txnSel    = document.getElementById('txn-filter-cat');

  if (addSel)    addSel.innerHTML    = options;
  if (budgetSel) budgetSel.innerHTML = options;
  // txn filter keeps "All Categories" prefix
  if (txnSel)    txnSel.innerHTML    = `<option value="all">All Categories</option>${options}`;
}

// ============================================================
// CATEGORY MANAGER
// ============================================================
function openCategoryManager() {
  renderCategoryManager();
  closeModal('profile-modal');
  openModal('catmgr-modal');
  document.getElementById('catmgr-name').value  = '';
  document.getElementById('catmgr-icon').value  = '';
  document.getElementById('catmgr-color').value = '#6366f1';
  document.getElementById('catmgr-error').classList.add('hidden');
}

function renderCategoryManager() {
  const cats = getUserCategories();
  const list = document.getElementById('catmgr-list');
  if (!cats.length) {
    list.innerHTML = '<div class="empty-state"><p>No categories yet</p></div>';
    return;
  }

  list.innerHTML = cats.map((c, idx) => {
    const txnCount = STATE.transactions.filter(t => t.category === c.name).length;
    return `
      <div class="catmgr-item" id="catmgr-item-${idx}">
        <div class="catmgr-icon-badge" style="background:${c.color}18;color:${c.color}">${c.icon}</div>
        <div class="catmgr-info">
          <div class="catmgr-name">${Security.sanitize(c.name)}</div>
          <div class="catmgr-count">${txnCount} transaction${txnCount !== 1 ? 's' : ''}</div>
        </div>
        <div class="catmgr-actions">
          ${!c.builtIn
            ? `<button class="catmgr-del-btn" onclick="deleteCategory(${idx})" title="Delete category">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>
                  <path d="M9 6V4h6v2"/>
                </svg>
              </button>`
            : `<span class="catmgr-builtin-badge">Built-in</span>`
          }
        </div>
      </div>
    `;
  }).join('');
}

async function addCategory() {
  const nameRaw  = document.getElementById('catmgr-name').value.trim();
  const iconRaw  = document.getElementById('catmgr-icon').value.trim();
  const colorRaw = document.getElementById('catmgr-color').value;
  const errEl    = document.getElementById('catmgr-error');
  errEl.classList.add('hidden');

  const name  = Security.sanitize(nameRaw);
  const icon  = Security.sanitizeIcon(iconRaw);
  const color = Security.validateHexColor(colorRaw) ? colorRaw : '#6366f1';

  if (!name) {
    errEl.textContent = 'Please enter a category name.';
    errEl.classList.remove('hidden');
    return;
  }
  if (name.length > 50) {
    errEl.textContent = 'Name must be 50 characters or fewer.';
    errEl.classList.remove('hidden');
    return;
  }

  const cats = getUserCategories();
  if (cats.find(c => c.name.toLowerCase() === name.toLowerCase())) {
    errEl.textContent = 'A category with that name already exists.';
    errEl.classList.remove('hidden');
    return;
  }

  cats.push({ name, icon, color, builtIn: false });
  STATE.settings.categories = cats;
  await saveData();

  populateCategoryDropdowns();
  renderCategoryManager();
  populateFilterDropdowns();

  document.getElementById('catmgr-name').value  = '';
  document.getElementById('catmgr-icon').value  = '';
  document.getElementById('catmgr-color').value = '#6366f1';
  showToast(`✅ "${name}" category added!`);
}

async function deleteCategory(idx) {
  const cats = getUserCategories();
  const cat  = cats[idx];
  if (!cat) return;
  if (cat.builtIn) { showToast('Built-in categories cannot be deleted.'); return; }

  const txnCount = STATE.transactions.filter(t => t.category === cat.name).length;
  const msg = txnCount > 0
    ? `Delete "${cat.name}"? It has ${txnCount} transaction${txnCount !== 1 ? 's' : ''} — they'll be moved to "Other".`
    : `Delete "${cat.name}"?`;

  if (!confirm(msg)) return;

  // Re-assign existing transactions to "Other"
  if (txnCount > 0) {
    STATE.transactions = STATE.transactions.map(t =>
      t.category === cat.name ? { ...t, category: 'Other' } : t
    );
  }

  // Remove budget entry for this category if exists
  if (STATE.budgets[cat.name]) {
    delete STATE.budgets[cat.name];
  }

  cats.splice(idx, 1);
  STATE.settings.categories = cats;
  await saveData();

  populateCategoryDropdowns();
  renderCategoryManager();
  populateFilterDropdowns();
  renderDashboard();
  renderBudget();
  showToast(`🗑 "${cat.name}" deleted`);
}

function populateFilterDropdowns() {
  const months = new Set();
  STATE.transactions.forEach(t => {
    const d = new Date(t.date);
    months.add(`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`);
  });

  ['txn-filter-month', 'analytics-month'].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="all">All Time</option>' +
      [...months].sort().reverse().map(m => {
        const [y, mo] = m.split('-');
        const label = new Date(y, mo-1).toLocaleDateString('en-IN', {month:'short', year:'numeric'});
        return `<option value="${m}" ${m === cur ? 'selected' : ''}>${label}</option>`;
      }).join('');
  });
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
  const sym  = CURRENCIES[STATE.settings.currency] || '₹';
  // Re-sanitize on render (defence-in-depth — data was sanitized on write too)
  const desc = Security.sanitizeLoaded(t.description);
  const cat  = Security.sanitizeLoaded(t.category);
  const pm   = Security.sanitizeLoaded(t.paymentMode || '');
  const icon = getCategoryIcon(t.category);
  const color = getCategoryColor(t.category);
  return `<div class="txn-item" onclick="openDetail('${t.id}')">
    <div class="txn-icon" style="background:${color}18;color:${color}">${icon}</div>
    <div class="txn-info">
      <div class="txn-desc">${desc}</div>
      <div class="txn-meta">
        <span class="txn-tag">${cat}</span>
        ${pm ? `<span>${PAYMENT_ICONS[t.paymentMode]||''} ${pm}</span>` : ''}
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
      const pct      = Math.min((g.saved / g.target) * 100, 100);
      const goalName = Security.sanitizeLoaded(g.name);
      return `<div class="goal-item">
        <div class="goal-top">
          <span class="goal-name">${goalName}</span>
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
// RECOVERY PHRASE FLOW
// ============================================================

// ── Show phrase to new user immediately after registration ──
function showPhraseModal(phrase, username, password) {
  // Build modal dynamically so it doesn't sit in the HTML permanently
  const words = phrase.split(' ');
  const grid  = words.map((w, i) =>
    `<div class="phrase-word"><span class="phrase-num">${i+1}</span><span class="phrase-w">${w}</span></div>`
  ).join('');

  const el = document.createElement('div');
  el.id = 'phrase-modal';
  el.className = 'modal';
  el.innerHTML = `
    <div class="modal-backdrop"></div>
    <div class="modal-sheet" style="max-height:95vh">
      <div class="modal-handle"></div>
      <div class="modal-header">
        <h3>🔑 Your Recovery Phrase</h3>
      </div>
      <div class="modal-body">
        <div class="phrase-warning">
          <strong>Write these 12 words down</strong> in order and store them somewhere safe — offline, on paper. This is the only way to recover your account if you forget your password. We will never show this again.
        </div>
        <div class="phrase-grid">${grid}</div>
        <button class="btn-sm phrase-copy-btn" id="btn-copy-phrase">📋 Copy to clipboard</button>
        <div class="phrase-confirm-row">
          <label class="phrase-check-label">
            <input type="checkbox" id="phrase-confirm-check" />
            I've written down my recovery phrase
          </label>
        </div>
        <div id="phrase-confirm-error" class="form-error hidden">Please confirm you've saved your recovery phrase.</div>
        <button class="btn-primary" id="btn-phrase-done" style="margin-top:8px">Continue to App</button>
      </div>
    </div>
  `;
  document.getElementById('app').appendChild(el);

  document.getElementById('btn-copy-phrase').addEventListener('click', () => {
    navigator.clipboard.writeText(phrase).then(() => {
      document.getElementById('btn-copy-phrase').textContent = '✅ Copied!';
      setTimeout(() => {
        const btn = document.getElementById('btn-copy-phrase');
        if (btn) btn.textContent = '📋 Copy to clipboard';
      }, 2000);
    }).catch(() => showToast('Copy failed — please write the words manually.'));
  });

  document.getElementById('btn-phrase-done').addEventListener('click', async () => {
    if (!document.getElementById('phrase-confirm-check').checked) {
      document.getElementById('phrase-confirm-error').classList.remove('hidden');
      return;
    }
    el.remove();
    showToast('Account created! Welcome to Expenseive 🎉');
    // Store phrase in session memory so saveData can keep backup in sync
    DB._sessionPhrase = phrase;
    await initApp(username, password);
  });
}

// ── Forgot password — step 1: enter username ──
function showForgotPassword() {
  const el = document.createElement('div');
  el.id = 'forgot-modal';
  el.className = 'modal';
  el.innerHTML = `
    <div class="modal-backdrop" id="forgot-backdrop"></div>
    <div class="modal-sheet">
      <div class="modal-handle"></div>
      <div class="modal-header">
        <h3>Reset Password</h3>
        <button class="close-btn" id="btn-close-forgot">✕</button>
      </div>
      <div class="modal-body">
        <p style="font-size:14px;color:var(--text2);margin-bottom:18px">Enter your username and 12-word recovery phrase to set a new password.</p>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="forgot-username" placeholder="your username" maxlength="50" autocomplete="username" />
        </div>
        <div class="form-group">
          <label>Recovery Phrase</label>
          <textarea id="forgot-phrase" placeholder="word1 word2 word3 ... word12" rows="4"
            style="width:100%;padding:12px 14px;border:1.5px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--text);font-family:var(--mono);font-size:13px;resize:none;outline:none;line-height:1.6"
            maxlength="200"></textarea>
          <small style="color:var(--text3);font-size:12px">Enter all 12 words separated by spaces, in the correct order.</small>
        </div>
        <div class="form-group">
          <label>New Password</label>
          <div class="pw-wrap">
            <input type="password" id="forgot-newpw" placeholder="min 8 characters" maxlength="128" autocomplete="new-password" />
            <button class="pw-toggle" id="btn-forgot-pwshow" type="button">👁</button>
          </div>
          <div class="pw-strength-bar"><div id="forgot-pw-fill"></div></div>
        </div>
        <div class="form-group">
          <label>Confirm New Password</label>
          <input type="password" id="forgot-confirmpw" placeholder="repeat password" maxlength="128" autocomplete="new-password" />
        </div>
        <div id="forgot-error" class="form-error hidden"></div>
        <button class="btn-primary" id="btn-do-reset">Reset Password</button>
      </div>
    </div>
  `;
  document.getElementById('app').appendChild(el);

  // Wire events
  document.getElementById('btn-close-forgot').addEventListener('click', () => el.remove());
  document.getElementById('forgot-backdrop').addEventListener('click', () => el.remove());

  document.getElementById('btn-forgot-pwshow').addEventListener('click', function() {
    togglePw('forgot-newpw', this);
  });

  document.getElementById('forgot-newpw').addEventListener('input', function() {
    const s    = Security.passwordStrength(this.value);
    const fill = document.getElementById('forgot-pw-fill');
    const colors = ['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
    fill.style.width = (s / 4 * 100) + '%';
    fill.style.background = colors[s];
  });

  document.getElementById('btn-do-reset').addEventListener('click', doPasswordReset);
}

async function doPasswordReset() {
  const errEl     = document.getElementById('forgot-error');
  errEl.classList.add('hidden');

  const username  = Security.sanitize(document.getElementById('forgot-username').value.trim().toLowerCase());
  const phrase    = document.getElementById('forgot-phrase').value.trim().toLowerCase().replace(/\s+/g,' ');
  const newPw     = document.getElementById('forgot-newpw').value;
  const confirmPw = document.getElementById('forgot-confirmpw').value;

  if (!username || !phrase || !newPw) {
    errEl.textContent = 'Please fill all fields.'; errEl.classList.remove('hidden'); return;
  }

  // Validate phrase format first
  const phraseCheck = Security.validatePhrase(phrase);
  if (!phraseCheck.valid) {
    errEl.textContent = phraseCheck.reason; errEl.classList.remove('hidden'); return;
  }

  if (newPw.length < 8) {
    errEl.textContent = 'New password must be at least 8 characters.'; errEl.classList.remove('hidden'); return;
  }
  if (newPw !== confirmPw) {
    errEl.textContent = 'Passwords do not match.'; errEl.classList.remove('hidden'); return;
  }

  const meta = DB.loadMeta();
  const user = meta.users[username];
  if (!user) {
    // Deliberate vague message — don't reveal whether username exists
    errEl.textContent = 'Recovery failed. Check your username and phrase.';
    errEl.classList.remove('hidden'); return;
  }
  if (!user.phraseSalt || !user.phraseHash) {
    errEl.textContent = 'This account has no recovery phrase set up. It was created before this feature was added.';
    errEl.classList.remove('hidden'); return;
  }

  // Verify phrase hash
  const btn = document.getElementById('btn-do-reset');
  btn.textContent = 'Verifying…'; btn.disabled = true;

  // Artificial delay — prevent phrase brute-force timing
  await new Promise(r => setTimeout(r, 600));

  const enteredHash = await Security.hashPhrase(phrase, user.phraseSalt);
  if (enteredHash !== user.phraseHash) {
    errEl.textContent = 'Recovery failed. Check your username and phrase.';
    errEl.classList.remove('hidden');
    btn.textContent = 'Reset Password'; btn.disabled = false;
    return;
  }

  // Phrase verified — decrypt backup data with phrase, re-encrypt with new password
  btn.textContent = 'Resetting…';

  try {
    const phraseDataRaw = localStorage.getItem(`exp_phrase_data_${username}`);
    if (!phraseDataRaw) {
      errEl.textContent = 'Recovery backup not found. If this is an old account, you may need to contact support.';
      errEl.classList.remove('hidden'); btn.textContent = 'Reset Password'; btn.disabled = false; return;
    }

    const phraseBlob = JSON.parse(phraseDataRaw);
    const data       = await Security.decryptData(phraseBlob, phrase);

    if (!data) {
      errEl.textContent = 'Could not decrypt your data. Phrase may be incorrect.';
      errEl.classList.remove('hidden'); btn.textContent = 'Reset Password'; btn.disabled = false; return;
    }

    // Update password hash in meta
    const newSalt  = Security.generateSalt();
    const newHash  = await Security.hashPassword(newPw, newSalt);
    meta.users[username].salt         = newSalt;
    meta.users[username].passwordHash = newHash;
    DB.saveMeta(meta);

    // Re-encrypt data under new password
    await DB.saveUserData(username, data, newPw);
    // Keep phrase backup current
    await DB.savePhraseBackup(username, data, phrase);

    // Remove modal and show success
    document.getElementById('forgot-modal').remove();
    showError('login-error', '✅ Password reset! Please sign in with your new password.');
    document.getElementById('login-error').style.background = 'var(--green-light)';
    document.getElementById('login-error').style.color = 'var(--green)';
    document.getElementById('login-error').classList.remove('hidden');

  } catch (e) {
    console.error('Reset error:', e);
    errEl.textContent = 'Something went wrong. Please try again.';
    errEl.classList.remove('hidden');
    btn.textContent = 'Reset Password'; btn.disabled = false;
  }
}
// ============================================================
// FORGOT USERNAME — lists accounts registered on this device
// ============================================================
function showForgotUsername() {
  const meta  = DB.loadMeta();
  const users = Object.values(meta.users || {});

  const old = document.getElementById('forgot-username-modal');
  if (old) old.remove();

  const el = document.createElement('div');
  el.id = 'forgot-username-modal';
  el.className = 'modal';
  el.style.zIndex = '300';

  const userRows = users.length === 0
    ? '<div class="empty-state"><div class="empty-icon">👤</div><p>No accounts found on this device.</p></div>'
    : users.map(u => `
        <div class="fu-user-row">
          <div class="fu-avatar">${(u.name || u.username || '?')[0].toUpperCase()}</div>
          <div class="fu-info">
            <div class="fu-name">${Security.sanitizeLoaded(u.name || '')}</div>
            <div class="fu-username">@${Security.sanitizeLoaded(u.username || '')}</div>
            <div class="fu-date">Since ${u.createdAt
              ? new Date(u.createdAt).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' })
              : 'unknown'}</div>
          </div>
          <button class="fu-use-btn" data-username="${Security.sanitizeLoaded(u.username || '')}">Use</button>
        </div>`
    ).join('');

  el.innerHTML = `
    <div class="modal-backdrop" id="fu-backdrop"></div>
    <div class="modal-sheet">
      <div class="modal-handle"></div>
      <div class="modal-header">
        <h3>Accounts on this device</h3>
        <button class="close-btn" id="fu-close">✕</button>
      </div>
      <div class="modal-body">
        <p class="auth-subtitle" style="margin-bottom:16px">
          Tap <strong>Use</strong> to fill in your username on the login form.
        </p>
        <div class="fu-list">${userRows}</div>
      </div>
    </div>`;

  document.getElementById('app').appendChild(el);
  document.getElementById('fu-close').addEventListener('click',    () => el.remove());
  document.getElementById('fu-backdrop').addEventListener('click', () => el.remove());
  el.querySelectorAll('.fu-use-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('login-username').value = btn.dataset.username;
      document.getElementById('login-password').focus();
      el.remove();
      showToast(`Username filled: @${btn.dataset.username}`);
    });
  });
}

function confirmLogout() {
  if (confirm('Sign out of Expenseive?')) {
    AutoLock.stop();
    DB.clearSession();
    STATE = { currentUser: null, transactions: [], budgets: {}, goals: [], settings: { income: 50000, currency: 'INR' }, editingTxnId: null, txnType: 'expense', theme: 'light', _password: null };
    applyTheme('light');
    document.body.classList.remove('app-active');
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
// EVENT WIRING — all handlers here, zero inline onclick in HTML
// ============================================================
document.addEventListener('DOMContentLoaded', () => {

  // ── Auth ──
  document.getElementById('btn-login').addEventListener('click', handleLogin);
  document.getElementById('btn-register').addEventListener('click', handleRegister);
  document.getElementById('link-go-register').addEventListener('click', e => { e.preventDefault(); switchAuth('register'); });
  document.getElementById('link-go-login').addEventListener('click', e => { e.preventDefault(); switchAuth('login'); });
  document.getElementById('link-forgot-password').addEventListener('click', e => { e.preventDefault(); showForgotPassword(); });
  document.getElementById('link-forgot-username').addEventListener('click', e => { e.preventDefault(); showForgotUsername(); });

  // Password toggles
  document.getElementById('btn-pw-login').addEventListener('click', function() { togglePw('login-password', this); });
  document.getElementById('btn-pw-reg').addEventListener('click', function() { togglePw('reg-password', this); });
  document.getElementById('btn-pw-confirm').addEventListener('click', function() { togglePw('reg-confirm', this); });

  // Password strength
  document.getElementById('reg-password').addEventListener('input', function() {
    const s = Security.passwordStrength(this.value);
    const fill  = document.getElementById('pw-strength-fill');
    const label = document.getElementById('pw-strength-label');
    const colors = ['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
    const labels = ['Too weak','Weak','Fair','Strong','Very strong'];
    fill.style.width = (s / 4 * 100) + '%';
    fill.style.background = colors[s];
    label.textContent = this.value ? labels[s] : '';
    label.style.color = colors[s];
  });

  // Enter key on login fields
  document.getElementById('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });
  document.getElementById('login-username').addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });

  // ── Navigation ──
  document.getElementById('nav-dashboard').addEventListener('click', () => switchTab('dashboard'));
  document.getElementById('nav-transactions').addEventListener('click', () => switchTab('transactions'));
  document.getElementById('nav-analytics').addEventListener('click', () => switchTab('analytics'));
  document.getElementById('nav-budget').addEventListener('click', () => switchTab('budget'));
  document.getElementById('link-see-all').addEventListener('click', e => { e.preventDefault(); switchTab('transactions'); });

  // ── Header ──
  document.getElementById('btn-open-search').addEventListener('click', () => openModal('search-modal'));
  document.getElementById('user-avatar').addEventListener('click', () => openModal('profile-modal'));

  // ── Add expense modal ──
  document.getElementById('btn-open-add').addEventListener('click', () => openModal('add-modal'));
  document.getElementById('save-txn-btn').addEventListener('click', saveTransaction);
  document.getElementById('toggle-expense').addEventListener('click', function() { setTxnType('expense', this); });
  document.getElementById('toggle-income').addEventListener('click', function() { setTxnType('income', this); });

  // ── Transaction filters ──
  document.getElementById('txn-filter-month').addEventListener('change', renderTransactions);
  document.getElementById('txn-filter-cat').addEventListener('change', renderTransactions);
  document.getElementById('txn-search').addEventListener('input', renderTransactions);
  document.getElementById('analytics-month').addEventListener('change', renderAnalytics);
  document.getElementById('global-search').addEventListener('input', globalSearch);

  // ── Profile / Settings ──
  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('settings-currency').addEventListener('change', saveSettings);
  document.getElementById('btn-toggle-theme').addEventListener('click', toggleTheme);
  document.getElementById('btn-export').addEventListener('click', exportData);
  document.getElementById('btn-open-catmgr').addEventListener('click', openCategoryManager);
  document.getElementById('btn-logout').addEventListener('click', confirmLogout);

  // ── Category manager ──
  document.getElementById('btn-add-category').addEventListener('click', addCategory);

  // ── Budget / Goal modals ──
  document.getElementById('btn-open-budget-modal').addEventListener('click', () => openModal('budget-modal'));
  document.getElementById('btn-save-budget').addEventListener('click', saveBudget);
  document.getElementById('btn-open-goal-modal').addEventListener('click', () => openModal('goal-modal'));
  document.getElementById('btn-save-goal').addEventListener('click', saveGoal);

  // ── Universal modal close — backdrop clicks and ✕ buttons ──
  document.addEventListener('click', e => {
    // data-close attribute on backdrop divs and close buttons
    const target = e.target.closest('[data-close]');
    if (target) closeModal(target.dataset.close);
  });

  // ── Auto-restore session ──
  const { username: savedUser, password: savedPw } = DB.getSession();
  if (savedUser && savedPw) {
    const meta = DB.loadMeta();
    if (meta.users[savedUser]) {
      initApp(savedUser, savedPw);
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
