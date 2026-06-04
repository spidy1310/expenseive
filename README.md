# Expenseive

A personal finance tracker built as a Progressive Web App (PWA). Works on Android and iPhone, install it to your home screen and it runs like a native app, fully offline.

No accounts, no subscriptions, no servers. Your data never leaves your device.

---

## Features

- **Dashboard** — monthly overview with income, spending, and remaining balance. Tracks the 50/30/20 rule (Needs / Wants / Savings) automatically.
- **Expense tracking** — log expenses and income with category, payment mode, type, date, and notes.
- **Analytics** — monthly spending trends, category breakdown, payment mode split, weekly analysis, and top expenses.
- **Budget management** — set per-category monthly budgets with live progress and over-budget alerts.
- **Savings goals** — track progress toward financial goals with a target date and amount.
- **Custom categories** — add or delete your own categories with a custom icon and colour. Changes are per-user and don't affect anyone else on the same device.
- **Search** — global search across all transactions.
- **Dark mode** — system-friendly dark/light toggle.
- **Export** — download all your data as JSON anytime.

---

## Security

Security was treated seriously, not as an afterthought.

- **Passwords** are hashed using PBKDF2-SHA256 with 310,000 iterations (OWASP 2023 standard). The actual password is never stored anywhere.
- **All financial data** (transactions, budgets, goals, settings) is encrypted at rest using AES-GCM 256-bit encryption. The encryption key is derived from your password on login and lives only in memory — if you forget your password, the data is unrecoverable by design.
- **Brute-force protection** uses an exponential lockout that persists across page reloads and phone restarts — not just in memory.
- **Auto-lock** kicks in after 10 minutes of inactivity and wipes the in-memory session.
- **Content Security Policy** blocks inline scripts, external connections, and iframe embedding.
- All user inputs are sanitized on both write and read (defence-in-depth against XSS).
- The app has been reviewed against the OWASP Top 10.

---

## Installation

**Android (Chrome)**
1. Open the app URL in Chrome
2. Tap the browser menu → *Add to Home Screen*
3. Done — it opens like a native app from your home screen

**iPhone (Safari)**
1. Open the app URL in Safari (must be Safari, not Chrome)
2. Tap the Share button → *Add to Home Screen*
3. Done

---

## Tech Stack

Vanilla HTML, CSS, and JavaScript, no frameworks, no build step, no dependencies. The Web Crypto API handles all encryption natively in the browser.

```
expenseive/
├── index.html        # App shell
├── app.js            # All application logic
├── app.css           # Styles + dark mode
├── sw.js             # Service worker (offline support)
├── manifest.json     # PWA install config
└── icons/            # App icons (192px, 512px)
```

---

## Data & Privacy

Everything stays on your device. There is no server, no analytics, no tracking, and no third-party services beyond Google Fonts (loaded for typography only). Uninstalling the browser or clearing site data will erase your local data — use the Export feature regularly if that's a concern.
