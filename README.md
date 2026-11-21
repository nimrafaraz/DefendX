# DEFEND-X — Integrated Multi-Domain Defence Awareness System

A **defensive, educational simulation** built with Python, Streamlit, SQLite and Plotly.
Every signal, network flow, radar track, event and account is **synthetic**. There is no
jamming, interception, intrusion, targeting or weapon-control capability.

## Quick start (Windows 10/11)

1. Install Python 3.10 or newer from <https://www.python.org/downloads/>.
   **Tick "Add python.exe to PATH"** on the first installer screen.
2. Unzip this project to a normal folder (for example `C:\DEFEND-X`).
3. Double-click **`run_windows.bat`**. The first time it creates a `.venv` folder and downloads
   the packages (internet needed, a few minutes). Then it starts the app.
4. Your browser opens at <http://localhost:8501>. If not, type that address yourself.
5. Sign in with a demo account:

| Username | Password | Role |
|---|---|---|
| admin | Admin@2026 | ADMIN |
| analyst | Analyst@2026 | ANALYST |
| operator | Operator@2026 | OPERATOR |
| viewer | Viewer@2026 | VIEWER |

To run the automated tests: `run_windows.bat test`

Manual alternative (Command Prompt inside the project folder):

```
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m streamlit run app.py
```

macOS/Linux: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && streamlit run app.py`

## What each part does

| Page | What you can do |
|---|---|
| Dashboard | Threat level, open alerts, domain status, correlated incidents. Operators/admins can inject a demo scenario. |
| Electronic Activity | Simulated 400–470 MHz spectrum + waterfall. Detector compares it with an authorised plan (unknown emitter, power deviation, offline emitter, noise rise). |
| Cyber Defence | Synthetic network flows. Rules detect port scan, brute force, data exfiltration, traffic flood. |
| Radar Simulation | Virtual PPI with 12 moving tracks and a restricted zone. Inject an unknown contact, switch on *Live sweep*, watch the alert. |
| Intelligence | Links events from different domains into incidents, scores risk 0–100, builds Markdown/HTML reports. |
| Secure Comms | Encrypted user-to-user messages; shows the ciphertext actually stored. |
| Administration | Users, roles, audit log, regenerate demo data. |

Who can see what: Viewer = dashboard + 3 sensor pages (read only). Operator = also run
scans/scenarios, manage events, messaging. Analyst = view, manage events, intelligence, reports,
messaging. Admin = everything.

## A suggested 5-minute demo

1. Sign in as **operator**, open Dashboard.
2. Electronic Activity → scenario *Unknown emitter* → Run scan (a red X appears, a HIGH event is logged).
3. Cyber Defence → *Port scan* → Run analysis.
4. Radar → *Inject unknown contact* → switch on *Live sweep* → wait up to ~30 s for the alert.
5. Sign out, sign in as **analyst** → Intelligence: the three events form one incident → Generate report → download.
6. Secure Comms: message another user; open "What the database actually stores".
7. Sign in as **admin** → Administration → Audit log.

## How the project is organised

```
app.py                  login, sidebar menu, role checks
defendx/
  config.py             all settings: roles, permissions, thresholds, demo accounts
  simulation.py         RF, cyber and radar simulators + detectors (pure functions)
  db.py / events.py     SQLite and the central event store
  auth.py / audit.py    passwords (scrypt), lockout, roles, audit trail
  messaging.py          Fernet encryption, per-conversation keys
  intel.py              risk score, correlation, reports
  services.py           connects simulators to the database
  pages/                one file per page
  ui/                   shared styling and widgets
tests/                  automated tests
data/                   created at run time: defendx.db and master.key
```

Layers: pages -> services/intel/auth/messaging -> db/events -> simulation (no I/O). Settings
live in `config.py` and the constants at the top of `simulation.py`.

## What has and has not been verified

Verified by running them (93 tests: 91 pass, 2 skipped — see below):
- Authentication, lockout, password/username policy, roles, last-admin protection
- Encryption round trip, ciphertext at rest, tamper detection, per-pair keys, key-file handling
- RF, cyber and radar simulators: determinism, **zero false positives** on normal data
  (150 RF seeds, 60 cyber seeds), each injected anomaly detected as itself
- Risk scoring, correlation, report content, event store, demo data, scans, scenarios
- Page code paths and permissions, using a *stand-in* for Streamlit (not the real library)

NOT verified (no Streamlit/Plotly/Windows available where this was built):
- The two `test_app_smoke.py` tests (real Streamlit AppTest) are written but were **skipped**.
  Run `run_windows.bat test` on your PC — they will run there and tell you if any page fails.
- How charts look and how the layout behaves in a real browser.
- `run_windows.bat` on a real Windows machine.
- The live radar mode (auto-refresh every 2 s) in a real browser.

## Known limits (by design)

- Encryption is server-side at rest, **not end-to-end**. Anyone who can read `data/master.key`
  can read all messages. No TLS in the default setup, no forward secrecy, no message deletion.
- Demo passwords are shown on the login screen. Remove demo seeding before any real use.
- Radar and last-scan state are per browser session; events are shared through the database.
- Detection is rule-based with fixed thresholds; radar tracks move in straight lines.

## Troubleshooting

- *"Python was not found"*: reinstall Python with "Add python.exe to PATH", reopen the window.
- *Port 8501 busy*: `.venv\Scripts\python.exe -m streamlit run app.py --server.port 8502`
- *Fresh start*: close the app and delete the `data` folder. Accounts and history are recreated;
  old messages become unreadable because a new master key is made.
