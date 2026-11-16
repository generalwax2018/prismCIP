# PrismCIP

NERC CIP **low impact** compliance for small utilities (co-ops, municipal utilities and small generators).
It covers CIP-002 R1.3/R2 and CIP-003-9, with a focus on the new **Attachment 1, Section 6 vendor electronic
remote access** controls, which took effect April 1, 2026.

> Proprietary. © Wax. All rights reserved.

## What it does

| Area | What you get |
|---|---|
| **Assets** (CIP-002 R1.3) | Assets containing low impact BCS, with connectivity flags and Section 2 / 3.1 control descriptions |
| **Vendor remote access** (Att1 S6) | Each vendor → asset path with its 6.1 / 6.2 / 6.3 methods, the accounts it uses, approved access windows, a session log, and a one-click **Disable access now** that closes open sessions |
| **Session import** | Load FortiGate VPN event logs (SSL VPN and IPsec dial-up tunnel up/down) or CSV exports from GlobalProtect, BeyondTrust, Secomea, etc. Each session is matched to an access path by account and checked against approved windows. Unapproved sessions, sessions on disabled paths, sessions that ran past their window, and unknown accounts become **findings**. A token-protected API (`POST /api/v1/sessions`) lets a log forwarder push logs automatically |
| **Vendor portal** | A private, expiring link per vendor. Vendors request access windows; you approve or deny them; approvals feed the session checks |
| **Findings** | One queue for import and check results. Resolving needs a written reason. Open high/medium findings count as gaps on their requirement |
| **Requirements tracker** | 16 requirements with 15/36-month due dates, the 180-day plan-update clock after each IR test (S4.6), statuses and gap detection |
| **Program trackers** | Security awareness (S1), incident response exercises (S4.5 / S4.6) and transient devices / removable media (S5). Each entry is filed as evidence; malware found on a device opens a finding |
| **Firewall review** (S3.1) | Upload a FortiGate config backup per asset. Flags any-to-any rules, any source/destination/service, rules with no reason, logging off, and vendor rules without IPS/AV or always on. Report filed as evidence; high issues become findings |
| **Sign-offs** | CIP Senior Manager / delegate approvals of the policy, the CIP-002 R2 asset review and the plan. Documents are frozen with SHA-256 at request; the signer re-enters their password and types their name; the hash is re-checked before signing; approvals are filed as evidence |
| **Reminders** | Email at 60, 30 and 7 days before each periodic deadline and when overdue, plus high findings and waiting sign-offs. Each milestone is sent once. SMTP, or `.eml` files in `data/outbox` when no server is set |
| **Plan** | CIP-003 low impact plan built from records, with in-app editing of the narrative sections. Printable; anything unknown stays marked TODO |
| **RSAW workbook** | Per requirement: what the auditor looks for, your written response (draft it from records, then edit), and the evidence index in RSAW columns. Exported on its own and inside the audit package, with working links to each file |
| **Audit package** | One zip: summary, plan, assets, access paths, sessions, evidence (hashed, by requirement), activity log, RSAW workbook, sign-offs with signed documents, findings |
| **Noncompliance log** | What happened, cause, risk (Minimal / Moderate / Serious), mitigation steps with due dates, and your self-report / self-log decision. PrismCIP records the decision; it doesn't make it |
| **Audit requests** | Track each RFI from the Regional Entity with a due date, attach evidence, and export the response. Attached evidence is locked |
| **Vendor offboarding & account review** | Offboarding checklist (auto-checks disabled paths, open sessions, portal link) and periodic review of every account on every access path, filed as evidence |
| **Live syslog** | Optional UDP/TCP syslog listener for FortiGate and Palo Alto GlobalProtect, accepting only listed senders. Palo Alto PAN-OS XML configs work in the firewall review too |
| **Board report** | One-page summary for the board or general manager, printable or downloadable |
| **Co-op / consultant mode** | One account working across several utilities, with a switcher and a portfolio view. Data stays separate per utility |
| **CIP-003-11 readiness** | Checklist per site for the new Section 3 (necessary access, malicious-communication detection, user authentication, credentials in transit, vendor access, dial-up) plus org-wide items, with hints from your existing records, owners, target dates and a CSV export. Shown on the board report |
| **Single sign-on** | OIDC (Entra ID, Okta, Google...) per utility or install-wide, bound to the utility's email domains, with an option to require it (admins keep password sign-in as a break-glass) |
| **AI drafting** | Opt-in per utility. Suggests plan sections and RSAW responses from your records; nothing is used until a person accepts it, and every request and decision is logged |
| **Hosted signup & billing** | Optional (`PRISMCIP_HOSTED=1`): self-service signup with a free trial, Stripe subscriptions, and read-only (still exportable) after the trial or a lapsed subscription |
| **Security** | Password change and reset (by link or temporary password), sign-in throttling, evidence locking once exported, N/A records with justification, scheduled and encrypted backups, tamper-evident activity log (SHA-256 hash chain with anchors kept outside the database), scrypt passwords, optional two-step sign-in (TOTP, secrets sealed at rest, replay-protected, QR drawn locally), CSRF on every form, strict CSP, roles (admin / editor / viewer), signer flag, per-org data separation, append-only activity log, non-root container |

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: python -m venv .venv; .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m scripts.seed_demo          # optional demo co-op: demo@prismcip.local / demo-password-123
python -m uvicorn app.main:app --reload
```

Demo walkthrough: sign in, go to **Remote access → Import sessions** and upload `samples/fortigate_vpn_events.log`
(one approved session, one unapproved, one unknown account, one ignored staff account). Upload
`samples/fortigate_north_sub.conf` on the North Substation asset for a firewall review. Request a sign-off from
Dana Ortiz (`dana@prismcip.local`, same password) and sign it as her.

Open http://localhost:8000. With no demo data loaded, the first visit takes you to set up your organization and admin account.
Data (the SQLite database, evidence files and session key) is stored in `./data`, or in `PRISMCIP_DATA_DIR` if that's set.

Tests: `pytest -q`

## Deploy (Docker + Caddy, free TLS)

1. Point a DNS name at the server and put that name in `Caddyfile`.
2. `echo "PRISMCIP_SECRET_KEY=$(openssl rand -base64 48)" > .env`
3. `docker compose up -d --build`

Data lives in the `prismcip-data` volume. Back it up. Evidence must be kept for 3 years, and an audit can look back as far as 6.

## Config

| Variable | Default | Purpose |
|---|---|---|
| `PRISMCIP_DATA_DIR` | `./data` | Database, evidence and session key |
| `PRISMCIP_DATABASE_URL` | SQLite in the data directory | e.g. `postgresql+psycopg://user:pass@host/prismcip` (install `requirements-postgres.txt`, or use `docker-compose.postgres.yml`) |
| `PRISMCIP_SECRET_KEY` | Generated and saved in the data directory | Session signing |
| `PRISMCIP_HTTPS` | `0` | Set to `1` behind TLS for secure cookies |
| `PRISMCIP_BASE_URL` | | Public URL, used in reminder emails |
| `PRISMCIP_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` | | Mail server for reminders (STARTTLS on 587, TLS on 465). Unset: messages go to `data/outbox` |
| `PRISMCIP_MAIL_FROM` | `prismcip@localhost` | Sender address |
| `PRISMCIP_REMINDERS` | `on` | `off` disables the in-app daily reminder job (use `python -m scripts.send_reminders` from cron instead) |
| `PRISMCIP_REMINDER_HOUR` | `7` | Server-local hour after which the daily reminder run happens |
| `PRISMCIP_BACKUPS` / `PRISMCIP_BACKUP_HOUR` | `on` / `2` | Nightly backup (SQLite installs; use `pg_dump` for Postgres) |
| `PRISMCIP_BACKUP_DIR` | `data/backups` | Put this on another disk or a mounted share |
| `PRISMCIP_BACKUP_PASSPHRASE` | | Encrypt backups (`.zip.enc`). Keep the passphrase somewhere else; without it a backup can't be restored |
| `PRISMCIP_SYSLOG_PORT` / `PRISMCIP_SYSLOG_HOST` | off / `0.0.0.0` | Live syslog listener (UDP and TCP) |
| `PRISMCIP_SYSLOG_SOURCES` | | Allowed senders: `10.0.5.1, 10.0.6.0/24=2` (`=<org id>` on multi-utility installs) |
| `PRISMCIP_PLATFORM_ADMINS` | | Emails allowed whole-install tasks (backups). Unset on a single-utility install: any admin |
| `PRISMCIP_PARTNERS` | | Emails allowed to create utilities (consultants, G&Ts). Can also be set per user |
| `PRISMCIP_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_EMAIL_CLAIM` | | Install-wide single sign-on. Each utility can instead set its own in Settings. Redirect URI: `<base URL>/login/sso/callback` |
| `PRISMCIP_AI_API_KEY` (or `ANTHROPIC_API_KEY`) | | Makes AI drafting available; each utility's admin still has to turn it on |
| `PRISMCIP_AI_MODEL` / `PRISMCIP_AI_DAILY_LIMIT` | `claude-sonnet-5-5` / `40` | Model and suggestions per utility per day |
| `PRISMCIP_HOSTED` | off | Turns on `/signup`, free trials and billing. Leave off for a utility's own install |
| `PRISMCIP_TRIAL_DAYS` / `PRISMCIP_GRACE_DAYS` | `30` / `14` | Trial length; days a failed payment stays writable |
| `PRISMCIP_STRIPE_SECRET_KEY` / `_PRICE_ID` / `_WEBHOOK_SECRET` | | Stripe test or live keys. Point a Stripe webhook at `<base URL>/billing/webhook` with `checkout.session.completed`, `customer.subscription.*`, `invoice.paid`, `invoice.payment_failed` |

## Pushing logs automatically

Create a token in **Settings → Session import**, then from a log server or a scheduled task:

```bash
curl -X POST -H "Authorization: Bearer pcip_..." --data-binary @vpn-events.log https://cip.example.com/api/v1/sessions
curl -X POST -H "Authorization: Bearer pcip_..." --data-binary @sessions.csv "https://cip.example.com/api/v1/sessions?format=csv"
```

Re-sending the same events is safe; duplicates are skipped.

## Assumptions to confirm

- "At least once every N calendar months" is calculated as due by the **last day of the calendar month** N months
  after the activity was last performed. Confirm this against your Regional Entity's guidance.
- Requirement summaries are paraphrased, not the text of the standard. Check them against the current standards on nerc.com.
- CIP-003-11 (FERC-approved March 2026, effective July 1, 2029) folds Section 6 into Section 3 and adds detection,
  user authentication and protection of credentials in transit. The readiness checklist paraphrases it; read the
  standard and implementation plan before relying on it.
- Have someone who knows your Regional Entity review the requirement catalog (`app/catalog.py`) against the current
  standards before using PrismCIP for a real audit.

## Upgrading

New versions add tables and columns to an existing database automatically at startup; nothing is dropped. Back up
the data folder before upgrading anyway.

## Roadmap ideas

- Add CIP-003-11 to the requirement catalog itself when entities start transitioning
- Cisco ASA / FTD config parsing in the firewall review
- AI help sorting uploaded evidence to requirements (human-approved, never setting status)
