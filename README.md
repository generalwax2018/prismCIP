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
| **Security** | scrypt passwords, optional two-step sign-in (TOTP, secrets sealed at rest, replay-protected, QR drawn locally), CSRF on every form, strict CSP, roles (admin / editor / viewer), signer flag, per-org data separation, append-only activity log, non-root container |

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
| `PRISMCIP_DATABASE_URL` | SQLite in the data directory | Point at Postgres later |
| `PRISMCIP_SECRET_KEY` | Generated and saved in the data directory | Session signing |
| `PRISMCIP_HTTPS` | `0` | Set to `1` behind TLS for secure cookies |
| `PRISMCIP_BASE_URL` | | Public URL, used in reminder emails |
| `PRISMCIP_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` | | Mail server for reminders (STARTTLS on 587, TLS on 465). Unset: messages go to `data/outbox` |
| `PRISMCIP_MAIL_FROM` | `prismcip@localhost` | Sender address |
| `PRISMCIP_REMINDERS` | `on` | `off` disables the in-app daily reminder job (use `python -m scripts.send_reminders` from cron instead) |
| `PRISMCIP_REMINDER_HOUR` | `7` | Server-local hour after which the daily reminder run happens |

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
- CIP-003-11 (effective July 1, 2029) folds Section 6 into Section 3 and adds authentication for remote users.
  The catalog in `app/catalog.py` is versioned in a way that makes adding it a data change.

## Upgrading

New versions add tables and columns to an existing database automatically at startup; nothing is dropped. Back up
the data folder before upgrading anyway.

## Roadmap ideas

- Native parsers for Palo Alto GlobalProtect syslog and Palo Alto / Cisco firewall configs
- CIP-003-11 catalog and a readiness checklist (effective July 1, 2029)
- Multi-org admin for consultants and G&T cooperatives that manage several members
- SSO (Entra ID / OIDC), reusing RiskPrism's implementation
- AI drafting help for plan sections and evidence sorting, human-approved, never setting status
