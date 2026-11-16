# PrismCIP

NERC CIP **low impact** compliance for small utilities (co-ops, municipal utilities and small generators).
It covers CIP-002 R1.3/R2 and CIP-003-9, with a focus on the new **Attachment 1, Section 6 vendor electronic
remote access** controls, which took effect April 1, 2026.

> Proprietary. © Wax. All rights reserved.

## What it does

| Area | What you get |
|---|---|
| **Assets** (CIP-002 R1.3) | The list of assets containing low impact BCS, with flags for routable external connectivity, dial-up and vendor remote access, plus Section 2 and 3.1 control descriptions for each asset |
| **Vendor remote access** (Att1 S6) | Each vendor-to-asset access path with its 6.1 determine, 6.2 disable and 6.3 detect methods. A **Disable access now** button closes any open sessions and logs it. There's also a session log with approver, purpose, end reason and a flag for malicious activity |
| **Requirements tracker** | 16 seeded requirements with plain-language summaries and hints on what makes good evidence. Due dates are calculated for the 15- and 36-month cadences. Statuses are Current, Due soon, Overdue, No evidence and Gap |
| **Gap detection** | Finds missing 6.1/6.2/6.3 methods, assets that allow vendor access but have no paths recorded (and the reverse), routable assets with no access control written down, sessions open longer than 24 hours, and a missing CIP Senior Manager |
| **Evidence** | File uploads (50 MB maximum, extension allowlist) with SHA-256 hashes. The date an activity was performed drives its next due date |
| **Plan generator** | A draft CIP-003 low impact cyber security plan built from your records. Anything the app doesn't know is marked TODO, so nobody signs a plan claiming controls that don't exist. It can be printed or saved as a PDF |
| **Audit package** | One-click zip containing a summary, the draft plan, CSVs (assets, access paths, sessions, evidence index with hashes and the 3-year retention flag, activity log) and the evidence files arranged by requirement |
| **Governance** | CIP Senior Manager (R3) and delegations (R4) with dates. Admin, editor and viewer roles. An append-only activity log |

Security notes: scrypt password hashing, signed session cookies (secure flag behind TLS), CSRF tokens on every
form, a strict CSP (no inline script or style), org-scoped queries on every record (built multi-tenant from day one),
and a container that runs as a non-root user.

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m scripts.seed_demo          # optional demo co-op: demo@prismcip.local / demo-password-123
uvicorn app.main:app --reload
```

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

## Assumptions to confirm

- "At least once every N calendar months" is calculated as due by the **last day of the calendar month** N months
  after the activity was last performed. Confirm this against your Regional Entity's guidance.
- Requirement summaries are paraphrased, not the text of the standard. Check them against the current standards on nerc.com.
- CIP-003-11 (effective July 1, 2029) folds Section 6 into Section 3 and adds authentication for remote users.
  The catalog in `app/catalog.py` is versioned in a way that makes adding it a data change.

## Roadmap ideas

- Connectors that pull vendor sessions automatically from firewall and VPN logs or remote access tools (Fortinet, Palo Alto, BeyondTrust, Secomea)
- Reminder emails before due dates, plus a CIP Senior Manager approval workflow with e-signature
- CIP-003-11 catalog and a migration checklist
- Multi-org admin for consultants and G&T cooperatives that manage several members
