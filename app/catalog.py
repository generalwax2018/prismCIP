"""Requirement catalog for low impact entities: CIP-002-5.1a and CIP-003-9.

Summaries are plain-language paraphrases to help users find the right evidence. They are not the
standard's text; always check the current standard on nerc.com before an audit.
cadence_months: 15 / 36 = periodic ("at least once every N calendar months"); None = ongoing or event-driven.
"""

CATALOG = [
    # --- CIP-002 ---
    dict(code="CIP-002 R1.3", standard="CIP-002", cadence_months=None, section6=False,
         title="Identify assets containing low impact BES Cyber Systems",
         summary="Identify each asset that contains a low impact BES Cyber System. A list of the BES Cyber "
                 "Systems themselves is not required for low impact.",
         evidence_hint="Dated list of assets containing low impact BCS, with the method used to identify them."),
    dict(code="CIP-002 R2", standard="CIP-002", cadence_months=15, section6=False,
         title="Review identifications and get CIP Senior Manager approval",
         summary="Review the R1 identifications and update them if needed, and have the CIP Senior Manager "
                 "(or delegate) approve them, at least once every 15 calendar months.",
         evidence_hint="Signed and dated review/approval record of the asset list."),
    # --- CIP-003 R1 ---
    dict(code="CIP-003 R1.2", standard="CIP-003", cadence_months=15, section6=False,
         title="Low impact cyber security policies approved by CIP Senior Manager",
         summary="Documented policies covering: security awareness, physical security, electronic access "
                 "controls, incident response, transient cyber assets and removable media, vendor electronic "
                 "remote access security controls (new in -9), and CIP Exceptional Circumstances. Reviewed "
                 "and approved by the CIP Senior Manager at least once every 15 calendar months.",
         evidence_hint="Current policy document showing all topics incl. vendor remote access, with dated CIP "
                       "Senior Manager approval."),
    # --- CIP-003 R2 / Attachment 1 ---
    dict(code="CIP-003 Att1 S1", standard="CIP-003", cadence_months=15, section6=False,
         title="Section 1 — Cyber security awareness",
         summary="Reinforce cyber security practices (which may include physical security practices) at "
                 "least once every 15 calendar months.",
         evidence_hint="Awareness materials sent (emails, posters, briefings) with the date delivered."),
    dict(code="CIP-003 Att1 S2", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 2 — Physical security controls",
         summary="Control physical access, based on need, to the asset or the locations of the low impact "
                 "BCS within it, and to any Cyber Assets that provide the Section 3.1 electronic access "
                 "controls.",
         evidence_hint="Description of physical controls per asset (locks, card readers, fences), plus "
                       "access lists or logs."),
    dict(code="CIP-003 Att1 S3.1", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 3.1 — Electronic access controls (routable)",
         summary="Where routable protocol communication crosses the asset boundary to/from low impact BCS, "
                 "permit only the inbound and outbound access needed and deny everything else (unless an "
                 "exception applies, such as time-sensitive protection or control functions between "
                 "intelligent electronic devices).",
         evidence_hint="Firewall/ACL rule sets with business justification for each permitted rule; network "
                       "diagrams."),
    dict(code="CIP-003 Att1 S3.2", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 3.2 — Authenticate dial-up connectivity",
         summary="Authenticate all Dial-up Connectivity, if any, that provides access to low impact BCS, "
                 "per the Cyber Asset's capability.",
         evidence_hint="Modem/dial-up configuration showing authentication, or a statement that none exists."),
    dict(code="CIP-003 Att1 S4", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 4 — Cyber security incident response plan",
         summary="Have incident response plan(s) covering identification, classification and response; "
                 "deciding if an incident is reportable and notifying E-ISAC; roles and responsibilities; "
                 "and incident handling.",
         evidence_hint="Current incident response plan document."),
    dict(code="CIP-003 Att1 S4.5", standard="CIP-003", cadence_months=36, section6=False,
         title="Section 4.5 — Test the incident response plan",
         summary="Test each incident response plan at least once every 36 calendar months (a tabletop, "
                 "drill, or responding to an actual Reportable Cyber Security Incident counts).",
         evidence_hint="Tabletop/drill record with date, participants and findings."),
    dict(code="CIP-003 Att1 S4.6", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 4.6 — Update plan after a test or reportable incident",
         summary="Update the plan, if needed, within 180 calendar days after completing a test or an actual "
                 "Reportable Cyber Security Incident.",
         evidence_hint="Plan revision history tied to the test or incident date."),
    dict(code="CIP-003 Att1 S5", standard="CIP-003", cadence_months=None, section6=False,
         title="Section 5 — Transient Cyber Assets and Removable Media",
         summary="Plan(s) to mitigate malicious code risk from Transient Cyber Assets (entity-managed and "
                 "third-party-managed) and Removable Media before connecting them to low impact BCS.",
         evidence_hint="TCA/RM plan, plus scan logs or checklists for devices used."),
    dict(code="CIP-003 Att1 S6.1", standard="CIP-003", cadence_months=None, section6=True,
         title="Section 6.1 — Determine vendor electronic remote access",
         summary="For assets that allow vendor electronic remote access, have one or more methods to "
                 "determine when that access is happening.",
         evidence_hint="Session logs, remote-access tool reports, or approval records showing each vendor "
                       "session."),
    dict(code="CIP-003 Att1 S6.2", standard="CIP-003", cadence_months=None, section6=True,
         title="Section 6.2 — Disable vendor electronic remote access",
         summary="Have one or more methods to disable vendor electronic remote access.",
         evidence_hint="Procedure plus proof it works: screenshots or logs of a session being terminated or "
                       "an account/tunnel disabled."),
    dict(code="CIP-003 Att1 S6.3", standard="CIP-003", cadence_months=None, section6=True,
         title="Section 6.3 — Detect malicious communications for vendor access",
         summary="Have one or more methods to detect known or suspected malicious communications, inbound "
                 "and outbound, for vendor electronic remote access.",
         evidence_hint="IDS/IPS, firewall threat signatures or monitoring config covering the vendor access "
                       "path, with sample alerts or reviews."),
    # --- CIP-003 R3 / R4 ---
    dict(code="CIP-003 R3", standard="CIP-003", cadence_months=None, section6=False,
         title="Identify the CIP Senior Manager",
         summary="Identify the CIP Senior Manager by name and document any change within 30 calendar days.",
         evidence_hint="Dated document naming the CIP Senior Manager."),
    dict(code="CIP-003 R4", standard="CIP-003", cadence_months=None, section6=False,
         title="Document delegations of CIP Senior Manager authority",
         summary="If the CIP Senior Manager delegates authority, document the delegate by name or title and "
                 "the date, and update changes within 30 calendar days.",
         evidence_hint="Delegation memo(s) with names/titles, authority delegated and dates."),
]


def seed_requirements(db):
    from .models import Requirement
    existing = {r.code: r for r in db.query(Requirement).all()}
    for i, item in enumerate(CATALOG):
        row = existing.get(item["code"])
        if row is None:
            db.add(Requirement(sort_order=i, **item))
        else:
            for k, v in item.items():
                setattr(row, k, v)
            row.sort_order = i
    db.commit()
