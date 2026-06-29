# Phishing & Email Analysis — Credential Lures (Microsoft + Binance Impersonation)

Two real, honeypot-collected phishing emails reconstructed and analyzed end-to-end 
no phishing email was ever sent, and no malicious link was ever visited directly.
This is Lab 5 of a self-directed SOC detection series.

**Series progression:** closes the initial-access loop. Labs 1–4 covered what happens
*after* a breach (logs, network, identity, malware); this lab analyzes how the breach
actually starts.

| | |
|---|---|
| **Source** | [`rf-peixoto/phishing_pot`](https://github.com/rf-peixoto/phishing_pot) — honeypot-collected real phishing, recipient anonymized to `phishing@pot` |
| **Topic / Family** | Phishing — credential harvesting via brand impersonation (Microsoft + Binance) |
| **Tools** | PowerShell, VirusTotal, CyberChef |
| **Method** | Detect → Analyze → Correlate → Harden → Validate |

---

## Disclaimer

This is a personal lab using two real samples from a public honeypot dataset, not
professional SOC experience, and nothing here was run against a live organization.
No phishing email was sent to anyone. No malicious URL was visited directly; the link
in Sample 2 was submitted to VirusTotal for sandboxed analysis instead. The raw
`.eml` files and the rendered HTML lure are **intentionally excluded** from this repo
— re-hosting live phishing content (even pre-anonymized) with a working malicious
link is poor hygiene for a public repo. They can be reproduced from the source link
above using the sample numbers cited throughout.

---

## Environment

| Item | Value |
|---|---|
| Analysis host | Windows 11 / PowerShell |
| Sample source | `phishing_pot` GitHub repo (`email/sample-10.eml`, `email/sample-12.eml`) |
| Detonation | VirusTotal (URL tab, cloud-hosted, sample never visited directly) |
| Decode / inspection | CyberChef (web) |

---

## Workflow

| Phase | What I did |
|---|---|
| **Detect** | Spotted the lures: a fake Microsoft "unusual sign-in" alert and a fake Binance "verification required" notice, both using manufactured urgency. |
| **Analyze** | Traced the `Received:` chain to the true origin on both samples; read the `Authentication-Results` line for SPF/DKIM/DMARC verdicts; compared `header.from` vs `smtp.mailfrom` vs `Reply-To`. |
| **Correlate** | Built a timeline per sample connecting origin IP, spoofed display domain, collection point (mailto vs. credential URL) into one attacker story. |
| **Harden** | Mapped each weakness (unenforced DMARC, lookalike domain, beacon/payload URL) to the real-world control that would close it, and to who actually owns that control. |
| **Validate** | Submitted Sample 2's URL to VirusTotal without visiting it, cross-read detection-engine identity against raw score, and confirmed domain-age signals against the email's own date. |

---

## Investigation Walkthrough

> A full visual breakdown — header crops, the rendered lures, and the VirusTotal
> results — published as a slide carousel. *(Link added once posted.)*

### 1 — Detect & Analyze: Sample 1 (Microsoft credential lure)

Reading the `Received:` chain bottom-to-top traced the message to an external server
announcing itself as `thcultarfdes.co.uk` at IP `89.144.44.2` — connecting straight
into Microsoft's own mail gateway (`*.mail.protection.outlook.com`), the trust
boundary between attacker infrastructure and Microsoft's internal relay.

Authentication failed across the board:

```
spf=none  (sender IP 89.144.44.2, smtp.mailfrom=thcultarfdes.co.uk)
dkim=none (message not signed)
dmarc=permerror action=none header.from=access-accsecurity.com
```

Three domains appear in this one email, none of them Microsoft, one sends
(`thcultarfdes.co.uk`), one displays (`access-accsecurity.com`), one collects replies
(`sotrecognizd@gmail.com`). Every "button" in the rendered email — *Report The User*,
*Unsubscribe*, *click here* — is a `mailto:` link to that same Gmail address. The
button's label and its actual destination are unrelated.

The body also hides a 1×1 tracking pixel beaconing to `thebandalisty.com`, and a
large block of randomized "word salad" text intended to dilute spam-filter scoring.

### 2 — Detect & Analyze: Sample 2 (Binance link lure)

Same skeleton, different fingerprint. Here DMARC ran successfully and correctly
**failed** the spoof (Binance's own policy works) but `action=none` let it through
regardless, proving a working DMARC check is worthless without enforcement. The
`Reply-To` matches the `From` this time (no reply-bait needed for a link-based
attack), and an `Authentication-Results-Original: auth=pass` line shows the attacker
simply logged into their **own** hosting relay , likely a compromised customer
account (`ilonasavola.com` via `wp-cloud.fi`), not anything vouching for legitimacy.

A single real malicious link was isolated by searching for structure, not wording:

```powershell
Select-String -Path .\sample-12.eml -Pattern 'href="[^"]*"' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
```

The body itself carried zero obfuscation — the entire attack relies on one
convincing link rather than text-evasion tricks.

### 3 — Correlate

> At 05:47:04 UTC on 8 Sep 2023, a server at `89.144.44.2` announcing itself as
> `thcultarfdes.co.uk` delivered a message displaying as "Microsoft account team"
> while routing both replies and a fake "Report The User" button to a disposable
> Gmail address — a reply-bait design built to start a conversation, not harvest a
> credential outright.
>
> At 21:39:41 UTC on 22 Aug 2022, a likely-compromised hosting account delivered a
> Binance impersonation that skipped reply-bait entirely and drove straight to a
> single credential-harvesting link — a faster, higher-conversion, higher-risk
> design than Sample 1's.

### 4 — Harden

See [Hardening recommendations](#hardening-recommendations) below.

### 5 — Validate

`https://zzdzw.com/` was submitted to VirusTotal, never visited directly and came
back **2 / 92**, which is *not* the same as "clean." The two engines that flagged it,
`alphaMountain.ai` and `Forcepoint ThreatSeeker`, are reputation/categorization
engines.  exactly the tools built to catch phishing sites; the 90 "clean" verdicts
are mostly file-malware engines with no opinion on a URL. alphaMountain additionally
tagged the domain **"Newly Registered."**

VirusTotal's "First Submission" date (2022-07-13) is when the URL was first
*scanned*, not a WHOIS registration date, it sits roughly five weeks before the
email itself (22 Aug 2022). Combined with the "Newly Registered" tag, the defensible
read is infrastructure stood up for a mid-2022 campaign window and used within weeks,
not long-running reused infrastructure.

---

## Indicators of Compromise

| Type | Sample 1 (Microsoft) | Sample 2 (Binance) |
|------|----------------------|---------------------|
| Sending IP | `89.144.44.2` | `84.34.166.151` |
| Envelope domain | `thcultarfdes.co.uk` | `ilonasavola.com` |
| Spoofed display domain | `access-accsecurity.com` | `ses.binance.com` |
| Collection point | `sotrecognizd@gmail.com` (mailto) | `https://zzdzw.com/` (credential site) |
| Tracking beacon | `thebandalisty.com/track/…` | — |
| Payload serving IP | — | `38.38.177.142` |
| Page content hash (SHA-256) | — | `7eef3d901005d440c98cb303bc95eb67de05691cab0ec65ecedef10d2b89b42f` |

> Excluded by design: every host above the `*.mail.protection.outlook.com` boundary
> (internal Microsoft relay hops) is the receiving provider's own infrastructure, not
> an indicator. Blocklisting it would mean hunting Microsoft itself.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Phishing (parent) | T1566 | Sample 1 — every clickable element is `mailto:`, not a credential-site link, so the `.002` sub-technique is deliberately *not* applied. |
| Spearphishing Link | T1566.002 | Sample 2 — a genuine `https://` URL leading to attacker-controlled credential-harvesting infrastructure. |
| Obfuscated Files or Information | T1027 | Sample 1 — randomized word-salad content padding engineered to evade spam-filter scoring. |

---

## Hardening recommendations

| Weakness | Control | Who owns it |
|---|---|---|
| SPF/DKIM none, DMARC unenforced | DMARC policy enforcement (`p=quarantine` / `p=reject`) | Receiving org's email-security/admin team |
| Brand impersonation from a new/lookalike domain | Domain-reputation / newly-registered-domain filtering | Email gateway admin |
| Tracking beacon / payload URL | URL & domain blocklisting | Network/gateway admin |
| Compromised legitimate hosting account (Sample 2) | Outbound-anomaly detection on customer accounts | The *hosting provider*, not the recipient org |
| `mailto` social-engineering buttons | User-awareness training | Security-awareness/GRC team |

> **Tier-1 scope, stated honestly:** a Tier-1 SOC analyst doesn't implement these
> directly — that lives with the email-security/admin tier. The Tier-1 job is to
> triage, document IOCs cleanly, and recommend/escalate.

---

## Timeline

| Date (UTC) | Sample | Event |
|---|---|---|
| 2022-07-13 | Sample 2 | `zzdzw.com` first appears in VirusTotal's records (first scan, not registration). |
| 2022-08-22 21:39:41 | Sample 2 | Binance-impersonation email delivered via likely-compromised hosting relay. |
| 2023-09-08 05:47:04 | Sample 1 | Microsoft-impersonation email delivered from `thcultarfdes.co.uk`. |
| 2023-09-08 05:47:06 | Sample 1 | Final delivery to mailbox — ~2 seconds end-to-end transit. |
| 2026-06 | Both | Analysis performed for this lab. |

---

## Repo Structure

```
phishing-email-analysis/
├── README.md
├── LICENSE
├── scripts/
│   └── phishing-triage.ps1
├── iocs/
│   ├── iocs.csv
│   └── iocs.md
└── docs/
    ├── Lab5_Phishing_Reference_Guide.html
    └── Lab5_Phishing_Cheat_Sheet.html
```

---

**Author:** Sean White — [LinkedIn](https://linkedin.com/in/seanwhite56) · [GitHub](https://github.com/UscTrojansDodgers56)
