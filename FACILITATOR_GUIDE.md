# Sentinel Lab facilitator guide and synthetic incident datasets

All times are UTC unless explicitly stated. Names, addresses, identifiers, domains, hostnames, and events below are fictional and must not be used to contact or investigate real systems. These are tabletop datasets, not indicators of real compromise.

## Exercise 1 — Identity compromise and MFA fatigue
**Level:** Foundation | **Duration:** 35–45 minutes | **Roles:** incident lead, identity analyst, communications lead.

### Synthetic evidence pack
| Time (UTC) | Source | Event | Confidence |
|---|---|---|---|
| 05:02 | Identity provider | Successful sign-in for user `samira.k`, Nairobi test tenant | High |
| 05:14 | Identity provider | Successful sign-in for same account, Frankfurt test tenant | High |
| 05:15–05:19 | MFA service | Seven push prompts; user reports none were initiated | High |
| 05:23 | Help desk | User reports password still works; no confirmed export | Medium |
| 05:31 | SaaS audit | New OAuth grant recorded; scope details unavailable in this exercise | Medium |

**Facilitator injects:** At minute 10, the user confirms they approved one prompt accidentally. At minute 20, the OAuth grant is found to be a synthetic calendar integration with read-only scope.

**Expected reasoning:** distinguish impossible-travel signal from proof; correlate MFA events; preserve sign-in and grant records; contain identity access proportionately; revoke suspicious sessions/grants after approval; reset credentials and re-register MFA; assess downstream access; avoid asserting data theft without evidence.

**Debrief:** What facts would change severity? Which evidence has the highest volatility? Who authorizes account containment? What would be communicated to the affected user?

## Exercise 2 — Ransomware response tabletop (no malware)
**Level:** Intermediate | **Duration:** 50–60 minutes | **Roles:** incident commander, endpoint lead, backup lead, business owner.

### Synthetic evidence pack
| Time (UTC) | Source | Event | Confidence |
|---|---|---|---|
| 09:00 | EDR | Unusual burst of file rename operations on `FIN-WS-07.lab.invalid` | High |
| 09:04 | File server | Write volume 9× normal on synthetic finance share | High |
| 09:07 | User report | Finance team cannot open several shared documents | Medium |
| 09:12 | Backup console | Last scheduled backup completed; restore not tested | Medium |
| 09:18 | Network operations | No confirmed lateral movement in available telemetry | Low |

**Facilitator injects:** At minute 15, a second workstation reports similar symptoms. At minute 30, backup team reports the immutable backup copy is outside the affected test segment but restore duration is unknown.

**Expected reasoning:** isolate affected test endpoints using approved controls; preserve volatile telemetry; do not power off or wipe systems without an evidence/recovery decision; scope affected shares and identities; validate backup integrity in an isolated environment; coordinate legal, privacy, and business stakeholders; restore only after containment and clean-state validation.

**Safety:** no malware sample, payload, exploit, encryption routine, or destructive command is included.

## Exercise 3 — Possible sensitive-data exposure
**Level:** Advanced | **Duration:** 45–60 minutes | **Roles:** privacy lead, cloud administrator, incident commander, auditor.

### Synthetic evidence pack
| Time (UTC) | Source | Event | Confidence |
|---|---|---|---|
| Day 1 16:40 | Cloud audit | Contractor creates public-share link for synthetic folder `/training/customer-demo` | High |
| Day 2 07:10 | Access log | 12 external views; identities not retained in exercise | High |
| Day 2 07:22 | DLP | No alert; policy coverage for this repository is unknown | Low |
| Day 2 08:05 | Owner interview | Folder should have been restricted to internal training staff | Medium |
| Day 2 08:30 | Cloud admin | Link disabled; preservation export not yet completed | Medium |

**Facilitator injects:** At minute 15, the owner finds a copy of the synthetic data in a training presentation. At minute 25, the team learns access logs are retained for only 14 days.

**Expected reasoning:** preserve available audit records before expiry; identify data classification and actual contents; scope access without attempting to identify unknown visitors; involve privacy/legal decision owners; distinguish exposure from confirmed acquisition; document notification decisions and remediate sharing defaults.

## Assessment and moderation
Score each dimension 0–4: evidence quality, reasoning, containment, preservation, and remediation. Reviewers must cite specific evidence or missing evidence in feedback. A second independent reviewer is required for inter-rater comparison; score differences greater than one point on any dimension require adjudication. Track agreement by dimension and cohort before making claims about assessment reliability.

## Facilitator preparation
- Assign roles and provide only the opening evidence.
- Reveal injects at the stated time; do not coach learners toward a predetermined conclusion.
- Require a timeline, fact/assumption register, containment decision log, evidence-preservation plan, stakeholder update, and remediation validation plan.
- Debrief uncertainty and decision quality, not merely whether learners guessed the facilitator's preferred answer.
- Never substitute real customer records, real credentials, or live infrastructure for these synthetic materials.
