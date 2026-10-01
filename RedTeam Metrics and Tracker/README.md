# Red Team Detection & Containment Metrics — User Guide

A single-workbook tool for tracking red team activity and measuring two
response metrics against your detection/response SLAs:

- **Time-to-Detection (TTD)** — how long until malicious activity is surfaced to incident responders.
- **Time-to-Containment (TTC)** — how long until the adversary is actually stopped (C2 blocked).

Everything is logged on one sheet; the dashboard recalculates automatically.

---

## The four tabs

| Tab | Purpose |
|---|---|
| **README** | Quick reference (this guide, in-workbook). |
| **Dashboard** | Read-only. KPIs, gap breakdowns, and charts for detection + containment. |
| **Settings** | Your SLA targets, dropdown lists, technique list, and engagement details. Edit the **yellow** cells. |
| **Activity & Event Log** | The single place you log everything. One row per action. |

---

## Color legend

- **Blue text** = an input you type.
- **Grey fill** = a calculated cell — don't edit it.
- **Yellow fill** = a key assumption on Settings you should set.
- **Header bands** on the log: **navy** = identity/detection, **green** = containment, **purple** = operator & deconfliction.

---

## First-time setup (Settings tab)

1. **SLA targets per severity** (yellow): set the *TTD SLA Target*, *Triage Threshold*, and *Containment SLA Target* (all in minutes) for Critical / High / Medium / Low. The shipped values are placeholders — replace them with your SOC's real targets.
2. **Priority threshold** (yellow): the number of misses + SLA breaches per technique that flags it **High** priority on the dashboard (default 2).
3. **Engagements** (yellow): name each engagement. These feed the dropdowns and the engagement trend. Fill in start/end dates, trusted agent / white cell, deconfliction contact, ROE reference, and time zone.
4. **Technique list** (cols O–Q): enter the ATT&CK techniques in scope (ID, name, parent tactic). This powers the Technique drill-down and the Technique ID dropdown on the log.

---

## Daily use (Activity & Event Log tab)

Log **one row per action**. Blue columns are inputs; grey columns calculate themselves.

**A row counts toward the dashboard only when its Severity (column G) is filled.**
That marks it a *measured detection/containment event*. Actions you log only for
deconfliction (recon steps, setup, cleanup) — leave Severity blank and they stay
as log entries without affecting the metrics.

### Column layout

| Columns | Block | What goes here |
|---|---|---|
| A–H | Identity | ID, engagement, tactic, technique, description, target, **Severity**, expected detection source |
| I–L | Detection timestamps | Action Executed (clock start), Telemetry Logged, Alert Generated, Alert Surfaced to IR (clock stop) |
| P–W | Detection calc | Stage latencies, Time-to-Detection, SLA target, within SLA?, Detection Result, Detected? |
| X–Z | Containment timestamps | Containment Action Started, Host Isolated, C2 Blocked (clock stop) |
| AC–AJ | Containment calc | Stage latencies, Time-to-Containment, SLA target, within SLA?, Containment Result, Contained? |
| AK–AU | Operator & deconfliction | Operator, source host/IP, command/procedure, tool/C2, worked?, result, deconfliction status, reported-by, cleanup status/notes, comments |

### Timestamps

Enter as date + time, e.g. `2026-09-14 10:32` (24-hour). All latencies are in minutes.
**Leave a stage's timestamp blank if that stage never happened** — blanks are what
drive the gap classification below.

---

## How the metrics work

### Time-to-Detection

- **Clock starts** when the action is executed (col I). **Clock stops** when an actionable alert is surfaced to IR (col L).
- Split into three stages so you can see where time is lost:
  1. **Telemetry Latency** = Telemetry Logged − Executed
  2. **Alert Generation Latency** = Alert Generated − Telemetry Logged
  3. **Triage Latency** = Alert Surfaced − Alert Generated

**Detection Result (col V):**

| Result | Meaning |
|---|---|
| Telemetry Blind Spot | No telemetry, alert, or surfaced timestamp recorded |
| Missed Alert | Telemetry exists but no alert generated/surfaced |
| Triage Delay | Alert generated but never surfaced, or triage latency over the threshold |
| Detected – SLA Breach | Surfaced, but TTD over the SLA target |
| Detected – Within SLA | Surfaced within the SLA target |

### Time-to-Containment

- **Clock starts** when the alert is surfaced to IR (col L). **Clock stops** when C2 is blocked and the attacker can no longer act (col Z).
- Resilient C2 can survive initial host isolation, so containment isn't complete until C2 is disrupted. Three stages:
  1. **Response Initiation** = Containment Started − Alert Surfaced (workflow efficiency)
  2. **Host Isolation Latency** = Host Isolated − Containment Started
  3. **C2 Disruption Latency** = C2 Blocked − Host Isolated

**Containment Result (col AI)** — maps to the three gap areas (host isolation, C2 disruption, workflow):

| Result | Meaning |
|---|---|
| No Containment Action | Responders never acted (workflow gap) |
| Host Isolation Gap | Action started but host never isolated |
| C2 Persisted | Host isolated but C2 never blocked (the resilient-C2 gap) |
| Contained – SLA Breach | C2 blocked, but over the containment SLA |
| Contained – Within SLA | C2 blocked within the containment SLA |
| N/A – Not Detected | Event never surfaced, so containment can't be measured |

---

## Reading the Dashboard

- **Left band** = Time-to-Detection; **right band** = Time-to-Containment.
- **KPIs**: detection/containment rates, % within SLA, mean / median / 90th percentile / max times, and open gaps.
- **Results breakdowns + pies**: distribution of detection and containment outcomes.
- **Pipeline stages**: average and max minutes at each stage — shows where time is lost.
- **By Tactic / Severity / Detection Source**: where detection is weakest, with color scales.
- **By ATT&CK Technique**: drill-down under each tactic, with a **Top Gap** and a **Priority** flag for detection-engineering backlog.
- **By Engagement**: detection and containment metrics side by side, so you can see response improving over time.

Everything updates as soon as you log rows — no manual refresh.

---

## Before real use

- Replace the placeholder **SLA targets** and **priority threshold** on Settings with your real numbers.
- Fill in the **technique list** and **engagement details** on Settings.
- **Clear the sample rows (5–19)** on the Activity & Event Log — they exist only so the dashboard renders out of the box.
- The log holds up to **500 events** (formulas run through row 504).

## A note on handling

This workbook will hold real operational detail — commands, targets, C2, and
deconfliction contacts. Keep it access-controlled and share it only with the
engagement's authorized stakeholders.
