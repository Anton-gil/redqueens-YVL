#!/usr/bin/env python3
"""Red Queen -- Continuous RWA Security Advisor.

Data-driven advisory generator. Takes a "finding record" (a dict / JSON file
emitted by the rest of the Red Queen pipeline) and renders:

  * ``advisories/<advisory_id>.md``  -- a Markdown advisory
  * ``advisories/<advisory_id>.pdf`` -- a styled PDF (reportlab / Platypus)

Public API
----------
    render_advisory(finding: dict) -> {"md_path": ..., "pdf_path": ...}

CLI
---
    python3 -m advisories.generate_advisory <finding.json>
    python3 -m advisories.generate_advisory            # renders bundled samples

The finding-record schema is the exact contract emitted by the pipeline; see
the two bundled ``SAMPLE_FINDINGS`` at the bottom of this file for worked
examples.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import json
import os
import sys
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
ADVISORY_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- #
# Severity colour palette
# --------------------------------------------------------------------------- #
_SEVERITY_COLORS = {
    "HIGH": colors.HexColor("#C0392B"),      # red / orange
    "CRITICAL": colors.HexColor("#7B241C"),  # deep red
    "MEDIUM": colors.HexColor("#D68910"),    # amber
    "LOW": colors.HexColor("#7F8C8D"),       # gray
    "INFO": colors.HexColor("#5D6D7E"),      # slate
}
_DEFAULT_SEVERITY_COLOR = colors.HexColor("#7F8C8D")

_PASS_GREEN = colors.HexColor("#1E8449")   # blocked bypass = good
_PASS_BG = colors.HexColor("#D5F5E3")
_FAIL_RED = colors.HexColor("#C0392B")     # successful bypass = bad
_FAIL_BG = colors.HexColor("#FADBD8")

_CODE_BG = colors.HexColor("#F4F6F7")
_INK = colors.HexColor("#1B2631")
_MUTED = colors.HexColor("#5D6D7E")
_ACCENT = colors.HexColor("#21618C")

_FOOTER_TEXT = "Red Queen - Continuous RWA Security Advisor"


def _severity_color(severity: str):
    return _SEVERITY_COLORS.get((severity or "").upper(), _DEFAULT_SEVERITY_COLOR)


# --------------------------------------------------------------------------- #
# Small formatting helpers
# --------------------------------------------------------------------------- #
def _fmt_usd(value: Any) -> str:
    try:
        return "${:,.0f}".format(float(value))
    except (TypeError, ValueError):
        return str(value)


def _fmt_num(value: Any) -> str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return "{:,}".format(value)
    if isinstance(value, float):
        # Keep small thresholds readable without noise.
        text = ("{:.6f}".format(value)).rstrip("0").rstrip(".")
        return text if text else "0"
    return str(value)


def _bool_badge(value: Any) -> str:
    return "yes" if value else "no"


# --------------------------------------------------------------------------- #
# Markdown rendering
# --------------------------------------------------------------------------- #
def render_markdown(finding: Dict[str, Any]) -> str:
    """Render the finding record to a Markdown advisory string (8 sections)."""
    lines: List[str] = []
    sev = str(finding.get("severity", "UNKNOWN")).upper()
    adv_id = finding.get("advisory_id", "RQ-UNKNOWN")

    # Title block
    lines.append(f"# Security Advisory {adv_id}")
    lines.append("")
    lines.append(f"**Severity:** {sev}  ")
    lines.append(f"**Category:** {finding.get('category', 'N/A')}  ")
    lines.append(f"**Target:** {finding.get('target', 'N/A')}"
                 f" ({finding.get('vuln_ref', 'N/A')})  ")
    lines.append(f"**Reference Pattern:** {finding.get('reference_pattern', 'N/A')}  ")
    impact = _fmt_usd(finding.get("impact_usd"))
    lines.append(f"**Impact:** {impact} - {finding.get('impact_label', 'N/A')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 1. Exploit Summary
    lines.append("## 1. Exploit Summary")
    lines.append("")
    lines.append(finding.get("exploit_summary", "_No summary provided._"))
    lines.append("")

    # 1a. Economics (rendered only when the pipeline supplied an economics block)
    econ = finding.get("economics") or {}
    if econ:
        lines.append("## Economics")
        lines.append("")
        lines.append("| Parameter | Value |")
        lines.append("| --- | --- |")
        if "pool_balance_before" in econ:
            lines.append(f"| Pool balance before | {_fmt_num(econ.get('pool_balance_before'))} |")
        if "donation" in econ:
            lines.append(f"| Donation | {_fmt_num(econ.get('donation'))} |")
        if "deposit" in econ:
            lines.append(f"| Deposit | {_fmt_num(econ.get('deposit'))} |")
        if "minted_usd" in econ:
            lines.append(f"| rwaUSD minted | {_fmt_usd(econ.get('minted_usd'))} |")
        if "attacker_cost_usd" in econ:
            lines.append(f"| Attacker cost | {_fmt_usd(econ.get('attacker_cost_usd'))} |")
        if "attacker_net_usd" in econ:
            lines.append(f"| Attacker net | {_fmt_usd(econ.get('attacker_net_usd'))} |")
        if "roi" in econ:
            lines.append(f"| ROI | {_fmt_num(econ.get('roi'))} |")
        if "bad_debt_usd" in econ:
            lines.append(f"| Protocol bad debt | {_fmt_usd(econ.get('bad_debt_usd'))} |")
        if "profitable" in econ:
            lines.append(f"| Profitable for attacker | {_bool_badge(econ.get('profitable'))} |")
        lines.append("")
        if econ.get("profit_condition"):
            lines.append(f"**Profit condition:** {econ.get('profit_condition')}")
            lines.append("")
        irr = econ.get("irrational_reference") or {}
        if irr:
            lines.append(
                "_Honesty note — the naive PoC is irrational:_ donation "
                f"{_fmt_num(irr.get('donation'))}, deposit {_fmt_num(irr.get('deposit'))} "
                f"nets the attacker {_fmt_usd(irr.get('attacker_net_usd'))} (a loss). "
                "The figures above use rational parameters."
            )
            lines.append("")

    # 2. Reproducible PoC
    lines.append("## 2. Reproducible Proof-of-Concept")
    lines.append("")
    lines.append("```solidity")
    lines.append(finding.get("poc_solidity", "// no PoC provided").rstrip("\n"))
    lines.append("```")
    lines.append("")

    # 3. Candidate Guard
    guard = finding.get("candidate_guard", {}) or {}
    lines.append("## 3. Candidate Guard")
    lines.append("")
    lines.append(f"**Invariant:** `{guard.get('invariant', 'N/A')}`")
    lines.append("")
    gas_measured = guard.get("gas_measured")
    gas_label = "measured" if gas_measured else "estimated"
    lines.append(f"**Gas overhead ({gas_label}):** {guard.get('gas_overhead', 'N/A')}")
    lines.append("")
    lines.append("**Guard implementation:**")
    lines.append("")
    lines.append("```solidity")
    lines.append(guard.get("solidity", "// no guard provided").rstrip("\n"))
    lines.append("```")
    lines.append("")

    # 4. Validation Report
    vr = finding.get("validation_report", {}) or {}
    lines.append("## 4. Validation Report")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Corpus size | {_fmt_num(vr.get('corpus_size', 'N/A'))} |")
    lines.append(f"| Violations in corpus | {_fmt_num(vr.get('violations_in_corpus', 'N/A'))} |")
    lines.append(f"| Max observed value | {_fmt_num(vr.get('max_observed_value', 'N/A'))} |")
    lines.append(f"| Threshold | {_fmt_num(vr.get('threshold', 'N/A'))} |")
    lines.append(f"| Margin ratio | {_fmt_num(vr.get('margin_ratio', 'N/A'))}x |")
    lines.append(f"| Validation confidence | {vr.get('validation_confidence', 'N/A')} |")
    lines.append("")
    warnings = vr.get("coverage_warnings", []) or []
    if warnings:
        lines.append("**Coverage warnings:**")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    # 5. Bypass Resistance
    br = finding.get("bypass_resistance", {}) or {}
    lines.append("## 5. Bypass Resistance")
    lines.append("")
    lines.append(f"**Resistance score:** {br.get('resistance_score', 'N/A')}")
    lines.append("")
    lines.append("| Strategy | Result | Detail |")
    lines.append("| --- | --- | --- |")
    for att in br.get("attempts", []) or []:
        # A successful bypass is BAD news -> flag it honestly.
        blocked = not att.get("success")
        result = "BLOCKED" if blocked else "BYPASSED"
        detail = att.get("reason", "")
        mit = att.get("mitigation_required")
        if mit:
            detail = f"{detail} (mitigation: {mit})"
        method = str(att.get("method", "")).replace("|", "\\|")
        detail = str(detail).replace("|", "\\|")
        lines.append(f"| `{method}` | {result} | {detail} |")
    lines.append("")

    # 5a. Guard History (v1 -> v2) -- rendered only when supplied
    history = finding.get("guard_history") or {}
    if history:
        lines.append("## Guard History (v1 -> v2)")
        lines.append("")
        lines.append("| Version | Guard class | Scope | Re-attack reverts | Bypasses | Note |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        # Accept either an ordered list or a {v1:..., v2:...} mapping.
        if isinstance(history, dict):
            items = [history[k] for k in sorted(history.keys()) if isinstance(history[k], dict)]
        else:
            items = [h for h in history if isinstance(h, dict)]
        for h in items:
            ver = str(h.get("version", "N/A"))
            gclass = str(h.get("guard_class", "N/A")).replace("|", "\\|")
            scope = str(h.get("scope", "N/A"))
            rev = _bool_badge(h.get("reattack_reverts"))
            nby = _fmt_num(h.get("n_bypassed", "N/A"))
            note = str(h.get("note", "")).replace("|", "\\|")
            lines.append(f"| {ver} | `{gclass}` | {scope} | {rev} | {nby} | {note} |")
        lines.append("")

    # 5b. Residual Risks -- rendered only when supplied
    residuals = finding.get("residual_risks") or []
    if residuals:
        lines.append("## Residual Risks")
        lines.append("")
        for r in residuals:
            if isinstance(r, dict):
                name = r.get("name", "risk")
                mx = r.get("max_extractable_usd")
                note = r.get("note", "")
                mx_str = f" (max extractable: {_fmt_usd(mx)})" if mx is not None else ""
                lines.append(f"- **{name}**{mx_str}: {note}")
            else:
                lines.append(f"- {r}")
        lines.append("")

    # 6. Recommended Actions
    lines.append("## 6. Recommended Actions")
    lines.append("")
    for act in finding.get("recommended_actions", []) or []:
        prio = act.get("priority", "Action")
        gov = act.get("governance")
        gov_str = f" _(governance: {gov})_" if gov else ""
        lines.append(f"- **{prio}:** {act.get('action', '')}{gov_str}")
    lines.append("")

    # 7. Governance Path (matches Multipli's emergency-role / timelock model)
    gp = finding.get("governance_path", {}) or {}
    lines.append("## 7. Governance Path")
    lines.append("")
    lines.append(f"- **Emergency-role compatible:** {_bool_badge(gp.get('emergency_role_compatible'))}")
    lines.append(f"- **Timelock required:** {_bool_badge(gp.get('timelock_required'))}")
    lines.append(f"- **Full vote required for:** {gp.get('full_vote_required_for', 'N/A')}")
    # Immediate mitigation = tighten-only via the emergency role (no timelock).
    imm = gp.get("immediate_mitigation") or (
        "Emergency role, tighten-only: switch to a conservative pause profile and "
        "cut the mint cap. No parameter is loosened, so no timelock is required."
    )
    lines.append(f"- **Immediate mitigation (emergency role, tighten-only):** {imm}")
    # Permanent fix = code change through the governance timelock.
    perm = gp.get("permanent_fix") or (
        "Deploy the guard as a code change through the standard governance timelock."
    )
    lines.append(f"- **Permanent fix (governance timelock):** {perm}")
    # Root-cause recommendation: fix the valuation formula alongside the guard.
    root = gp.get("root_cause_fix") or (
        "Recommended alongside the guard: fix the valuation formula itself so credited "
        "value is computed as shares x price-per-share (or tokensIn x independent unit price), "
        "removing dependence on the manipulable pool-derived rate."
    )
    lines.append(f"- **Root-cause fix (recommended):** {root}")
    lines.append("")

    # 8. Footer / provenance
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    lines.append("## 8. Provenance")
    lines.append("")
    lines.append(f"Generated {ts} by {_FOOTER_TEXT}.")
    lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# PDF rendering
# --------------------------------------------------------------------------- #
def _styles():
    ss = getSampleStyleSheet()
    styles = {}
    styles["title"] = ParagraphStyle(
        "RQTitle", parent=ss["Title"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=_INK, spaceAfter=2,
    )
    styles["subtitle"] = ParagraphStyle(
        "RQSubtitle", parent=ss["Normal"], fontName="Helvetica",
        fontSize=10, leading=14, textColor=_MUTED, spaceAfter=2,
    )
    styles["h2"] = ParagraphStyle(
        "RQH2", parent=ss["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=_ACCENT, spaceBefore=14, spaceAfter=6,
    )
    styles["body"] = ParagraphStyle(
        "RQBody", parent=ss["Normal"], fontName="Helvetica",
        fontSize=9.5, leading=13, textColor=_INK, spaceAfter=4,
    )
    styles["meta"] = ParagraphStyle(
        "RQMeta", parent=ss["Normal"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=_INK,
    )
    styles["cell"] = ParagraphStyle(
        "RQCell", parent=ss["Normal"], fontName="Helvetica",
        fontSize=8.5, leading=11, textColor=_INK,
    )
    styles["cell_bold"] = ParagraphStyle(
        "RQCellBold", parent=ss["Normal"], fontName="Helvetica-Bold",
        fontSize=8.5, leading=11, textColor=_INK,
    )
    styles["code"] = ParagraphStyle(
        "RQCode", parent=ss["Code"], fontName="Courier",
        fontSize=6.3, leading=7.6, textColor=_INK,
        backColor=_CODE_BG, leftIndent=4, rightIndent=4,
        borderPadding=(5, 5, 5, 5), spaceBefore=2, spaceAfter=2,
    )
    styles["badge"] = ParagraphStyle(
        "RQBadge", parent=ss["Normal"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=colors.white, alignment=TA_CENTER,
    )
    styles["footer"] = ParagraphStyle(
        "RQFooter", parent=ss["Normal"], fontName="Helvetica",
        fontSize=7.5, leading=9, textColor=_MUTED, alignment=TA_CENTER,
    )
    return styles


def _wrap_code(text: str, width: int = 95) -> str:
    """Hard-wrap long code lines so a monospaced block never overflows the page.

    Preserves indentation on continuation lines and expands tabs.
    """
    out_lines: List[str] = []
    for raw in (text or "").rstrip("\n").split("\n"):
        line = raw.replace("\t", "    ")
        if len(line) <= width:
            out_lines.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        cont_pad = " " * min(indent + 4, width - 10)
        first = True
        remaining = line
        while len(remaining) > width:
            out_lines.append(remaining[:width])
            remaining = (cont_pad + remaining[width:].lstrip(" "))
            first = False
        out_lines.append(remaining)
        _ = first
    return "\n".join(out_lines)


def _para(text: str, style) -> Paragraph:
    return Paragraph(_html.escape(str(text)), style)


def _severity_badge_table(adv_id: str, severity: str, styles) -> Table:
    """Title-block row: advisory id on the left, colour-coded severity badge."""
    sev = (severity or "UNKNOWN").upper()
    badge = Table(
        [[Paragraph(sev, styles["badge"])]],
        colWidths=[1.4 * inch],
        rowHeights=[0.42 * inch],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _severity_color(sev)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))

    left = Paragraph(
        f'<font color="#1B2631"><b>Security Advisory</b></font><br/>'
        f'<font size="15" color="#1B2631"><b>{_html.escape(adv_id)}</b></font>',
        styles["subtitle"],
    )
    row = Table([[left, badge]], colWidths=[4.7 * inch, 1.6 * inch])
    row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return row


def _meta_table(finding: Dict[str, Any], styles) -> Table:
    rows = [
        ["Category", finding.get("category", "N/A")],
        ["Target", f"{finding.get('target', 'N/A')} ({finding.get('vuln_ref', 'N/A')})"],
        ["Reference Pattern", finding.get("reference_pattern", "N/A")],
        ["Impact",
         f"{_fmt_usd(finding.get('impact_usd'))} - {finding.get('impact_label', 'N/A')}"],
    ]
    data = [[_para(k, styles["cell_bold"]), _para(v, styles["cell"])] for k, v in rows]
    t = Table(data, colWidths=[1.5 * inch, 4.8 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EBF0F3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _code_flowable(text: str, styles) -> Preformatted:
    wrapped = _wrap_code(text)
    return Preformatted(wrapped, styles["code"])


def _validation_table(vr: Dict[str, Any], styles) -> Table:
    rows = [
        ("Corpus size", _fmt_num(vr.get("corpus_size", "N/A"))),
        ("Violations in corpus", _fmt_num(vr.get("violations_in_corpus", "N/A"))),
        ("Max observed value", _fmt_num(vr.get("max_observed_value", "N/A"))),
        ("Threshold", _fmt_num(vr.get("threshold", "N/A"))),
        ("Margin ratio", f"{_fmt_num(vr.get('margin_ratio', 'N/A'))}x"),
        ("Validation confidence", str(vr.get("validation_confidence", "N/A"))),
    ]
    data = [[_para("Metric", styles["cell_bold"]), _para("Value", styles["cell_bold"])]]
    for k, v in rows:
        data.append([_para(k, styles["cell"]), _para(v, styles["cell"])])
    t = Table(data, colWidths=[2.6 * inch, 3.7 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F4F6F7")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    # Header cells must be white on accent (override the Paragraph ink colour).
    data[0][0] = Paragraph('<font color="white"><b>Metric</b></font>', styles["cell"])
    data[0][1] = Paragraph('<font color="white"><b>Value</b></font>', styles["cell"])
    return t


def _bypass_table(br: Dict[str, Any], styles) -> Table:
    header = [
        Paragraph('<font color="white"><b>Strategy</b></font>', styles["cell"]),
        Paragraph('<font color="white"><b>Result</b></font>', styles["cell"]),
        Paragraph('<font color="white"><b>Detail</b></font>', styles["cell"]),
    ]
    data = [header]
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]
    attempts = br.get("attempts", []) or []
    for i, att in enumerate(attempts, start=1):
        blocked = not att.get("success")
        result = "BLOCKED" if blocked else "BYPASSED"
        detail = str(att.get("reason", ""))
        mit = att.get("mitigation_required")
        if mit:
            detail = f"{detail}  [mitigation: {mit}]"
        data.append([
            _para(att.get("method", ""), styles["cell"]),
            _para(result, styles["cell_bold"]),
            _para(detail, styles["cell"]),
        ])
        # Colour the result cell: blocked=green (good), bypassed=red (bad).
        cell_bg = _PASS_BG if blocked else _FAIL_BG
        cell_fg = _PASS_GREEN if blocked else _FAIL_RED
        style_cmds.append(("BACKGROUND", (1, i), (1, i), cell_bg))
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), cell_fg))
    t = Table(data, colWidths=[2.1 * inch, 1.0 * inch, 3.2 * inch])
    t.setStyle(TableStyle(style_cmds))
    return t


def _footer(canvas, doc):
    canvas.saveState()
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(_MUTED)
    canvas.setStrokeColor(colors.HexColor("#D5DBDB"))
    canvas.line(0.75 * inch, 0.62 * inch, LETTER[0] - 0.75 * inch, 0.62 * inch)
    canvas.drawString(0.75 * inch, 0.45 * inch, f"Generated {ts}")
    canvas.drawCentredString(LETTER[0] / 2.0, 0.45 * inch, _FOOTER_TEXT)
    canvas.drawRightString(
        LETTER[0] - 0.75 * inch, 0.45 * inch, f"Page {doc.page}"
    )
    canvas.restoreState()


def render_pdf(finding: Dict[str, Any], pdf_path: str) -> str:
    """Render the finding record to a styled PDF at ``pdf_path``."""
    styles = _styles()
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.8 * inch,
        title=f"Security Advisory {finding.get('advisory_id', '')}",
        author=_FOOTER_TEXT,
    )
    story: List[Any] = []

    adv_id = finding.get("advisory_id", "RQ-UNKNOWN")
    sev = str(finding.get("severity", "UNKNOWN")).upper()

    # --- Title block -----------------------------------------------------
    story.append(_severity_badge_table(adv_id, sev, styles))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.2,
                            color=_severity_color(sev), spaceAfter=8))
    story.append(_meta_table(finding, styles))

    # --- 1. Exploit Summary ---------------------------------------------
    story.append(_para("1. Exploit Summary", styles["h2"]))
    story.append(_para(finding.get("exploit_summary", "No summary provided."),
                       styles["body"]))

    # --- 1a. Economics (only when supplied) -----------------------------
    econ = finding.get("economics") or {}
    if econ:
        story.append(_para("Economics", styles["h2"]))
        econ_rows: List[Any] = []
        _maybe = [
            ("Pool balance before", "pool_balance_before", _fmt_num),
            ("Donation", "donation", _fmt_num),
            ("Deposit", "deposit", _fmt_num),
            ("rwaUSD minted", "minted_usd", _fmt_usd),
            ("Attacker cost", "attacker_cost_usd", _fmt_usd),
            ("Attacker net", "attacker_net_usd", _fmt_usd),
            ("ROI", "roi", _fmt_num),
            ("Protocol bad debt", "bad_debt_usd", _fmt_usd),
        ]
        for label, key, fmt in _maybe:
            if key in econ:
                econ_rows.append((label, fmt(econ.get(key))))
        if "profitable" in econ:
            econ_rows.append(("Profitable for attacker", _bool_badge(econ.get("profitable"))))
        if econ_rows:
            edata = [[_para(k, styles["cell_bold"]), _para(v, styles["cell"])]
                     for k, v in econ_rows]
            etable = Table(edata, colWidths=[2.6 * inch, 3.7 * inch])
            etable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EBF0F3")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(etable)
        if econ.get("profit_condition"):
            story.append(Spacer(1, 2))
            story.append(Paragraph(
                f'<b>Profit condition:</b> {_html.escape(str(econ.get("profit_condition")))}',
                styles["body"],
            ))
        irr = econ.get("irrational_reference") or {}
        if irr:
            story.append(Paragraph(
                "<i>Honesty note - the naive PoC is irrational:</i> donation "
                f"{_html.escape(_fmt_num(irr.get('donation')))}, deposit "
                f"{_html.escape(_fmt_num(irr.get('deposit')))} nets the attacker "
                f"{_html.escape(_fmt_usd(irr.get('attacker_net_usd')))} (a loss). "
                "The figures above use rational parameters.",
                styles["body"],
            ))

    # --- 2. Reproducible PoC --------------------------------------------
    story.append(_para("2. Reproducible Proof-of-Concept", styles["h2"]))
    story.append(_code_flowable(finding.get("poc_solidity", "// no PoC provided"),
                                styles))

    # --- 3. Candidate Guard ---------------------------------------------
    guard = finding.get("candidate_guard", {}) or {}
    story.append(_para("3. Candidate Guard", styles["h2"]))
    gas_label = "measured" if guard.get("gas_measured") else "estimated"
    story.append(Paragraph(
        f'<b>Invariant:</b> <font face="Courier">'
        f'{_html.escape(str(guard.get("invariant", "N/A")))}</font><br/>'
        f'<b>Gas overhead ({gas_label}):</b> '
        f'{_html.escape(str(guard.get("gas_overhead", "N/A")))}',
        styles["body"],
    ))
    story.append(Spacer(1, 2))
    story.append(_code_flowable(guard.get("solidity", "// no guard provided"),
                               styles))

    # --- 4. Validation Report -------------------------------------------
    vr = finding.get("validation_report", {}) or {}
    story.append(_para("4. Validation Report", styles["h2"]))
    story.append(_validation_table(vr, styles))
    warnings = vr.get("coverage_warnings", []) or []
    if warnings:
        story.append(Spacer(1, 4))
        story.append(_para("Coverage warnings:", styles["cell_bold"]))
        for w in warnings:
            story.append(Paragraph(f"&bull; {_html.escape(str(w))}", styles["body"]))

    # --- 5. Bypass Resistance -------------------------------------------
    br = finding.get("bypass_resistance", {}) or {}
    story.append(_para("5. Bypass Resistance", styles["h2"]))
    story.append(Paragraph(
        f'<b>Resistance score:</b> '
        f'{_html.escape(str(br.get("resistance_score", "N/A")))}',
        styles["body"],
    ))
    story.append(Spacer(1, 2))
    story.append(_bypass_table(br, styles))

    # --- 5a. Guard History (v1 -> v2), only when supplied ---------------
    history = finding.get("guard_history") or {}
    if history:
        story.append(_para("Guard History (v1 -> v2)", styles["h2"]))
        if isinstance(history, dict):
            items = [history[k] for k in sorted(history.keys()) if isinstance(history[k], dict)]
        else:
            items = [h for h in history if isinstance(h, dict)]
        hheader = [
            Paragraph('<font color="white"><b>Version</b></font>', styles["cell"]),
            Paragraph('<font color="white"><b>Guard class</b></font>', styles["cell"]),
            Paragraph('<font color="white"><b>Scope</b></font>', styles["cell"]),
            Paragraph('<font color="white"><b>Reverts</b></font>', styles["cell"]),
            Paragraph('<font color="white"><b>Bypasses</b></font>', styles["cell"]),
        ]
        hdata = [hheader]
        for h in items:
            hdata.append([
                _para(h.get("version", "N/A"), styles["cell"]),
                _para(h.get("guard_class", "N/A"), styles["cell"]),
                _para(h.get("scope", "N/A"), styles["cell"]),
                _para(_bool_badge(h.get("reattack_reverts")), styles["cell"]),
                _para(_fmt_num(h.get("n_bypassed", "N/A")), styles["cell"]),
            ])
        htable = Table(hdata, colWidths=[0.8 * inch, 2.5 * inch, 1.2 * inch,
                                         0.9 * inch, 0.9 * inch])
        htable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F4F6F7")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(htable)
        for h in items:
            if h.get("note"):
                story.append(Paragraph(
                    f'<b>{_html.escape(str(h.get("version", "")))}:</b> '
                    f'{_html.escape(str(h.get("note")))}', styles["body"]))

    # --- 5b. Residual Risks, only when supplied -------------------------
    residuals = finding.get("residual_risks") or []
    if residuals:
        story.append(_para("Residual Risks", styles["h2"]))
        for r in residuals:
            if isinstance(r, dict):
                name = _html.escape(str(r.get("name", "risk")))
                note = _html.escape(str(r.get("note", "")))
                mx = r.get("max_extractable_usd")
                mx_str = (f" <font color='#5D6D7E'>(max extractable: "
                          f"{_html.escape(_fmt_usd(mx))})</font>") if mx is not None else ""
                story.append(Paragraph(f"&bull; <b>{name}</b>{mx_str}: {note}", styles["body"]))
            else:
                story.append(Paragraph(f"&bull; {_html.escape(str(r))}", styles["body"]))

    # --- 6. Recommended Actions -----------------------------------------
    story.append(_para("6. Recommended Actions", styles["h2"]))
    for act in finding.get("recommended_actions", []) or []:
        prio = _html.escape(str(act.get("priority", "Action")))
        action = _html.escape(str(act.get("action", "")))
        gov = act.get("governance")
        gov_str = (f' <font color="#5D6D7E"><i>(governance: '
                   f'{_html.escape(str(gov))})</i></font>') if gov else ""
        story.append(Paragraph(f"<b>{prio}:</b> {action}{gov_str}", styles["body"]))

    # --- 7. Governance Path ---------------------------------------------
    gp = finding.get("governance_path", {}) or {}
    story.append(_para("7. Governance Path", styles["h2"]))
    _imm = gp.get("immediate_mitigation") or (
        "Emergency role, tighten-only: conservative pause profile + cut mint cap. "
        "Nothing loosened, so no timelock required."
    )
    _perm = gp.get("permanent_fix") or (
        "Deploy the guard as a code change through the standard governance timelock."
    )
    _root = gp.get("root_cause_fix") or (
        "Recommended alongside the guard: fix the valuation formula so credited value is "
        "shares x price-per-share (or tokensIn x independent unit price), removing the "
        "dependence on the manipulable pool-derived rate."
    )
    gov_rows = [
        ("Emergency-role compatible", _bool_badge(gp.get("emergency_role_compatible"))),
        ("Timelock required", _bool_badge(gp.get("timelock_required"))),
        ("Full vote required for", str(gp.get("full_vote_required_for", "N/A"))),
        ("Immediate mitigation (tighten-only)", str(_imm)),
        ("Permanent fix (timelock)", str(_perm)),
        ("Root-cause fix (recommended)", str(_root)),
    ]
    gdata = [[_para(k, styles["cell_bold"]), _para(v, styles["cell"])]
             for k, v in gov_rows]
    gtable = Table(gdata, colWidths=[2.6 * inch, 3.7 * inch])
    gtable.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EBF0F3")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(gtable)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return pdf_path


# --------------------------------------------------------------------------- #
# Top-level render
# --------------------------------------------------------------------------- #
def render_advisory(finding: Dict[str, Any], out_dir: str = ADVISORY_DIR) -> Dict[str, str]:
    """Render ``finding`` to Markdown + PDF; return the two output paths."""
    if not isinstance(finding, dict):
        raise TypeError("finding must be a dict")
    adv_id = str(finding.get("advisory_id") or "RQ-UNKNOWN")
    os.makedirs(out_dir, exist_ok=True)

    md_path = os.path.join(out_dir, f"{adv_id}.md")
    pdf_path = os.path.join(out_dir, f"{adv_id}.pdf")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(finding))

    render_pdf(finding, pdf_path)

    return {"md_path": md_path, "pdf_path": pdf_path}


# --------------------------------------------------------------------------- #
# Bundled sample findings (for standalone demo)
# --------------------------------------------------------------------------- #
_POC_A = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GoldAdapter} from "../src/adapters/GoldAdapter.sol";
import {RwaUSD} from "../src/RwaUSD.sol";
import {MockGold} from "../test/mocks/MockGold.sol";

/// @notice Vuln A -- adapter donation / exchange-rate inflation.
/// A direct token transfer into the pool inflates exchangeRate() without
/// minting shares; a subsequent small deposit is credited at the inflated
/// rate and mints unbacked rwaUSD.
contract GoldAdapterDonationTest is Test {
    GoldAdapter adapter;
    RwaUSD rwaUSD;
    MockGold gold;
    address attacker = address(0xA11CE);

    function setUp() public {
        gold = new MockGold();
        rwaUSD = new RwaUSD();
        adapter = new GoldAdapter(address(gold), address(rwaUSD));
        gold.mint(attacker, 1_000_000e18);
    }

    function test_donation_inflates_rate_and_mints_unbacked() public {
        vm.startPrank(attacker);
        uint256 rateBefore = adapter.exchangeRate();

        // 1. Donate directly to the pool -- no shares minted.
        gold.transfer(address(adapter.pool()), 999_000e18);
        uint256 rateAfter = adapter.exchangeRate();
        assertGt(rateAfter, rateBefore * 10, "rate should spike >10x");

        // 2. Small deposit captured at the inflated rate.
        gold.approve(address(adapter), 1_000e18);
        uint256 shares = adapter.deposit(1_000e18);

        // 3. Mint rwaUSD against the inflated principal.
        uint256 minted = adapter.mint(shares);
        emit log_named_uint("unbacked rwaUSD minted", minted);
        assertGt(minted, 45_000e18, "attacker mints far above fair value");
        vm.stopPrank();
    }
}
"""

_GUARD_A = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ExchangeRateDeltaBound
/// @notice Post-condition guard: reverts if exchangeRate() moves more than
/// `maxDeltaBps` within a single block. Tighten-only, emergency-role settable.
abstract contract ExchangeRateDeltaBound {
    uint256 public immutable maxDeltaBps; // e.g. 100 = 1.00%
    uint256 private _lastRate;
    uint256 private _lastBlock;

    error RateDeltaExceeded(uint256 prev, uint256 next, uint256 bps);

    constructor(uint256 _maxDeltaBps) {
        maxDeltaBps = _maxDeltaBps;
    }

    function _currentRate() internal view virtual returns (uint256);

    modifier boundRateDelta() {
        uint256 before = _currentRate();
        _;
        uint256 nowRate = _currentRate();
        if (_lastBlock == block.number && _lastRate != 0) {
            uint256 hi = nowRate > _lastRate ? nowRate : _lastRate;
            uint256 lo = nowRate > _lastRate ? _lastRate : nowRate;
            uint256 deltaBps = ((hi - lo) * 10_000) / lo;
            if (deltaBps > maxDeltaBps) {
                revert RateDeltaExceeded(_lastRate, nowRate, deltaBps);
            }
        }
        _lastRate = nowRate;
        _lastBlock = block.number;
        // silence unused warning on `before`
        before;
    }
}
"""

_POC_C = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AccountManager} from "../src/AccountManager.sol";
import {GoldAdapter} from "../src/adapters/GoldAdapter.sol";
import {MockGold} from "../test/mocks/MockGold.sol";

/// @notice Vuln C -- stale oracle read across a multicall.
/// depositAndMint() reads the price ONCE and reuses it for both the
/// share-calculation and the principal valuation. Moving the rate before
/// the single read lets share-calc and principal disagree.
contract StaleMulticallTest is Test {
    AccountManager mgr;
    GoldAdapter adapter;
    MockGold gold;
    address attacker = address(0xBEEF);

    function setUp() public {
        gold = new MockGold();
        adapter = new GoldAdapter(address(gold), address(0));
        mgr = new AccountManager(address(adapter));
        gold.mint(attacker, 1_000_000e18);
    }

    function test_single_read_feeds_two_operations() public {
        vm.startPrank(attacker);

        // Move the rate immediately before the single cached read.
        gold.transfer(address(adapter.pool()), 999_000e18);

        gold.approve(address(mgr), 1_000e18);
        // One price read feeds BOTH share-calc and principal valuation.
        uint256 minted = mgr.depositAndMint(1_000e18);

        uint256 fair = adapter.fairValue(1_000e18);
        emit log_named_uint("minted", minted);
        emit log_named_uint("fair", fair);
        assertGt(minted, fair * 10, "minted exceeds post-deposit fair value");
        vm.stopPrank();
    }
}
"""

_GUARD_C = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AdapterConversionIntegrity
/// @notice Guard for the multicall boundary: re-reads the conversion rate
/// AFTER each state-changing sub-operation and requires that the value used
/// for minting matches the freshly-read conversion within `maxDeltaBps`.
abstract contract AdapterConversionIntegrity {
    uint256 public immutable maxDeltaBps; // e.g. 100 = 1.00%

    error ConversionDrift(uint256 usedRate, uint256 freshRate, uint256 bps);

    constructor(uint256 _maxDeltaBps) {
        maxDeltaBps = _maxDeltaBps;
    }

    function _conversionRate() internal view virtual returns (uint256);

    /// @dev Call at the END of depositAndMint() with the rate the mint used.
    function _assertConversionFresh(uint256 usedRate) internal view {
        uint256 fresh = _conversionRate();
        uint256 hi = fresh > usedRate ? fresh : usedRate;
        uint256 lo = fresh > usedRate ? usedRate : fresh;
        require(lo != 0, "zero rate");
        uint256 deltaBps = ((hi - lo) * 10_000) / lo;
        if (deltaBps > maxDeltaBps) {
            revert ConversionDrift(usedRate, fresh, deltaBps);
        }
    }
}
"""


SAMPLE_FINDINGS: List[Dict[str, Any]] = [
    {
        "advisory_id": "RQ-2026-0001",
        "severity": "HIGH",
        "category": "Adapter Conversion Integrity",
        "reference_pattern": "Edel Finance, July 2026 ($403K loss)",
        "target": "GoldAdapter",
        "vuln_ref": "Vuln A",
        "exploit_summary": (
            "GoldAdapter.exchangeRate() derives the price from the raw pool "
            "balance, so a direct token transfer into the pool inflates the "
            "rate without minting shares. A subsequent small deposit is "
            "credited at the inflated rate and mints rwaUSD far in excess of "
            "the collateral's fair value, leaving the protocol holding "
            "unbacked debt."
        ),
        "impact_usd": 46000,
        "impact_label": "unbacked rwaUSD minted (protocol bad debt)",
        "poc_solidity": _POC_A,
        "candidate_guard": {
            "invariant": "ExchangeRateDeltaBound(GoldAdapter, 100 bps, 1 block)",
            "solidity": _GUARD_A,
            "gas_overhead": "8,234 gas per deposit (+2.1%)",
            "gas_measured": True,
        },
        "validation_report": {
            "corpus_size": 2000,
            "violations_in_corpus": 0,
            "max_observed_value": 0.0008,
            "threshold": 0.01,
            "margin_ratio": 12.5,
            "coverage_warnings": [
                "No deposits > $1M in corpus - threshold should get manual "
                "review for large deposits",
                "Exchange rate never moves under benign activity - threshold "
                "is a floor, not a fitted bound",
            ],
            "validation_confidence": "HIGH within covered scenarios",
        },
        "bypass_resistance": {
            "attempts": [
                {"method": "split_into_10_subtransactions", "success": False,
                 "reason": "per-block invariant catches accumulated delta"},
                {"method": "spread_across_20_blocks", "success": False,
                 "reason": "windowed checkpoint still bounds cumulative delta"},
                {"method": "use_multicall_path", "success": True,
                 "reason": "depositAndMint bypasses the per-function guard on deposit()",
                 "mitigation_required": "add invariant at the multicall boundary"},
                {"method": "gas_variance", "success": False,
                 "reason": "guard is state-based, not gas-based; N/A"},
            ],
            "resistance_score": "MEDIUM - requires layered defense",
        },
        "recommended_actions": [
            {"priority": "Immediate",
             "action": "Deploy as a post-condition on GoldAdapter.deposit() - "
                       "emergency-role compatible, tighten-only, no governance vote",
             "governance": "emergency-role"},
            {"priority": "Follow-up",
             "action": "Add a layered guard at the AccountManager.depositAndMint() "
                       "multicall boundary - closes the alternate-path bypass",
             "governance": "full-vote"},
        ],
        "governance_path": {
            "emergency_role_compatible": True,
            "timelock_required": False,
            "full_vote_required_for": "follow-up multicall-boundary guard only",
        },
    },
    {
        "advisory_id": "RQ-2026-0002",
        "severity": "HIGH",
        "category": "Stale Oracle Read (Multicall)",
        "reference_pattern": "Generic stale-read pattern (RWA multicall class)",
        "target": "GoldAdapter",
        "vuln_ref": "Vuln C",
        "exploit_summary": (
            "AccountManager.depositAndMint() reads the GoldAdapter conversion "
            "rate exactly once and reuses that cached value for both the "
            "share calculation and the principal valuation. An attacker moves "
            "the rate (via a direct pool donation) immediately before the "
            "single read, so the deposit is sized against one price while "
            "rwaUSD is minted against a stale, more favourable price - minting "
            "value well above the collateral's post-deposit fair value."
        ),
        "impact_usd": 46000,
        "impact_label": "over-minted rwaUSD from a stale cached price",
        "poc_solidity": _POC_C,
        "candidate_guard": {
            "invariant": "AdapterConversionIntegrity(GoldAdapter, 100 bps)",
            "solidity": _GUARD_C,
            "gas_overhead": "6,102 gas per depositAndMint (+1.6%)",
            "gas_measured": True,
        },
        "validation_report": {
            "corpus_size": 2000,
            "violations_in_corpus": 0,
            "max_observed_value": 0.0011,
            "threshold": 0.01,
            "margin_ratio": 9.1,
            "coverage_warnings": [
                "Corpus contains no multi-adapter multicalls - re-review if "
                "batched cross-adapter routes are enabled",
                "Benign price drift within a single multicall never exceeded "
                "11 bps; threshold is a conservative floor, not a fitted bound",
            ],
            "validation_confidence": "HIGH within covered scenarios",
        },
        "bypass_resistance": {
            "attempts": [
                {"method": "split_into_10_subtransactions", "success": False,
                 "reason": "post-op re-read compares the mint rate against the "
                           "fresh rate regardless of sub-transaction count"},
                {"method": "spread_across_20_blocks", "success": False,
                 "reason": "each multicall re-validates conversion at its own "
                           "boundary; spreading gains nothing"},
                {"method": "use_multicall_path", "success": False,
                 "reason": "the multicall path is exactly what this guard "
                           "instruments - it is the vuln surface, now covered"},
                {"method": "gas_variance", "success": False,
                 "reason": "guard is state-based, not gas-based; N/A"},
            ],
            "resistance_score": "HIGH - guard sits on the exact exploit path",
        },
        "recommended_actions": [
            {"priority": "Immediate",
             "action": "Instrument AccountManager.depositAndMint() to re-read "
                       "the conversion rate after the deposit leg and assert it "
                       "matches the mint rate within 100 bps",
             "governance": "emergency-role"},
            {"priority": "Follow-up",
             "action": "Adopt a single fresh-read-per-operation convention "
                       "across all multicall entrypoints to eliminate the class",
             "governance": "full-vote"},
        ],
        "governance_path": {
            "emergency_role_compatible": True,
            "timelock_required": False,
            "full_vote_required_for": "protocol-wide fresh-read convention rollout",
        },
    },
]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv:
        print("No finding file given - rendering bundled sample advisories.")
        results = [render_advisory(f) for f in SAMPLE_FINDINGS]
    else:
        results = []
        for path in argv:
            with open(path, "r", encoding="utf-8") as fh:
                finding = json.load(fh)
            results.append(render_advisory(finding))

    for res in results:
        print(f"  MD : {res['md_path']}")
        print(f"  PDF: {res['pdf_path']}")
    print(f"Rendered {len(results)} advisory/advisories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
