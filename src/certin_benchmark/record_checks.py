"""Record checks (Suite Section 10.1): engagement obligations recorded in the report.

Each is reported Pass or Fail with its clause and carries no weight in the composite score. Where
the report does not record the obligation, it is outside the scope of the Suite ("Not recorded").
"""

from __future__ import annotations

from .context import Context
from .results import RecordCheck
from .util import contains_any, norm_text, parse_date

NOT_RECORDED = "Not recorded"


def _er(ctx: Context, key: str):
    return ctx.report.get(f"appendices.engagement_record.{key}")


def run_record_checks(ctx: Context) -> list[RecordCheck]:
    r = ctx.report
    out: list[RecordCheck] = []

    nda = _er(ctx, "nda_signed")
    out.append(RecordCheck("Non-disclosure agreement executed before commencement", ["§13.2.1(i)"],
                           ["appendices.engagement_record.nda_signed"],
                           NOT_RECORDED if nda is None else ("Pass" if nda is True else "Fail")))

    approvals = [a for a in (_er(ctx, "approvals") or []) if isinstance(a, dict)]
    eng = ctx.curated.engagements
    required: set[str] = set()
    for t in r.audit_types:
        for k, v in (eng.get("required_approvals_by_audit_type") or {}).items():
            if norm_text(k) == norm_text(t):
                required |= set(v)
    method_text = " ".join(str(x) for x in [r.get("methodology.narrative"), r.get("methodology.manual_testing"),
                                            r.get("methodology.automated_testing")] if x)
    for typ, words in (eng.get("required_approvals_by_keyword") or {}).items():
        if contains_any(method_text, words):
            required.add(typ)
    if _er(ctx, "approvals") is None:
        out.append(RecordCheck("Written approvals for the tests performed", ["§13.2.2(v)", "§13.2.7", "§15.2.2(ii)", "§15.2.2(iii)"],
                               ["appendices.engagement_record.approvals[]", "report_meta.audit_types[]"], NOT_RECORDED))
    else:
        have = {a.get("type") for a in approvals if a.get("granted_by") or a.get("reference")}
        missing = sorted(required - have)
        out.append(RecordCheck("Written approvals for the tests performed", ["§13.2.2(v)", "§13.2.7", "§15.2.2(ii)", "§15.2.2(iii)"],
                               ["appendices.engagement_record.approvals[]", "report_meta.audit_types[]"],
                               "Fail" if missing else "Pass",
                               f"approval not recorded for: {', '.join(missing)}" if missing else
                               f"required: {', '.join(sorted(required)) or 'none identified'}"))

    tools = [t for t in (r.get("tools_used") or []) if isinstance(t, dict)]
    flags = [t.get("approved_by_auditee") for t in tools]
    if not tools or all(f is None for f in flags):
        res, detail = NOT_RECORDED, ""
    else:
        unapproved = [t.get("tool_name") for t in tools if t.get("approved_by_auditee") is not True]
        res, detail = ("Fail", "not approved: " + ", ".join(map(str, unapproved))) if unapproved else ("Pass", "")
    out.append(RecordCheck("Tools approved by the auditee before use", ["§13.2.2(iv)"],
                           ["tools_used[].approved_by_auditee"], res, detail))

    dates = {"entry conference": r.get("audit_timeline.entry_conference_date"),
             "exit conference": r.get("audit_timeline.exit_conference_date"),
             "Board presentation": _er(ctx, "board_presentation_date")}
    if all(v is None for v in dates.values()):
        out.append(RecordCheck("Entry and exit conferences held; presentation made to the Board", ["§9.6(vii)", "§17(iii)"],
                               ["audit_timeline.entry_conference_date", "audit_timeline.exit_conference_date",
                                "appendices.engagement_record.board_presentation_date"], NOT_RECORDED))
    else:
        missing = [k for k, v in dates.items() if parse_date(v) is None]
        out.append(RecordCheck("Entry and exit conferences held; presentation made to the Board", ["§9.6(vii)", "§17(iii)"],
                               ["audit_timeline.entry_conference_date", "audit_timeline.exit_conference_date",
                                "appendices.engagement_record.board_presentation_date"],
                               NOT_RECORDED if missing else "Pass",
                               f"recorded: {', '.join(k for k in dates if k not in missing)}; not recorded: {', '.join(missing)}"
                               if missing else ""))

    wn = _er(ctx, "working_notes_provided")
    out.append(RecordCheck("Working notes provided to the auditee", ["§18(i)"],
                           ["appendices.engagement_record.working_notes_provided"],
                           NOT_RECORDED if wn is None else ("Pass" if wn is True else "Fail")))

    ddc = _er(ctx, "data_disposal_certificate")
    if not isinstance(ddc, dict) or ddc.get("provided") is None:
        res = NOT_RECORDED
    else:
        res = "Pass" if ddc.get("provided") is True else "Fail"
    out.append(RecordCheck("Certificate of data disposal issued", ["§10.3(iv)"],
                           ["appendices.engagement_record.data_disposal_certificate"], res))

    shared = parse_date(_er(ctx, "metadata_shared_with_certin_on"))
    end = parse_date(r.get("audit_timeline.assessment_end_date"))
    if _er(ctx, "metadata_shared_with_certin_on") is None:
        res, detail = NOT_RECORDED, ""
    elif shared is None or end is None:
        res, detail = "Fail", "date of sharing or assessment end date not determinable"
    else:
        days = (shared - end).days
        res, detail = ("Pass" if days <= 5 else "Fail"), f"shared {days} days after completion"
    out.append(RecordCheck("Audit metadata shared with CERT-In within five days of completion", ["§10.6"],
                           ["appendices.engagement_record.metadata_shared_with_certin_on",
                            "audit_timeline.assessment_end_date"], res, detail))
    return out
