# CERT-In's audit report formats, the master schema and the Suite

CERT-In supplied two report formats in October 2026: "Audit Report for Compliance / Regulatory Audits" and "Audit Report Format for Technical Security Assessment Report (VAPT / Red Team / Cloud)". They share a cover page, document control, a distribution list and twelve sections; they differ in the scope table of section 2, the frameworks section 7 names for risk assessment (ISO/IEC 27005 and NIST SP 800-30 in the compliance format only), the findings table of section 9 and one appendix, and the technical format has an illustrative finding. The Guidelines leave the format to be agreed between auditee and auditing organisation (§16.1(i)), so the Suite does not require a report to follow either: it reads the master schema v2 that Objective 1 produces from any layout, and the table below shows where each item of the formats lands and which check reads it.

Two things follow from the formats in this release:

* **MC-10** reads the audit team's "Listed on CERT-In Website (Y/N)" (`auditing_team[].listed_on_certin_website`) beside the empanelment records, never in their place, since MC-10 asks whether each person is declared in the records. A person the report itself marks "N" and the records do not list is referred with that statement; a person marked "Y" and not found is referred as before, the deficiency saying that the report marks the person "Y"; a person marked "N" but declared is noted; and where the records cannot be read for the organisation, the persons marked "N" are noted. MC-10 still returns Fail only on the reviewer's confirmation (Section 5).
* **Q5 (K)** also compares the "Overall Report Rating" of section 8 with the findings, by the severity criteria the formats give each level (`curated/report_formats.yaml`). A rating better than the Critical and High findings not closed allow sets K to 0, as an inconsistency between the summary and the detailed observations would. Section 6.5 defines K by the summary table and counts alone, so this is an addition pending CERT-In's confirmation, and `apply_in_q5: false` removes it. The criteria on Medium and Low findings, systemic failures and repeated issues overlap between levels and are left to judgement.

## Mapping

"C" marks the compliance format only, "T" the technical format only. A dash under the schema means master schema v2 has no field for the item (see the list at the end).

| Format item | Master schema v2 | Read by |
| --- | --- | --- |
| Cover: Report Title | `report_meta.report_title` | |
| Cover: Organization Name (auditee) | `report_meta.auditee_organization.name` | Q2 (rows 3 and 4 of the methods of verification) |
| Cover: Type of Audit | `report_meta.audit_types[]` | MC-16, engagement modules (Section 9) |
| Cover: Type of Report (First / Follow-up) | — (`report_type` holds the assessment type as the report names it) | |
| Cover: Audit Period Covered | `report_meta.audit_period` | |
| Cover: Report Release Date | `report_meta.report_release_date` | MC-10 (the empanelment set and register in force); the reference date where neither an observation nor the assessment is dated (Section 11.3) |
| Document Control: Document Title, ID, Version | `document_control.document_title`, `document_id`, `document_version`; the version also as `report_meta.report_version` | MC-14 (`report_version` and `change_history[]`) |
| Document Control: Prepared By, Reviewed By, Approved By | `document_control.prepared_by`, `reviewed_by`, `approved_by` | MC-08, MC-10 |
| Document Control: Release Date | `document_control.release_date` | |
| Document Distribution List: Name, Organization, Designation, Email ID | `document_control.distribution_list[]` | |
| 1. Introduction: Purpose, Objectives | — | |
| 1. Introduction: Confidentiality Statement | `report_meta.classification` | |
| 2. Scope of Work (regulations, compliance standards) | `methodology.standards_referred[]`, `compliance_assessments[].framework` | MC-05, MC-06, Q2 |
| 2. Audit Period | `report_meta.audit_period` | |
| 2. Audit Coverage (C): IT infrastructure / geographical locations / third-party vendors, Assets Details | `engagement_scope.assets[]` | MC-11, Q8 |
| 2. Audit Coverage (C): Location Detail | — | |
| 2. Audit Coverage (T): Asset Description, Criticality of Asset | `engagement_scope.assets[].asset_description`, `criticality` | MC-07 and Q8 (criticality), Q4.b (description) |
| 2. Audit Coverage (T): Internal IP / External Public IP, URL / Hostname | `engagement_scope.assets[].internal_ip`, `public_ip`, `url` | Q4.b (affected assets found in scope) |
| 2. Audit Coverage (T): Location | — | |
| 2. Audit Coverage (T): Hash Value, Version (applications) | `engagement_scope.assets[].hash`, `version` | MC-13, module check `certificate_artefacts` |
| 2. Exemptions, assumptions, limitations | `engagement_scope.exclusions[]`, `methodology.limitations[]` | Q1 (limitations) |
| 3. Audit team: Name, Designation, Email ID, Qualifications/Certifications | `auditing_team[].name`, `designation`, `email`, `certifications`, `qualifications` | MC-08, MC-10, Q3 |
| 3. Audit team: Listed on CERT-In Website (Y/N) | — (read as `auditing_team[].listed_on_certin_website`) | MC-10, beside the records |
| 4. Kick-off Meeting | `audit_timeline.entry_conference_date` | Record checks (Section 10.1) |
| 4. Fieldwork | `audit_timeline.assessment_start_date`, `assessment_end_date` | Q1 (duration), MC-19 |
| 4. Report Draft | `document_control.change_history[]` | MC-14 |
| 4. Final Report | `report_meta.report_release_date` | |
| 5. Methodology and standards; manual or automated testing; sampling criteria | `methodology.standards_referred[]`, `standards_detail[]`, `narrative`, `manual_testing`, `automated_testing`, `sampling_decisions` | MC-05, Q1 |
| 6. Tools: Name, Version, Open Source / Licensed | `tools_used[].tool_name`, `version`, `license_type` | Q1 (tool disclosure) |
| 7. Risk matrix and frameworks (C: ISO/IEC 27005, NIST SP 800-30; both: OWASP Risk Rating, CVSS v3.1) | `methodology.severity_scheme`, `appendices.risk_rating_criteria[]` | Q6 |
| 8. Key Strengths, Key Findings, Graphical Representation, Conclusion | `executive_summary.narrative` (no field of their own) | Q5 (Cl, Co) |
| 8. Summary Table: SN, Observation Title, Risk Rating, Status, New/Repeat | `executive_summary.summary_table[]` | Q5 (K) |
| 8. Summary Table: Audit Control Area, Target Date | — | |
| 8. Recommendations | `executive_summary.key_recommendations[]` | Q5 (Ac) |
| 8. Overall Report Rating | `executive_summary.overall_security_posture.rating` | Q5 (Po; K, rating rule) |
| 9 (C). Standards / Compliance / Regulation, Observation Title / Control Requirement, Compliance Status | `compliance_assessments[].framework`, `framework_name`, `requirement_id`, `requirement_text`, `status` | MC-06, Q2, Q4.f |
| 9 (C). Control Area | — | |
| 9 (C). Detailed Observation, Affected System, Risk rating, Impact, Root Cause, Recommendations, Deadline, Status, New/Repeat | the linked `detailed_observations[]` (`compliance_assessments[].related_finding_ids[]`) | Q4, MC-18 |
| 9 (T). Affected Asset, Vulnerability Title, Detailed Observation | `detailed_observations[].affected_asset[]`, `affected_asset_sr_nos[]`, `title`, `observation_description` | Q4.a, Q4.b |
| 9 (T). CVE/CWE | `detailed_observations[].cve_id[]`, `cwe[]` | MC-02, MC-03, MC-04, Q7 |
| 9 (T). "EVSS Score" | `cvss_score` and `reported_epss_score` (the Guidelines require both, §5(xxiv), §16.2(ii)) | MC-01, MC-02, Q6, Q7 |
| 9 (T). Risk rating (C/H/M/L) | `detailed_observations[].severity` | MC-01, MC-19 |
| 9 (T). Reference, Proof of Concept | `reference`, `proof_of_concept[]` | Q4.a, MC-17, Q4.c |
| 9 (T). Vulnerable Parameter/Point | — (part of `observation_description`) | |
| 9. Auditor recommendations / Corrective actions | `recommendation` | Q4.d |
| 9. Management response | — | |
| 9. Deadline of corrective action(s) | `closure_timeline` | Q4.a |
| 9. Status (Open/Closed), New/Repeat | `status`, `new_or_repeat` | MC-18, MC-20, Q4.e, Q5 (K) |
| 9. Root Cause | `likely_root_cause` | Q4.a |
| 10. Glossary | — | |
| 10. Audit Evidence: Control Area, Control Objective, Sampling Methodology, Test Approach, Sample Size, Source, Work Paper Reference | `compliance_assessments[].evidence_refs[]` (in part), `methodology.sampling_decisions` | Q4.f, Q1 |
| 10 (T). List of Controls Tested for VAPT / Configuration Audit | — | |
| 11. Guidelines for Audit Governance: review by the audit lead and a quality reviewer, approval before distribution | `document_control.reviewed_by`, `approved_by` | MC-08 |
| 11. Corrective action and follow-up: closure verified by evidence | `appendices.retest_closure[]`, `proof_of_concept[].is_retest`, `audit_timeline.revalidation_end_date` | Q4.e; module check `certificate_after_followup` (revalidation dates) |
| 12. General Guidelines: report classification | `report_meta.classification` | |
| 12. General Guidelines: version control, authorised reviewers and approvers, new and repeat issues, management comments and deadlines, redaction | `document_control.change_history[]`, the MC-08 fields, `new_or_repeat`, `closure_timeline`, `proof_of_concept[].redacted` | MC-14, MC-08, MC-18, Q4 |

The technical format's illustrative finding ("SQL Injection (CWE-89) on /login ... Risk: Critical") gives a rating without a CVSS score or vector; MC-01 requires both.

## Fields the formats ask for that master schema v2 lacks

For Objective 1, if the schema is to carry everything the formats ask for:

* `auditing_team[].listed_on_certin_website` (boolean): "Listed on CERT-In Website (Y/N)". The Suite reads it from this release.
* `report_meta.follow_up` (boolean): "Type of Report (First / Follow-up)".
* `detailed_observations[].management_response`: the formats' "Management response" in both findings tables, and "Include management comments and corrective deadlines".
* `compliance_assessments[].control_area` and `executive_summary.summary_table[].control_area`.
* `executive_summary.summary_table[].target_date`; the status "Exception Taken" maps to `Risk Accepted` with `risk_treatment.decision` "Exception".
* `executive_summary.key_strengths[]` and `executive_summary.conclusion`.
* `engagement_scope.assets[].location`.
* `detailed_observations[].vulnerable_parameter`.
* `appendices.audit_evidence[]`: control area, control objective, sampling methodology, test approach, sample size, source, work paper reference.
* `appendices.controls_tested[]` (technical format) and `appendices.glossary[]`.
* `report_meta.purpose` and `report_meta.objectives[]`.
