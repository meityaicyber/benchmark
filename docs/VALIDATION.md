# Validation of external data

Every external fact the Suite relies on was checked against the publisher's live site or repository on 12 October 2026, and the sources of NVD history and the CVE List on 13 October 2026, when query APIs were removed from acquisition. The documents CERT-In supplied in October 2026 were checked against CERT-In's site on 16 October 2026. This file records what was checked, the result, and the evidence, so that the check can be repeated before each calibration round.

## CVSS calculation

| Check | Result | Evidence |
| --- | --- | --- |
| CVSS v3.1: the `cvss` library against an independent implementation of the FIRST specification (equations 7.1, weights 7.4, Roundup in Appendix A), all 2,592 base vectors | Agree on all 2,592 | first.org/cvss/v3.1/specification-document; `tools/cvss31_from_spec.py` |
| CVSS v4.0: the `cvss` library against Red Hat's maintained reference calculator (commit b0930b7, 17 September 2026), all 104,976 base vectors | Agree on all 104,976 | github.com/RedHatProductSecurity/cvss-v4-calculator |
| CVSS v4.0: the same vectors against the snapshot in FIRST's GitHub organisation (FIRSTdotorg/cvss-v4-calculator, commit c5b0d40, August 2024) | Agree on 104,454; differ by 0.1 on 522 | github.com/FIRSTdotorg/cvss-v4-calculator; `tools/cvss40_check_first.js` |
| Qualitative rating scale (None 0.0, Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0) | Matches v3.1 Section 5 and v4.0 Table 22 | first.org specification documents |

The 522 v4.0 vectors are exact halves (for example 8.55). The August 2024 snapshot rounds them down because of a floating-point artefact (8.5499999…); Red Hat corrected this in November 2024 ("Fixes other rounding errors", pull request 67). The `cvss` library rounds half up, matching the corrected calculator. Whether first.org's hosted calculator serves the snapshot or the corrected code could not be determined from here. The difference is 0.1, inside the Q6 tolerance of 0.1 and the Q7 tolerance of 0.5. None of the 522 cases sits on a rating boundary.

`src/certin_benchmark/data/cvss_vectors.json` now holds 3,264 reference vectors: the full v3.1 base space scored from the specification, and 672 v4.0 vectors (150 spread across the space plus the 522 half cases) scored by the corrected calculator. The package build refuses to proceed if the library disagrees with any of them.

## Data sources

| Item | Result | Evidence |
| --- | --- | --- |
| NVD JSON 2.0 yearly feeds (2002 to 2026), modified and recent feeds, `.meta` fields | Verified | nvd.nist.gov/feeds/json/cve/2.0/ |
| `.meta` sha256 covers the uncompressed JSON | Not stated by NVD; `size` is the uncompressed length. The builder now accepts a hash of either form, checks the size, and records which matched | nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2021.meta |
| NVD JSON structure read by the builder (metrics source and type, cvssData, weaknesses) | Verified | services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41773 |
| NVD Change History API | No longer used (13 October 2026): acquisition uses downloadable datasets only | — |
| NVD mirror: layout (one NVD JSON 2.0 `cve` object per file, `CVE-YYYY/CVE-YYYY-NNNNxx/`), synchronisation every two hours, history from April 2023, NVD and CVE terms of use in `LICENSES/`, not affiliated with NIST | Verified by cloning the repository. Extraction run on the real mirror for CVE-2021-41773 and CVE-2021-42013 gives NVD 7.5 with lastModified 2022-10-28 (first synchronisation), then 9.8 from 2026-02-17, matching NIST's record; CISA-ADP metrics are ignored | github.com/fkie-cad/nvd-json-data-feeds (commit bee52a7, 13 October 2026) |
| CVE List v5: repository layout (`cves/YYYY/Nxxx/CVE-*.json`), record fields, ADP containers; bulk release naming and nested `cves.zip` (still read if staged) | Verified; acquisition now clones the repository at its latest commit instead of locating the bulk release through GitHub's API | github.com/CVEProject/cvelistV5; github.com/CVEProject/cve-schema |
| CISA KEV fields and schema requirements | Verified; the builder now enforces the required fields and the `cveID` pattern | github.com/cisagov/kev-data |
| EPSS download host, archive start (2021-04-14), percentile definition | Verified | first.org/epss/data_stats; first.org/epss/data; github.com/empiricalsec/epss_scores |
| EPSS file format | Corrected: files before 2022-02-04 have no model line, and files before 2021-09-01 have no percentile column. Both are now read; the percentile is derived by FIRST's definition where absent. Current model v2026.06.15 | github.com/empiricalsec/epss_scores |
| CWE download URLs, XML namespace (cwe-7), Related_Weakness attributes, Status values | Verified | cwe.mitre.org/data/downloads.html; cwe.mitre.org/data/xsd/cwe_schema_latest.xsd |
| CWE release dates | Verified from the CWE news archive (the archive page lists no dates): 4.9 2022-10-13, 4.10 2023-01-31, 4.11 2023-04-27, 4.12 2023-06-29, 4.13 2023-10-26, 4.14 2024-02-29, 4.15 2024-07-16, 4.16 2024-11-19, 4.17 2025-04-03, 4.18 2025-09-09, 4.19 2025-12-11, 4.20 2026-04-30 | cwe.mitre.org/news/archives/ |

## Test fixtures

| Item | Result |
| --- | --- |
| CVE-2021-41773 on NVD | Corrected: 7.5 from the Initial Analysis of 2021-10-12, rescored to 9.8 on 2026-02-17. The fixture and the sample report now carry both, and the as-at-date lookup returns 7.5 or 9.8 according to the date |
| CVE-2021-41773 CWE, publication date, KEV date | Verified: CWE-22, published 2021-10-05, KEV 2021-11-03 |
| CWE-1395 first release | Corrected: 4.10, not 4.15. The test of a CWE not yet published now uses CWE-1426 (first in 4.15) |
| CWE names and ChildOf relations used in tests | Verified |
| CERT-In advisory "CIAD-2021-0381" in the sample report | Did not exist. Replaced by the synthetic identifier CIVN-2021-0000, labelled as such; the real CERT-In note for this CVE could not be found |
| WSTG reference for path traversal in the sample report | Corrected from WSTG-CONF-04 to WSTG-ATHZ-01 |

## Curated lists

| List | Result | Evidence |
| --- | --- | --- |
| CERT-In Directions of 28 April 2022 | Corrected: six directions, not seven. Point of Contact and furnishing information are both direction (iii); logs are (iv); data centre and VPN records (v); virtual asset providers (vi) | cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf; FAQs, May 2022 |
| CERT-In methods of verification document | Supplied by CERT-In in October 2026; the requirements of Q2 (D) are now its rows (see below). CERT-In's link to it still returns "not found" (16 October 2026) | cert-in.org.in/PDF/Methods_of_Verification.pdf |
| MeitY 282-point checklist | Not published | Guidelines §8(v) only |
| Cyber Security Audit Baseline Requirements | Verified; issued by NSCS (NSCS-46-16 Rev 1.0, October 2020), hosted by CERT-In. Its 68 marker identifiers (csm.1 to 19, pro.1 to 21, det.1 to 9, res.1 to 11, rec.1 to 3, imp.1 to 5) are recognised exactly, with the markers recommended rather than mandatory for medium and low risk (see below) | cert-in.org.in/PDF/CyberSecurityAuditbaseline.pdf |
| CERT-In advisory identifiers | Verified: CIAD-YYYY-NNNN and CIVN-YYYY-NNNN; the pattern is now exact | cert-in.org.in advisory pages |
| Banking and NBFC regulations | Corrected: RBI Directions of 31 July 2026 for commercial banks (RBI/DoS/2026-27/410) and for NBFCs (RBI/DoS/2026-27/461) repeal the 2023 Master Direction and the 2016 framework for those entities. Regulations now carry the dates they are in force, and Q2 applies those in force on the report's reference date | rbi.org.in notifications 13643, 13592, 12562, 10435 |
| Payment system operators | Title corrected to "...for non-bank Payment System Operators" (RBI/DPSS/2024-25/123, 30 July 2024) | rbi.org.in notification 12715 |
| SEBI CSCRF, Telecom Cyber Security Rules 2024 | Verified | sebi.gov.in circular of 20 August 2024; G.S.R. 720(E) |
| IRDAI Information and Cyber Security Guidelines, 2023 | Verified from a secondary source only; irdai.gov.in was not reachable | IRDAI/GA&HR/GDL/MISC/88/04/2023 |
| Power sector | Corrected: CEA Regulations, 2026 (notified 31 July 2026, in force 1 April 2027) supersede the 2021 Guidelines. Seen in news reports only; confirm on cea.nic.in | — |
| Framework identifier formats (WSTG, ASVS 4 and 5, MASTG, MASVS, CCM v4) | Verified; ASVS 5 citations added, and bare `V1.2.3` matching made case-sensitive so software versions are not read as ASVS requirements | OWASP and CSA repositories and pages |
| Certifications | Verified; OSCE, GSSP, CCNA Security and Azure Security Engineer Associate marked retired; OSCE3, OSED, EnCE and CCNA Cybersecurity added | Issuers' sites |
| Tool names | Verified; renamed tools carry their current names with former names as aliases (Invicti, NetExec, ZAP, Nipper InfraSight, HCL AppScan, OpenText Fortify); DIRB and DirBuster, sslscan and SSLyze separated | Vendor sites and project repositories |

## CERT-In documents supplied in October 2026

| Document | File and SHA-256 | Checked against CERT-In's site, 16 October 2026 |
| --- | --- | --- |
| Methods of verification to compliance with CERT-In Directions issued on 28.04.2022 | `Methods_of_Verification.pdf`, 4 pages, created 22 March 2024; `2afc77cc0c2e99dd0ef2d94b4a4a2a118658dcca4827628bc4cc1a8d2d884f7e` | Linked from CERT-In's page for empanelled auditing organisations (cert-in.org.in/s2cMainServlet?pageid=CERTEMPANEL), but the link, which is also the URL the key recommendations give (www.cert-in.org.in/PDF/Methods_of_Verification.pdf), returns "The requested URL is not found", with or without "www". The supplied copy is the source |
| Cyber Security Audit Baseline Requirements, NSCS-46-16 Rev 1.0, October 2020 | `CyberSecurityAuditbaseline.pdf`, 19 pages; `282558b90ecceffd0fd975c82a6850198de74d345b067fc132efbb4e838f0898` | Same document number, revision and date on cert-in.org.in/PDF/CyberSecurityAuditbaseline.pdf, and the same markers recommended for medium risk (pro.12, pro.13, pro.20, det.3, res.1, res.8) and for low risk (csm.11, csm.12, csm.14, csm.15, pro.12, pro.13, pro.16, pro.20, pro.21, det.3, det.4, det.7, det.9, res.1, res.8, res.9, imp.4, imp.5) |
| CERT-In Advisory: Key recommendations for CERT-In empanelled auditing organisations | `CERT-In_Key_Recommendations.pdf`, 3 pages, footer "September 2024", created 1 October 2024; `15f7acd12d7169a4c411d5c5dd458e7359c745568c1e3f4e3d1b11d0e678a340` | Listed, marked new, on CERT-In's page for empanelled auditing organisations as cert-in.org.in/PDF/CERT-In_Key_Recommendations.pdf; the published file itself was not compared. TeamLease RegTech reports it as notified on 1 October 2024, and its account of items i to ix matches the supplied copy |
| Guidelines for Secure Application Design, Development, Implementation & Operations, version 1.1, updated January 2024 | `Application_Security_Guidelines.pdf`, 15 pages, created 25 January 2024; `89acd6b83672443a9e094a95e2fb5ba8fd60634e3c85f21590baf390304a308d` | Same title, version and sections on cert-in.org.in/PDF/Application_Security_Guidelines.pdf: Phase III "Guidelines for Audit of Applications", 5.1 to 5.6, with the precondition for assessment at 5.6. The copy at csk.gov.in/documents/Application_Security_Guidelines.pdf is an earlier edition, also marked 1.1 but without the update date: its Phase III is "Provision of Detection of Errors and Vulnerability in Application Design & Development", it has no section on the timeline for completion of audit, and the precondition is 5.5. A report citing section numbers may be using either edition |
| Empanelled Information Security Auditing Organisations by CERT-In | `Empanel_org.pdf`, 997 pages, dated 5 October 2026; `f7c29fb9ad0a62aa48d42e51d138bdbc7a78a3e6b2d18707fc8f835ddc15eb0c` | The list on cert-in.org.in/PDF/Empanel_org.pdf has the same directory of 236 organisations (1. M/s AAA Technologies Ltd to 236. M/s Yoganandh & Ram LLP), and the same dates of declaration for the organisations compared (AAA Technologies, 15-11-2024; Bharat Electronics, 23-10-2020) |

Conversion of the list by `rdp convert-empanelment` (set dated 5 October 2026). Two independent reviews on 16 October 2026 compared conversions with the PDF. The first found rows dropped where the PDF's table structure leaves a row outside the table found on the page (24 people in 10 organisations), people divided into several records by merged cells (about 25 records in 12 organisations), a qualifications column lost, designations read as names, and a misread declaration date. The second found names divided by space glyphs the PDF draws over letters (52 people in 5 organisations, for example "S atya Rane"), a table body drawn offset from its headings that put experience under qualifications (174 people of Grant Thornton), and three fields cut short where a cell continues on the next page. The converter was corrected after each, and the list converted again. The results below are for the corrected converter.

| Item | Result |
| --- | --- |
| Organisations | 236, matching the directory: 232 with one snapshot, 2 with two snapshots, and 2 directory entries without a snapshot |
| Personnel | 4,801 people named in 230 organisations |
| Comparison with the list | For each snapshot, the people read were compared with the serial numbers of section 7 in the PDF's text (the longest run 1, 2, 3, ... in each snapshot, read with `pdftotext`). They agree for 202 of the 215 single-snapshot organisations whose section 7 is numbered, and for both snapshots of Qadit Systems and Solutions (14 and 28) and of Cybertryzub InfoSec (8 and 11). The other 13 differ because of the list itself: numbers skipped or repeated by the organisation (ANZEN, ASPL, DigitalTrack, eSec Forte, INNSPARK, Levithan, Netrika, Tribastion), a person listed without a number (Andhra Pradesh Technology Services), the same person listed twice (Codec Networks), and designations given in place of names (Shieldbyte, Secnuo, Trinay). Of the other 17 single-snapshot organisations, 3 list no manpower. For the remaining 14, whose snapshots number their sections differently or set out the manpower in an annexure, the people read agree with the numbering of the table for 12 (AKS, Audix, Aurionpro, Cypros, DREAMWORKS, Deccan, Grant Thornton, whose 217 people are in an annexure, INFOCUS, SecureInteli, Softcell, Swadesh, x-Biz) and with the count of section 6 for 2 (Software Technology Parks of India; Yoganandh & Ram) |
| Names and particulars | No entry read as a person is a tool, certification, heading or placeholder; the names a scan for digits, brackets, designations and unusual length flags are names as the list writes them (for example "Amit Kumar 2", "Lt. Col. (R) Sushil Pradhan", "Nishant (Singh) Tomar"). A scan of every pair of adjacent words in every name against the PDF's text finds two written differently from the text, both as the PDF draws them ("Asit-Kamble"; "SRIKANTH KANUMA R R", where a space is drawn between the initials); Indusface's "Soman S ukale" and "Rohith kanapura m" are broken inside a word across two lines of the list's own cells, and are named in a warning. Fifteen people chosen at random (seed 2027) were checked field by field against the PDF (name, duration, experience, qualifications, designation, date of declaration) and are correct; the organisations where the reviews found errors were checked again after the corrections |
| Date of declaration ("Information as provided by ... on") | Read for 229 of the 234 organisations with a snapshot, in the forms the list uses ("Ltdon 14-11-2024", "on28 June 2021", "Date: 03.01.2025", "Information provided by", names or dates wrapped onto later lines); the 18 dates in those forms were checked by hand against the text. No date is given by Army Cyber Group, Cyethack Solutions, Innovador Infotech or Swadesh System, and Tata Advanced Systems leaves the form's "<date>" unfilled. 4,745 of the 4,801 people carry the date of their organisation's declaration |
| Identifiers, periods of validity, designations | Not given by the list for any organisation (identifiers and validity) or for most (designations, read for 165 people in 8 organisations, some from the column for duration where an organisation wrote them there); see README, interpretation 20 |
| Warnings for review (36) | No manpower to verify: Net Square Solutions (marked confidential), QRC Assurance and Solutions (in an annexure not in the list), Army Cyber Group (none listed) and Trinay Cyber Technologies (designations in place of names); Shieldbyte and Secnuo also give "Consultant 1" and similar for some entries. Two snapshots: Qadit Systems and Solutions (pages 472 and 903) and Cybertryzub InfoSec (pages 520 and 829). No snapshot: Pyramid Cyber Security & Forensic (entry 161) and Tsaaro Solutions (entry 226). Serial numbers out of sequence in the list itself: 8 organisations. Section 7 naming more people than section 6 counts: 16 organisations, in each of which the people read agree with the list's numbering. Names broken inside a word by the list itself: Indusface |
| Lookups on the converted set | "AAA Technologies Limited" is found by name with 88 people; "M/s Qadit Systems & Solutions Pvt Ltd" on 10 October 2026 gives the declaration of 20 August 2026 (28 people); "AAA Technology" is not found and returns the closest names; "Private Limited" is not found; "D K Agarwal" matches the listed "D.K.Agarwal" and "Sushil Pradhan" the listed "Lt. Col. (R) Sushil Pradhan" |

The real list and its conversion are not held in the repository; they are staged on the preparation host and enter the Suite only through a signed package.

## Still to confirm

1. CERT-In's acceptance of the NVD mirror (Fraunhofer FKIE) as the source of NVD's earlier values, since NIST's CVE feeds carry only each record's current values and its change history is served through a query API.
2. The CEA Regulations, 2026 on cea.nic.in, and the IRDAI guidelines on irdai.gov.in.
3. Whether first.org's hosted CVSS v4.0 calculator includes the November 2024 rounding correction.
4. The real CERT-In note for CVE-2021-41773, if the sample report is to cite it.
5. The MeitY 282-point checklist and the CERT-In advisories file, from CERT-In (the methods of verification document and the list of empanelled organisations were supplied in October 2026).
6. CERT-In's confirmation of the readings of its documents in the README (interpretations 19 to 23), in particular the five module checks added from them.
7. The broken link to the methods of verification document on CERT-In's site, and a comparison of the published key recommendations with the supplied copy.
