# Validation of external data

Every external fact the Suite relies on was checked against the publisher's live site or repository on 12 October 2026. This file records what was checked, the result, and the evidence, so that the check can be repeated before each calibration round.

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
| NVD Change History API response fields and value formats | Verified; a third value format (plain `AV:N/...`, used by NVD from 2026) is handled | services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2021-41773 |
| Change History API limits (120-day window, 5,000 per page, `apiKey` header, pacing) | Not verifiable: NVD's developer pages render client-side. Confirm in a browser before the first package | nvd.nist.gov/developers |
| CVE List v5 bulk release naming, nested `cves.zip`, record fields, ADP containers | Verified; the builder now reads ADP containers and streams the 691 MB inner archive to disk | github.com/CVEProject/cvelistV5; github.com/CVEProject/cve-schema |
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
| CERT-In methods of verification document | Not retrievable: the cited URL returns "not found" | cert-in.org.in/PDF/Methods_of_Verification.pdf |
| MeitY 282-point checklist | Not published | Guidelines §8(v) only |
| Cyber Security Audit Baseline Requirements | Verified; issued by NSCS (NSCS-46-16 Rev 1.0, October 2020), hosted by CERT-In. Its marker identifiers (csm.1, pro.1, det.1, res.1, rec.1, imp.1) are now recognised | cert-in.org.in/PDF/CyberSecurityAuditbaseline.pdf |
| CERT-In advisory identifiers | Verified: CIAD-YYYY-NNNN and CIVN-YYYY-NNNN; the pattern is now exact | cert-in.org.in advisory pages |
| Banking and NBFC regulations | Corrected: RBI Directions of 31 July 2026 for commercial banks (RBI/DoS/2026-27/410) and for NBFCs (RBI/DoS/2026-27/461) repeal the 2023 Master Direction and the 2016 framework for those entities. Regulations now carry the dates they are in force, and Q2 applies those in force on the report's reference date | rbi.org.in notifications 13643, 13592, 12562, 10435 |
| Payment system operators | Title corrected to "...for non-bank Payment System Operators" (RBI/DPSS/2024-25/123, 30 July 2024) | rbi.org.in notification 12715 |
| SEBI CSCRF, Telecom Cyber Security Rules 2024 | Verified | sebi.gov.in circular of 20 August 2024; G.S.R. 720(E) |
| IRDAI Information and Cyber Security Guidelines, 2023 | Verified from a secondary source only; irdai.gov.in was not reachable | IRDAI/GA&HR/GDL/MISC/88/04/2023 |
| Power sector | Corrected: CEA Regulations, 2026 (notified 31 July 2026, in force 1 April 2027) supersede the 2021 Guidelines. Seen in news reports only; confirm on cea.nic.in | — |
| Framework identifier formats (WSTG, ASVS 4 and 5, MASTG, MASVS, CCM v4) | Verified; ASVS 5 citations added, and bare `V1.2.3` matching made case-sensitive so software versions are not read as ASVS requirements | OWASP and CSA repositories and pages |
| Certifications | Verified; OSCE, GSSP, CCNA Security and Azure Security Engineer Associate marked retired; OSCE3, OSED, EnCE and CCNA Cybersecurity added | Issuers' sites |
| Tool names | Verified; renamed tools carry their current names with former names as aliases (Invicti, NetExec, ZAP, Nipper InfraSight, HCL AppScan, OpenText Fortify); DIRB and DirBuster, sslscan and SSLyze separated | Vendor sites and project repositories |

## Still to confirm

1. NVD Change History API limits, in a browser at nvd.nist.gov/developers.
2. The CEA Regulations, 2026 on cea.nic.in, and the IRDAI guidelines on irdai.gov.in.
3. Whether first.org's hosted CVSS v4.0 calculator includes the November 2024 rounding correction.
4. The real CERT-In note for CVE-2021-41773, if the sample report is to cite it.
5. The CERT-In methods of verification document and the MeitY checklist, from CERT-In.
