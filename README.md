# Cybersecurity Audit Report Benchmarking Suite (Objective 3)

Implementation of the Cybersecurity Audit Report Benchmarking Suite approved by CERT-In (specification dated 6 October 2026). The Suite evaluates a standardised audit report, produced by Objective 1 (`report-to-json`) in the master schema v2, against the CERT-In Comprehensive Cyber Security Audit Policy Guidelines (CIGU-2025-0002).

For each report the Suite returns a compliance status (Compliant, Non-compliant or Pending review), the mandatory checks not met with their clauses, the quality score Q, the composite score, every criterion and sub-dimension score, and a full evaluation record. Section references below (for example "Section 6.4") refer to the specification; clause references (for example §16.2(ii)) refer to the Guidelines.

## Contents

| Path | Purpose |
| --- | --- |
| `src/certin_benchmark/engine.py` | Algorithm 1: single evaluation pass, compliance status, Q, cap, composite, evaluation record |
| `src/certin_benchmark/mandatory.py` | MC-01 to MC-21 (Section 5) |
| `src/certin_benchmark/criteria/q1.py` to `q8.py` | Quality criteria Q1 to Q8 (Section 6) |
| `src/certin_benchmark/modules.py` | Engagement modules and their checks (Section 9) |
| `src/certin_benchmark/record_checks.py` | Record checks (Section 10.1) |
| `src/certin_benchmark/evaluators/` | Sampled distribution scoring and local model backends (Section 4) |
| `src/certin_benchmark/refdata/` | Reference Data Package: acquisition, build, signing, import, as-at-date lookups (Section 11) |
| `src/certin_benchmark/calibration/` | Agreement measures, reference set split, weight and threshold fitting (Section 8) |
| `config/suite.yaml` | Weights, cap, thresholds, tolerances, sampling and model settings |
| `curated/` | Curated reference lists transferred inside each Reference Data Package (Section 11.1) |
| `tests/` | 91 tests, including an end-to-end run on a sample report and a synthetic signed package |
| `docs/VALIDATION.md` | Check of every external fact against the publishers' sites, 12 October 2026 |
| `tools/` | Scripts that re-validate the CVSS reference vectors against the specification and FIRST's calculator |

## Installation

Python 3.10 or later. Runtime dependencies are PyYAML, `cvss` (the open-source CVSS v3.1 and v4.0 calculator) and `cryptography` (Ed25519 signing). Inside the CERT-In environment, install from wheels transferred with the code:

```
pip download -d wheels .            # on a connected host
pip install --no-index --find-links wheels .   # inside the environment
```

## Evaluating a report

```
certin-benchmark evaluate report.json --rdp-store /srv/rdp --assets-dir report_images/ --out record.json
certin-benchmark summary record.json
```

The command exits with status 2 for a non-compliant report. Options:

* `--rdp` or `--rdp-store`: the imported Reference Data Package, or the store from which the latest is taken.
* `--assets-dir`: directory holding the proof-of-concept images referenced in `proof_of_concept[].reference`.
* `--overrides`: reviewer decisions (Section 2, principle 8), as JSON:
  ```json
  {"checks":   {"MC-10": {"result": "Fail", "reviewer": "name", "reason": "not declared"}},
   "items":    {"Q5.Cl": {"score": 50, "reviewer": "name", "reason": "jargon in paragraph 2"}},
   "criteria": {"Q3": {"score": 60, "reviewer": "name", "reason": "..."}}}
  ```
* `--record-responses file` and `--replay file`: record every model response, and later recompute the evaluation exactly from that record without the model (Section 11).
* `--no-models`: run without the language and vision models. Items that need them are not evaluated, and the composite score is designated provisional.

From Python:

```python
from certin_benchmark import BenchmarkEngine
from certin_benchmark.evaluators import backend_from_config
engine = BenchmarkEngine(refdata="/srv/rdp/RDP-2026-10-12", text_backend=..., vision_backend=...)
record = engine.evaluate(report_json)
```

## Language and vision models

Both models run locally at a fixed version behind an OpenAI-compatible endpoint (for example vLLM); see `models` in `config/suite.yaml`. Set `model_version` to the exact model build so that it appears in every evaluation record. No backend contacts an external service.

Every sampled item records its n ratings, distribution, score, variance, one-line rationales, seeds and model version. Report content is passed to the model inside delimiters and the model is instructed to treat it as data.

## Reference Data Package

The Suite reads every external source from a dated, signed package (Section 11). The workflow:

1. On the preparation host (outside the CERT-In environment):
   ```
   certin-benchmark rdp fetch --staging staging/ --epss-from 2021-04-14 --history-from 2021-01-01 \
       --cwe-releases cwe_releases.json          # first package; later packages use --epss-days 7
   # place CERT-In advisories (certin_advisories/advisories.json) and empanelment records (empanelment/*.json)
   certin-benchmark rdp build --staging staging/ --out-root packages/ --previous packages/RDP-<previous>
   certin-benchmark rdp sign packages/RDP-<date> --key private.pem
   ```
   The build validates the CVSS library against 3,264 reference vectors (the whole v3.1 base space and 672 v4.0 vectors; see `docs/VALIDATION.md`), verifies each source (NVD SHA-256 metadata, KEV structure, full parse, record counts against the previous package), carries forward any source that fails verification, and writes a manifest with retrieval times, publisher versions, file hashes, record counts and EPSS model versions. Each preparation is appended to `preparation_log.jsonl`.
2. Transfer on write-once media or through the approved unidirectional mechanism.
3. Inside the environment:
   ```
   certin-benchmark rdp import RDP-<date> --store /srv/rdp --key public.pem
   ```
   Import verifies the signature and every file hash, rejects unlisted files, and never overwrites an existing package.

Lookups follow Section 11.3: EPSS from the daily file for the reference date; KEV by date of addition; NVD scores and NVD CWE assignments from the latest package on or before the reference date, or reconstructed from the NVD change history before the earliest package; CWE validity from the catalogue in force on the date; advisories issued on or before the date; empanelment records from the set in force on the release date.

Input formats for the two CERT-In sources are defined in `src/certin_benchmark/refdata/build.py`. `rdp keygen` creates the Ed25519 key pair.

## Calibration (Section 8)

```
certin-benchmark calibrate split --strata strata.csv
certin-benchmark calibrate agreement --records suite_records/ --experts experts.csv --retest retest_records/
certin-benchmark calibrate fit-weights --records suite_records/ --experts experts.csv
```

The agreement report gives Cohen's kappa and precision of Fail per mandatory check, ICC(A,1) per criterion against the inter-expert bound, quadratic weighted kappa per language-model sub-dimension, Spearman correlation for the composite and test-retest ICC, each against its acceptance target. `all_targets_met` is true only when every measure is present and met. A check that misses its targets is placed in `referral_mode_checks` in `config/suite.yaml`.

## Status of the curated lists

Every name, date and identifier format in `curated/` was checked against the issuers on 12 October 2026 (`docs/VALIDATION.md`). The following remain provisional until CERT-In supplies or confirms them:

* the requirements of the CERT-In Directions dated 28 April 2022: the six published directions are listed, pending the CERT-In document on methods of verification, whose published URL returns "not found";
* the 282 control points of the MeitY Comprehensive Audit Program Checklist, which is not published (empty; MC-07 counts distinct assessed identifiers until the list is supplied);
* the controlled list of sectors and the mandatory regulations for each, which now carry the dates they are in force (the RBI Directions of 31 July 2026 and the CEA Regulations, 2026 change the banking, NBFC and power entries);
* the designation lists for mid-management, the head of an organisation and prohibited categories, and the mapping of qualifications to engagement modules.

## Interpretations for confirmation with CERT-In

The specification leaves the following points open. The code takes the reading stated here; each is a configuration or a single function and can be changed on CERT-In's direction.

1. **MC-08 and MC-10.** Fail is returned automatically only where a required signature is absent. Every determination about a person (membership of the audit team, mid-management designation, head of organisation, declaration in the empanelment records) returns Indeterminate and becomes Fail on the reviewer's confirmation through `--overrides`. MC-09 treats a signatory's role mismatch the same way.
2. **MC-13 and the web and mobile modules** do not require a version and hash for an asset recorded as inaccessible under MC-11.
3. **MC-14** also requires the current `report_version` to appear in the version history.
4. **MC-19** requires `notified_on` and fails where it is later than the assessment end date.
5. **MC-01** accepts a severity of None or Informational for a CVSS score of 0.0.
6. **MC-05** treats the Cyber Security Audit Baseline Requirements as a comprehensive framework, and NIST SP 800-115, PTES and the CERT-In Directions as supporting methodologies that do not satisfy MC-05 on their own.
7. **Q1.** Where no tool is named in the proof-of-concept descriptions, tool disclosure is measured over the declared tools. The duration item is met by assessment dates or man-hours.
8. **Q2.** "Not applicable" with a reason scores 100. A non-compliant sector entry without linked findings is limited to 50. Where the sector is not stated, R is excluded and the report is referred.
9. **Q3.** The expertise denominator is the members recorded as in the audit team. Components are renormalised before the D_pro deduction. A trainee counts as a fresher.
10. **Q4.** Substantive text is at least three words. The executive summary's asset reference for a finding is counted among that finding's asset references. Evidence declared redacted scores 100 on redaction without assessment. A retest captured on or before the original evidence scores 0 on distinctness without sampling.
11. **Q6.** Plausibility variance is measured on the inferred CVSS rating band (0 to 4) against the same v_max.
12. **Q7.** P_d is the share of the day's scores at or below the reported score, as FIRST defines its percentile. CWE parent or child means a direct ChildOf relation in view 1000. An observation with no evaluable check is left out of the mean.
13. **Q8.** A category excluded with a reason is not penalised under CA (Section 6.8, final paragraph), since the schema does not record who made the exclusion.
14. **Section 10.1.** An obligation is reported Pass, Fail or Not recorded. A missing conference or Board presentation date is Not recorded.
15. **Sampling.** v_max = 0.8 and a minimum of three valid ratings are initial values for calibration.
16. **CVSS v4.0 rounding.** Scores that are exact halves (522 of 104,976 base vectors) are rounded half up, as the `cvss` library and Red Hat's corrected reference calculator do. The August 2024 calculator snapshot in FIRST's GitHub organisation gives 0.1 less for these vectors.

## Known limitations

* Image proof-of-concept entries need the image files beside the JSON (`--assets-dir`) and a vision model. Without them those entries are not evaluated and the composite score is provisional.
* CWE validity as at a past date depends on every CWE release since that date being staged; `rdp fetch --cwe-releases` takes the list.
* The KEV catalogue is checked against the required fields and patterns of CISA's published schema in code rather than with a JSON Schema validator, to avoid a further dependency.
* The NVD Change History API limits used by `rdp fetch` (120-day window, 5,000 results a page, request pacing) could not be re-read from NVD's documentation on 12 October 2026 and should be confirmed before the first package is prepared.
* Engagement module checks for third-party certificates, network devices, pipelines and forensics use curated keyword lists in `curated/modules.yaml`.

## Tests

```
python3 -m unittest discover -s tests -p 'test_*.py'
```

`tests/fixtures/staging.py` builds a synthetic package (NVD, change history, CVE List, EPSS, KEV, CWE, advisories, empanelment) that is signed and imported before the tests run. `tests/fixtures/sample_report.json` is a complete master schema v2 report.
