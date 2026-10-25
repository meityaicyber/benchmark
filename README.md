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
| `src/certin_benchmark/images.py` | Proof-of-concept images: Objective 1 tags resolved through the image manifest and deep storage |
| `src/certin_benchmark/evaluators/` | Sampled distribution scoring and local model backends (Section 4) |
| `src/certin_benchmark/refdata/` | Reference Data Package: acquisition, build, signing, import, as-at-date lookups (Section 11) |
| `src/certin_benchmark/refdata/empanelment_pdf.py` | Conversion of CERT-In's list of empanelled auditing organisations (PDF) into an empanelment set |
| `src/certin_benchmark/refdata/empanelment_register.py` | Conversion of CERT-In's register of the organisations' AMBAK codes, CERT-In references and validity of empanelment (spreadsheet) |
| `src/certin_benchmark/calibration/` | Agreement measures, reference set split, weight and threshold fitting (Section 8) |
| `config/suite.yaml` | Weights, cap, thresholds, tolerances, sampling and model settings |
| `curated/` | Curated reference lists transferred inside each Reference Data Package (Section 11.1) |
| `tests/` | 207 tests, including an end-to-end run on a sample report, a synthetic signed package, and a synthetic list and register in the layout of CERT-In's |
| `docs/VALIDATION.md` | Check of every external fact against the publishers' sites (12, 13 and 16 October 2026) and of the CERT-In documents supplied in October 2026 |
| `docs/REPORT_FORMATS.md` | CERT-In's two audit report formats mapped to the master schema and the Suite's checks, with the fields the schema lacks |
| `tools/` | Scripts that re-validate the CVSS reference vectors against the specification and FIRST's calculator |
| `setup.py`, `MANIFEST.in` | Build hook that places a copy of `config/` and `curated/` inside the wheel, for an installed Suite |

## Installation

Python 3.10 or later. Runtime dependencies are PyYAML, `cvss` (the open-source CVSS v3.1 and v4.0 calculator) and `cryptography` (Ed25519 signing). The preparation host also needs `pdfplumber` to convert CERT-In's list of empanelled organisations and `openpyxl` to read its register of their identifiers and validity (`pip install -e ".[preparation]"`); neither is needed inside the environment.

A source checkout, or an editable install of one (`pip install -e`), reads `config/suite.yaml` and `curated/` from the repository. A wheel carries a copy of both inside the package (`setup.py`), so an installed Suite finds them without the source tree; `--config` and `--curated` override either, and a configuration or list folder that cannot be found stops the command with an error naming the option to use. Inside the CERT-In environment, install from wheels built on a connected host with the same operating system, processor architecture and Python version as the environment:

```
pip wheel -w wheels .                                         # on the connected host, in the repository
pip install --no-index --find-links wheels certin-benchmark   # inside the environment
```

pip keeps an installed copy of the same version, so an update built from later code at version 1.0.0 is installed with `--force-reinstall` added to the second command.

Mistakes in what a command is given, such as a file or folder that is not there, a folder that is not a package, a package that fails verification, a key file of another form or a CWE release list of the wrong form, are reported on one line beginning `error:`, with exit status 1. A malformed option or date is reported by the argument parser with the command's usage, and exit status 2.

## Evaluating a report

```
certin-benchmark evaluate outputs/report.json --rdp-store /srv/rdp --deep-storage /srv/deep_storage --out record.json
certin-benchmark summary record.json
```

The command exits with status 2 for a non-compliant report. Options:

* `--rdp` or `--rdp-store`: the imported Reference Data Package, or the store from which the latest is taken. A path that holds no package stops the command; without either option the evaluation runs without reference data, and the record says so.
* `--deep-storage` and `--image-manifest`: where the proof-of-concept images are (see "Proof-of-concept images" below). Without either, the manifest named in `report.meta.json` beside the report is used.
* `--assets-dir`: directory holding proof-of-concept images whose `reference` is a file path rather than an Objective 1 tag.
* `--overrides`: reviewer decisions (Section 2, principle 8), as JSON:
  ```json
  {"checks":   {"MC-10": {"result": "Fail", "reviewer": "name", "reason": "not declared"}},
   "items":    {"Q5.Cl": {"score": 50, "reviewer": "name", "reason": "jargon in paragraph 2"}},
   "criteria": {"Q3": {"score": 60, "reviewer": "name", "reason": "..."}}}
  ```
* `--record-responses file` and `--replay file`: record every model response, and later recompute the evaluation exactly from that record without the model (Section 11).
* `--no-models`: run without the language and vision models. Items that need them are not evaluated, and the composite score is designated provisional.
* `--jobs N`: evaluate several reports at once, in N separate processes (see "Language and vision models" below).

From Python:

```python
from certin_benchmark import BenchmarkEngine
from certin_benchmark.evaluators import backend_from_config
engine = BenchmarkEngine(refdata="/srv/rdp/RDP-2026-10-12", text_backend=..., vision_backend=...)
record = engine.evaluate(report_json)
```

## Proof-of-concept images

Objective 1 removes every figure from a report before its model reads the pages, stores the image in deep storage under its SHA-256, and writes a tag such as `[IMAGE_PAGE_12_FIG_1]` in its place. For image evidence the tag is the value of `proof_of_concept[].reference`, and the image manifest (`deep_storage/manifests/<document_id>.json`) maps each tag to the stored object. The run report beside the JSON (`<name>.meta.json`) names the manifest and the document.

For each image entry under Q4.c the Suite:

1. follows the tag through the manifest to the stored object (by its URI, or by SHA-256 under `--deep-storage` if storage has moved) and checks that the file still hashes to the manifest's SHA-256;
2. sends the image itself to the vision model, with the observation it is meant to prove, and rates legibility, relevance to the claim and redaction, five samples each;
3. for a retest entry, scores retest distinctness 0 without the model where the retest image is byte-for-byte an original image of the same finding; otherwise sends the retest image together with the finding's original images, so the model compares the two.

An entry whose tag is not in the manifest, whose stored object is missing or altered, or for which no manifest was supplied, is not scored: it is referred for human review with the reason, and the composite score is designated provisional. The record lists, for every image entry, the tag, the file used, its SHA-256 and page (`reference_values.proof_of_concept_images` of Q4).

## Language and vision models

Both models run locally at a fixed version behind an OpenAI-compatible endpoint (for example vLLM); see `models` in `config/suite.yaml`. Both may point at one server serving one model, for example the model Objective 1 uses. Set `model_version` to the exact model build so that it appears in every evaluation record; `evaluate` warns while it is "unset". No backend contacts an external service.

Before the first report, `evaluate` asks each configured server which models it serves and stops with an error if it cannot be reached or does not serve the configured `model`, rather than leaving every model-judged item unevaluated. Every request states its own settings, since vLLM fills any setting a request leaves out from the model's `generation_config.json`:

* `top_p`, `top_k` and `min_p` (1.0, 0 and 0.0: the whole distribution at `sampling.temperature`), so that the five samples of an item can differ as Section 4 requires;
* `chat_template_kwargs` (`enable_thinking: false`), which turns off the reasoning trace of models such as Nemotron 3 Nano Omni; a trace does not fit in a rating reply of `max_tokens`, and any trace that a server returns in the reply is never read as the answer;
* `mm_processor_kwargs`, the model's image processing settings, sent with requests that carry images.

The samples of an item are sent together (`concurrency`, 5), and `evaluate --jobs N` evaluates several reports at once in separate processes, so that the server can batch requests; the results are the same as one at a time. A server's error message is kept in the note of the item it affected. Images are sent as stored when JPEG or PNG and converted to PNG otherwise (Objective 1 keeps JPEG 2000, TIFF and other formats as embedded in the PDF); the stored file is not changed. A retest comparison sends the retest image with at most `max_images_per_request` − 1 of the finding's original images (8 in all by default), and the server must accept that many (vLLM `--limit-mm-per-prompt`).

Every sampled item records its n ratings, distribution, score, variance, one-line rationales, seeds and model version. Report content is passed to the model inside delimiters and the model is instructed to treat it as data.

## Reference Data Package

The Suite reads every external source from a dated, signed package (Section 11). Each source is obtained as a complete downloadable dataset and kept as a local knowledge database: the package's SQLite database (`reference.sqlite`) with its EPSS daily archive and curated lists. No query API is called when the package is prepared, and no external service is contacted when a report is evaluated; the only network connection during evaluation is to the local model server inside the environment.

| Source | Dataset downloaded | From |
| --- | --- | --- |
| NVD (current values) | JSON 2.0 yearly and modified feeds with `.meta` files | nvd.nist.gov/feeds/json/cve/2.0/ |
| NVD (earlier values) | Git history of the NVD mirror (one JSON record per CVE, synchronised every two hours since April 2023) | github.com/fkie-cad/nvd-json-data-feeds |
| CVE List | Git repository of CVE records | github.com/CVEProject/cvelistV5 |
| EPSS | Daily score files from 2021-04-14 | epss.empiricalsecurity.com |
| KEV | Catalogue file | cisa.gov |
| CWE | Catalogue release files | cwe.mitre.org |
| CERT-In empanelment records | List of empanelled information security auditing organisations, with each organisation's snapshot of skills and competence (PDF), converted by `rdp convert-empanelment` | cert-in.org.in (`Empanel_org.pdf`), or as supplied by CERT-In |
| CERT-In register of identifiers and validity | Spreadsheet of the empanelled organisations with each one's CERT-In reference, AMBAK code and the date up to which its empanelment is valid, converted by `rdp convert-register` | As supplied by CERT-In (not published) |
| CERT-In advisories | Files supplied by CERT-In | CERT-In |

The workflow:

1. On the preparation host (outside the CERT-In environment):
   ```
   certin-benchmark rdp fetch --staging staging-<date>/ --epss-from 2021-04-14 --nvd-mirror "$PWD/nvd-mirror" \
       --cwe-releases cwe_releases.json                                   # first package
   certin-benchmark rdp fetch --staging staging-<date>/ --previous packages/RDP-<previous> \
       --nvd-mirror "$PWD/nvd-mirror" --cwe-releases cwe_releases.json      # later packages
   certin-benchmark rdp convert-empanelment Empanel_org.pdf --staging staging-<date>/ --set-date <received>
   certin-benchmark rdp convert-register register.xlsx --staging staging-<date>/ --register-date <received>
   # place CERT-In advisories (certin_advisories/advisories.json)
   certin-benchmark rdp build --staging staging-<date>/ --out-root packages/ --previous packages/RDP-<previous>
   certin-benchmark rdp keygen --private keys/rdp-signing.pem --public keys/rdp-signing.pub   # once
   certin-benchmark rdp sign packages/RDP-<date> --key keys/rdp-signing.pem
   ```
   `fetch` checks its arguments, the CWE release list and the previous package among them, before the first download. On a later package, `--previous` starts EPSS on the day after the previous package's last day and NVD history on the day before the UTC date of the mirror commit the previous fetch read; the day of overlap gives the same answers twice, where a gap would lose NVD's changes. Where the previous package holds no EPSS files or no NVD history, `--previous` fetches that source whole (EPSS from 2021-04-14, the mirror's history from its start), and `fetch` prints the window it reads. `--epss-from` and `--history-since` (read from midnight UTC of the date given) override it. `--history-since` is never given for a first package. Every file is written anew, as a temporary file renamed into place, so a later fetch never changes a package that shares EPSS files with the staging folder through hard links; a staging folder of its own for each package keeps each package's originals apart.
   The build validates the CVSS library against 3,264 reference vectors (the whole v3.1 base space and 672 v4.0 vectors; see `docs/VALIDATION.md`), verifies each source (NVD SHA-256 metadata, KEV structure, full parse, record counts against the previous package), carries forward any source that fails verification, and writes a manifest with retrieval times, publisher versions, file hashes, record counts and EPSS model versions. Each preparation is appended to `preparation_log.jsonl`. `--previous` is left out for the first package, and otherwise names a package (a folder holding its manifest). The build refuses NVD history read from a date when it is not given the package that history continues, when that package holds no NVD history, or when the history starts after the UTC date of the last mirror commit that package read; it also refuses NVD history staged without the `SOURCE.json` that describes it. Where a source's record count legitimately moves outside the expected range of the previous package's, `--accept-change <source>` accepts it and the manifest records the acceptance; without it the source is carried forward from the previous package. The sources are named `nvd`, `nvd_history`, `cve_list`, `epss`, `kev`, `cwe`, `certin_advisories`, `empanelment` and `empanelment_register`, and any other name is refused. A package is assembled in a hidden folder beside its place and renamed into it once complete. A build that fails therefore leaves nothing behind, and one killed outright leaves only its hidden folder (`.RDP-<date>.partial`), which the next build of that date removes. Temporary files left by an interrupted download (`.<name>.part`) are not copied into the package's originals. Packages built from the test fixtures hold synthetic empanelment records and are never named as `--previous` of a package for use.
2. Transfer on write-once media or through the approved unidirectional mechanism.
3. Inside the environment:
   ```
   certin-benchmark rdp import RDP-<date> --store /srv/rdp --key public.pem
   ```
   Import verifies the signature and every file hash, rejects unlisted files, and never overwrites an existing package. It copies the package into a hidden folder of the store and renames it into place once complete, so an interrupted import leaves nothing that could be taken for the latest package.

`convert-empanelment` writes `empanelment/set_<date>.json` with the PDF beside it, never overwrites an earlier set, and prints warnings for review. The list carries no date of its own, so the set is dated by the PDF's modification date unless `--set-date` (YYYY-MM-DD) gives the date the list was received. The converter reads each snapshot's section 7 table of named technical manpower, including rows the PDF's table structure leaves outside the table found on the page, people whose cells the document's merged cells divide into several rows, table bodies drawn offset from their headings, and words into which the PDF draws a stray space. Its warnings name, for review: snapshots that list no manpower (or give designations in place of names), directory entries without a snapshot, organisations with more than one snapshot (each kept with its date of declaration), section 7 serial numbers that are not in sequence, snapshots whose section 7 names more people than section 6 counts, and names that look divided inside a word. Every set received is kept: a set held in the previous package and no longer staged is carried into the new one, so that the set in force on any earlier release date can still be applied, and the record count is checked for the latest set against the previous package's latest set.

`convert-register` writes `empanelment_register/register_<date>.json` with the spreadsheet beside it, and never overwrites an earlier register. It finds the heading row by its headings (S.No., Code(Reference), AMBAK Code (Primary), Organisation Name, Empanelment Validity, and common variants; where two columns name the AMBAK code, the one marked Primary), fills merged cells, reads dates written as dates, as Excel serial numbers or as text, and keeps the former or other names a row gives ("Formerly ...", "Now ..."). It warns of a CERT-In reference or AMBAK code given to more than one row, a cell holding something other than one AMBAK code, an AMBAK code of another length than most or whose month is not 01 to 12, and rows without a code or a validity date, which are kept. Each row is numbered by its row in the sheet, with the sheet's own S.No. beside it. The register is dated by the day the spreadsheet was last saved, in India Standard Time (the workbook records the time in UTC), unless `--register-date` (YYYY-MM-DD) gives the date it was received. The build keeps every register received, as it keeps the sets, and links each row to the organisation of each set that it names, by name, former or other name, or, for a row whose name links to none, by the AMBAK code of a row of another register already linked; the manifest records, for the latest register and the latest set, the rows linked (and how many by AMBAK code) and any row naming no organisation of the set, or several. The register of 16 October 2026 links one to one with the 236 organisations of the list of 5 October 2026.

The first `fetch` clones the NVD mirror with its full history and reads it once, which is the slowest step of the first preparation; later preparations update the clone and read only synchronisations since the previous package, whose history rows are carried into the new one. Read from a date, the history also marks each record whose first state in the window lacks a value of some version; the build records that NVD removed the value only where the earlier packages held one. Before the mirror's values are used, the build compares the mirror's latest value of every CVE with NIST's own feed wherever both carry the same lastModified time; if more than 0.1% differ, the mirror's history is not used in that package. The comparison is recorded in the manifest.

Lookups follow Section 11.3: EPSS from the daily file for the reference date; KEV by date of addition; NVD scores from the NVD state in force on the reference date (each value holds from the record's lastModified date, from NIST's feeds or the mirror's history), and NVD CWE assignments from the latest package on or before the reference date; CWE validity from the catalogue in force on the date; advisories issued on or before the date; empanelment records from the set in force on the release date (by the identifier the report states, through CERT-In's register where it is an AMBAK code or CERT-In reference, or by the organisation's name; where an organisation has declared its manpower more than once, the declaration made on or before the release date); the organisation's identifiers and the validity of its empanelment from the register in force on the release date (the latest dated on or before it, else the earliest).

The format of the advisories file is defined in `src/certin_benchmark/refdata/build.py`, the empanelment set is the format written by `src/certin_benchmark/refdata/empanelment_pdf.py`, and the register the format written by `src/certin_benchmark/refdata/empanelment_register.py`; an advisory's `issued_on` is a date of the form YYYY-MM-DD. `rdp keygen` creates the Ed25519 key pair once: it creates the key's folder where needed, open to its owner alone, writes the private key readable by its owner only, and never replaces an existing key, since packages signed with it would no longer import. It refuses one path for both keys and a path already taken, a broken link included, and warns where an existing folder of the key can be read by others.

## Calibration (Section 8)

```
certin-benchmark calibrate split --strata strata.csv
certin-benchmark calibrate agreement --records suite_records/ --experts experts.csv --retest retest_records/
certin-benchmark calibrate fit-weights --records suite_records/ --experts experts.csv
```

The agreement report gives Cohen's kappa and precision of Fail per mandatory check, ICC(A,1) per criterion against the inter-expert bound, quadratic weighted kappa per language-model sub-dimension, Spearman correlation for the composite and test-retest ICC, each against its acceptance target. `all_targets_met` is true only when every measure is present and met. A check that misses its targets is placed in `referral_mode_checks` in `config/suite.yaml`.

## Status of the curated lists

Every name, date and identifier format in `curated/` was checked against the issuers on 12 October 2026, and the CERT-In documents supplied in October 2026 against CERT-In's site on 16 October 2026 (`docs/VALIDATION.md`). From those documents:

* the requirements of the CERT-In Directions dated 28 April 2022 are now the rows of CERT-In's document on methods of verification (file dated 22 March 2024), each with its method of verification (`curated/regulatory.yaml`); CERT-In's link to the document still returns "not found", so the copy supplied by CERT-In is the source;
* the Cyber Security Audit Baseline Requirements (NSCS-46-16 Rev 1.0) are recorded with their 68 markers in six categories and the markers recommended rather than mandatory for medium and low risk infrastructure (`curated/frameworks.yaml`);
* the CERT-In Guidelines for Secure Application Design, Development, Implementation & Operations (version 1.1, updated January 2024) are recognised as a supporting framework (§8(vii));
* the list of empanelled organisations is converted into the Reference Data Package (see above), replacing the synthetic records.

From the register and the report formats CERT-In supplied on 16 October 2026:

* CERT-In's register of the organisations' AMBAK codes, CERT-In references and validity of empanelment (16 October 2026) is converted into the Reference Data Package and read by MC-10 (items 20 and 24 to 26);
* CERT-In's audit report formats for compliance / regulatory audits and for technical security assessments are mapped to the master schema and the Suite's checks in `docs/REPORT_FORMATS.md`; the overall rating scale of their executive summary is in `curated/report_formats.yaml` and read by Q5 (item 27).

The following remain provisional until CERT-In supplies or confirms them:

* the 282 control points of the MeitY Comprehensive Audit Program Checklist, which is not published (empty; MC-07 counts distinct assessed identifiers until the list is supplied);
* the controlled list of sectors and the mandatory regulations for each, which carry the dates they are in force (the RBI Directions of 31 July 2026 and the CEA Regulations, 2026 change the banking, NBFC and power entries), and the two sectors added for rows 3 and 4 of the methods of verification;
* the designation lists for mid-management, the head of an organisation and prohibited categories, and the mapping of qualifications to engagement modules;
* the CERT-In advisories file and auditee feedback, which are not yet supplied;
* the register's AMBAK codes, references and validity dates, which CERT-In does not publish and which therefore cannot be checked against its site, in particular one reference given to two organisations and one AMBAK code of a form unlike the others (`docs/VALIDATION.md`).

## Interpretations for confirmation with CERT-In

The specification leaves the following points open. The code takes the reading stated here; each is a configuration or a single function and can be changed on CERT-In's direction.

1. **MC-08 and MC-10.** Fail is returned automatically only where a required signature is absent. Every determination about a person (membership of the audit team, mid-management designation, head of organisation, declaration in the empanelment records) returns Indeterminate and becomes Fail on the reviewer's confirmation through `--overrides`. MC-09 treats a signatory's role mismatch the same way. See also item 20.
2. **MC-13 and the web and mobile modules** do not require a version and hash for an asset recorded as inaccessible under MC-11.
3. **MC-14** also requires the current `report_version` to appear in the version history.
4. **MC-19** requires `notified_on` and fails where it is later than the assessment end date.
5. **MC-01** accepts a severity of None or Informational for a CVSS score of 0.0.
6. **MC-05** treats the Cyber Security Audit Baseline Requirements as a comprehensive framework, and NIST SP 800-115, PTES and the CERT-In Directions as supporting methodologies that do not satisfy MC-05 on their own.
7. **Q1.** Where no tool is named in the proof-of-concept descriptions, tool disclosure is measured over the declared tools. The duration item is met by assessment dates or man-hours.
8. **Q2.** "Not applicable" with a reason scores 100, except on the requirements of the methods of verification (item 19), where it scores 50 if the requirement applies to the auditee and is otherwise not scored. A non-compliant sector entry without linked findings is limited to 50. Where the sector is not stated, R is excluded and the report is referred.
9. **Q3.** The expertise denominator is the members recorded as in the audit team. Components are renormalised before the D_pro deduction. A trainee counts as a fresher.
10. **Q4.** Substantive text is at least three words. The executive summary's asset reference for a finding is counted among that finding's asset references. Evidence declared redacted scores 100 on redaction without assessment. A retest captured on or before the original evidence scores 0 on distinctness without sampling.
11. **Q6.** Plausibility variance is measured on the inferred CVSS rating band (0 to 4) against the same v_max.
12. **Q7.** P_d is the share of the day's scores at or below the reported score, as FIRST defines its percentile. CWE parent or child means a direct ChildOf relation in view 1000. An observation with no evaluable check is left out of the mean.
13. **Q8.** A category excluded with a reason is not penalised under CA (Section 6.8, final paragraph), since the schema does not record who made the exclusion.
14. **Section 10.1.** An obligation is reported Pass, Fail or Not recorded. A missing conference or Board presentation date is Not recorded.
15. **Sampling.** v_max = 0.8 and a minimum of three valid ratings are initial values for calibration.
16. **NVD values before the earliest recorded state.** NVD's value on a date is known only from the earliest state recorded for that CVE: the record's lastModified date in the mirror's first synchronisation (24 April 2023) or in NIST's feed. For an earlier date the Q7 CVSS accuracy check of that CVE is not evaluable and is excluded, as Section 6.7 provides for a check with no authoritative value. Reports with observations from 2021 and 2022 are affected where NVD changed the record after the observation.
17. **NVD mirror.** NVD's earlier values come from Fraunhofer FKIE's mirror of NVD records rather than from NIST, since NIST's CVE feeds carry only each record's current values and its change history is served through a query API. The build checks the mirror against NIST's feed before use (see the Reference Data Package). CERT-In's acceptance of the mirror as a source under Section 11.2 is to be confirmed.
18. **CVSS v4.0 rounding.** Scores that are exact halves (522 of 104,976 base vectors) are rounded half up, as the `cvss` library and Red Hat's corrected reference calculator do. The August 2024 calculator snapshot in FIRST's GitHub organisation gives 0.1 less for these vectors.
19. **Directions (Q2, D).** The requirements "as enumerated in the CERT-In document on methods of verification" are its rows 1 to 5: NTP synchronisation (Direction (i)), incident reporting within 6 hours ((ii)), subscriber records of data centre, VPS, cloud and VPN providers ((v)), KYC records of virtual asset service providers ((vi)) and logs kept for 180 days ((iv)). The two numberings differ (row 3 is Direction (v), and Direction (iii) has no row), and reports use both, so an entry is assigned as follows. An identifier that names its numbering ('MoV-3', 'DIR-v', 'Row 3', 'Direction 5') is followed, unless the entry's text matches another requirement best, when the entry is referred with both. Otherwise the text decides where one requirement matches best; failing that, a number that means the same in both numberings (1 and 2, or i and ii). A number from 3 to 6 alone, Arabic or Roman (including 'S. No. 3', usually the report's own serial number), or text that matches two requirements equally, is referred to the reviewer, and the rows it may be are left unscored rather than scored "not assessed". Rows 3 and 4 apply to the auditee where its sector or name establishes that it provides those services, or where the report assesses them (compliant, partially compliant or non-compliant); where neither, they are not scored, and an entry recording them "Not applicable" or "Not assessed" is noted without credit or penalty. "Not applicable" on a row that applies (rows 1, 2 and 5 always) scores 50 with a deficiency. Row 6 (the requirements communicated to the auditee and included in the report) is met by the verification in the report itself (MC-06). Direction (iii), the Point of Contact, has no row: an entry for it is accepted but not scored. The requirement and the methods of verification of each row, word for word, are given to the language model when it judges whether an entry's evidence relates to the requirement.
20. **MC-10 and CERT-In's list.** CERT-In's list gives no identifier, no period of validity and, for most organisations, no designations (the converted list of 5 October 2026 has designations for 165 people in 8 organisations); CERT-In's register supplies the identifiers and validity (items 24 and 25). Without an identifier the register holds, the organisation is found by name: exact after normalisation of case, "M/s", punctuation and legal-form words, against every name under which the list shows it, or under which the register gives it (item 25). A name that does not correspond exactly, or corresponds to more than one organisation, returns Indeterminate with the closest names in the list. A person is found by exact name after normalisation of case, dots, hyphens, leading honorifics and service ranks (Mr, Mrs, Ms, Dr, Shri, Smt, Sri, Kumari, Er, Col., Lt., Maj., Cdr., "(R)") and the numerals some lists set after a repeated name ("Amit Kumar 2"); other punctuation, initials and spellings are compared as written. "Valid" is read as listed in the set in force on the release date and, where a register is held, within the validity the register in force records (item 24). Where an organisation's snapshot lists no manpower (marked confidential, in an annexure not in the list, or designations given in place of names), MC-10 returns Indeterminate. MC-08 relies on the designations stated in the report.
21. **Q3 (EX) and declared qualifications.** Where the credentials a report states for a member do not establish expertise for the declared audit types, the qualifications declared for that member to CERT-In are read (Section 11.1), and `expertise_source` in the record says which was used. They are not read where the list declares more than one person of that name with different particulars, and the record notes a declaration dated after the release date. Credentials stated in the report but not among those declared are noted for the reviewer and do not reduce the score.
22. **Module checks added from CERT-In's documents.** Five checks not in the table of Section 9 are applied under Q8 (MD), each recorded with its basis and flagged as pending confirmation. Where an application is audited (an application audit type is declared, or a web, mobile or API asset is tested): compliance with CERT-In's Guidelines for Secure Application Design, Development, Implementation & Operations is assessed, each practice with evidence and each "Not applicable" with a reason (key recommendation iv; the guidelines are the document §8(vii) names); the certificate identifies the certified applications with version and hash, and gives its date (vi; §9.5(i), §16.1(v)); where production was not tested, the certificate states that the audit was not conducted on the production environment (x; §16.3(v) asks the same of the final report, which MC-12 checks); and the certificate is issued on or after the end of revalidation (x). In every compliance audit, the Baseline Requirements are assessed: each of the 50 markers mandatory for every risk profile has an entry with a compliance status, read as one check (Tables 2 to 4; §8(iii); Section 9 expects the Baseline under every module). Removing them from `curated/modules.yaml` applies the table of Section 9 alone.
23. **Baseline markers.** The report does not state the auditee's risk profile, so the Baseline check requires the 50 markers mandatory for every profile. The other 18 are mandatory for high risk infrastructure, and 12 of them for medium risk; if CERT-In wishes, the profile can be added to the schema and the check made to follow it.
24. **Validity of empanelment (MC-10).** The register gives the date up to which each organisation's empanelment is valid, not the date from which it runs. MC-10 applies the register in force on the release date (on the assessment end date where no release date is stated, as the record says). A release date after the date it records is referred with that deficiency, naming any later register that records a renewal, whose date of renewal it does not give. Where the register in force no longer holds an organisation that an earlier register held, the latest earlier register is read: a validity that ended before the release date is referred as above, and one that had not ended is referred as an organisation dropped from the register. Each becomes Fail only on the reviewer's confirmation, since Section 5 allows MC-10 to fail only so. For a release date before the earliest register held, the earliest is applied and noted; it says when the empanelment ends, not when it began. An organisation that no register up to the release date holds is noted, without a deficiency. Where a register lists an organisation more than once, its identifiers are read from the row whose code the report states (else the row valid longest) and its validity from the row valid longest, and this is noted.
25. **Identifiers (MC-10).** `certin_empanelment_id` is read as the set's own identifier, an AMBAK code or a CERT-In reference, with or without words such as "AMBAK Code:" or "CERT-In" before it. A reference is compared by its letters and numbers in order, ignoring case, the spaces and punctuation between them and leading zeros ("RE-2099-07" and "RE 2099 7" are the same; "F2099002" is not "F-2099-002"). A code one register gives to more than one organisation identifies none, and the organisation is then found by name; across registers a code is taken to stay with its organisation unless rows of different registers are linked to different organisations of the set. An identifier and a name that denote different organisations are referred, including an identifier of an organisation the set in force does not list. Where the identifier finds the organisation and the name does not correspond to the records, the identifier is followed and the name noted. A name the list does not show but the register gives, a new name or a former one, finds the organisation through the register (the register of 16 October 2026 gives one organisation's new name, with the former name under which the list of 5 October 2026 shows it). The evaluation record carries the organisation's AMBAK code and reference (`auditing_organisation`), by which Objective 4 can group an agency's reports.
26. **"Listed on CERT-In Website (Y/N)" (MC-10).** CERT-In's report formats ask for this column in the audit team table; master schema v2 has no field for it, and the Suite reads `auditing_team[].listed_on_certin_website` where Objective 1 supplies it, beside the records and never in their place. A person the report itself marks "N" and the records do not list is referred with that statement; one marked "Y" and not found is referred, the deficiency saying so; one marked "N" but declared is noted. Where the records cannot be read for the organisation, the persons the report marks "N" are noted. A value extracted below the confidence threshold is not read, and does not hold MC-10 back.
27. **Overall rating (Q5, K).** CERT-In's report formats rate a report on four levels (Well Controlled / Strong, Adequately Controlled / Moderate, Needs Improvement / Weak, Unsatisfactory / Critical) with severity criteria for each. K is also set to 0 where the stated rating is better than the Critical and High findings not closed allow: none for Strong; no Critical and at most two High for Moderate; no Critical and at most five High for Weak. A rating is recognised by the level's words ("Medium" for Moderate), or as "<level> risk". It is not compared where it names two levels in any way ("Moderate to High"), is a bare "High" or "Low" (which do not say which way the scale runs), or carries a negation ("Not Strong"); nor where a Critical or High finding states no status, or a severity or status was extracted below the confidence threshold. A status beginning "Closed" is closed, and C and H are read as Critical and High. The criteria on Medium and Low findings, systemic failures and repeated issues overlap between levels and are left to judgement. Section 6.5 defines K by the summary table and counts alone, so this addition is pending CERT-In's confirmation; `apply_in_q5: false` in `curated/report_formats.yaml` removes it.

## Known limitations

* Image proof-of-concept entries need Objective 1's deep storage (or the image files) and a vision model. Without them those entries are not evaluated and the composite score is provisional.
* CWE validity as at a past date depends on every CWE release since that date being staged; `rdp fetch --cwe-releases` takes the list.
* The KEV catalogue is checked against the required fields and patterns of CISA's published schema in code rather than with a JSON Schema validator, to avoid a further dependency.
* `rdp fetch` needs `git` on the preparation host. Inside the CERT-In environment `git` is not needed.
* `rdp fetch` stops at the first file that still cannot be downloaded after four tries, leaving the later sources unfetched, and a rerun downloads every source again (with `--no-history` it keeps NVD history already extracted).
* Engagement module checks for third-party certificates, network devices, pipelines and forensics use curated keyword lists in `curated/modules.yaml`.
* The empanelment converter reads the layout of CERT-In's list as published in October 2026 (a directory, then a snapshot per organisation in thirteen numbered sections, the manpower in section 7). On that list it reads every snapshot's people as the list numbers them, and the names and particulars checked against the PDF are read correctly (`docs/VALIDATION.md`); a name the list breaks inside a word across two lines of its cell is read as written there, with a warning. A different layout may be read wrongly without a warning; the warnings (serial numbers out of sequence, more people named than counted, names divided inside a word) catch most such errors, and the people read should be checked against the list before a new layout is relied on. A person listed in an annexure that is not in the PDF, or under an organisation whose manpower is marked confidential, cannot be verified and leaves MC-10 Indeterminate.
* Manpower names are compared as written, apart from the normalisation above. A person listed under a different spelling or with initials expanded is referred for review rather than matched.
* The register's identifiers and validity are taken as CERT-In supplies them: CERT-In does not publish them, so they could be checked against its site only for the organisations' names (`docs/VALIDATION.md`). The register gives no date from which an empanelment runs.

## Tests

```
python3 -m unittest discover -s tests -p 'test_*.py'
```

`tests/fixtures/staging.py` builds a synthetic package (NVD, a miniature git repository in the layout of the NVD mirror, CVE List, EPSS, KEV, CWE, advisories, and empanelment records in the converter's format) that is signed and imported before the tests run. `tests/fixtures/sample_report.json` is a complete master schema v2 report. `tests/test_certin_documents.py` builds a small list in the layout of CERT-In's PDF with `reportlab` and converts it; the test is skipped where `pdfplumber` or `reportlab` is not installed. No real CERT-In list is held in the repository.
