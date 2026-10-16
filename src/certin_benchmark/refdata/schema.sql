-- Normalised tables of the Reference Data Package (Suite Section 11.2, step 3).

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- NVD CVSS. Each row is a value NVD held from valid_from (the record's lastModified date).
-- source = 'feed': from NIST's feeds, with the date of the package that recorded it (package_date);
-- source = 'history': from the git history of the NVD mirror, without a package_date.
CREATE TABLE IF NOT EXISTS nvd_cvss (
    cve_id TEXT NOT NULL, version TEXT NOT NULL, score REAL, vector TEXT,
    package_date TEXT, valid_from TEXT, source TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_nvd_cvss ON nvd_cvss (cve_id, version, source, package_date, valid_from);

-- CWE assigned to each CVE, by NVD or by the CVE Numbering Authority
-- NVD rows carry the date of the package that recorded the assignment, as for nvd_cvss
CREATE TABLE IF NOT EXISTS cve_cwe (cve_id TEXT NOT NULL, cwe_id INTEGER, assigner TEXT NOT NULL, package_date TEXT);
CREATE INDEX IF NOT EXISTS ix_cve_cwe ON cve_cwe (cve_id);

-- CVSS assigned by the CNA where NVD has none (CVE List)
CREATE TABLE IF NOT EXISTS cna_cvss (cve_id TEXT NOT NULL, version TEXT, score REAL, vector TEXT);
CREATE INDEX IF NOT EXISTS ix_cna_cvss ON cna_cvss (cve_id);

CREATE TABLE IF NOT EXISTS cve_list (
    cve_id TEXT PRIMARY KEY, state TEXT, date_reserved TEXT, date_published TEXT, date_rejected TEXT
);

CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY, date_added TEXT);

CREATE TABLE IF NOT EXISTS cwe (
    cwe_id INTEGER PRIMARY KEY, name TEXT, kind TEXT, status TEXT, first_seen TEXT, deprecated_on TEXT
);
CREATE TABLE IF NOT EXISTS cwe_parent (child INTEGER NOT NULL, parent INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_cwe_parent_c ON cwe_parent (child);
CREATE INDEX IF NOT EXISTS ix_cwe_parent_p ON cwe_parent (parent);
CREATE TABLE IF NOT EXISTS cwe_release (version TEXT PRIMARY KEY, release_date TEXT);

CREATE TABLE IF NOT EXISTS advisory (advisory_id TEXT PRIMARY KEY, issued_on TEXT, title TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS advisory_cve (advisory_id TEXT NOT NULL, cve_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_advisory_cve ON advisory_cve (cve_id);
CREATE TABLE IF NOT EXISTS advisory_product (advisory_id TEXT NOT NULL, product TEXT NOT NULL);

-- CERT-In empanelment records: one set per list received from CERT-In (set_date). The list gives no
-- identifier for an organisation; org_id is derived from its name, and empanel_org_name holds every
-- normalised form of the name under which it is listed. A person carries the date of the organisation's
-- declaration ("Information as provided ... on"), where the list holds more than one for it.
CREATE TABLE IF NOT EXISTS empanel_org (
    set_date TEXT NOT NULL, org_id TEXT NOT NULL, org_name TEXT, valid_from TEXT, valid_to TEXT,
    list_no INTEGER, information_as_on TEXT, personnel_listed INTEGER, manpower_statement TEXT, details TEXT
);
CREATE INDEX IF NOT EXISTS ix_empanel_org ON empanel_org (org_id, set_date);
CREATE TABLE IF NOT EXISTS empanel_org_name (set_date TEXT NOT NULL, org_id TEXT NOT NULL, name_norm TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_empanel_org_name ON empanel_org_name (name_norm, set_date);
CREATE TABLE IF NOT EXISTS empanel_person (
    set_date TEXT NOT NULL, org_id TEXT NOT NULL, name TEXT, name_norm TEXT, designation TEXT,
    qualifications TEXT, experience TEXT, experience_years REAL, with_organisation TEXT, declared_on TEXT
);
CREATE INDEX IF NOT EXISTS ix_empanel_person ON empanel_person (org_id, set_date, name_norm);

-- CERT-In's register of the empanelled organisations: CERT-In reference, AMBAK code and the date up to which the
-- empanelment is valid, one register per sheet received (register_date; row_no is the row of the sheet, serial
-- its S.No.). empanel_register_name holds every normalised form of each row's name, former and other names
-- included; empanel_register_link ties each row to the organisation of each set that it names (or, failing a
-- name, whose AMBAK code it shares with a linked row), and is rebuilt with every package.
CREATE TABLE IF NOT EXISTS empanel_register (
    register_date TEXT NOT NULL, row_no INTEGER NOT NULL, serial TEXT, ambak_code TEXT, certin_ref TEXT,
    certin_ref_norm TEXT, org_name TEXT, valid_to TEXT, former_names TEXT, other_names TEXT
);
CREATE INDEX IF NOT EXISTS ix_empanel_register_ambak ON empanel_register (ambak_code);
CREATE INDEX IF NOT EXISTS ix_empanel_register_ref ON empanel_register (certin_ref_norm);
CREATE TABLE IF NOT EXISTS empanel_register_name (register_date TEXT NOT NULL, row_no INTEGER NOT NULL, name_norm TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_empanel_register_name ON empanel_register_name (name_norm, register_date);
CREATE TABLE IF NOT EXISTS empanel_register_link (
    register_date TEXT NOT NULL, row_no INTEGER NOT NULL, set_date TEXT NOT NULL, org_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_empanel_register_link ON empanel_register_link (set_date, org_id);

-- Original publisher records, zlib-compressed, retained alongside the normalised fields
CREATE TABLE IF NOT EXISTS publisher_record (source TEXT NOT NULL, key TEXT NOT NULL, record BLOB);
CREATE INDEX IF NOT EXISTS ix_publisher_record ON publisher_record (source, key);
