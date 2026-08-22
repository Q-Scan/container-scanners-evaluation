# Analysis: adjudicating precision and recall

## Source of truth - one rule per layer

| layer | source of truth | note |
|---|---|---|
| **narrative, conclusions, figures** | `evaluation_analysis.ipynb` (English) | edited **by hand**; the only notebook |
| **Polish figures** | `figures/pl/` | same notebook, run with `FIG_LANG=pl`; labels from the inline `T()` dict in the notebook |
| **parsers, `GROUND_TRUTH`** | `scanlib.py` (hand-authored) | the single place parsing lives; imported by the notebook **and** the scripts |
| **the numbers** | `analysis/*.py` -> `data/*.csv` | the scripts query OSV / Red Hat and write CSVs |
| **artifacts** | `data/`, `figures/` | versioned so the notebook runs **offline** |

`scanlib.py` is the shared parsing layer; the numbers flow one way, scripts -> `data/*.csv` -> notebook:

```
                    scanlib.py   (parsers + constants, hand-authored)
                   /                                    \
       from scanlib import ...                   from scanlib import ...
            the notebook                             analysis/*.py
                 ^                                        |
                 |                                        v
                 +---------- the notebook reads ------  data/*.csv
```

### Who makes what - the one boundary that matters

| | where it happens | where it does **not** |
|---|---|---|
| **Figures** (`figures/en`, `figures/pl`) | **the notebook, and only the notebook** - the `save_fig()` calls in its code cells | no script in `analysis/` imports matplotlib or plots anything; `save_fig` and the palette live in the notebook's first cell |
| **Numbers** (`data/*.csv`) | **`analysis/*.py`, and only those** - the adjudication scripts call `to_csv()` | the notebook **never writes** to `data/`; it contains zero `to_csv()` calls and only reads |

So: **`analysis/` computes, the notebook narrates and draws.** A figure is never produced outside the
notebook, and a number is never computed inside it. That is what lets the notebook run offline in seconds
(everything expensive - OSV, Red Hat - already happened in `analysis/` and is frozen in `data/`), and it is
why a changed figure can never silently change a result.

To regenerate figures you re-execute the notebook (see below); to regenerate numbers you re-run the scripts.
The two are independent.

The notebook covers detection counts, scanner agreement, SBOM behaviour and **recall** - both the five
injected reference vulnerabilities (§4) and, in §6, a pooled cross-scanner reference. This directory adds
**precision**, confronting every finding with an independent source of truth (OSV for the whole application
layer — Maven, Go and PyPI — and the Red Hat Security Data API for RPMs).

## Files

| file | role | produces |
|---|---|---|
| `scanlib.py` | shared parsers (Trivy/Grype/Snyk/Scout -> one schema), `GROUND_TRUTH`, `load_all()`; imported by the notebook and every script | - |
| `sanitize_results.py` | strips personal data from `results/` before publishing; `--check` proves no number changed | - |
| `osv_adjudicate.py` | application-layer precision against OSV across **all ecosystems** (Maven via an inlined comparator; Go/PyPI via OSV `querybatch`) | `app_precision_findings.csv` |
| `os_adjudicate.py` | OS-layer precision (RPM) against Red Hat; inlines an RPM version comparator | `os_precision_findings.csv` |

## How the adjudication works

Both scripts have the same shape. Two **independent** inputs meet in `classify()`:

```
results/  (the scanners' raw reports)  --parsers-->  FINDINGS ---+
                                                                 +--> classify() --> data/*_precision_findings.csv
oracle API  (OSV / Red Hat)  --queries-->  CACHE  --------------+
```

* **FINDINGS** are what the **scanners** claim. Built from local files in `results/` via the `scanlib` parsers, **direct scans only** (`input='direct'`, never SBOM-based), across **all four scanners**. No network.
* **CACHE** is what the **oracle** knows. One JSON file of raw API responses, kept so a rerun works **offline**. The notebook never reads it - it exists only for the scripts.
* **CSV** is every finding **confronted** with its cache entry: the scanner side plus a `verdict` / `reason`.

Findings come first (they define what to ask the oracle about), then the cache, then the verdict.

### What a finding looks like

One row per **(image, scanner, CVE, package)**. The left columns come from the scanner, the right ones (`verdict`, `reason`, ...) are added by `classify()`.

`app_precision_findings.csv` (Maven layer):

| image | ecosystem | scanner | cve | coord | version | severity | verdict | reason | osv_range | year |
|---|---|---|---|---|---|---|---|---|---|---|
| DOCKERFILE-jvm | Maven | Trivy | CVE-2026-54512 | `com.fasterxml.jackson.core:jackson-databind` | 2.20.1 | HIGH | TP | version listed in OSV versions[] | versions[13] | 2026 |

`os_precision_findings.csv` (OS / RPM layer):

| image | scanner | cve | package | src | version | severity | verdict | reason | advisory |
|---|---|---|---|---|---|---|---|---|---|
| BUILDPACK-jvm | Trivy | CVE-2026-25068 | alsa-lib | alsa-lib | 1.2.10-2.el8 | MEDIUM | TP-nofix | Red Hat: Fix deferred | *(empty)* |

The differing columns are the differing match key: app matches on `coord` (the package coordinate - Maven `group:artifact`, a Go module path, or a PyPI name), OS matches on `package`/`src` (RPM names) plus the RHEL major.

### How we query OSV

OSV is queried **by package, not by CVE** - CVE->GHSA aliases are sometimes one-directional (see trap 1 below). Three endpoints:

```
# 1. main - every advisory for a coordinate (builds the cache, one call per coordinate)
POST https://api.osv.dev/v1/query
{"package": {"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind"}}

# 2. single record - resolve GHSA -> CVE, and "does OSV know this CVE for Maven at all?"
GET  https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx

# 3. querybatch - settles the version for Go/PyPI (OSV does the version math, no comparator needed)
POST https://api.osv.dev/v1/querybatch
{"queries": [{"package": {"ecosystem": "Go", "name": "golang.org/x/net"}, "version": "0.20.0"}, ...]}
```

Maven is adjudicated by the coordinate index (query #1) plus the inlined Maven comparator. Go and PyPI are
adjudicated straight from `querybatch` (query #3): OSV reports which CVEs apply to that exact version, so no
Go/PyPI version comparator is written.

### How we query Red Hat

One endpoint, **by CVE**, one CVE at a time (the record is self-contained), one call per unique CVE in the findings. A `User-Agent` header is required:

```
GET https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2018-20657.json
User-Agent: container-scanner-evaluation/1.0 (academic research)
```

### Query shapes side by side

| | OSV | Red Hat |
|---|---|---|
| queried by | **package** (`group:artifact`) | **CVE** |
| why | CVE->GHSA aliases are one-directional | the CVE record is complete on its own |
| endpoints | 3 (`query`, `vulns/{id}`, `querybatch`) | 1 (`cve/{id}.json`) |
| calls | 1 per coordinate (+ batch on 1 image) | 1 per unique CVE |
| headers | none | `User-Agent` mandatory |

### Precision in the scripts, recall in the notebook

The scripts adjudicate each **reported** finding as TP or FP. Recall and false negatives are inherently
cross-scanner, so they are derived in the **notebook** (§6), not the scripts: per (image, layer) the **pooled
union** of TP-adjudicated CVEs is the confirmed reference, and each scanner's FN = confirmed CVEs it did not
report. This is *relative* recall - a CVE missed by all four tools cannot enter the union, so recall is an
upper bound. It complements the absolute-but-narrow recall of the 5 injected reference CVEs.

## Reproducing

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt jupyter
.venv/bin/python analysis/osv_adjudicate.py      # -> data/app_precision_findings.csv
.venv/bin/python analysis/os_adjudicate.py       # -> data/os_precision_findings.csv

FIG_LANG=pl .venv/bin/python -m jupyter nbconvert --to notebook \
    --execute evaluation_analysis.ipynb --stdout >/dev/null   # -> figures/pl/
FIG_LANG=en .venv/bin/python -m jupyter nbconvert --to notebook \
    --execute evaluation_analysis.ipynb --inplace             # -> figures/en/
```

The caches (`data/osv_cache.json`, `data/redhat_cache.json`) are versioned, so a repeat run works **without
network access**. `--refresh` forces the sources to be queried again. The oracle snapshots carry their own
date, separate from the July 2026 scans: the OSV application-layer data (Maven, Go, PyPI) was captured in
**August 2026**.

> `figures/` holds **PDFs only** (vectors for LaTeX) in two language directories - raster previews are already
> embedded in the notebook, so PNGs would be a duplicate. The writer is **deterministic**
> (`metadata={'CreationDate': None}` in `save_fig`), so re-running the notebook produces **byte-identical**
> files and does not pollute the diff.

## Structure of the notebook

The notebook is organised into six sections, numbered from 1:

| section | topic |
|---|---|
| **1** | Identifier normalization (the comparison unit) |
| **2** | Detection counts and severity profile |
| **3** | Scanner agreement (3.1 CVE overlap, 3.2 severity disagreement) |
| **4** | Image-variant detections (4.1 build method, 4.2 JVM vs native, 4.3 size) |
| **5** | SBOM scanning (5.1 retention, 5.2 inventory divergence, 5.3 format control) |
| **6** | Effectiveness (precision + recall) against reference sources (6.1 direct scans, 6.2 SBOM scans) |

### Which figures this directory feeds

Of the notebook's **12 figures**, this directory's CSVs feed only `fig10`, `fig11` and `fig12` (§6,
precision + recall). The other nine come from the scan data alone. Every figure is written by `save_fig()`
in the notebook section that produces it - that is the only place it exists; see the notebook for the full
figure-to-section map.

## Traps that had to be avoided

Each of these produces a **silently** falsified result - not an error, just a wrong number.

1. **You cannot adjudicate by CVE identifier** (OSV). The `GET /v1/vulns/CVE-...` record is often ecosystem-empty:
   `CVE-2015-6420` is a stub with no `affected[]` **and no aliases**, while all the Maven content lives in
   `GHSA-6hgm-866r-3cjv`, which points to the CVE - not the other way round (OSV aliases are sometimes
   **one-directional**). So we query **coordinate -> advisory** (`POST /v1/query` by package). The first approach,
   "by CVE", produced **100% undecidable** - a result that looked perfectly sensible.
2. **Package names are not comparable across scanners.** Trivy/Snyk emit `group:artifact`, Grype/Scout the bare
   `artifactId`; OSV keys on `groupId:artifactId`. We recover coordinates from the **purls**, not from the `package`
   field.
3. **The RPM epoch.** Grype states it plainly (`1:1.1.1k-15.el8_6`), Scout **URL-encodes** it
   (`1%3A1.1.1k-14.el8_6`), and Trivy and Snyk **omit it entirely**. Red Hat always gives the full NVR with the
   epoch. Without normalisation, every Trivy/Snyk finding for a package with epoch > 0 looks older than it is. The
   rule: compare epochs only when **both** sides supply one.
4. **Binary vs source package.** Scanners report `openssl-libs`; Red Hat keys on the `openssl` component. We recover
   the map from the `upstream=` field in Grype's purl.
5. **Versions do not compare lexicographically.** `4.1.9.Final` > `4.1.128.Final` as text; RPM `release 15` >
   `release 9`. Hence the dedicated Maven and RPM version comparators inlined in `osv_adjudicate.py` and
   `os_adjudicate.py`.

## Results in brief

Numbers below are recomputed from the frozen CSVs in `data/`; the authoritative narrative lives in the notebook.

* **Application layer** (OSV, **all ecosystems** Maven+Go+PyPI, 5 JVM images, per-image reference of **318
  confirmed CVEs**): precision is 95.9-100%; recall is **99.7%** Scout, **97.5%** Grype, **96.5%** Trivy,
  **74.2%** Snyk. The gap is ecosystem-specific — on the **Go** modules of the buildpack lifecycle (72 CVEs)
  Trivy/Grype/Scout all reach 98.6-100% while **Snyk gets 2.8%** (2 of 72), and the PyPI packages (setuptools)
  are reported **only** by Scout in direct scans.
  Maven alone is ~98-100% for everyone. (`osv_adjudicate.py` multi-ecosystem + notebook, `fig10`/`fig12`.)
* **OS layer** (Red Hat, 7 images, pooled reference of **1381 confirmed CVEs**, 67% no-fix): Trivy, Grype and
  Snyk reach **99.3-99.9%** precision and **99.2-99.8%** recall. Docker Scout collapses to **83.6%** precision
  and **25.6%** recall, missing **1028** confirmed CVEs (as low as 7.6% recall on `DOCKERFILE-jvm`).
  (`os_adjudicate.py` + notebook, `fig11`.)
