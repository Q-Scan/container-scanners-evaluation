# Container image vulnerability scanner evaluation

The same Quarkus application (Java 21),
carrying **five deliberately introduced vulnerabilities**, was built **9 ways** (5 x JVM, 4 x GraalVM
native) and scanned with **4 scanners** (Trivy, Grype, Snyk, Docker Scout) through **4 input modes**
(the image itself + SBOMs from 3 generators).

The five reference vulnerabilities (snakeyaml, commons-text, dom4j, commons-collections,
commons-fileupload) are defined once in `analysis/scanlib.py` as `GROUND_TRUTH`; a sixth, transitive one
(the pgjdbc driver, `CVE-2026-42198`) is documented in the app repo.

## What lives where

This is one of three pieces of the project:

| piece | what it is | where |
|---|---|---|
| **the app** | the vulnerable Quarkus target + its 9 build variants | separate repo: [`Q-Scan/vulnerable-quarkus`](https://github.com/Q-Scan/vulnerable-quarkus) |
| **the images** | the exact 9 scanned images, prebuilt | Docker Hub: [`pgorgolew/q-scan`](https://hub.docker.com/r/pgorgolew/q-scan) |
| **this repo** | the scans, the adjudication, the analysis and every figure | here |

Start at [`evaluation_analysis.ipynb`](evaluation_analysis.ipynb) - the full analysis and every conclusion
(identifier normalization, detection counts, scanner agreement, image-variant detections, SBOM scanning,
precision and recall). The numbers it reads come from `analysis/`; the adjudication methodology is in
[`analysis/README.md`](analysis/README.md).

## Two figure languages, one notebook

| | |
|---|---|
| `evaluation_analysis.ipynb` | **the single source** - edited by hand; its prose is in English |
| `figures/en/`, `figures/pl/` | 12 vector PDFs each, produced from the *same* code |

Figure labels go through a small inline `T()` in the notebook's first cell, driven by the `FIG_LANG`
environment variable, so one notebook renders both languages - run it once per language. The Polish strings
are a dict right next to `T()`, keyed by the English string; an untranslated label falls back to English and
is listed by `report()` in the notebook's last cell, so a half-translated figure set cannot pass unnoticed.

```bash
FIG_LANG=pl jupyter nbconvert --to notebook --execute evaluation_analysis.ipynb --stdout >/dev/null  # -> figures/pl/
FIG_LANG=en jupyter nbconvert --to notebook --execute evaluation_analysis.ipynb --inplace            # -> figures/en/ (+ refresh inline outputs)
```

## What is in the repository

| | |
|---|---|
| `evaluation_analysis.ipynb` | the analysis, the narrative and the conclusions |
| `analysis/` | the scripts that compute the results (adjudication against OSV / Red Hat) |
| `figures/en`, `figures/pl` | 12 figures per language, vector PDFs for LaTeX |
| `Makefile`, `install/` | running the scans, installing the tools |
| **`results.zip`** (19 MB) | **the raw scanner reports** - 191 files, unzip into `results/` |
| **`data.zip`** (6.5 MB) | **the frozen oracle cache** (OSV incl. Go/PyPI + Red Hat) + the adjudication CSVs, unzip into `data/` |

`results/` and `data/` are in `.gitignore` - we keep them **zipped** so that git history stays light. Without
unzipping them **the notebook will not run** (cell 3 reads `results/`).

> ### Why the data is frozen rather than regenerated
>
> **Re-running the scans will produce different numbers.** The vulnerability databases of Trivy, Grype, Snyk and
> Scout, and the adjudication sources (OSV, Red Hat), change **daily**. The scans in `results.zip` were
> taken in **July 2026** and they are the primary evidence of this study - they cannot be reproduced, only
> repeated against a new state of the world. The reference-source snapshots in `data.zip` carry their own
> date, separate from the scans: the OSV application-layer data (Maven, Go and PyPI) was captured in
> **August 2026**.
>
> To **verify the published numbers** -> path A (unzip the archives).
> To **repeat the experiment today** -> path B; the results will differ, and that is correct.

---

## Path A - reproduce the published results (offline, ~2 min)

```bash
git clone https://github.com/Q-Scan/container-scanners-evaluation.git
cd container-scanners-evaluation

unzip results.zip          # -> results/   raw scanner reports
unzip data.zip             # -> data/      oracle cache + adjudication CSVs

python -m venv .venv
.venv/Scripts/pip install -r requirements.txt jupyter      # Linux/macOS: .venv/bin/pip

FIG_LANG=en .venv/Scripts/python -m jupyter nbconvert --to notebook \
    --execute evaluation_analysis.ipynb --inplace
```

The notebook runs **offline** - the cache in `data/` holds every OSV and Red Hat response. Figures land in
`figures/en/`; the writer is deterministic, so the files come out byte-identical.

To recompute the **adjudication** itself (still offline, from the cache):

```bash
for s in osv_adjudicate os_adjudicate; do
    .venv/Scripts/python analysis/$s.py
done
```

Each script writes one `data/*.csv` file, which the notebook reads
(`app_precision_findings.csv`, `os_precision_findings.csv`).

---

## Path B - run the experiment from scratch (new results)

### 1. Requirements

| tool | note |
|---|---|
| Docker | the images must be visible locally |
| Trivy, Grype, Syft, Docker Scout | install scripts in [`install/`](install/) |
| Snyk CLI | **requires login**: `snyk auth` |
| `jq`, `make`, Python >= 3.10 | |

### 2. Build the 9 images

The application **does not live in this repository** - it is a separate project
([`Q-Scan/vulnerable-quarkus`](https://github.com/Q-Scan/vulnerable-quarkus), the vulnerable Quarkus app plus
9 build variants). Build it from source, **or pull the exact scanned images** from Docker Hub
([`pgorgolew/q-scan`](https://hub.docker.com/r/pgorgolew/q-scan)), so that exactly 9 tags appear in your local Docker:

```
qscan.io/vulnerable-quarkus:DOCKERFILE-jvm            # UBI 8 + OpenJDK
qscan.io/vulnerable-quarkus:DOCKERFILE-jvm-alpine     # Alpine
qscan.io/vulnerable-quarkus:DOCKERFILE-jvm-corretto   # Amazon Corretto
qscan.io/vulnerable-quarkus:JIB-jvm                   # JIB (UBI 9 runtime)
qscan.io/vulnerable-quarkus:BUILDPACK-jvm             # Paketo Buildpacks
qscan.io/vulnerable-quarkus:DOCKERFILE-native         # GraalVM native
qscan.io/vulnerable-quarkus:DOCKERFILE-native-micro   # native, micro base
qscan.io/vulnerable-quarkus:DOCKERFILE-native-sbom    # native + --enable-sbom
qscan.io/vulnerable-quarkus:JIB-native                # JIB + native
```

Check: `docker images | grep vulnerable-quarkus` -> **9 entries**.

To use the published images instead of building, pull them and retag to the names the Makefile expects:

```sh
for t in DOCKERFILE-jvm DOCKERFILE-jvm-alpine DOCKERFILE-jvm-corretto JIB-jvm BUILDPACK-jvm \
         DOCKERFILE-native DOCKERFILE-native-micro DOCKERFILE-native-sbom JIB-native; do
  docker pull pgorgolew/q-scan:$t
  docker tag  pgorgolew/q-scan:$t qscan.io/vulnerable-quarkus:$t
done
```

### 3. Scan (9 images x 16 scans = 144)

```bash
make scan-vulnerable-quarkus-local     # all 9 images, the full set
```

or one at a time:

```bash
make scan-everything IMAGE=qscan.io/vulnerable-quarkus:DOCKERFILE-jvm   # 4 direct + 12 SBOM-based
make scan-all        IMAGE=<image>     # direct scans only
make scan-sbom-all   IMAGE=<image>     # SBOM-based scans only
make help                              # all targets
```

Results land in `results/<image>/`. This takes tens of minutes and about **300 MB**.

#### CycloneDX format control

Separately from the 144-scan core matrix, a **format control** checks whether the
SBOM *format* (SPDX vs CycloneDX) — rather than its content — explains the loss seen when SBOMs are
exchanged between tools. It re-runs the SBOM scans in CycloneDX for two representative images
(`DOCKERFILE-jvm`, `DOCKERFILE-native`) with the two generators that export CycloneDX (Syft, Trivy;
Docker Scout has none), scanned by all four scanners — **2 × 2 × 4 = 16** configs, written as
`*.cdx.json` next to the SPDX results:

```bash
make scan-cyclonedx-control            # the full 16-config control
# or per image/generator:
make scan-sbom-cdx-syft  IMAGE=qscan.io/vulnerable-quarkus:DOCKERFILE-jvm
make scan-sbom-cdx-trivy IMAGE=qscan.io/vulnerable-quarkus:DOCKERFILE-native
```

### 4. Strip personal data from the reports

Grype writes the path of its own cache into the report (`/home/<user>/.cache/grype/db`) as well as your local Maven
repository, and Snyk writes the slug of your account's organisation. **Before publishing `results/`:**

```bash
.venv/Scripts/python analysis/sanitize_results.py --check    # data fingerprint BEFORE
.venv/Scripts/python analysis/sanitize_results.py            # redact
.venv/Scripts/python analysis/sanitize_results.py --check    # the fingerprint MUST be identical
```

The script touches only the report headers (`descriptor`, `org`) - never the findings. `--check` computes a `sha256`
over every parsed finding, so you get **proof** that no number changed.

### 5. Adjudication and analysis (needs network)

```bash
.venv/Scripts/python analysis/osv_adjudicate.py    --refresh   # OSV
.venv/Scripts/python analysis/os_adjudicate.py     --refresh   # Red Hat Security Data API

FIG_LANG=pl .venv/Scripts/python -m jupyter nbconvert --to notebook \
    --execute evaluation_analysis.ipynb --stdout >/dev/null    # -> figures/pl/
FIG_LANG=en .venv/Scripts/python -m jupyter nbconvert --to notebook \
    --execute evaluation_analysis.ipynb --inplace              # -> figures/en/
```

Querying the sources is **rate-limited**; with an empty cache it takes tens of minutes (Red Hat alone: ~5000 CVEs).
The responses land in `data/*_cache.json`, so subsequent runs are offline. Without `--refresh` the scripts use the
cache and **never touch the network**.

### 6. Repack the archives

```bash
make archives          # results/ and data/ -> results.zip, data.zip (these are what git tracks)
```

---

## Layout of the scan results

```
results/qscan.io_vulnerable-quarkus_<VARIANT>/
├── trivy.json                              # direct image scan
├── grype.json
├── snyk.json
├── docker-scout.sarif.json
└── sbom/
    ├── syft/    sbom.cdx.json  + 4 scanners
    ├── trivy/   sbom.spdx.json + 4 scanners
    └── scout/   sbom.spdx.json + 4 scanners
```

## Licence

[MIT](LICENSE).
