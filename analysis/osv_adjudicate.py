"""Application-layer adjudication against OSV, across every ecosystem OSV covers.

The application layer is not only Maven. The Cloud Native Buildpacks lifecycle ships Go modules
(golang.org/x/net, ...), and a few Python packages appear too. All of them are real, scannable
components, so precision and recall must be measured over the whole application layer, not Maven alone.

For every finding (scanner, ecosystem, coordinate, version, CVE) on the target images:
  TP        - the installed version is vulnerable to that CVE per OSV
  FP        - the version is not vulnerable (OSV knows the CVE for the package/ecosystem but not this version)
  too-fresh - OSV has no data for this CVE -> undecidable

Two adjudication paths, one per how OSV answers best:
  * Maven  -> query by coordinate, then compare versions with a Maven comparator (org.apache.maven order).
  * Go/PyPI-> ask OSV `querybatch` whether the exact (ecosystem, package, version) is affected; OSV
              does the version math, so no per-ecosystem comparator is needed.

Coordinates come from the purls in the raw files, not from the parser's `package` field:
Trivy/Snyk emit 'group:artifact' for Maven, Grype and Scout only 'artifact'; Go/PyPI names come straight
from the purl. OSV keys advisories on the ecosystem-native name.

Usage:  python analysis/osv_adjudicate.py [--refresh]
Writes: data/osv_cache.json, data/app_precision_findings.csv
"""
import os
import re
import sys
import json
import time
import argparse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
from scanlib import PARSERS, PREFIX, JVM_IMAGES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, 'results')
DATA = os.path.join(ROOT, 'data')
CACHE = os.path.join(DATA, 'osv_cache.json')
OUT_CSV = os.path.join(DATA, 'app_precision_findings.csv')

# purl -> (ecosystem, coordinate). Maven keeps 'group:artifact'; Go/PyPI keep the native name.
PURL = re.compile(r'pkg:(maven|golang|pypi)/([^@?]+)@?([^?#]*)')
ECOSYSTEM = {'maven': 'Maven', 'golang': 'Go', 'pypi': 'PyPI'}


def _coord(ecosystem, name):
    if ecosystem == 'Maven':
        group, _, artifact = name.partition('/')
        return f'{group}:{artifact}'
    return name


def _norm_ver(ecosystem, version):
    """Canonicalise a version for the OSV query. Go's own 'go1.20.14' form is not a semver and
    makes OSV return every advisory for the package (all versions), so strip the 'go' prefix.
    Scanners disagree on this: Grype emits 'go1.20.14', Trivy 'v1.20.14', Scout '1.20.14'."""
    v = version or ''
    if ecosystem == 'Go' and v.startswith('go'):
        return v[2:]
    return v


# ---------------------------------------------------------------- coordinates
def _resolve_gopypi(pkg, go_modules, pypi_names):
    """Recover the ecosystem of a purl-less finding by matching against coordinates other
    scanners did tag. Needed because Snyk emits no purls for Go and reports Go at subpackage
    granularity (golang.org/x/net/idna -> module golang.org/x/net)."""
    if pkg in pypi_names:
        return ('PyPI', pkg)
    for module in go_modules:                      # longest module first
        # exact, a subpackage path (Snyk: golang.org/x/net/idna), or a truncated tail (Scout: x/net)
        if pkg == module or pkg.startswith(module + '/') or module.endswith('/' + pkg):
            return ('Go', module)
    return None


def _coords_from_raw(image):
    """(scanner, package, version) -> (ecosystem, coordinate) plus the Go/PyPI coordinates seen
    across all scanners, so purl-less findings can be recovered later."""
    base = os.path.join(RESULTS, PREFIX + image)
    coord_index = {}
    seen_coords = set()

    def add(scanner, pkg, ver, purl):
        purl_match = PURL.match(purl or '')
        if not purl_match:
            return
        eco_raw, name, purl_version = purl_match.groups()
        ecosystem = ECOSYSTEM[eco_raw]
        resolved = (ecosystem, _coord(ecosystem, name))
        coord_index[(scanner, pkg, ver)] = resolved
        seen_coords.add(resolved)
        # fallback keys for scanners that report a shorter package name than the purl carries
        coord_index.setdefault((scanner, name, purl_version), resolved)
        coord_index.setdefault((scanner, name.rsplit('/', 1)[-1], purl_version), resolved)

    def load_report(filename):
        try:
            with open(os.path.join(base, filename), encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    trivy = load_report('trivy.json') or {}
    for result in trivy.get('Results') or []:
        for vuln in result.get('Vulnerabilities') or []:
            add('Trivy', vuln.get('PkgName', ''), vuln.get('InstalledVersion', ''),
                (vuln.get('PkgIdentifier') or {}).get('PURL'))

    grype = load_report('grype.json') or {}
    for match in grype.get('matches') or []:
        artifact = match.get('artifact', {})
        add('Grype', artifact.get('name', ''), artifact.get('version', ''), artifact.get('purl'))

    snyk = load_report('snyk.json')
    for project in (snyk if isinstance(snyk, list) else [snyk]) if snyk else []:
        if not isinstance(project, dict):
            continue
        vuln_lists = [project.get('vulnerabilities')] + [app.get('vulnerabilities') for app in project.get('applications') or []]
        for vuln_list in vuln_lists:
            for vuln in vuln_list or []:
                add('Snyk', vuln.get('packageName', ''), vuln.get('version') or '', vuln.get('packageUrl'))

    scout = load_report('docker-scout.sarif.json') or {}
    for run in scout.get('runs') or []:
        for rule in run.get('tool', {}).get('driver', {}).get('rules') or []:
            for purl in (rule.get('properties') or {}).get('purls') or []:
                purl_match = PURL.match(purl)
                if purl_match:
                    eco_raw, name, purl_version = purl_match.groups()
                    add('Docker Scout', name.rsplit('/', 1)[-1], purl_version, purl)

    go_modules = sorted((coord for eco, coord in seen_coords if eco == 'Go'), key=len, reverse=True)
    pypi_names = {coord for eco, coord in seen_coords if eco == 'PyPI'}
    return coord_index, go_modules, pypi_names


def build_findings(images):
    """Application-layer findings from direct scans, with (ecosystem, coordinate, version)."""
    findings = []
    for image in images:
        base = os.path.join(RESULTS, PREFIX + image)
        coord_index, go_modules, pypi_names = _coords_from_raw(image)
        for scanner, (filename, parse) in PARSERS.items():
            records, status = parse(os.path.join(base, filename), image, 'direct')
            if status != 'ok':
                print(f'  WARNING: {image}/{scanner}: {status}', file=sys.stderr)
            for finding in records:
                if finding['layer'] != 'app':
                    continue
                resolved = coord_index.get((scanner, finding['package'], finding['version']))
                if resolved is None and ':' in finding['package']:
                    resolved = ('Maven', finding['package'])     # Trivy/Snyk already give group:artifact
                if resolved is None:
                    resolved = _resolve_gopypi(finding['package'], go_modules, pypi_names)   # purl-less Go/PyPI
                if resolved is None:
                    continue
                finding['ecosystem'], finding['coord'] = resolved
                findings.append(finding)
    findings_df = pd.DataFrame(findings).drop_duplicates(
        subset=['image', 'input', 'scanner', 'vuln_id', 'package']).reset_index(drop=True)
    findings_df = findings_df[findings_df.vuln_id.str.startswith('CVE-')].reset_index(drop=True)
    return findings_df


# ============================ OSV client ============================
# One cache dict holds entries keyed apart so they never collide:
#   'CVE-...' / 'GHSA-...'   -> a single OSV vulnerability record
#   '_pkg:<eco>:<coord>'     -> the advisories OSV returns for a coordinate (query by package)
#   '_qb:<eco>:<coord>@<v>'  -> the CVEs OSV deems applicable to an exact version (querybatch)
OSV_API = 'https://api.osv.dev'


def _get_json(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


def _post_json(url, body, timeout=45):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


class OSV:
    """OSV transport with an on-disk cache. Every network read goes through here."""

    def __init__(self, path):
        self.path = path
        self.cache = {}

    # -- cache file --------------------------------------------------------
    def load(self, refresh=False):
        if os.path.exists(self.path) and not refresh:
            with open(self.path, encoding='utf-8') as f:
                self.cache = json.load(f)
        return self.cache

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(self.cache, f, indent=1)

    # -- endpoints ---------------------------------------------------------
    def vuln(self, vuln_id, delay=0.2):
        """GET /v1/vulns/{id}. Absence from OSV is cached as {'_absent': True}."""
        if vuln_id in self.cache:
            return self.cache[vuln_id]
        try:
            self.cache[vuln_id] = _get_json(f'{OSV_API}/v1/vulns/{vuln_id}')
        except urllib.error.HTTPError as e:
            self.cache[vuln_id] = {'_absent': True, '_status': e.code}    # 404 == not in OSV
        except Exception as e:                                        # noqa: BLE001
            print(f'  error {vuln_id}: {e}', file=sys.stderr)
            return None
        time.sleep(delay)
        return self.cache[vuln_id]

    def advisories(self, coord, ecosystem='Maven', delay=0.2):
        """POST /v1/query by package alone -> every OSV advisory for a coordinate.

        The coordinate -> advisory direction is the only reliable one for Maven, where CVE->GHSA
        aliases are sometimes one-directional (a CVE stub points at a GHSA that holds the content,
        not the reverse). Querying by package returns the GHSAs, whose CVE aliases we then read.
        """
        key = '_pkg:' + coord if ecosystem == 'Maven' else f'_pkg:{ecosystem}:{coord}'
        if key in self.cache:
            return self.cache[key]
        body = {'package': {'ecosystem': ecosystem, 'name': coord}}
        try:
            self.cache[key] = _post_json(f'{OSV_API}/v1/query', body).get('vulns') or []
        except Exception as e:                                        # noqa: BLE001
            print(f'  query error {ecosystem}/{coord}: {e}', file=sys.stderr)
            self.cache[key] = []
        time.sleep(delay)
        return self.cache[key]

    def applicable(self, pairs, ecosystem, delay=0.5):
        """POST /v1/querybatch: (coord, version) -> the CVEs OSV deems applicable to that version.

        OSV does the version math, so this works for any ecosystem without a version comparator.
        querybatch returns bare ids (mostly GHSA/GO), each resolved to its CVE aliases via vuln().
        """
        pairs = sorted(set(pairs))
        to_fetch = [pair for pair in pairs if f'_qb:{ecosystem}:{pair[0]}@{pair[1]}' not in self.cache]
        for start in range(0, len(to_fetch), 100):
            chunk = to_fetch[start:start + 100]
            body = {'queries': [{'package': {'ecosystem': ecosystem, 'name': coord}, 'version': version}
                                for coord, version in chunk]}
            try:
                response = _post_json(f'{OSV_API}/v1/querybatch', body, timeout=60)
            except Exception as e:                                   # noqa: BLE001
                print(f'  querybatch error {ecosystem}: {e}', file=sys.stderr)
                continue
            for (coord, version), result in zip(chunk, response.get('results') or []):
                cves = set()
                for advisory in result.get('vulns') or []:
                    advisory_id = advisory.get('id', '')
                    if advisory_id.startswith('CVE-'):
                        cves.add(advisory_id)
                        continue
                    record = self.vuln(advisory_id)
                    for alias in (record or {}).get('aliases') or []:
                        if alias.startswith('CVE-'):
                            cves.add(alias)
                self.cache[f'_qb:{ecosystem}:{coord}@{version}'] = sorted(cves)
            time.sleep(delay)
        self.save()
        return {pair: set(self.cache.get(f'_qb:{ecosystem}:{pair[0]}@{pair[1]}', [])) for pair in pairs}


# ============================ OSV interpretation ============================
def _is_eco(pkg, ecosystem):
    """True if an OSV affected[].package entry belongs to the given ecosystem."""
    return (pkg or {}).get('ecosystem', '').split(':')[0].strip().lower() == ecosystem.lower()


def _affects(entry, coord, ecosystem):
    """The affected[] entries in an advisory that concern this exact coordinate."""
    return [a for a in entry.get('affected') or []
            if _is_eco(a.get('package'), ecosystem)
            and (a.get('package') or {}).get('name', '').strip().lower() == coord.lower()]


def _cves_of(entry):
    """Every CVE a given OSV record represents (its id + aliases)."""
    ids = [entry.get('id', '')] + (entry.get('aliases') or [])
    return {i for i in ids if i.startswith('CVE-')}


def cve_known_in(osv, cve, ecosystem):
    """-> (known, reason). known=True if OSV knows this CVE in the ecosystem (for any package),
    which separates a false positive (wrong coordinate) from an undecidable one (no data)."""
    record = osv.vuln(cve)
    if not record or record.get('_absent'):
        return False, 'CVE not in OSV'
    ghsa_ids = [alias for alias in (record.get('aliases') or []) + (record.get('related') or [])
                if alias.startswith('GHSA-')]
    records = [record] + [r for r in (osv.vuln(ghsa_id) for ghsa_id in ghsa_ids) if r and not r.get('_absent')]
    if any(_is_eco(affected.get('package'), ecosystem) for rec in records for affected in rec.get('affected') or []):
        return True, f'OSV knows this CVE for {ecosystem}, but not for this coordinate'
    return False, f'no {ecosystem} data for this CVE in OSV'


# ---- Maven path: coordinate index + version comparator --------------------
def build_index(osv, coords):
    """coord -> {cve -> [affected[] entries]} for Maven coordinates."""
    coord_to_cves = {}
    coords = sorted(coords)
    for i, coord in enumerate(coords, 1):
        cve_to_affected = {}
        for advisory in osv.advisories(coord, 'Maven'):
            affected_entries = _affects(advisory, coord, 'Maven')
            if not affected_entries:
                continue
            for cve in _cves_of(advisory):
                cve_to_affected.setdefault(cve, []).extend(affected_entries)
        coord_to_cves[coord] = cve_to_affected
        if i % 10 == 0 or i == len(coords):
            print(f'  Maven coordinate index {i}/{len(coords)}')
    osv.save()
    return coord_to_cves


def _range_desc(version_range):
    introduced = fixed = last_affected = None
    for event in version_range.get('events') or []:
        introduced = event.get('introduced', introduced)
        fixed = event.get('fixed', fixed)
        last_affected = event.get('last_affected', last_affected)
    if fixed:
        return introduced, fixed, last_affected, f'[{introduced or "0"}, {fixed})'
    if last_affected:
        return introduced, fixed, last_affected, f'[{introduced or "0"}, {last_affected}]'
    return introduced, fixed, last_affected, f'[{introduced or "0"}, ...)'


def classify_maven(osv, coord_to_cves, coord, version, cve):
    """-> (verdict, reason, range_desc) using the Maven version comparator."""
    cve_to_affected = coord_to_cves.get(coord) or {}
    affected_entries = cve_to_affected.get(cve)
    if not affected_entries:
        known, why = cve_known_in(osv, cve, 'Maven')
        return ('FP' if known else 'too-fresh'), why, ''

    range_descriptions = []
    for affected in affected_entries:
        versions = affected.get('versions') or []
        if versions and any(mvcompare(version, listed) == 0 for listed in versions):
            return 'TP', 'version listed in OSV versions[]', f'versions[{len(versions)}]'
        for version_range in affected.get('ranges') or []:
            if version_range.get('type') == 'GIT':
                continue
            introduced, fixed, last_affected, desc = _range_desc(version_range)
            range_descriptions.append(desc)
            if not (introduced in (None, '0') or mvge(version, introduced)):
                continue
            if fixed and not mvlt(version, fixed):
                continue
            if last_affected and mvcompare(version, last_affected) > 0:
                continue
            return 'TP', 'version inside an OSV vulnerable range', desc
        if versions and not (affected.get('ranges') or []):
            range_descriptions.append(f'versions[{len(versions)}]')

    if not range_descriptions:
        return 'too-fresh', 'Maven advisory with no range/version', ''
    return 'FP', 'version outside every vulnerable range', ' | '.join(sorted(set(range_descriptions))[:3])


# ---- Go / PyPI path: OSV does the version math (querybatch) ----------------
def package_cves(osv, coord, ecosystem):
    """Every CVE OSV associates with a coordinate, any version (to tell FP from too-fresh)."""
    cves = set()
    for advisory in osv.advisories(coord, ecosystem):
        if _affects(advisory, coord, ecosystem):
            cves |= _cves_of(advisory)
    return cves


def classify_osv(osv, applicable, pkg_cves, coord, version, cve, ecosystem):
    """-> (verdict, reason, '') for a non-Maven ecosystem, using OSV's own version verdict."""
    if cve in applicable.get((coord, _norm_ver(ecosystem, version)), set()):
        return 'TP', 'OSV: this version is affected', ''
    if cve in pkg_cves.get(coord, set()):
        return 'FP', 'OSV: this version is not affected', ''
    known, why = cve_known_in(osv, cve, ecosystem)
    return ('FP' if known else 'too-fresh'), why, ''


# ============================ Maven version comparison ============================

# --- Maven version comparison (an approximation of org.apache.maven ComparableVersion) ---
# Java versions do not compare lexicographically: '4.1.9' > '4.1.128' as text.
# Qualifiers ('.Final', '-rc1', '-SNAPSHOT') must be ordered relative to the base release.
_QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp']
_ALIASES = {'a': 'alpha', 'b': 'beta', 'm': 'milestone', 'cr': 'rc', 'ga': '', 'final': '', 'release': ''}


def _qual_rank(tok):
    tok = _ALIASES.get(tok, tok)
    if tok in _QUALIFIERS:
        return (_QUALIFIERS.index(tok), '')
    # an unknown qualifier sorts AFTER the known ones, alphabetically (Maven rule)
    return (len(_QUALIFIERS), tok)


def _tokenize(v):
    """Splits a version into tokens: int for numbers, (rank, str) for qualifiers."""
    v = (v or '').strip().lower()
    v = re.sub(r'[-_+]', '.', v)
    v = re.sub(r'(\d)([a-z])', r'\1.\2', v)   # 1.0Final -> 1.0.final
    v = re.sub(r'([a-z])(\d)', r'\1.\2', v)   # rc1 -> rc.1
    tokens = []
    for part in v.split('.'):
        if not part:
            continue
        if part.isdigit():
            tokens.append((1, int(part), ''))     # numbers rank above qualifiers at the same position
        else:
            rank, suffix = _qual_rank(part)
            tokens.append((0, rank, suffix))
    return tokens


def _pad(tokens_a, tokens_b):
    # a missing position == the final release (qualifier rank of '')
    padding = (0, _QUALIFIERS.index(''), '')
    length = max(len(tokens_a), len(tokens_b))
    return tokens_a + [padding] * (length - len(tokens_a)), tokens_b + [padding] * (length - len(tokens_b))


def mvcompare(v1, v2):
    """-1 / 0 / 1 for v1 <, ==, > v2 (Maven order)."""
    tokens1, tokens2 = _pad(_tokenize(v1), _tokenize(v2))
    for x, y in zip(tokens1, tokens2):
        if x != y:
            return -1 if x < y else 1
    return 0


def mvlt(a, b):
    return mvcompare(a, b) < 0


def mvge(a, b):
    return mvcompare(a, b) >= 0


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--refresh', action='store_true', help='bypass the OSV cache')
    ap.add_argument('--images', nargs='*', default=JVM_IMAGES)
    args = ap.parse_args()

    findings_df = build_findings(args.images)
    by_ecosystem = findings_df.ecosystem.value_counts().to_dict()
    print(f'App-layer findings (direct): {len(findings_df)} | images: {findings_df.image.nunique()} '
          f'| unique CVEs: {findings_df.vuln_id.nunique()} | by ecosystem: {by_ecosystem}')

    osv = OSV(CACHE)
    osv.load(refresh=args.refresh)

    # Maven: coordinate index + version comparator
    maven_findings = findings_df[findings_df.ecosystem == 'Maven']
    print(f'OSV: indexing {maven_findings.coord.nunique()} Maven coordinates')
    maven_index = build_index(osv, set(maven_findings.coord))

    # Go / PyPI: OSV querybatch settles the version, advisories give the package CVE set
    other_findings = findings_df[findings_df.ecosystem != 'Maven']
    applicable, pkg_cves = {}, {}
    for ecosystem in sorted(other_findings.ecosystem.unique()):
        ecosystem_findings = other_findings[other_findings.ecosystem == ecosystem]
        pairs = {(coord, _norm_ver(ecosystem, version))
                 for coord, version in ecosystem_findings[['coord', 'version']].drop_duplicates().values}
        print(f'OSV: querybatch for {ecosystem} ({len(pairs)} package-version pairs)')
        applicable[ecosystem] = osv.applicable(pairs, ecosystem)
        pkg_cves[ecosystem] = {coord: package_cves(osv, coord, ecosystem)
                               for coord in ecosystem_findings.coord.unique()}
    osv.save()

    verdict_rows = []
    for finding in findings_df.itertuples():
        if finding.ecosystem == 'Maven':
            verdict, reason, range_desc = classify_maven(osv, maven_index, finding.coord,
                                                         finding.version, finding.vuln_id)
        else:
            verdict, reason, range_desc = classify_osv(osv, applicable[finding.ecosystem],
                                                       pkg_cves[finding.ecosystem], finding.coord,
                                                       finding.version, finding.vuln_id, finding.ecosystem)
        verdict_rows.append(dict(image=finding.image, ecosystem=finding.ecosystem, scanner=finding.scanner,
                                 cve=finding.vuln_id, coord=finding.coord, version=finding.version,
                                 severity=finding.severity, verdict=verdict, reason=reason,
                                 osv_range=range_desc, year=int(finding.vuln_id.split('-')[1])))
    verdicts_df = pd.DataFrame(verdict_rows)
    osv.save()

    os.makedirs(DATA, exist_ok=True)
    verdicts_df.to_csv(OUT_CSV, index=False, encoding='utf-8')
    print(f'\nwrote {OUT_CSV} ({len(verdicts_df)} rows)')

    print('\n== class distribution per scanner and ecosystem (per finding) ==')
    class_counts = verdicts_df.pivot_table(index=['ecosystem', 'scanner'], columns='verdict',
                                           values='cve', aggfunc='size', fill_value=0)
    print(class_counts.to_string())

    print('\n== actual FPs (version mismatch) ==')
    false_positives = verdicts_df[verdicts_df.verdict == 'FP'][['image', 'ecosystem', 'scanner',
                                                                'cve', 'coord', 'version', 'reason']]
    print(false_positives.drop_duplicates(['ecosystem', 'scanner', 'cve', 'coord']).to_string(index=False)
          if len(false_positives) else '  none')


if __name__ == '__main__':
    main()
