"""OS-layer (RPM) adjudication against the Red Hat Security Data API.

Application-layer precision (osv_adjudicate.py) covers only ~15% of the report. The OS layer is the
other ~85%, and that is where nearly all the divergence between scanners lives - Docker Scout reports
far fewer OS CVEs than the other three. Whether that gap is policy or missed detections is decided
here, by confronting every finding with the distribution vendor's own data.

Oracle: https://access.redhat.com/hydra/rest/securitydata/cve/{CVE}.json
  affected_release[] -> {product_name, package: 'openssl-1:1.1.1k-12.el8_9', advisory}  (a fix exists)
  package_state[]    -> {product_name, package_name, fix_state}                          (no fix)

Classes:
  TP-fixable     - Red Hat shipped a fix (RHSA) and the installed version is OLDER  -> real and fixable
  TP-nofix       - Red Hat confirms the flaw but will not fix it
                   (Affected / Will not fix / Fix deferred / Out of support scope)   -> real, unfixable
  FP-patched     - the installed version is >= the version Red Hat fixed             -> false positive
  FP-notaffected - Red Hat explicitly says "Not affected" for this package/product   -> false positive
  no-entry       - Red Hat knows the CVE but does not list this package for this RHEL -> no ruling
  unknown        - Red Hat does not know the CVE at all                               -> no ruling

Usage:  python analysis/os_adjudicate.py [--refresh]
Writes: data/redhat_cache.json, data/os_precision_findings.csv
"""
import os
import re
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
from scanlib import PARSERS, PREFIX, IMAGES, load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, 'results')
DATA = os.path.join(ROOT, 'data')
CACHE = os.path.join(DATA, 'redhat_cache.json')
OUT_CSV = os.path.join(DATA, 'os_precision_findings.csv')

NOFIX = {'Affected', 'Will not fix', 'Fix deferred', 'Out of support scope'}
UNKNOWN_STATE = {'New', 'Under investigation'}


# ------------------------------------------------------------ Red Hat images
def rhel_major(image):
    """The image's RHEL major per Trivy metadata; None for non-Red Hat bases (alpine/amazon)."""
    trivy_report = load(os.path.join(RESULTS, PREFIX + image, 'trivy.json')) or {}
    os_meta = (trivy_report.get('Metadata') or {}).get('OS') or {}
    if (os_meta.get('Family') or '') != 'redhat':
        return None
    major_match = re.match(r'(\d+)', os_meta.get('Name') or '')
    return major_match.group(1) if major_match else None


# ------------------------------------------------- binary -> source map
def src_map(image):
    """binary RPM -> source package, from Grype's purl (upstream=openssl-...src.rpm).

    Red Hat keys package_state on the component (often the source one: 'openssl'),
    while the scanners report the binary package ('openssl-libs'). Without this map half
    of the findings would never meet their Red Hat entry.
    """
    grype_data = load(os.path.join(RESULTS, PREFIX + image, 'grype.json')) or {}
    binary_to_source = {}
    for match in grype_data.get('matches') or []:
        artifact = match.get('artifact') or {}
        if artifact.get('type') != 'rpm':
            continue
        purl = artifact.get('purl') or ''
        upstream_match = re.search(r'upstream=([^&?]+)', purl)
        if upstream_match:
            upstream = upstream_match.group(1)
            source = re.sub(r'-\d[^-]*-[^-]+\.src\.rpm$', '', upstream)
            source = re.sub(r'\.src\.rpm$', '', source)
            binary_to_source[artifact.get('name', '')] = source
    return binary_to_source


# ============================= Red Hat client =============================
# The Security Data API answers one CVE at a time; the cache maps 'CVE-...' -> its record
# (or {'_absent': True} for a 404). Every network read goes through here.
RH_API = 'https://access.redhat.com/hydra/rest/securitydata'
UA = {'User-Agent': 'container-scanner-evaluation/1.0 (academic research)'}


class RedHat:
    """Red Hat Security Data API transport with an on-disk cache."""

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
            json.dump(self.cache, f)

    # -- endpoint ----------------------------------------------------------
    def get(self, cve, delay=0.12):
        """GET /cve/{CVE}.json. A 404 (Red Hat does not know the CVE) is cached as {'_absent': True}."""
        if cve in self.cache:
            return self.cache[cve]
        req = urllib.request.Request(f'{RH_API}/cve/{cve}.json', headers=UA)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                self.cache[cve] = json.load(response)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.cache[cve] = {'_absent': True}
            else:
                print(f'  HTTP {e.code} for {cve}', file=sys.stderr)
                return None
        except Exception as e:                                 # noqa: BLE001
            print(f'  error {cve}: {e}', file=sys.stderr)
            return None
        time.sleep(delay)
        return self.cache[cve]


def _prod_match(product_name, major):
    """Does this Red Hat entry concern our RHEL (rather than OpenShift, Hummingbird etc.)?"""
    p = (product_name or '')
    return p.startswith('Red Hat Enterprise Linux ' + major) or p == 'Red Hat Enterprise Linux ' + major


def evr_cmp(installed, fixed):
    """EVR comparison, robust to the fact that scanners treat the epoch differently.

    Grype states the epoch ('1:1.1.1k-15.el8_6'), Scout URL-encodes it
    ('1%3A1.1.1k-14.el8_6'), and Trivy and Snyk OMIT it entirely ('1.1.1k-15.el8_6').
    Red Hat always gives the full NVR with the epoch ('openssl-1:1.1.1k-12.el8_9'). Compared
    naively, every Trivy/Snyk finding for a package with epoch > 0 would look
    older than it is (epoch 0 < 1) and land falsely in TP-fixable.
    The rule: compare epochs only when BOTH sides supply one.
    """
    installed = urllib.parse.unquote(installed or '')
    if ':' not in installed and ':' in fixed:
        fixed = fixed.split(':', 1)[1]
    return evrcompare(installed, fixed)


def classify(redhat_record, candidate_names, installed_evr, major):
    """candidate_names = candidate package names at Red Hat (binary + source)."""
    if not redhat_record or redhat_record.get('_absent'):
        return 'unknown', 'Red Hat does not know this CVE', ''
    candidate_names = {name for name in candidate_names if name}
    installed_evr = urllib.parse.unquote(installed_evr or '')

    # 1) is there a fix (RHSA) for our RHEL and our package?
    for release in redhat_record.get('affected_release') or []:
        if not _prod_match(release.get('product_name'), major):
            continue
        package_nvr = release.get('package') or ''
        for name in candidate_names:
            if package_nvr == name or package_nvr.startswith(name + '-'):
                fixed_evr = strip_name(package_nvr, name)
                if not re.match(r'\d', fixed_evr):
                    continue
                comparison = evr_cmp(installed_evr, fixed_evr)
                advisory = release.get('advisory', '')
                if comparison >= 0:
                    return 'FP-patched', f'installed {installed_evr} >= fixed {fixed_evr}', advisory
                return 'TP-fixable', f'fixed in {fixed_evr} ({advisory})', advisory

    # 2) no fix -> package state
    for state_entry in redhat_record.get('package_state') or []:
        if not _prod_match(state_entry.get('product_name'), major):
            continue
        if (state_entry.get('package_name') or '') not in candidate_names:
            continue
        fix_state = state_entry.get('fix_state') or ''
        if fix_state in NOFIX:
            return 'TP-nofix', f'Red Hat: {fix_state}', ''
        if fix_state == 'Not affected':
            return 'FP-notaffected', 'Red Hat: Not affected', ''
        if fix_state in UNKNOWN_STATE:
            return 'no-entry', f'Red Hat: {fix_state}', ''

    return 'no-entry', f'Red Hat knows the CVE but does not list this package for RHEL {major}', ''


# ============================= RPM version comparison =============================

# --- RPM version comparison (an rpmvercmp implementation + EVR comparison) ---
# RPM versions compare neither lexicographically nor like Maven: release 15 > release 9,
# the tilde '~' sorts before everything, '^' after, and the epoch dominates the rest.
_SEG = re.compile(r'(\d+|[a-zA-Z]+|~|\^)')


def _segments(s):
    return [x for x in _SEG.findall(s or '') if x]


def rpmvercmp(a, b):
    """Canonical rpmvercmp: -1 / 0 / 1."""
    if a == b:
        return 0
    segments_a, segments_b = _segments(a), _segments(b)
    for x, y in zip(segments_a, segments_b):
        if x == '~' or y == '~':                 # tilde sorts below everything (even a missing segment)
            if x != y:
                return -1 if x == '~' else 1
            continue
        if x == '^' or y == '^':
            if x != y:
                return 1 if x == '^' else -1
            continue
        x_is_digit, y_is_digit = x.isdigit(), y.isdigit()
        if x_is_digit and y_is_digit:
            x_num, y_num = int(x), int(y)
            if x_num != y_num:
                return -1 if x_num < y_num else 1
        elif x_is_digit != y_is_digit:
            return 1 if x_is_digit else -1       # a number ranks above a letter
        else:
            if x != y:
                return -1 if x < y else 1
    if len(segments_a) == len(segments_b):
        return 0
    # the longer wins, unless its next segment is a tilde
    longer, sign = (segments_a, 1) if len(segments_a) > len(segments_b) else (segments_b, -1)
    next_segment = longer[min(len(segments_a), len(segments_b))]
    if next_segment == '~':
        return -sign
    return sign


def parse_evr(evr):
    """'1:1.1.1k-15.el8_6' -> (epoch, version, release)."""
    evr = (evr or '').strip()
    epoch = '0'
    if ':' in evr:
        epoch, evr = evr.split(':', 1)
    if '-' in evr:
        ver, rel = evr.rsplit('-', 1)
    else:
        ver, rel = evr, ''
    return epoch.strip(), ver.strip(), rel.strip()


def evrcompare(evr1, evr2):
    """Comparison of full EVRs (epoch:version-release): -1 / 0 / 1."""
    e1, v1, r1 = parse_evr(evr1)
    e2, v2, r2 = parse_evr(evr2)
    for x, y in ((e1, e2), (v1, v2), (r1, r2)):
        c = rpmvercmp(x, y)
        if c:
            return c
    return 0


def strip_name(nvr, name):
    """'openssl-1:1.1.1k-15.el8_6' + 'openssl' -> '1:1.1.1k-15.el8_6'.

    Red Hat gives a full NVR in affected_release, with the package name in front (sometimes
    with a module suffix, e.g. 'alsa-lib-main-1.2.15.3-3.1.hum1'), while scanners give the bare EVR.
    """
    nvr = (nvr or '').strip()
    if name and nvr.startswith(name + '-'):
        return nvr[len(name) + 1:]
    # fallback: cut everything up to the first segment that starts with a digit
    m = re.search(r'-(\d[^-]*-[^-]+)$', nvr)
    if m:
        return m.group(1)
    m = re.search(r'-(\d.*)$', nvr)
    return m.group(1) if m else nvr


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--refresh', action='store_true')
    args = ap.parse_args()

    redhat = RedHat(CACHE)
    redhat.load(refresh=args.refresh)

    # --- collect every OS-layer CVE finding across all four scanners on the Red Hat images ---
    findings = []
    for image in IMAGES:
        major = rhel_major(image)
        if not major:                                          # skip alpine / amazon bases
            continue
        binary_to_source = src_map(image)
        base = os.path.join(RESULTS, PREFIX + image)
        for scanner, (filename, parse) in PARSERS.items():
            records, status = parse(os.path.join(base, filename), image, 'direct')
            if status != 'ok':
                continue
            for finding in records:
                if finding['layer'] != 'os' or not finding['vuln_id'].startswith('CVE-'):
                    continue
                package = finding['package']
                findings.append(dict(image=image, major=major, scanner=scanner, cve=finding['vuln_id'],
                                     package=package, src=binary_to_source.get(package, ''),
                                     version=finding['version'], severity=finding['severity']))
    findings_df = pd.DataFrame(findings).drop_duplicates(subset=['image', 'scanner', 'cve', 'package'])
    print(f'OS-layer findings (Red Hat images): {len(findings_df)} | images: {findings_df.image.nunique()} '
          f'| unique CVEs: {findings_df.cve.nunique()}')
    print(f'The binary->source map covers {findings_df.src.ne("").mean()*100:.0f}% of findings')

    # --- fetch each unique CVE's Red Hat record (cache first; network only for the missing ones) ---
    unique_cves = sorted(findings_df.cve.unique())
    to_fetch = [cve for cve in unique_cves if cve not in redhat.cache]
    print(f'Red Hat API: {len(unique_cves)} CVEs, {len(to_fetch)} to fetch (cache: {len(redhat.cache)})')
    for i, cve in enumerate(to_fetch, 1):
        redhat.get(cve)
        if i % 50 == 0 or i == len(to_fetch):
            print(f'  {i}/{len(to_fetch)}')
            redhat.save()
    redhat.save()

    # --- adjudicate each finding against its record ---
    verdict_rows = []
    for finding in findings_df.itertuples():
        verdict, reason, advisory = classify(redhat.cache.get(finding.cve),
                                             {finding.package, finding.src}, finding.version, finding.major)
        verdict_rows.append(dict(image=finding.image, scanner=finding.scanner, cve=finding.cve,
                                 package=finding.package, src=finding.src, version=finding.version,
                                 severity=finding.severity, verdict=verdict, reason=reason, advisory=advisory))
    verdicts_df = pd.DataFrame(verdict_rows)
    verdicts_df.to_csv(OUT_CSV, index=False, encoding='utf-8')
    print(f'\nwrote {OUT_CSV} ({len(verdicts_df)} rows)')

    print('\n== classes per scanner (all Red Hat images, per finding) ==')
    class_counts = verdicts_df.pivot_table(index='scanner', columns='verdict', values='cve',
                                           aggfunc='size', fill_value=0)
    class_counts['n'] = class_counts.sum(axis=1)
    print(class_counts.to_string())

    print('\n== OS-layer FALSE POSITIVES ==')
    false_positives = verdicts_df[verdicts_df.verdict.str.startswith('FP')]
    if len(false_positives):
        print(false_positives.groupby(['scanner', 'verdict']).size().to_string())
        print('\nexamples:')
        print(false_positives[['image', 'scanner', 'cve', 'package', 'version', 'reason']].head(15).to_string(index=False))
    else:
        print('  none')

    # THE KEY QUESTION: what are the CVEs Scout omits?
    focus_image = 'DOCKERFILE-jvm'
    image_verdicts = verdicts_df[verdicts_df.image == focus_image]
    scout_cves = set(image_verdicts[image_verdicts.scanner == 'Docker Scout'].cve)
    other_cves = set(image_verdicts[image_verdicts.scanner != 'Docker Scout'].cve)
    scout_omitted = other_cves - scout_cves
    print(f'\n== {focus_image}: what are the {len(scout_omitted)} CVEs Scout omits? ==')
    omitted_verdicts = image_verdicts[image_verdicts.cve.isin(scout_omitted)].drop_duplicates(subset=['cve'])
    print(omitted_verdicts.verdict.value_counts().to_string())
    print(f'\n  -> real (TP-*): {omitted_verdicts.verdict.str.startswith("TP").sum()} / {len(omitted_verdicts)}')
    print(f'  -> of which unfixable (TP-nofix): {(omitted_verdicts.verdict == "TP-nofix").sum()}')
    scout_only = scout_cves - other_cves
    if scout_only:
        scout_only_verdicts = image_verdicts[image_verdicts.cve.isin(scout_only)].drop_duplicates(subset=['cve'])
        print(f'\n== {len(scout_only)} CVEs reported ONLY by Scout ==')
        print(scout_only_verdicts.verdict.value_counts().to_string())


if __name__ == '__main__':
    main()
