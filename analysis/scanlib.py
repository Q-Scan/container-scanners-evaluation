"""Parsers and shared constants - the single source of truth for the analysis.

Both the notebook and the adjudication scripts import from here, so every finding is
parsed exactly once, the same way. Keep the *parsing* in this module; the *figure* setup
(palette, matplotlib, save_fig) lives in the notebook's first cell.

load() opens files with encoding='utf-8' - without it, on Windows/cp1250 every report
silently loads as 'missing'.
"""
import os
import json
import re

import pandas as pd

SCANNERS = ['Trivy', 'Grype', 'Snyk', 'Docker Scout']

IMAGES = ['BUILDPACK-jvm', 'DOCKERFILE-jvm', 'DOCKERFILE-jvm-alpine',
          'DOCKERFILE-jvm-corretto', 'DOCKERFILE-native', 'DOCKERFILE-native-micro',
          'DOCKERFILE-native-sbom', 'JIB-jvm', 'JIB-native']
JVM_IMAGES = ['DOCKERFILE-jvm', 'DOCKERFILE-jvm-alpine', 'DOCKERFILE-jvm-corretto',
              'JIB-jvm', 'BUILDPACK-jvm']
IMAGES_ORDER = JVM_IMAGES + ['DOCKERFILE-native', 'DOCKERFILE-native-micro', 'JIB-native',
                             'DOCKERFILE-native-sbom']
PREFIX = 'qscan.io_vulnerable-quarkus_'

GROUND_TRUTH = {
    'CVE-2022-1471':    ('snakeyaml', '1.30', 'active'),
    'CVE-2022-42889':   ('commons-text', '1.9', 'active'),
    'CVE-2018-1000632': ('dom4j', '1.6.1', 'active'),
    'CVE-2015-6420':    ('commons-collections', '3.2.1', 'passive'),
    'CVE-2023-24998':   ('commons-fileupload', '1.4', 'passive'),
}

SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
SEV_MAP = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM',
           'MODERATE': 'MEDIUM', 'LOW': 'LOW', 'NEGLIGIBLE': 'LOW',
           'UNKNOWN': 'UNKNOWN', 'NONE': 'UNKNOWN', '': 'UNKNOWN'}


def norm_sev(s):
    return SEV_MAP.get((s or '').upper(), 'UNKNOWN')


def load(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def parse_trivy(path, image, input_):
    data = load(path)
    if data is None:
        return [], 'missing'
    rows = []
    for result in data.get('Results') or []:
        cls = result.get('Class', '')
        layer = 'os' if cls == 'os-pkgs' else ('app' if cls == 'lang-pkgs' else 'unknown')
        for v in result.get('Vulnerabilities') or []:
            cvss = None
            for vendor in ('nvd', 'redhat', 'ghsa', 'bitnami'):
                sc = (v.get('CVSS') or {}).get(vendor, {})
                if sc.get('V3Score'):
                    cvss = sc['V3Score']; break
            if cvss is None:
                for sc in (v.get('CVSS') or {}).values():
                    if sc.get('V3Score'):
                        cvss = sc['V3Score']; break
            rows.append(dict(image=image, input=input_, scanner='Trivy',
                             vuln_id=v.get('VulnerabilityID', ''), raw_id=v.get('VulnerabilityID', ''),
                             package=v.get('PkgName', ''), version=v.get('InstalledVersion', ''),
                             severity=norm_sev(v.get('Severity')), cvss=cvss, layer=layer,
                             artifact_type=result.get('Type', '')))
    return rows, 'ok'


def parse_grype(path, image, input_):
    data = load(path)
    if data is None:
        return [], 'missing'
    rows = []
    for m in data.get('matches') or []:
        vuln = m.get('vulnerability', {})
        art = m.get('artifact', {})
        vid = vuln.get('id', '')
        cve = vid if vid.startswith('CVE-') else next(
            (rv['id'] for rv in m.get('relatedVulnerabilities', []) if rv.get('id', '').startswith('CVE-')), vid)
        cvss = None
        for c in vuln.get('cvss') or []:
            if (c.get('metrics') or {}).get('baseScore'):
                cvss = c['metrics']['baseScore']; break
        atype = art.get('type', '')
        layer = 'os' if atype in ('rpm', 'deb', 'apk') else (
            'app' if atype in ('java-archive', 'graalvm-native-image', 'binary', 'go-module', 'python') else 'unknown')
        rows.append(dict(image=image, input=input_, scanner='Grype',
                         vuln_id=cve, raw_id=vid, package=art.get('name', ''),
                         version=art.get('version', ''), severity=norm_sev(vuln.get('severity')),
                         cvss=cvss, layer=layer, artifact_type=atype))
    return rows, 'ok'


_SNYK_OS_ID = re.compile(r'^SNYK-(ALPINE|RHEL|DEBIAN|UBUNTU|AMZN|CENTOS|ORACLE|SLES|LINUX)')


def _snyk_layer(v):
    purl = v.get('packageUrl') or ''
    if purl.startswith('pkg:'):
        ptype = purl[4:].split('/')[0]
        if ptype in ('rpm', 'deb', 'apk', 'alpine', 'redhat', 'amzn'):
            return 'os'
        if ptype in ('maven', 'golang', 'pypi', 'npm'):
            return 'app'
    sid = v.get('id', '')
    if _SNYK_OS_ID.match(sid):
        return 'os'
    if sid.startswith(('SNYK-JAVA', 'SNYK-GOLANG', 'SNYK-PYTHON', 'SNYK-JS')):
        return 'app'
    lang, pm = v.get('language', ''), v.get('packageManager', '')
    if lang == 'linux' or pm in ('rpm', 'deb', 'apk', 'linux'):
        return 'os'
    if lang or pm:
        return 'app'
    return 'unknown'


def _snyk_vulns(vlist, image, input_, layer_hint=None):
    rows = []
    for v in vlist or []:
        cves = (v.get('identifiers') or {}).get('CVE') or []
        vid = cves[0] if cves else v.get('id', '')
        purl = v.get('packageUrl') or ''
        atype = purl[4:].split('/')[0] if purl.startswith('pkg:') else (v.get('packageManager') or '')
        rows.append(dict(image=image, input=input_, scanner='Snyk',
                         vuln_id=vid, raw_id=v.get('id', ''), package=v.get('packageName', ''),
                         version=(v.get('version') or ''), severity=norm_sev(v.get('severity')),
                         cvss=v.get('cvssScore'), layer=layer_hint or _snyk_layer(v),
                         artifact_type=atype))
    return rows


def parse_snyk(path, image, input_):
    data = load(path)
    if data is None:
        return [], 'missing'
    if isinstance(data, dict) and data.get('ok') is False and 'error' in data and 'vulnerabilities' not in data:
        return [], 'error: ' + str(data.get('error', ''))[:120]
    rows = []
    for proj in (data if isinstance(data, list) else [data]):
        rows += _snyk_vulns(proj.get('vulnerabilities'), image, input_)
        for app in proj.get('applications') or []:
            rows += _snyk_vulns(app.get('vulnerabilities'), image, input_, layer_hint='app')
    return rows, 'ok'


PURL_RE = re.compile(r'pkg:([^/]+)/(?:([^/]+)/)?([^@]+)@([^?]+)')


def parse_scout(path, image, input_):
    data = load(path)
    if data is None:
        return [], 'missing'
    runs = data.get('runs') or []
    if not runs:
        return [], 'error: no runs'
    run = runs[0]
    rules = {r['id']: r for r in (run.get('tool', {}).get('driver', {}).get('rules') or [])}
    rows = []
    for res in run.get('results') or []:
        rid = res.get('ruleId', '')
        rule = rules.get(rid, {})
        props = rule.get('properties', {})
        pkg, ver, ptype = '', '', ''
        purls = props.get('purls') or []
        if purls:
            m = PURL_RE.match(purls[0])
            if m:
                ptype, _, pkg, ver = m.groups()
        vid = rid
        if not rid.startswith('CVE-'):
            m = re.search(r'CVE-\d{4}-\d+', json.dumps(rule))
            if m:
                vid = m.group(0)
        layer = 'os' if ptype in ('rpm', 'deb', 'apk', 'alpine', 'redhat') else (
            'app' if ptype in ('maven', 'golang', 'pypi', 'npm') else 'unknown')
        rows.append(dict(image=image, input=input_, scanner='Docker Scout',
                         vuln_id=vid, raw_id=rid, package=pkg, version=ver,
                         severity=norm_sev(props.get('cvssV3_severity')),
                         cvss=props.get('cvssV3'), layer=layer, artifact_type=ptype))
    return rows, 'ok'


PARSERS = {'Trivy': ('trivy.json', parse_trivy), 'Grype': ('grype.json', parse_grype),
           'Snyk': ('snyk.json', parse_snyk), 'Docker Scout': ('docker-scout.sarif.json', parse_scout)}
GENERATORS = {'syft': 'sbom-syft', 'trivy': 'sbom-trivy', 'scout': 'sbom-scout'}


def load_all(results_dir='results'):
    rows, statuses = [], []
    for image in IMAGES:
        base = os.path.join(results_dir, PREFIX + image)
        for scanner, (fname, fn) in PARSERS.items():
            r, st = fn(os.path.join(base, fname), image, 'direct')
            rows += r
            statuses.append(dict(image=image, input='direct', scanner=scanner, status=st, n=len(r)))
        for gen, input_ in GENERATORS.items():
            for scanner, (fname, fn) in PARSERS.items():
                r, st = fn(os.path.join(base, 'sbom', gen, fname), image, input_)
                rows += r
                statuses.append(dict(image=image, input=input_, scanner=scanner, status=st, n=len(r)))
    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=['image', 'input', 'scanner', 'vuln_id', 'package']).reset_index(drop=True)
    return df, pd.DataFrame(statuses)


CDX_PARSERS = {'Trivy': ('trivy.cdx.json', parse_trivy), 'Grype': ('grype.cdx.json', parse_grype),
               'Snyk': ('snyk.cdx.json', parse_snyk), 'Docker Scout': ('docker-scout.sarif.cdx.json', parse_scout)}
CDX_IMAGES = ['DOCKERFILE-jvm', 'DOCKERFILE-native']


def load_sbom_cdx(results_dir='results', images=None, generators=('syft', 'trivy')):
    """Parse the CycloneDX SBOM control series (images x generators x scanners).

    Mirrors load_all() but reads the *.cdx.json reports under results/<image>/sbom/<gen>/
    and tags each run with input 'cdx-<gen>'. Returns (df, status_df) shaped exactly like
    load_all()'s output, so the two status frames concatenate into one 160-run completeness
    view and the findings can be reused without parsing the files a second time.
    """
    if images is None:
        images = CDX_IMAGES
    rows, statuses = [], []
    for image in images:
        base = os.path.join(results_dir, PREFIX + image)
        for gen in generators:
            for scanner, (fname, fn) in CDX_PARSERS.items():
                r, st = fn(os.path.join(base, 'sbom', gen, fname), image, f'cdx-{gen}')
                rows += r
                statuses.append(dict(image=image, input=f'cdx-{gen}', scanner=scanner, status=st, n=len(r)))
    return pd.DataFrame(rows), pd.DataFrame(statuses)
