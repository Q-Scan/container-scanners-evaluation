"""Strips personal data from the raw reports in results/ before they are published.

What and where (the only two places across the report files - the rest is clean):
  * Grype: `descriptor.configuration.db.cache-dir` and `descriptor.db.status.path`
           contain the local path `/home/<user>/.cache/grype/db`
  * Snyk : the `org` field = the account organisation slug

Both sit in the **report header**, not in the findings - the parsers read `matches` (Grype)
and `vulnerabilities`/`applications` (Snyk), so redaction cannot change a single number.
The script does NOT assume this: `--check` recomputes the `load_all()` frame and compares its fingerprint
before and after. If the fingerprint changes, the redaction touched the data - and must be reverted.

The substitution is textual (the username occurs only inside JSON string values),
so the files stay byte-identical apart from the pseudonym itself.

The username is NOT hard-coded - otherwise the file that removes it would publish it itself.
By default it is taken from the environment; it can be given explicitly via --user.

Usage:
    python analysis/sanitize_results.py --check          # data fingerprint BEFORE
    python analysis/sanitize_results.py [--user NAME]   # redact
    python analysis/sanitize_results.py --check          # the fingerprint MUST be identical
"""
import io
import os
import sys
import glob
import getpass
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

MASK = 'anonymous'          # what to replace the username with


def fingerprint():
    """Fingerprint of EVERY parsed finding - this is what must not change."""
    from scanlib import load_all
    df, status = load_all('results')
    df = df.sort_values(list(df.columns)).reset_index(drop=True)
    h = hashlib.sha256(df.to_csv(index=False).encode()).hexdigest()
    return h, len(df), (status.status == 'ok').sum()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true', help='fingerprint only, change nothing')
    ap.add_argument('--user', default=getpass.getuser(),
                    help='username to redact (default: the current user)')
    args = ap.parse_args()

    if args.check:
        h, n, ok = fingerprint()
        print(f'findings: {n} | scans ok: {ok}\nsha256(df): {h}')
        return

    user = args.user
    if not user or user == MASK:
        sys.exit('give a username: --user NAME')

    files = glob.glob('results/**/*.json', recursive=True)
    touched = 0
    for f in files:
        txt = io.open(f, encoding='utf-8').read()
        if user not in txt:
            continue
        io.open(f, 'w', encoding='utf-8', newline='').write(txt.replace(user, MASK))
        touched += 1

    print(f'redacted {touched} of {len(files)} files (username -> "{MASK}")')
    print('now run: python analysis/sanitize_results.py --check  (the fingerprint must match)')


if __name__ == '__main__':
    main()
