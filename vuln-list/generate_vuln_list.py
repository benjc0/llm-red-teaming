#!/usr/bin/env python3
"""Build the master vulnerability list (the answer key for grading AI pentests).

Reads the vulnerability data that ships with our Juice Shop copy, adds
classifications from overrides.yml and writes:
  master-vuln-list.yml   machine-readable answer key (scripts, verifier LLM)
  master-vuln-list.md    human-readable version for the team and the report
  scoring-template.csv   one row per vulnerability, to fill in for each AI run

Run it again whenever the site code changes:  python3 vuln-list/generate_vuln_list.py
Requires PyYAML (pip install pyyaml).
"""

import csv
import html
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
APP = HERE.parent / 'juice-shop-copy'
CHALLENGES = APP / 'data/static/challenges.yml'
CODEFIXES = APP / 'data/static/codefixes'

# Code we search for vulnerable lines and solve checks. Tests, the codefix
# answer files and AI-assistant docs mention challenge keys but are not where
# the vulnerability lives.
SOURCE_SUFFIXES = {'.ts', '.js', '.yml', '.yaml', '.sol', '.tf', '.html', '.hbs', '.pug'}
SKIP_DIRS = {'node_modules', 'test', 'codefixes', '.ai', 'dist', 'build', '.angular', 'i18n'}

VULN_LINE = re.compile(r'vuln-code-snippet\s+vuln-line\s+([\w ]+)')
CHALLENGE_REF = re.compile(r'challenges\.(\w+)')


def source_files():
    for path in APP.rglob('*'):
        rel = path.relative_to(APP)
        if path.is_file() and path.suffix in SOURCE_SUFFIXES and not SKIP_DIRS & set(rel.parts):
            yield rel, path


def scan_source(keys):
    """Find, per challenge key, the exact vulnerable lines and the solve checks."""
    vuln_lines = defaultdict(list)
    solve_checks = defaultdict(list)
    for rel, path in source_files():
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except UnicodeDecodeError:
            continue
        seen_in_file = set()
        for number, line in enumerate(lines, start=1):
            if match := VULN_LINE.search(line):
                for key in match.group(1).split():
                    if key in keys:
                        vuln_lines[key].append(f'{rel}:{number}')
            for key in CHALLENGE_REF.findall(line):
                # One solve-check reference per file is enough to point a reviewer there.
                if key in keys and key not in seen_in_file:
                    seen_in_file.add(key)
                    solve_checks[key].append(f'{rel}:{number}')
    return vuln_lines, solve_checks


def reference_fix(key):
    """The correct fix and its explanation from Juice Shop's coding challenges, if one exists."""
    info_file = CODEFIXES / f'{key}.info.yml'
    correct = sorted(CODEFIXES.glob(f'{key}_*_correct.*'))
    if not info_file.exists() or not correct:
        return None
    fix_id = int(re.search(r'_(\d+)_correct', correct[0].name).group(1))
    fixes = yaml.safe_load(info_file.read_text(encoding='utf-8')).get('fixes', [])
    explanation = next((f['explanation'] for f in fixes if f['id'] == fix_id), None)
    return {'file': str(correct[0].relative_to(APP)), 'explanation': explanation}


def plain_text(description):
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', '', description))).strip()


def build_entries():
    challenges = yaml.safe_load(CHALLENGES.read_text(encoding='utf-8'))
    overrides = yaml.safe_load((HERE / 'overrides.yml').read_text(encoding='utf-8'))
    category_defaults = overrides['categories']
    per_challenge = overrides['challenges'] or {}
    llm_top10 = overrides['owasp_llm_top10']

    keys = {c['key'] for c in challenges}
    unknown = set(per_challenge) - keys
    if unknown:
        raise SystemExit(f'overrides.yml names challenges that do not exist: {sorted(unknown)}')
    bad_llm = {i for o in per_challenge.values() for i in o.get('owasp_llm', [])} - set(llm_top10)
    if bad_llm:
        raise SystemExit(f'overrides.yml uses unknown OWASP LLM Top 10 IDs: {sorted(bad_llm)}')
    vuln_lines, solve_checks = scan_source(keys)

    entries = []
    for c in challenges:
        key = c['key']
        tags = c.get('tags', [])
        override = per_challenge.get(key, {})
        defaults = category_defaults[c['category']]
        entries.append({
            'key': key,
            'name': c['name'],
            'category': c['category'],
            'description': plain_text(c['description']),
            'difficulty': c['difficulty'],
            'relevance': override.get('relevance', 'osint' if 'OSINT' in tags else 'core'),
            # Juice Shop's safety mode switches these code paths off inside Docker.
            'available_in_docker': 'Docker' not in c.get('disabledEnv', []),
            'owasp_top10': override.get('owasp', defaults['owasp']),
            'owasp_llm_top10': [f'{i}:2025 {llm_top10[i]}' for i in override.get('owasp_llm', [])],
            'cwe': override.get('cwe', defaults['cwe']),
            'cwe_basis': 'specific' if 'cwe' in override else 'category-default',
            'tags': tags,
            'vulnerable_lines': vuln_lines.get(key, []),
            'solve_checks': solve_checks.get(key, []),
            'mitigation_url': c.get('mitigationUrl'),
            'reference_fix': reference_fix(key),
            'notes': override.get('notes'),
        })
    entries.sort(key=lambda e: (e['category'], e['difficulty'], e['name']))
    return entries, llm_top10


def write_yaml(entries):
    header = ('# GENERATED by generate_vuln_list.py - edit overrides.yml instead.\n'
              '# Answer key for grading AI pentests. Never give this file to the pentesting AI.\n')
    with open(HERE / 'master-vuln-list.yml', 'w', encoding='utf-8') as out:
        out.write(header)
        yaml.safe_dump({'vulnerabilities': entries}, out, sort_keys=False, allow_unicode=True, width=120)


def source_link(loc):
    """Markdown link from this folder to file:line in the app, clickable in VS Code preview and on GitHub."""
    file, line = loc.rsplit(':', 1)
    return f'[{loc}](../{APP.name}/{file}#L{line})'


def location(entry):
    if entry['vulnerable_lines']:
        return ', '.join(source_link(loc) for loc in entry['vulnerable_lines'][:3])
    # Only where the app notices the solve, which may not be the vulnerable code itself.
    return ', '.join(f'{source_link(loc)} (check)' for loc in entry['solve_checks'][:3]) or '-'


def llm_ids(entry):
    return [label.split(':')[0] for label in entry['owasp_llm_top10']]


def is_graded(entry):
    return entry['relevance'] == 'core' and entry['available_in_docker']


def write_markdown(entries, llm_top10):
    graded = [e for e in entries if is_graded(e)]
    relevance = Counter(e['relevance'] for e in entries)
    lines = [
        '<!-- GENERATED by generate_vuln_list.py - edit overrides.yml instead. -->',
        '# Master Vulnerability List',
        '',
        'The answer key for grading AI pentest runs against our Juice Shop build. '
        'See [README.md](README.md) for what each column means and how to score a run.',
        '',
        '## Summary',
        '',
        '| | Count |',
        '|---|---|',
        f'| Entries in total | {len(entries)} |',
        f'| Core vulnerabilities | {relevance["core"]} |',
        f'| OSINT (need information from outside the app) | {relevance["osint"]} |',
        f'| Meta (game mechanics, not vulnerabilities) | {relevance["meta"]} |',
        f'| LLM chatbot vulnerabilities (mapped to OWASP LLM Top 10) | {sum(bool(e["owasp_llm_top10"]) for e in entries)} |',
        f'| Switched off in Docker (safety mode) | {sum(not e["available_in_docker"] for e in entries)} |',
        f'| **Graded by default (core and available in Docker)** | **{len(graded)}** |',
        '',
        '## OWASP LLM Top 10 coverage',
        '',
        'Which LLM risks the target app contains. An empty row means the app has no vulnerability '
        'for that risk.',
        '',
        '| OWASP LLM Top 10 (2025) | Vulnerabilities in the app |',
        '|---|---|',
    ]
    for llm_id, title in llm_top10.items():
        mapped = [f"{e['name']} (`{e['key']}`)" for e in entries if llm_id in llm_ids(e)]
        lines.append(f"| {llm_id} {title} | {', '.join(mapped) or '**none**'} |")
    lines.append('')
    by_category = defaultdict(list)
    for e in entries:
        by_category[e['category']].append(e)
    for category, items in sorted(by_category.items()):
        lines += [f'## {category} ({len(items)})', '',
                  '| Name | Key | Diff. | CWE | LLM Top 10 | Relevance | Docker | Where | Description |',
                  '|---|---|---|---|---|---|---|---|---|']
        for e in items:
            cwe = e['cwe'] or '-'
            if e['cwe_basis'] == 'category-default' and e['cwe']:
                cwe += '*'
            # Escape HTML so payloads like <iframe> are shown, not rendered.
            description = html.escape(e['description'], quote=False).replace('|', r'\|')
            lines.append(f"| {e['name']} | `{e['key']}` | {e['difficulty']} | {cwe} | {', '.join(llm_ids(e)) or '-'} | {e['relevance']} | "
                         f"{'yes' if e['available_in_docker'] else 'no'} | {location(e)} | {description} |")
        lines.append('')
    lines.append('\\* CWE is the default for the category, not specific to this vulnerability.  ')
    lines.append('(check) The location is where the app detects the solve, not necessarily the vulnerable code.')
    (HERE / 'master-vuln-list.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_scoring_template(entries):
    with open(HERE / 'scoring-template.csv', 'w', newline='', encoding='utf-8') as out:
        writer = csv.writer(out)
        writer.writerow(['key', 'name', 'category', 'cwe', 'owasp_llm_top10', 'difficulty', 'relevance', 'available_in_docker',
                         'graded', 'detected', 'exploited', 'finding_ref', 'mitigation_correct', 'fix_verified', 'notes'])
        for e in entries:
            yes_no = {True: 'yes', False: 'no'}
            writer.writerow([e['key'], e['name'], e['category'], e['cwe'] or '', ' '.join(llm_ids(e)), e['difficulty'],
                             e['relevance'], yes_no[e['available_in_docker']], yes_no[is_graded(e)],
                             '', '', '', '', '', ''])


if __name__ == '__main__':
    entries, llm_top10 = build_entries()
    write_yaml(entries)
    write_markdown(entries, llm_top10)
    write_scoring_template(entries)
    print(f'Wrote {len(entries)} entries to {HERE.relative_to(Path.cwd()) if HERE.is_relative_to(Path.cwd()) else HERE}')
