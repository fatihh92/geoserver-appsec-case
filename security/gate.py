"""Fail closed on invalid reports; block HIGH/CRITICAL SAST and SCA results.

No baselines, severity overrides, or suppression lists are accepted by this PoC.
Exit 0: policy passed, 1: blocking findings, 2: invalid/incomplete evidence.
"""

import argparse
import json
import math
import os
from pathlib import Path
import sys


def codeql_findings(directory):
    files = sorted(Path(directory).glob('*.sarif'))
    if not files:
        raise ValueError('CodeQL SARIF report is missing')
    findings = []
    for path in files:
        report = json.loads(path.read_text())
        if report.get('version') != '2.1.0' or not report.get('runs'):
            raise ValueError('Invalid or empty SARIF runs')
        for run in report['runs']:
            driver = run['tool']['driver']
            if 'CodeQL' not in driver.get('name', ''):
                raise ValueError('Expected a CodeQL SARIF report')
            for invocation in run.get('invocations', []):
                if invocation.get('executionSuccessful') is False:
                    raise ValueError('CodeQL execution was unsuccessful')
            rules = {rule['id']: rule for rule in driver.get('rules', [])}
            if not rules or not isinstance(run.get('results'), list):
                raise ValueError('CodeQL rule definitions or results are missing')
            for result in run['results']:
                rule_id = result.get('ruleId')
                if rule_id not in rules:
                    raise ValueError('CodeQL result has no matching rule definition')
                properties = rules[rule_id].get('properties', {})
                score = properties.get('security-severity')
                if score is None:
                    # Non-security quality rules have no security severity.
                    if 'security' in properties.get('tags', []):
                        raise ValueError('Security rule has no security-severity')
                    continue
                score = float(score)
                if not math.isfinite(score) or not 0 <= score <= 10:
                    raise ValueError('Invalid CodeQL security-severity')
                if score >= 7:
                    findings.append({'rule': rule_id, 'security_severity': score})
    return findings


def trivy_findings(filename):
    report = json.loads(Path(filename).read_text())
    if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results'), list):
        raise ValueError('Invalid Trivy report schema')
    packages = 0
    findings = []
    for result in report['Results']:
        for package in result.get('Packages', []):
            if not package.get('Name') or not package.get('Version'):
                raise ValueError('A dependency name or version is unresolved')
            packages += 1
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity')
            if severity not in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
                raise ValueError('A vulnerability has unknown or missing severity; review required')
            if severity in {'HIGH', 'CRITICAL'}:
                findings.append({
                    'target': result['Target'],
                    'package': vuln['PkgName'],
                    'version': vuln['InstalledVersion'],
                    'id': vuln['VulnerabilityID'],
                    'severity': severity,
                })
    if packages == 0:
        raise ValueError('No dependency inventory found; a clean scan cannot be claimed')
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scanner', choices=['codeql', 'trivy'])
    parser.add_argument('report')
    args = parser.parse_args()
    try:
        findings = (codeql_findings if args.scanner == 'codeql' else trivy_findings)(args.report)
        status = 'blocked' if findings else 'passed'
        result = {'scanner': args.scanner, 'status': status, 'blocking_findings': findings}
        exit_code = 1 if findings else 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        result = {'scanner': args.scanner, 'status': 'invalid-evidence', 'error': str(exc)}
        exit_code = 2
    output = json.dumps(result, indent=2)
    print(output)
    Path('reports').mkdir(exist_ok=True)
    Path(f'reports/{args.scanner}-gate.json').write_text(output + '\n')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write(f'### {args.scanner}: {result["status"]}\n\n')
            stream.write('See the report artifacts for details.\n\n')
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
