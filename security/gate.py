"""Fail closed on invalid reports; block HIGH/CRITICAL SAST and SCA results.

No baselines, severity overrides, or suppression lists are accepted by this PoC.
Exit 0: policy passed or findings reported, 1: blocked, 2: invalid evidence.
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
            # CodeQL query packs can store descriptors in tool.extensions,
            # while tool.driver.rules is empty. Do not treat that as no rules.
            components = [driver] + run['tool'].get('extensions', [])
            rules = {}
            for component in components:
                for rule in component.get('rules', []):
                    rule_id = rule['id']
                    if rule_id in rules and rules[rule_id] != rule:
                        raise ValueError('Ambiguous CodeQL rule definitions')
                    rules[rule_id] = rule
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
                    locations = result.get('locations', [])
                    physical = locations[0].get('physicalLocation', {}) if locations else {}
                    findings.append({
                        'rule': rule_id,
                        'security_severity': score,
                        'file': physical.get('artifactLocation', {}).get('uri'),
                        'line': physical.get('region', {}).get('startLine'),
                    })
    return findings


def trivy_findings(filename, report_only=False, coverage_warnings=None):
    report = json.loads(Path(filename).read_text())
    if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results'), list):
        raise ValueError('Invalid Trivy report schema')
    packages = 0
    findings = []
    warnings = []
    for result in report['Results']:
        for package in result.get('Packages', []):
            name = package.get('Name')
            if not isinstance(name, str) or not name.strip():
                raise ValueError('A dependency name is missing or invalid')
            version = package.get('Version')
            if version is not None and not isinstance(version, str):
                raise ValueError('A dependency version has an invalid type')
            if not version or not version.strip() or '${' in version:
                warnings.append({
                    'reason': 'unresolved-version',
                    'target': result.get('Target'),
                    'package': name,
                    'version': version,
                    'relationship': package.get('Relationship'),
                    'locations': package.get('Locations', []),
                })
            packages += 1
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity')
            if severity == 'UNKNOWN' and report_only:
                continue
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
    if coverage_warnings is not None:
        coverage_warnings.extend(warnings)
    elif warnings and not report_only:
        raise ValueError('Dependency versions are unresolved')
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scanner', choices=['codeql', 'trivy'])
    parser.add_argument('report')
    parser.add_argument('--mode', choices=['enforce', 'report-only'], default='enforce')
    args = parser.parse_args()
    try:
        coverage_warnings = []
        findings = (codeql_findings(args.report) if args.scanner == 'codeql'
                    else trivy_findings(args.report, report_only=args.mode == 'report-only',
                                        coverage_warnings=coverage_warnings))
        blocked = bool(findings or coverage_warnings) and args.mode == 'enforce'
        status = 'reported' if args.mode == 'report-only' else ('blocked' if blocked else 'passed')
        result = {'scanner': args.scanner, 'mode': args.mode, 'status': status,
                  'high_critical_findings': findings,
                  'coverage_warnings': coverage_warnings,
                  'unresolved_version_count': len(coverage_warnings)}
        exit_code = 1 if blocked else 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        result = {'scanner': args.scanner, 'mode': args.mode, 'status': 'invalid-evidence', 'error': str(exc)}
        exit_code = 2
    output = json.dumps(result, indent=2)
    print(output)
    Path('reports').mkdir(exist_ok=True)
    Path(f'reports/{args.scanner}-gate.json').write_text(output + '\n')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write(f'### {args.scanner}: {result["status"]}\n\n')
            stream.write(f'Mode: {args.mode}. See the report artifacts for details.\n\n')
            if result.get('coverage_warnings'):
                stream.write(f'Coverage warning: {result["unresolved_version_count"]} package '
                             'records have unresolved versions. See coverage_warnings in '
                             'the JSON artifact; dependency coverage is incomplete.\n\n')
            if args.mode == 'report-only':
                stream.write('Report-only does not certify the absence of vulnerabilities.\n\n')
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
