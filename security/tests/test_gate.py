"""Synthetic policy tests, not scan evidence for GeoServer."""

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('gate', Path(__file__).parents[1] / 'gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sarif = {
            'version': '2.1.0', 'runs': [{
                'tool': {'driver': {'name': 'CodeQL', 'rules': [{
                    'id': 'java/example',
                    'properties': {'security-severity': '7.0', 'tags': ['security']},
                }]}}, 'results': [],
            }],
        }
        self.trivy = {'SchemaVersion': 2, 'Results': [{
            'Target': 'pom.xml', 'Packages': [{'Name': 'example:library', 'Version': '1.0'}],
            'Vulnerabilities': [],
        }]}

    def write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data))
        return path

    def test_codeql_clean_report_passes(self):
        self.write('java.sarif', self.sarif)
        self.assertEqual(gate.codeql_findings(self.root), [])

    def test_codeql_high_result_blocks(self):
        self.sarif['runs'][0]['results'] = [{'ruleId': 'java/example'}]
        self.write('java.sarif', self.sarif)
        self.assertEqual(len(gate.codeql_findings(self.root)), 1)

    def test_codeql_security_severity_overrides_warning_level(self):
        self.sarif['runs'][0]['results'] = [{'ruleId': 'java/example', 'level': 'warning'}]
        self.write('java.sarif', self.sarif)
        self.assertEqual(len(gate.codeql_findings(self.root)), 1)

    def test_codeql_missing_report_fails(self):
        with self.assertRaises(ValueError):
            gate.codeql_findings(self.root)

    def test_codeql_missing_rule_fails(self):
        self.sarif['runs'][0]['results'] = [{'ruleId': 'unknown'}]
        self.write('java.sarif', self.sarif)
        with self.assertRaises(ValueError):
            gate.codeql_findings(self.root)

    def test_codeql_invalid_score_fails(self):
        self.sarif['runs'][0]['results'] = [{'ruleId': 'java/example'}]
        self.sarif['runs'][0]['tool']['driver']['rules'][0]['properties']['security-severity'] = 'NaN'
        self.write('java.sarif', self.sarif)
        with self.assertRaises(ValueError):
            gate.codeql_findings(self.root)

    def test_codeql_query_pack_extension_rules_are_supported(self):
        run = self.sarif['runs'][0]
        rules = run['tool']['driver'].pop('rules')
        run['tool']['driver']['rules'] = []
        run['tool']['extensions'] = [{'name': 'codeql/java-queries', 'rules': rules}]
        run['results'] = [{'ruleId': 'java/example', 'rule': {
            'id': 'java/example', 'index': 0, 'toolComponent': {'index': 0},
        }}]
        self.write('java.sarif', self.sarif)
        self.assertEqual(len(gate.codeql_findings(self.root)), 1)

    def test_codeql_clean_extension_report_passes(self):
        run = self.sarif['runs'][0]
        rules = run['tool']['driver'].pop('rules')
        run['tool']['extensions'] = [{'name': 'codeql/java-queries', 'rules': rules}]
        self.write('java.sarif', self.sarif)
        self.assertEqual(gate.codeql_findings(self.root), [])

    def test_codeql_conflicting_rule_definitions_fail(self):
        run = self.sarif['runs'][0]
        other = copy.deepcopy(run['tool']['driver']['rules'])
        other[0]['properties']['security-severity'] = '0.0'
        run['tool']['extensions'] = [{'name': 'other-pack', 'rules': other}]
        self.write('java.sarif', self.sarif)
        with self.assertRaises(ValueError):
            gate.codeql_findings(self.root)

    def test_trivy_clean_inventory_passes(self):
        self.assertEqual(gate.trivy_findings(self.write('trivy.json', self.trivy)), [])

    def test_trivy_high_and_critical_block_even_without_fix(self):
        for severity in ['HIGH', 'CRITICAL']:
            report = copy.deepcopy(self.trivy)
            report['Results'][0]['Vulnerabilities'] = [{
                'Severity': severity, 'PkgName': 'example:library',
                'InstalledVersion': '1.0', 'VulnerabilityID': 'CVE-TEST',
            }]
            self.assertEqual(len(gate.trivy_findings(self.write('trivy.json', report))), 1)

    def test_trivy_empty_inventory_fails(self):
        self.trivy['Results'][0]['Packages'] = []
        with self.assertRaises(ValueError):
            gate.trivy_findings(self.write('trivy.json', self.trivy))

    def test_trivy_unresolved_version_fails(self):
        self.trivy['Results'][0]['Packages'][0]['Version'] = ''
        with self.assertRaises(ValueError):
            gate.trivy_findings(self.write('trivy.json', self.trivy))

    def test_trivy_unknown_severity_fails(self):
        self.trivy['Results'][0]['Vulnerabilities'] = [{'Severity': 'UNKNOWN'}]
        with self.assertRaises(ValueError):
            gate.trivy_findings(self.write('trivy.json', self.trivy))

    def run_cli(self, scanner, report, mode):
        proc = subprocess.run(
            [sys.executable, '-B', str(Path(gate.__file__).resolve()),
             scanner, str(report), '--mode', mode],
            cwd=self.root, capture_output=True, text=True)
        return proc.returncode, json.loads(proc.stdout)

    def test_cli_modes_for_both_scanners(self):
        self.sarif['runs'][0]['results'] = [{'ruleId': 'java/example'}]
        self.write('java.sarif', self.sarif)
        self.trivy['Results'][0]['Vulnerabilities'] = [{
            'Severity': 'CRITICAL', 'PkgName': 'example:library',
            'InstalledVersion': '1.0', 'VulnerabilityID': 'CVE-TEST'}]
        trivy_path = self.write('trivy.json', self.trivy)
        for scanner, report in [('codeql', self.root), ('trivy', trivy_path)]:
            for mode, expected, status in [('enforce', 1, 'blocked'),
                                            ('report-only', 0, 'reported')]:
                with self.subTest(scanner=scanner, mode=mode):
                    code, result = self.run_cli(scanner, report, mode)
                    self.assertEqual(code, expected)
                    self.assertEqual(result['status'], status)
                    self.assertEqual(len(result['high_critical_findings']), 1)

    def test_report_only_missing_reports_still_fail(self):
        for scanner in ['codeql', 'trivy']:
            with self.subTest(scanner=scanner):
                code, result = self.run_cli(scanner, self.root / 'missing', 'report-only')
                self.assertEqual(code, 2)
                self.assertEqual(result['status'], 'invalid-evidence')

    def test_report_only_empty_inventory_still_fails(self):
        self.trivy['Results'][0]['Packages'] = []
        code, result = self.run_cli('trivy', self.write('trivy.json', self.trivy), 'report-only')
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'invalid-evidence')

    def test_report_only_unknown_severity_is_reported(self):
        self.trivy['Results'][0]['Vulnerabilities'] = [{'Severity': 'UNKNOWN'}]
        code, result = self.run_cli('trivy', self.write('trivy.json', self.trivy), 'report-only')
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'reported')

    def test_any_unresolved_versions_are_collected_in_both_modes(self):
        for count in [1, 17]:
            self.trivy['Results'][0]['Packages'] = [
                {'Name': f'arbitrary:package-{i}', 'Version': [None, '', '  ', '${revision}'][i % 4]}
                for i in range(count)]
            self.trivy['Results'][0]['Vulnerabilities'] = [{
                'Severity': 'HIGH', 'PkgName': 'known:library',
                'InstalledVersion': '1', 'VulnerabilityID': 'CVE-TEST'}]
            path = self.write('trivy.json', self.trivy)
            for mode, expected in [('enforce', 1), ('report-only', 0)]:
                with self.subTest(count=count, mode=mode):
                    code, result = self.run_cli('trivy', path, mode)
                    self.assertEqual(code, expected)
                    self.assertEqual(result['unresolved_version_count'], count)
                    self.assertEqual(len(result['coverage_warnings']), count)
                    self.assertEqual(len(result['high_critical_findings']), 1)

    def test_missing_version_without_vulnerabilities(self):
        del self.trivy['Results'][0]['Packages'][0]['Version']
        path = self.write('trivy.json', self.trivy)
        for mode, expected in [('enforce', 1), ('report-only', 0)]:
            code, result = self.run_cli('trivy', path, mode)
            self.assertEqual(code, expected)
            self.assertEqual(result['unresolved_version_count'], 1)

    def test_report_only_missing_name_is_still_invalid(self):
        del self.trivy['Results'][0]['Packages'][0]['Name']
        code, result = self.run_cli('trivy', self.write('trivy.json', self.trivy), 'report-only')
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'invalid-evidence')

    def test_report_only_invalid_version_type_is_still_invalid(self):
        self.trivy['Results'][0]['Packages'][0]['Version'] = {'unexpected': 'object'}
        code, result = self.run_cli('trivy', self.write('trivy.json', self.trivy), 'report-only')
        self.assertEqual(code, 2)

    def test_report_only_malformed_json_is_still_invalid(self):
        path = self.root / 'broken.json'
        path.write_text('{broken')
        code, result = self.run_cli('trivy', path, 'report-only')
        self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
