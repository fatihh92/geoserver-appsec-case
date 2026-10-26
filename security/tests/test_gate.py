"""Synthetic policy tests, not scan evidence for GeoServer."""

import copy
import importlib.util
import json
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


if __name__ == '__main__':
    unittest.main()
