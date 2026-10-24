"""Regression tests for the Skill Bill scanner. Standard library only.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(HERE, "..", "skills", "skill-bill", "scripts", "scan.py")
sys.path.insert(0, HERE)
import make_fixture  # noqa: E402

spec = importlib.util.spec_from_file_location("scan", SCAN)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def run_scan(path):
    entries = scan.entries_from_dir(path)
    s = scan.Scan(entries).run()
    return scan.build_report(path, {"source": "local directory"}, [], s, [])


class MaliciousFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        make_fixture.build(cls.tmp.name)
        cls.report = run_scan(cls.tmp.name)
        cls.rules = {f["rule"] for f in cls.report["findings"] if f["severity"] != "info"}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_level_is_critical(self):
        self.assertEqual(self.report["level"], "CRITICAL")

    def test_each_attack_class_is_caught(self):
        expected = {
            "UC1": "invisible Unicode tag smuggling",
            "HC1": "hidden HTML comment",
            "PI1": "instruction override",
            "EX4": "exfiltration instruction",
            "DX8": "base64 piped to shell",
            "DX1-B64": "payload hidden in base64",
            "RS1": "reverse shell",
            "PS1": "shell-profile persistence",
            "PS2": "cron persistence",
            "HK2": "auto-approving hook",
            "EX5": "secrets + network in one file",
            "OB3": "exec of decoded payload",
            "PY5": "subprocess shell=True",
            "IN1": "npm postinstall",
            "MCP1": "remote MCP server",
            "SC5": "git dependency",
            "PI9": "memory poisoning",
        }
        missing = {k: v for k, v in expected.items() if k not in self.rules}
        self.assertFalse(missing, f"not detected: {missing}")

    def test_hidden_text_is_decoded(self):
        uc1 = [f for f in self.report["findings"] if f["rule"] == "UC1"]
        self.assertIn("id_rsa", uc1[0]["snippet"])


class BenignSamples(unittest.TestCase):
    def scan_files(self, files):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(text)
            return run_scan(d)

    def test_plain_skill_is_clean(self):
        r = self.scan_files({"skills/fmt/SKILL.md": "---\nname: fmt\ndescription: Format Python files with ruff.\n---\n"
                             "# fmt\nRun `ruff format <file>` and show the diff.\n"})
        self.assertIn(r["level"], ("CLEAN", "LOW"))

    def test_detection_rule_literals_are_downgraded(self):
        r = self.scan_files({"src/rules.py": 'PATTERNS = [\n    (r"~/.ssh/id_rsa", "ssh key"),\n    "pastebin.com",\n]\n'})
        self.assertNotIn(r["level"], ("CRITICAL",))

    def test_emoji_zwj_and_math_operators_are_not_hidden_text(self):
        r = self.scan_files({"README.md": "Team \U0001F468‍\U0001F4BB rocks.\n",
                             "src/tex.rs": 'let s = "<mo>⁡</mo>";\n'})
        self.assertIn(r["level"], ("CLEAN", "LOW"))


class Cli(unittest.TestCase):
    def test_cli_exit_code_and_header(self):
        with tempfile.TemporaryDirectory() as d:
            make_fixture.build(d)
            p = subprocess.run([sys.executable, "-I", SCAN, d, "--no-meta"], capture_output=True, text=True,
                               encoding="utf-8")
        self.assertEqual(p.returncode, 3)
        self.assertIn("Skill Bill report", p.stdout)
        self.assertIn("Threat level: CRITICAL", p.stdout)


if __name__ == "__main__":
    unittest.main()
