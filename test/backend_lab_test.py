import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("lab", Path(__file__).with_name("backend-lab.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class VerdictTest(unittest.TestCase):
    def record(self):
        return {"status": "passed", "checks": {key: True for key in lab.REQUIRED_CHECKS},
                "phases_seconds": {key: 0.1 for key in lab.REQUIRED_PHASES},
                "output_sha256": "a" * 64}

    def test_partial_or_failed_runs_never_pass(self):
        self.assertTrue(lab.valid_result(self.record()))
        for key in lab.REQUIRED_CHECKS:
            record = self.record()
            record["checks"][key] = False
            self.assertFalse(lab.valid_result(record))
            del record["checks"][key]
            self.assertFalse(lab.valid_result(record))
        for key in lab.REQUIRED_PHASES:
            record = self.record()
            del record["phases_seconds"][key]
            self.assertFalse(lab.valid_result(record))
        record = self.record()
        record["status"] = "unavailable"
        self.assertFalse(lab.valid_result(record))

    def test_ambiguous_or_missing_output_is_an_error(self):
        for text in ["", 'AIRBAG_RESULT {}\nAIRBAG_RESULT {}\n']:
            with self.assertRaises(ValueError):
                lab.parse_result(text)

    def test_invalid_duration_is_not_a_measurement(self):
        for value in [float("nan"), float("inf"), -1, "0.1"]:
            record = self.record()
            record["phases_seconds"]["cold_build"] = value
            self.assertFalse(lab.valid_result(record))
