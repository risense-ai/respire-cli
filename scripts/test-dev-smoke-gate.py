import copy
import importlib.util
import json
from pathlib import Path
import unittest

root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("gate", root / "dev-smoke-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BusinessSummaryTests(unittest.TestCase):
    def setUp(self):
        self.mapping = json.loads((root / "dev-runtime-business-coverage.json").read_text())
        self.rows = [{"action": row["action"],
                      **({"removed_by_requirement": True} if row.get("removed_by_requirement") else {"passed": True})}
                     for row in self.mapping["actions"]]

    def test_current_contract_is_64_and_8(self):
        self.assertEqual(gate.business_summary(self.rows, self.mapping),
                         {"passed": True, "observed": 64, "removed_by_requirement": 8})

    def test_invalid_partition_and_counts_rejected(self):
        overlap = copy.deepcopy(self.rows)
        overlap[0]["removed_by_requirement"] = True
        missing = copy.deepcopy(self.rows)
        missing[0].pop("passed")
        wrong = dict(self.mapping, retained=66, removed_by_requirement=6)
        for rows, mapping in [(overlap, self.mapping), (missing, self.mapping),
                              (self.rows + [self.rows[0]], self.mapping), (self.rows[:-1], self.mapping),
                              (self.rows, wrong)]:
            with self.subTest(rows=len(rows), retained=mapping["retained"]):
                with self.assertRaises(RuntimeError):
                    gate.business_summary(rows, mapping)


if __name__ == "__main__":
    unittest.main()
