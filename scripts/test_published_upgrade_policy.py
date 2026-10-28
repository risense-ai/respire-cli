import unittest
from published_upgrade_policy import platform_applicability


class UpgradePolicyTest(unittest.TestCase):
    def test_only_exact_documented_arm_gaps_are_not_applicable(self):
        for target in ["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"]:
            for tag in ["v1.0.15", "v1.0.16", "v1.0.17-dev.12"]:
                self.assertIsNotNone(platform_applicability(tag, target, []))
            for tag in ["v1.0.7", "v1.0.10", "v1.0.12", "v1.0.17", "v1.0.18"]:
                with self.assertRaises(ValueError):
                    platform_applicability(tag, target, [])

    def test_partial_or_non_arm_missing_assets_always_fail(self):
        target = "aarch64-unknown-linux-gnu"
        for asset in [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]:
            with self.assertRaises(ValueError):
                platform_applicability("v1.0.16", target, [asset])
        with self.assertRaises(ValueError):
            platform_applicability("v1.0.16", "x86_64-unknown-linux-gnu", [])

    def test_present_historical_arm_assets_remain_required(self):
        target = "aarch64-unknown-linux-musl"
        assets = [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]
        for tag in ["v1.0.7", "v1.0.16"]:
            self.assertIsNone(platform_applicability(tag, target, assets))


if __name__ == "__main__":
    unittest.main()
