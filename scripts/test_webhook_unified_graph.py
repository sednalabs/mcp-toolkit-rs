"""Exercise both acceptance and fail-closed feature/lock evidence checks."""

import copy
import unittest

from check_webhook_unified_graph import check, REQUIRED_FEATURES, REQUIRED_PACKAGES


class UnifiedGraphTests(unittest.TestCase):
    def setUp(self):
        packages = [
            {"id": name, "name": name, "version": "1.0.0", "source": "registry+fixture"}
            for name in sorted(REQUIRED_PACKAGES | {"reqwest"})
        ]
        self.metadata = {
            "packages": packages,
            "resolve": {"nodes": [
                {"id": p["id"], "features": sorted(REQUIRED_FEATURES) if p["name"] == "reqwest" else []}
                for p in packages
            ]},
        }
        self.lock = {"package": copy.deepcopy(packages)}

    def test_accepts_matching_resolved_graph(self):
        self.assertTrue(check(self.metadata, self.lock)["lock_matches_resolved_graph"])

    def test_rejects_missing_decoder_feature(self):
        node = next(n for n in self.metadata["resolve"]["nodes"] if n["id"] == "reqwest")
        node["features"].remove("brotli")
        with self.assertRaisesRegex(ValueError, "missing reqwest features"):
            check(self.metadata, self.lock)

    def test_rejects_unresolved_test_package(self):
        self.metadata["resolve"]["nodes"] = [
            n for n in self.metadata["resolve"]["nodes"] if n["id"] != "native-tls"
        ]
        with self.assertRaisesRegex(ValueError, "missing unified packages"):
            check(self.metadata, self.lock)

    def test_rejects_stale_lock(self):
        self.lock["package"] = [p for p in self.lock["package"] if p["name"] != "async-compression"]
        with self.assertRaisesRegex(ValueError, "absent from archived lock"):
            check(self.metadata, self.lock)

    def test_rejects_wrong_package_version_or_source(self):
        for field in ["version", "source"]:
            lock = copy.deepcopy(self.lock)
            lock["package"][0][field] = "different"
            with self.assertRaisesRegex(ValueError, "absent from archived lock"):
                check(self.metadata, lock)

    def test_rejects_ambiguous_reqwest_versions(self):
        self.metadata["packages"].append({"id": "other", "name": "reqwest", "version": "2.0.0"})
        with self.assertRaisesRegex(ValueError, "expected one"):
            check(self.metadata, self.lock)


if __name__ == "__main__":
    unittest.main()
