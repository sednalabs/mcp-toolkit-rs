"""Regression tests for source identity and the unpublished custody boundary."""

import copy
from pathlib import Path
import tempfile
import unittest

from cargo_package_readiness import validate_excluded_publication_posture
from check_dpop_git_consumer import DEFAULT_REPOSITORY, validate_graph


class CustodyGuards(unittest.TestCase):
    def test_vendor_must_explicitly_disable_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor" / "dpop-verifier"
            vendor.mkdir(parents=True)
            manifest = vendor / "Cargo.toml"
            for field in ("", "publish = true\n", 'publish = ["crates-io"]\n'):
                with self.subTest(field=field):
                    manifest.write_text('[package]\nname = "dpop-verifier"\n' + field)
                    self.assertTrue(validate_excluded_publication_posture(root, set()))
            manifest.write_text('[package]\nname = "dpop-verifier"\npublish = false\n')
            self.assertEqual(validate_excluded_publication_posture(root, set()), [])

    def setUp(self):
        self.revision = "a" * 40
        source = f"git+{DEFAULT_REPOSITORY}?rev={self.revision}#{self.revision}"
        self.metadata = {"packages": [
            {"name": "mcp-toolkit-auth", "version": "0.1.0", "source": source},
            {"name": "dpop-verifier", "version": "4.4.1", "source": source},
            {"name": "crypto-bigint", "version": "0.7.8", "source": "registry+test"},
        ]}

    def validate(self, metadata):
        return validate_graph(metadata, DEFAULT_REPOSITORY, self.revision)

    def test_canonical_git_graph_is_accepted(self):
        self.assertEqual(self.validate(self.metadata)["verifier_version"], "4.4.1")

    def test_duplicate_or_registry_verifier_is_rejected(self):
        duplicate = copy.deepcopy(self.metadata)
        duplicate["packages"].append(copy.deepcopy(duplicate["packages"][1]))
        with self.assertRaises(ValueError):
            self.validate(duplicate)
        self.metadata["packages"][1]["source"] = "registry+test"
        with self.assertRaises(ValueError):
            self.validate(self.metadata)

    def test_wrong_revision_is_rejected(self):
        for package in self.metadata["packages"][:2]:
            package["source"] = package["source"].replace(self.revision, "b" * 40)
        with self.assertRaises(ValueError):
            self.validate(self.metadata)

    def test_vulnerable_and_unqualified_crypto_versions_are_rejected(self):
        for version in ("0.5.5", "0.7.5", "0.7.6-rc.1"):
            with self.subTest(version=version):
                self.metadata["packages"][2]["version"] = version
                with self.assertRaises(ValueError):
                    self.validate(self.metadata)


if __name__ == "__main__":
    unittest.main()
