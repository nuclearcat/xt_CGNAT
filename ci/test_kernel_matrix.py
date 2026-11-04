"""Exercise release filtering so a green matrix cannot silently lose coverage."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("matrix", Path(__file__).with_name("kernel-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def kernel(version, channel="stable", eol=False):
    return {"version": version, "moniker": channel, "iseol": eol,
            "source": f"https://cdn.kernel.org/pub/linux/linux-{version}.tar.xz"}


def fedora(version, subvariant="Cloud_Base"):
    return {"version": version, "subvariant": subvariant, "arch": "x86_64",
            "link": f"https://download.fedoraproject.org/{version}/test.qcow2",
            "sha256": "0" * 64}


class MatrixTests(unittest.TestCase):
    def test_active_branches_and_rc_keep_actual_source_url(self):
        rc = kernel("7.4-rc1", "mainline")
        rc["source"] = "https://git.kernel.org/torvalds/t/linux-7.4-rc1.tar.gz"
        rows = matrix.upstream_matrix({"releases": [
            rc, kernel("7.3.1"), kernel("6.18.60", "longterm"),
            kernel("7.2.15", eol=True), kernel("next-20261103", "linux-next"),
        ]})["include"]
        self.assertEqual([r["version"] for r in rows], ["7.4-rc1", "7.3.1", "6.18.60"])
        self.assertEqual(rows[0]["url"], rc["source"])

    def test_mainline_release_deduplicates(self):
        releases = [kernel("7.3", "mainline"), kernel("7.3")]
        for order in (releases, releases[::-1]):
            rows = matrix.upstream_matrix({"releases": order})
            self.assertEqual(len(rows["include"]), 1)
            self.assertEqual(rows["include"][0]["channel"], "stable")

    def test_missing_stable_fails_closed(self):
        with self.assertRaises(ValueError):
            matrix.upstream_matrix({"releases": [kernel("7.4-rc1", "mainline")]})

    def test_unexpected_source_fails_closed(self):
        release = kernel("7.3.1")
        release["source"] = "https://example.org/linux.tar.xz"
        with self.assertRaises(ValueError):
            matrix.upstream_matrix({"releases": [release]})

    def test_fedora_released_only_and_both_ubuntu_tracks(self):
        rows = matrix.distro_matrix([
            fedora("46 Beta"), fedora("45"), fedora("44"), fedora("43"),
            fedora("45", "Cloud_Base_UKI"),
        ])["include"]
        self.assertEqual([r["name"] for r in rows], [
            "ubuntu-24.04-ga", "ubuntu-24.04-hwe", "ubuntu-26.04-ga",
            "debian-13", "fedora-45", "fedora-44",
        ])
        self.assertEqual(rows[1]["packages"], "linux-generic-hwe-24.04")

    def test_missing_fedora_fails_closed(self):
        with self.assertRaises(ValueError):
            matrix.distro_matrix([fedora("46 Beta"), fedora("45")])


if __name__ == "__main__":
    unittest.main()
