"""Check that deferred-rule waits select the right pool and fail on leaked refs."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class RuleTeardownTests(unittest.TestCase):
    def wait_for_pool(self, pool):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "pools"
            fixture.write_text("pool default\n  rules referencing: 2\npool extra\n  rules referencing: 0\n")
            return subprocess.run([
                "bash", "-uc", '''
source "$1/testnet.sh"
fixture=$2
# Read a fixture instead of host procfs; keep the production awk parser.
awk() { command awk "${@:1:$#-1}" "$fixture"; }
sleep() { echo retry >&2; }
wait_pool_rules_gone "$3"
''', "test", str(ROOT), str(fixture), pool,
            ], capture_output=True, text=True, timeout=10)

    def test_unreferenced_pool_does_not_wait_for_other_pools(self):
        result = self.wait_for_pool("extra")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("retry", result.stderr)

    def test_reference_leak_fails_after_bounded_wait(self):
        result = self.wait_for_pool("default")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.count("retry"), 50)
        self.assertIn("still has 2 rule references", result.stderr)


if __name__ == "__main__":
    unittest.main()
