"""Test the host boot/collection protocol with real ext4 images and a fake VM."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which("mkfs.ext4") and shutil.which("debugfs"), "requires e2fsprogs")
class VMRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xtnat-runner-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        for name in ("run-vm.sh", "Makefile", "qemu-tests.sh", "safety-tests.py", "testnet.sh", "bench-cps.sh"):
            shutil.copy(ROOT / name, self.src / name)
        for path in [*ROOT.glob("*.c"), *ROOT.glob("*.h")]:
            shutil.copy(path, self.src / path.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        XDG_CACHE_HOME=str(self.root / "cache"), MOCK_STATE=str(self.root / "boots"))
        self.url = "https://example.invalid/test.qcow2"
        cache = self.root / "cache" / "xt_CGNAT-vm"
        cache.mkdir(parents=True)
        image_key = hashlib.sha256(self.url.encode()).hexdigest()[:16]
        (cache / f"{image_key}-test.qcow2").write_bytes(b"fake root disk")
        self.tool("qemu-img", '#!/bin/bash\ntouch "${@: -2:1}"\n')
        self.tool("cloud-localds", '#!/bin/bash\ncat "$2" "$3" > "$1"\n')
        self.tool("qemu-system-x86_64", '''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
state = pathlib.Path(os.environ["MOCK_STATE"])
boot = int(state.read_text()) + 1 if state.exists() else 1
state.write_text(str(boot))
disk = next(a.split("file=", 1)[1].split(",", 1)[0] for a in sys.argv if "payload.img" in a)
seed = next(a.split("file=", 1)[1].split(",", 1)[0] for a in sys.argv if "seed.iso" in a)
assert f"-{boot}\\n" in pathlib.Path(seed).read_text(), "new cloud-init instance required"
assert "mount -t ext4 /dev/vdc" in pathlib.Path(seed).read_text()
def debug(command):
    subprocess.run(["debugfs", "-w", "-R", command, disk], check=True, capture_output=True)
def write(name, contents):
    tmp = state.with_suffix(".data")
    tmp.write_text(contents)
    debug(f"write {tmp} /artifacts/{name}")
debug("mkdir /artifacts")
mode = os.environ.get("MOCK_MODE", "success")
if boot == 1:
    write("reboot-request", "")
elif mode != "missing-result":
    write("exit-code", "1" if mode == "test-failure" else "0")
    write("env.txt", "kernel=mock-kernel\\n")
    write("tests.txt", "PASS example\\n     passed 1, failed 0, skipped 0\\n")
    write("dmesg.txt", "")
sys.exit(1 if boot == 2 and mode == "qemu-failure" else 0)
''')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def run_vm(self, mode, *extra):
        return subprocess.run([
            "bash", str(self.src / "run-vm.sh"), "--image", self.url,
            "--transport", "disk", "--kernel-packages", "linux-generic", "--timeout", "10",
            *extra,
        ], env=dict(self.env, MOCK_MODE=mode), capture_output=True, text=True, timeout=30)

    def test_kernel_preparation_reboots_then_collects_results(self):
        result = self.run_vm("success")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "boots").read_text(), "2")
        self.assertIn("mock-kernel", (self.src / "vm-results" / "report.md").read_text())

    def test_no_result_cannot_pass(self):
        result = self.run_vm("missing-result")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guest never reported a result", result.stdout)

    def test_guest_failure_propagates(self):
        self.assertNotEqual(self.run_vm("test-failure").returncode, 0)

    def test_qemu_failure_overrides_guest_success(self):
        self.assertNotEqual(self.run_vm("qemu-failure").returncode, 0)

    def test_refresh_invalidates_all_overlays_of_replaced_base(self):
        cache = self.root / "cache" / "xt_CGNAT-vm"
        key = hashlib.sha256(self.url.encode()).hexdigest()[:16]
        stale = [cache / f"prepared-{key}-{track}.qcow2" for track in ("ga", "hwe")]
        unrelated = cache / "prepared-other-image.qcow2"
        for path in [*stale, unrelated]:
            path.write_bytes(b"old overlay")
        self.tool("curl", '''#!/bin/bash
case "${@: -1}" in *SHA256SUMS) exit 1 ;; esac
while [ "$1" != -o ]; do shift; done
printf 'new base' > "$2"
''')
        result = self.run_vm("success", "--refresh-image")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(unrelated.exists())
        self.assertTrue(all(not path.exists() for path in stale))


if __name__ == "__main__":
    unittest.main()
