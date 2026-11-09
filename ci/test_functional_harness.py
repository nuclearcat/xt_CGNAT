"""Exercise echo-server idle lifetime and bounded filling without a NAT module."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "qemu-tests.sh").read_text()


class EchoLifetimeTests(unittest.TestCase):
    def test_echo_servers_survive_safety_suite_idle_time(self):
        helpers = SOURCE[SOURCE.index("write_helpers() {"):SOURCE.index("srv_start() {")]
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["bash", "-uc", helpers + '\nwrite_helpers', "test"],
                           env=dict(os.environ, TMPD=directory), check=True)
            processes = []
            clients = []
            try:
                for protocol, filename, old_port in (
                    (socket.SOCK_DGRAM, "udp_srv.py", 7777),
                    (socket.SOCK_STREAM, "tcp_srv.py", 7778),
                ):
                    # Bind an ephemeral local port instead of claiming suite ports.
                    with socket.socket(socket.AF_INET, protocol) as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                    script = Path(directory) / filename
                    script.write_text(script.read_text().replace(
                        f"('0.0.0.0', {old_port})", f"('127.0.0.1', {port})"))
                    process = subprocess.Popen(["python3", str(script)],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    processes.append(process)
                    clients.append((protocol, port, process))

                def echo(protocol, port, process):
                    with socket.socket(socket.AF_INET, protocol) as client:
                        client.settimeout(1)
                        client.connect(("127.0.0.1", port))
                        client.send(b"ping")
                        self.assertEqual(client.recv(2048), b"127.0.0.1")
                    self.assertIsNone(process.poll())

                for client in clients:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            echo(*client)
                            break
                        except (ConnectionRefusedError, TimeoutError):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.05)
                # Both original helpers exited on an unhandled 15s idle timeout.
                time.sleep(16)
                for client in clients:
                    echo(*client)
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=5)


class SessionFillTests(unittest.TestCase):
    def run_fill(self, mode):
        helper = SOURCE[SOURCE.index("fill_sessions() {"):SOURCE.index("t_aging_ports() {")]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", "-uc", helper + r'''
info() { echo "$*"; }
# Advance the poll count without spending 30 wall-clock seconds in unit tests.
sleep() {
    local count=0
    [ ! -f "$TMPD/polls" ] || read -r count < "$TMPD/polls"
    echo "$((count + 1))" > "$TMPD/polls"
    command sleep 0.02
}
nat_stat() {
    local count
    read -r count < "$TMPD/polls"
    if [ "$FILL_MODE" = slow ] && [ "$count" -ge 12 ]; then echo 60000
    else echo 30000; fi
}
if [ "$FILL_MODE" = error ]; then
    fill_sessions 60000 bash -c 'echo broken-generator; exit 7'
else
    fill_sessions 60000 bash -c 'echo $$ > "$TMPD/gen.pid"; exec sleep 60'
fi
''', "test"], env=dict(os.environ, TMPD=directory, FILL_MODE=mode),
                capture_output=True, text=True, timeout=5)
            polls = int((Path(directory) / "polls").read_text())
            pid_file = Path(directory) / "gen.pid"
            if pid_file.exists():
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), 0)
            return result, polls

    def test_slow_fill_continues_past_old_eight_second_budget(self):
        result, polls = self.run_fill("slow")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(polls, 12)
        self.assertIn("60000 of 60000", result.stdout)

    def test_stalled_fill_is_bounded_and_reports_low_count(self):
        result, polls = self.run_fill("stalled")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(polls, 30)
        self.assertIn("30000 of 60000", result.stdout)

    def test_generator_error_is_not_an_expected_stop(self):
        result, polls = self.run_fill("error")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertLess(polls, 30)
        self.assertIn("generator exited 7: broken-generator", result.stdout)


if __name__ == "__main__":
    unittest.main()
