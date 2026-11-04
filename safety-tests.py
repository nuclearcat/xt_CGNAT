#!/usr/bin/env python3
"""VM-only regression cases. Invoked by qemu-tests.sh after its safety checks."""
import concurrent.futures
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent
SUB, INET = 'xtnat-sub', 'xtnat-inet'
SELF = str(pathlib.Path(__file__).resolve())


def run(*args, ok=True):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ok and p.returncode:
        raise AssertionError(f'{args}: {p.stderr.strip()}')
    return p


def rules(action):
    run('bash', '-c', '. "$1/testnet.sh"; "$2"', 'safety', str(ROOT), action)


def pool(command):
    pathlib.Path('/proc/net/CGNAT/pools').write_text(command + '\n')


def sessions():
    return pathlib.Path('/proc/net/CGNAT/sessions').read_text()


def send(ns, src, dst, proto, sport=0, dport=0, payload='guard'):
    run('ip', 'netns', 'exec', ns, sys.executable, SELF, 'send', src, dst,
        str(proto), str(sport), str(dport), payload)


def child_send():
    src, dst, proto, sport, dport, payload = sys.argv[2:]
    proto, sport, dport = int(proto), int(sport), int(dport)
    body = payload.encode()
    if proto == 17:
        body = struct.pack('!HHHH', sport, dport, len(body) + 8, 0) + body
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        for n in range(35 if sys.argv[1] == 'burst' else 1):
            source = f'10.0.1.{n+1}' if sys.argv[1] == 'burst' else src
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(body) + 20, 0, 0, 64, proto, 0,
                                 socket.inet_aton(source), socket.inet_aton(dst))
            sock.sendto(header + body, (dst, 0))


def capture(ns, iface, marker):
    return subprocess.Popen(['ip', 'netns', 'exec', ns, sys.executable, SELF,
                             'capture', iface, marker], text=True, stdout=subprocess.PIPE)


def child_capture():
    iface, marker = sys.argv[2:]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.bind((iface, 0)); sock.settimeout(4)
        print('ready', flush=True)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            frame = sock.recv(65535)
            if marker.encode() in frame[34:]:
                print(socket.inet_ntoa(frame[30:34]), flush=True)
                return
        raise AssertionError('capture timeout')


def main():
    assert os.geteuid() == 0 and os.environ.get('XT_NAT_SAFETY_VM') == '1'
    module = sys.argv[1]
    rules('rules_down'); run('rmmod', 'xt_CGNAT')
    collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    collector.bind(('127.0.0.1', 0)); collector.settimeout(5)
    port = collector.getsockname()[1]
    run('ip', 'route', 'add', 'unreachable', '192.0.2.200/32')
    try:
        # Both load-time and live pool paths must reject ambiguous input.
        for spec in ['abcdefghijklmnop:203.0.113.1-203.0.113.1',
                     'bad name:203.0.113.1-203.0.113.1',
                     'bad:203.0.113.999-203.0.113.999',
                     'bad:203.0.113.1junk-203.0.113.2',
                     'bad:203.0.113.1-203.0.113.2:not-an-ip/24:1008']:
            assert run('insmod', module, 'nat_pool=' + spec, ok=False).returncode
        run('insmod', module, 'nat_pool=default:203.0.113.1-203.0.113.1',
            f'nf_dest=127.0.0.1:{port},192.0.2.200:{port}', 'user_max_sessions=16')
        rules('rules_up')
        for cmd in ['add abcdefghijklmnop:203.0.113.90-203.0.113.90',
                    'add bad:203.0.113.90junk-203.0.113.90']:
            try:
                pool(cmd)
            except OSError:
                pass
            else:
                raise AssertionError('invalid live pool accepted')
        # Test a supported hook: OUTPUT would reject even the vulnerable module.
        args = ['iptables', '-A', 'FORWARD', '-j', 'CGNAT', '--snat']
        assert run('ip', 'netns', 'exec', SUB, *args, ok=False).returncode
        for options in [[], ['--pool', 'default'], ['--snat', '--dnat'],
                        ['--pool', 'default', '--snat', '--dnat'],
                        ['--snat', '--snat'], ['!', '--snat']]:
            assert run('iptables', '-A', 'FORWARD', '-j', 'CGNAT', *options, ok=False).returncode
        for action in ['--snat', '--dnat']:
            run('iptables', '-A', 'FORWARD', '-j', 'CGNAT', action, '--pool', 'default')
            run('iptables', '-D', 'FORWARD', '-j', 'CGNAT', action, '--pool', 'default')
        print('PASS namespace, CLI and pool parsing boundaries', flush=True)

        # Generic ownership: second subscriber must not steal the first key.
        run('ip', '-n', SUB, 'addr', 'add', '10.0.0.20/32', 'dev', 'xn-s1')
        send(SUB, '10.0.0.20', '198.51.100.2', 253)
        send(SUB, '10.0.0.21', '198.51.100.2', 253)
        rows = [line for line in sessions().splitlines() if line.startswith('253 ')]
        assert len(rows) == 1 and '10.0.0.20:' in rows[0], rows
        receiver = capture(SUB, 'xn-s1', 'owner-check')
        assert receiver.stdout.readline().strip() == 'ready'
        send(INET, '198.51.100.2', '203.0.113.1', 253, payload='owner-check')
        assert receiver.communicate(timeout=6)[0].strip() == '10.0.0.20'
        assert receiver.returncode == 0
        run('ip', '-n', SUB, 'addr', 'del', '10.0.0.20/32', 'dev', 'xn-s1')
        print('PASS generic protocol preserves original subscriber delivery', flush=True)

        # Concurrent quota reservations cannot overshoot a small cap.
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda n: send(SUB, '10.0.0.22', '198.51.100.2', 17, 20000+n, 9999), range(64)))
        rows = [line for line in sessions().splitlines() if '10.0.0.22:' in line and line.startswith('17 ')]
        assert len(rows) == 16, rows
        print('PASS concurrent subscriber quota remains exact', flush=True)

        # Existing mapping accepts a different remote endpoint (full cone).
        run('ip', '-n', INET, 'addr', 'add', '198.51.100.3/32', 'dev', 'xn-i1')
        send(SUB, '10.0.0.2', '198.51.100.2', 17, 41000, 9998)
        row = next(line for line in sessions().splitlines() if '10.0.0.2:41000 ' in line)
        public = row.split('->')[1].strip().split()[0]
        ip, mapped_port = public.split(':')
        receiver = capture(SUB, 'xn-s1', 'second-peer')
        assert receiver.stdout.readline().strip() == 'ready'
        send(INET, '198.51.100.3', ip, 17, 9997, int(mapped_port), 'second-peer')
        assert receiver.communicate(timeout=6)[0].strip() == '10.0.0.2'
        assert receiver.returncode == 0
        run('ip', '-n', INET, 'addr', 'del', '198.51.100.3/32', 'dev', 'xn-i1')
        print('PASS full-cone second remote peer', flush=True)

        data = collector.recv(65535)
        assert struct.unpack('!H', data[:2])[0] == 9 and len(data) >= 20
        # Enough independent events to force a full batch as well as timer flush.
        run('ip', 'netns', 'exec', SUB, sys.executable, SELF, 'burst',
            '10.0.1.1', '198.51.100.2', '17', '42000', '9999', 'batch')
        while True:
            data = collector.recv(65535)
            if struct.unpack('!H', data[2:4])[0] == 31:
                break
        # The second collector had an unreachable route during those exports.
        # Making it local must allow the worker's next setup retry to recover.
        run('ip', 'addr', 'add', '192.0.2.200/32', 'dev', 'lo')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as recovered:
            recovered.bind(('192.0.2.200', port)); recovered.settimeout(5)
            send(SUB, '10.0.2.1', '198.51.100.2', 17, 45000, 9999)
            assert struct.unpack('!H', recovered.recv(65535)[:2])[0] == 9
        print('PASS NetFlow timer/full-batch exports and failed-connect recovery', flush=True)

        # Read proc while slots are retired/reused; race checkentry with writer.
        stop = threading.Event()
        errors = []
        mutations = 0
        def reader():
            try:
                while not stop.is_set():
                    pathlib.Path('/proc/net/CGNAT/statistics').read_text()
                    pathlib.Path('/proc/net/CGNAT/pools').read_text()
            except BaseException as exc:
                errors.append(exc)
        def registrar():
            try:
                while not stop.is_set():
                    result = run('iptables', '-A', 'FORWARD', '-s', '192.0.2.254', '-j', 'CGNAT', '--snat', '--pool', 'race', ok=False)
                    if result.returncode == 0:
                        run('iptables', '-D', 'FORWARD', '-s', '192.0.2.254', '-j', 'CGNAT', '--snat', '--pool', 'race')
            except BaseException as exc:
                errors.append(exc)
        threads = [threading.Thread(target=reader), threading.Thread(target=registrar)]
        for thread in threads: thread.start()
        for _ in range(100):
            for command in ['add race:203.0.113.90-203.0.113.90', 'del race']:
                try:
                    pool(command)
                    mutations += 1
                except OSError: pass # EBUSY/EEXIST are expected race outcomes.
        stop.set()
        for thread in threads: thread.join(timeout=10); assert not thread.is_alive()
        assert not errors, errors
        assert mutations > 0, 'pool mutation stress made no progress'
        print('PASS live pool reader/registration/deletion stress', flush=True)
    finally:
        run('ip', 'addr', 'del', '192.0.2.200/32', 'dev', 'lo', ok=False)
        run('ip', 'route', 'del', 'unreachable', '192.0.2.200/32', ok=False)
        collector.close()
        rules('rules_down')
        run('rmmod', 'xt_CGNAT', ok=False)
        run('insmod', module, 'nat_pool=203.0.113.1-203.0.113.4')
        rules('rules_up')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('send', 'burst'): child_send()
    elif len(sys.argv) > 1 and sys.argv[1] == 'capture': child_capture()
    else: main()
