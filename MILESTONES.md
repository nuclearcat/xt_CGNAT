# Correctness, safety and performance milestones

This tracks the November 2026 source review and its remediation. A source finding
is not a reproduced crash. Mark an item complete only after its implementation
and relevant checks pass; record any remaining platform or measurement gaps.

## M1 — Mapping lifetime and isolation

- [x] **Session expiry and port ownership.** Packet paths refresh `timeout`
  without coordinating with GC. A reader can find a live entry, GC can expire it
  and release its port, then the reader can revive it. A second subscriber can
  acquire the same public tuple. Make expiry irreversible and synchronize every
  timeout/flag update, including TCP FIN, UDP reply/DNS and related ICMP paths.
  Preserve the compact session layout, configurable timeouts and both quarantine
  modes. Validate forced refresh/expiry interleavings and VM churn; a retired
  session must never become lookup-visible again or release a port twice.
- [x] **Network namespace boundary.** Rules installed by a namespace-local
  administrator currently access global host pools/session tables. Reject CGNAT
  rules outside the initial network namespace: this matches the existing global
  proc interface and exporter. Test rejection in another namespace and ordinary
  root-namespace NAT. Full per-namespace NAT is a separate feature.
- [x] **Generic protocol reverse-key collisions.** Protocols other than
  TCP/UDP/ICMP have no port discriminator. Two subscribers sharing a public IP
  produce the same reverse key and the newest mapping wins. Reserve each public
  IP/protocol tuple for one subscriber, refusing conflicting creation without
  changing the existing mapping; honor quarantine. Test two subscribers with a
  generic protocol and verify delivery remains with the original owner. Document
  the capacity limitation rather than claiming arbitrary multiplexing.

## M2 — Safe configuration and telemetry

- [x] **Pool lifetime synchronization.** Runtime deletion holds a writer mutex,
  but statistics readers and rule lookup/reference acquisition do not. A normal
  administrative deletion can race a read or new rule into freed storage or a
  reused slot. Protect process-context readers and reference acquisition with
  the same lifetime mutex. Stress reads/rule creation against add/delete and
  verify busy-pool rejection under KASAN/lockdep.
- [x] **NetFlow atomic context.** First export/reconnect calls socket creation
  and connect under a spinlock in packet/timer context. These operations can
  sleep; late `GFP_ATOMIC` assignment and nonblocking sends do not fix setup.
  Move socket operations to process-context work with bounded buffering, explicit
  drop accounting and safe teardown. Preserve event format, sequence handling,
  collector fanout and periodic flushing. Test timer/full-batch export, failed
  collector setup and unload in a debug VM.
- [x] **32-bit allocation overflow.** Bitmap size multiplication can wrap:
  174763 addresses × 24576 bytes becomes 8192 bytes on 32-bit. Packet indexing
  still assumes the full pool; lock-array multiplication is also unchecked.
  Check both products before allocation/initialization. Exercise arithmetic
  boundaries and normal pools; record separately whether a 32-bit kernel was
  actually boot-tested. Host administrative configuration is a prerequisite.

## M3 — CLI, pool parsing and quotas

- [x] **Action validation with `--pool`.** The final check compares the entire
  flag word, so `--pool` allows missing actions and `--snat --dnat` together.
  Validate action bits independently, reject duplicate/inverted unsupported
  options, and preserve valid SNAT/DNAT plus pool save/restore. Exercise every
  flag combination through the real extension or exact parser helpers.
- [x] **Pool input validation.** Names are silently truncated by `strscpy`, and
  IPv4 parsing is permissive. Reject overlong/invalid names and malformed address
  or CIDR input explicitly, using the same parser for load-time and live updates.
  Preserve documented names, unnamed default pools and timeout syntax.
- [x] **Concurrent subscriber quotas.** Check-before-create followed by a later
  increment permits parallel creations to exceed the cap. Reserve quota under
  the user-table lock before publication, roll back every failed creation and
  refuse creation if accounting cannot be allocated. Test parallel creation at
  a small limit, duplicate requests, allocation refusal and eventual cleanup.
- [x] **Quota documentation.** TCP and UDP have separate counters; ICMP and all
  other protocols share `other_count`. Document these actual groups consistently.
- [x] **TCP teardown policy.** Any inbound FIN/RST can currently shorten a
  mapping without TCP sequence validation. Full-cone filtering is intentional,
  but trusting unauthenticated teardown is an availability exposure. Use a
  conservative inbound policy and test that forged teardown cannot shorten the
  established mapping, while subscriber-originated close remains supported.

## M4 — Reliable measurements before optimization

- [x] **Delivered throughput.** Existing benchmark PPS is the generator's sent
  count, not receiver-confirmed forwarding. Label offered traffic honestly and
  add receiver counters/sequence validation, recording offered, delivered and
  dropped traffic separately. Keep session-creation rate distinct from goodput.
- [ ] **Directional coverage.** Measure SNAT, DNAT and bidirectional established
  traffic; validate translated endpoints and checksums as well as packet counts.
- [ ] **Allocator saturation.** Add sparse, 95%, 99% and fully occupied cases
  using enough subscribers below their quotas. Confirm `noport`, not `ulimit`,
  drives exhaustion. Record CPU/lock contention and allocation/rejection rate.
- [ ] **Exhausted allocation cost.** The allocator can scan roughly 8 KiB under
  a per-address lock on every rejected attempt. After obtaining the saturation
  baseline, evaluate an exact occupancy count or advisory summary bitmap. Do not
  claim a speedup without repeatable measurements or compromise port ownership.
- [ ] **Telemetry and noise.** Compare NetFlow disabled/enabled/failed collector
  after the context fix; measure queue drops. Repeat runs and report variability
  and generator limits instead of treating historical throughput as current.

## M5 — Regression coverage and documentation

- [ ] Add focused regressions for M1–M3 to the isolated VM suite and portable
  helper checks; run syntax/build checks, then upstream debug and distro guests.
- [x] Add an explicit full-cone second-remote-peer test: arbitrary remote source
  acceptance is intended for an existing mapping, independent of the collision
  and namespace bugs above.
- [x] Refresh stale TODO/TESTING claims and document compatibility limitations,
  test outcomes and remaining measurement/platform gaps here.

## Validation log

- Review baseline: 13 CI helper tests passed. Extracted CLI final-check test
  reproduced the `--pool` bypass. Kernel findings were established by source
  traces; no exploit/crash or fresh performance benchmark was run in that review.
- Earlier kernel coverage work passed 18 tests with zero failures/skips on
  Linux 5.10.273, Linux 7.4-rc1, Debian 13 and Fedora 45. These results precede
  the fixes tracked here and do not validate them.

### Implemented and validated in this change

- M1–M3 are implemented. Packed 32-bit atomic session state retains the 64-byte
  layout; expiry cannot be reversed by any refresh. Pool session references
  remain held until the RCU free callback, including cross-pool lookup readers.
  Quotas are reserved before publication and rolled back on every failed create.
- Namespace-local rule registration is rejected. Generic protocols preserve the
  first subscriber's reverse mapping and refuse a competing owner. Full-cone
  acceptance from a second remote peer remains intact.
- NetFlow now uses a 64-PDU queue and process-context socket worker. Queue drops
  are visible in statistics. Timer/full-batch export and failed-connect recovery
  passed in the debug guest, followed by module unload without warnings.
- Pool parsing rejects silent name truncation and malformed IPv4/CIDR addresses.
  Names use letters, digits, underscore or dot. Deterministic `/0` subscriber
  counting and rounded address requirements now use 64-bit arithmetic rather
  than wrapping or losing the last subscriber.
- The reviewer found no concrete surviving bypass/regression in the patch.
- `python3 -m unittest discover -s ci -p 'test_*.py'`: **15 passed**. This includes
  actual session helper concurrency/control tests and a 32-bit arithmetic
  instantiation of the allocation guard.
- `shellcheck -S warning qemu-tests.sh run-vm.sh bench-cps.sh`, shell syntax,
  module/plugin builds and `git diff --check`: passed.
- Linux **5.10.273** and **7.4-rc1**: strict VM suites each **19 passed, 0 failed,
  0 skipped** with KASAN, lockdep and clean dmesg. Both completed the five-cycle
  60,000-port reuse soak. The later NetFlow failure/recovery test passed in an
  additional 7.4-rc1 run: **17 passed, 0 failed, 2 expected skips** because that
  extra run did not repeat the two already-passing soak tests.
- Receiver accounting was exercised with two senders, one public address and a
  three-second run on the instrumented mainline VM: **105,920 offered; 64,512
  receiver-counted packets; 41,355 no-port refusals; zero quota refusals and zero
  duplicate public tuples**. The offered/received gap also includes traffic not
  reaching the module; it must not all be attributed to allocator rejection.
  These debug-VM values validate counters/exhaustion, not production capacity.

### Remaining work and limits

- M4's controlled near-full occupancy, DNAT/bidirectional, repeated telemetry
  and baseline-versus-optimization measurements remain open. No allocator
  optimization or speedup is claimed. The existing benchmark already raises
  the quota to 65535; the old TODO claim that every exhausted run hits 4096 was
  stale and has been corrected.
- M5's post-fix distro-kernel reruns remain open. The two debug guests used an
  Ubuntu userspace image with explicitly selected upstream kernels, not distro
  kernels. CI's configured distro matrix is not evidence of completed runs.
- No actual 32-bit kernel boot or KCSAN run was performed. The 32-bit overflow
  guard is tested using 32-bit destination arithmetic; this is not a substitute
  for a full architecture compatibility run. Stress success does not prove all
  interleavings are safe.
