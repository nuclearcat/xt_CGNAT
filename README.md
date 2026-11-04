# xt_CGNAT

A Full Cone NAT xtables target, built to replace conntrack NAT where a Linux box
has to act as a Carrier-Grade NAT. It keeps its own session tables rather than
using conntrack, and exports NAT events over NetFlow v9.

- [Credits](#credits)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Rule placement](#rule-placement)
- [Pools](#pools)
  - [Named pools](#named-pools)
  - [Runtime pool management](#runtime-pool-management)
  - [Deterministic mapping (RFC 7422)](#deterministic-mapping-rfc-7422)
- [Timeouts](#timeouts)
- [Module parameters](#module-parameters)
- [Runtime tuning](#runtime-tuning)
- [The /proc interface](#the-proc-interface)
- [NetFlow v9 export](#netflow-v9-export)
- [Sizing](#sizing)
- [Troubleshooting](#troubleshooting)
- [Features](#features)
- [Limitations](#limitations)
- [Migrating from xt_NAT](#migrating-from-xt_nat)
- [Testing](#testing)

## Credits

xt_CGNAT is derived from **xt_NAT** by **Andrei Sharaev**
<andr.sharaev@gmail.com>, which is where the design comes from: the paired
inner/outer session tables, endpoint-independent (full cone) semantics, the
timer-driven session GC, the NetFlow v9 event export and the iptables target
interface are all his. The original reported 40 Gbps on 2×Xeon E5-2698 v3 with
Intel X710/XL710/X540 adapters, and was tested against Linux 3.18 and 4.1.

This tree renames the module because `-j NAT` collides with netfilter's own NAT
table and targets, and because it has diverged enough in implementation to be
worth telling apart. What changed since the fork is in the git history and in
[TESTING.md](TESTING.md); the short version is a rewritten session object,
bitmap port allocation, an optional RFC 7422 deterministic mode, per-pool
timeouts, a set of memory-safety fixes, and a test rig.

## How it works

Two hash tables hold one session object each, linked into both at once:

- **inner**, keyed on `(protocol, subscriber address, subscriber port)`
- **outer**, keyed on `(protocol, NAT address, NAT port)`

Outbound packets look up the inner table, inbound ones the outer table. Because
the key does not include the destination, one subscriber source port maps to
exactly one public port no matter how many destinations it talks to — that is
what makes the mapping *endpoint independent*, and it is also what keeps port
consumption proportional to the subscriber's open sockets rather than to its
number of conversations.

Ports come from a bitmap, one per `(NAT address, protocol)`, so TCP 5000 and UDP
5000 on the same address are distinct mappings and each protocol gets the full
64512 ports (1024–65535). The allocator tries to preserve the subscriber's own
source port first and falls back to a scan.

A timer sweeps the whole session table every 10 seconds, ages each session it
passes, releases the port when the timer reaches zero and unlinks the session
one sweep later. Conntrack is not involved at any point, which is why the rules
below disable it for the traffic this target handles.

## Installation

```
$ make
$ sudo make install
$ sudo depmod -a
```

`make install` places `xt_CGNAT.ko` and the iptables plugin `libxt_CGNAT.so`.
The plugin has to be where iptables looks for extensions, or `-j CGNAT` will
fail with "Couldn't load target".

## Quick start

The smallest working configuration — one pool, one subscriber network:

```
$ sudo modprobe xt_CGNAT nat_pool=203.0.113.1-203.0.113.4

# outbound: translate subscriber traffic leaving the uplink
$ sudo iptables -A FORWARD -s 10.0.0.0/16 -o eth0 -j CGNAT --snat

# keep conntrack out of it - these have to come before the --dnat rule below
$ sudo iptables -t raw -A PREROUTING -s 10.0.0.0/16 -j CT --notrack
$ sudo iptables -t raw -A PREROUTING -d 203.0.113.0/24 -j CT --notrack

# inbound: translate replies before routing
$ sudo iptables -t raw -A PREROUTING -d 203.0.113.0/24 -j CGNAT --dnat

# let the translated return traffic through
$ sudo iptables -A FORWARD -d 10.0.0.0/16 -i eth0 -j ACCEPT
```

Check it:

```
$ cat /proc/net/CGNAT/pools
$ cat /proc/net/CGNAT/sessions
```

## Rule placement

Both directions need a rule, and they go in different places.

| direction | table/chain | target | why there |
|---|---|---|---|
| subscriber → internet | `filter`/`FORWARD` | `-j CGNAT --snat` | the routing decision has been made, so `-o <uplink>` is available to scope the rule |
| internet → subscriber | `raw`/`PREROUTING` | `-j CGNAT --dnat` | the destination is still the public address; it has to be rewritten before routing, or the box will not route the packet to the subscriber |

The target is terminating for what it accepts, so put it ahead of anything that
might shadow it — and below anything that has to see the packet first. This is
the exact rule set the test suite uses, in the order it ends up in:

```
# raw/PREROUTING
1  -d <pool net>   -j CT --notrack
2  -s <subscriber> -j CT --notrack
3  -d <pool net>   -j CGNAT --dnat

# filter/FORWARD
1  -s <subscriber> -o <uplink> -j CGNAT --snat
2  -d <subscriber> -i <uplink> -o <downlink> -j ACCEPT
```

Rules 1 and 2 in `raw` keep conntrack from building state for traffic this
module already tracks itself; on a CGNAT-scale box that is the difference
between working and running out of conntrack entries.

**They have to be above the `--dnat` rule.** `CT --notrack` returns
`XT_CONTINUE` and falls through to the next rule; `CGNAT` returns `NF_ACCEPT`,
which ends traversal of the table. Put the `--dnat` rule first and rule 1 —
which matches the same packets — never runs, so every inbound flow allocates a
conntrack entry after all. The symptom is a conntrack table that fills under
load while `/proc/net/CGNAT/sessions` looks healthy.

`--snat` and `--dnat` are mutually exclusive and one of them is required; the
plugin rejects a rule with both or neither.

**Hairpinning.** Two subscribers behind the same NAT can reach each other
through a public pool address, because the `raw`/`PREROUTING` `--dnat` rule
matches on destination alone and does not care which interface the packet
arrived on. Note that the source address is *not* translated on that path — the
`--snat` rule above is scoped to the uplink — so the target subscriber sees the
originator's private address. This behaviour is inherited from xt_NAT and is not
covered by the test suite.

## Pools

For a short pool syntax reminder and a link back to this guide, run
`iptables -j CGNAT -h` after installing the userspace extension.

A pool is a contiguous range of public addresses. Its full spec is:

```
[<name>:]<start>-<end>[:<subscriber_cidr>:<ports_per_subscriber>][:<key>=<value>...]
```

- `<name>` is optional and limited to 15 characters. Without one, there is a
  single pool called `default`. Names may contain only letters, digits, underscore
  and dot. A first field containing `-` is recognised as a range, which
  is how the old unnamed syntax keeps working.
- The two bare trailing fields turn on [deterministic
  mapping](#deterministic-mapping-rfc-7422). Both or neither.
- Any field containing `=` is a [timeout override](#timeouts). These may appear
  in any order relative to the positional fields.

Subscribers are assigned to an address in the pool by a hash of their private
address, and every session from that subscriber uses the same public address
(*IP pooling, paired*). Up to **8 pools**; names must be unique and ranges must
not overlap. Both are refused, at load and at runtime.

### Named pools

`nat_pool` takes several pools, comma separated, and each rule picks one with
`--pool`. Omitting `--pool` selects the first.

```
$ sudo modprobe xt_CGNAT nat_pool="retail:203.0.113.1-203.0.113.64,\
biz:198.51.100.1-198.51.100.64:10.20.0.0/20:1008"

$ sudo iptables -A FORWARD -s 10.0.0.0/16  -o eth0 -j CGNAT --snat --pool retail
$ sudo iptables -A FORWARD -s 10.20.0.0/20 -o eth0 -j CGNAT --snat --pool biz

$ sudo iptables -t raw -A PREROUTING -d 203.0.113.0/24  -j CGNAT --dnat --pool retail
$ sudo iptables -t raw -A PREROUTING -d 198.51.100.0/24 -j CGNAT --dnat --pool biz
```

Each pool needs **both** directions pointed at it. The pool name is resolved to
a pointer once, when the rule is inserted, so a rule naming a pool that does not
exist is refused by `iptables` rather than failing per packet. `iptables-save`
preserves `--pool`.

A session belongs to the pool it was created in, and it keeps using that pool's
addresses and timeouts for its whole life — not the pool named by whichever rule
a later packet happened to traverse.

### Runtime pool management

Pools can be added and removed through `/proc/net/CGNAT/pools` without reloading
the module and dropping every session:

```
# echo "add wholesale:198.51.100.128-198.51.100.191" > /proc/net/CGNAT/pools
# echo "add trial:203.0.113.200-203.0.113.230:10.30.0.0/22:2016" > /proc/net/CGNAT/pools
# echo "add cheap:203.0.113.240-203.0.113.250:udp_dns=20" > /proc/net/CGNAT/pools
# echo "del trial" > /proc/net/CGNAT/pools
```

`add` takes exactly the same spec as `nat_pool`. `del` takes a name.

Deleting is refused while anything still points at the pool — any iptables rule
naming it, or any live session — and the error says which:

```
xt_CGNAT: pool 'trial' still in use: 1 rule(s), 4211 session(s)
```

Drop the rules and let the sessions age out first. The file is mode 0600 and the
write path also requires `CAP_NET_ADMIN`: it reconfigures the NAT.

### Deterministic mapping (RFC 7422)

With the two trailing positional fields, the public address and port block are
computed arithmetically from the subscriber address instead of being allocated
on demand:

```
biz:198.51.100.1-198.51.100.64:10.20.0.0/20:1008
                               ^ subscribers  ^ ports each
```

Subscribers are laid out in order from the base of the CIDR: `64512 / 1008 = 64`
subscribers share each public address, each with its own 1008-port block, and
the module refuses to load if the pool does not have enough addresses to cover
the CIDR.

The point is attribution without logging. Given a public address, port and
timestamp, the subscriber follows by arithmetic — no per-session record needed,
which removes the log-retention problem that shared-port CGNAT creates.

The cost is that a subscriber can never exceed its block, no matter how idle the
rest of the pool is. Size the block for the peak, not the average: with
endpoint-independent mapping a subscriber consumes one port per distinct source
port regardless of how many destinations it talks to, so a 1008-port block is
1008 concurrent connections in total.

Subscribers outside the CIDR get no mapping at all, and their packets are
dropped — the `failed unmapped subscriber` counter.

## Timeouts

How long a mapping is held after the last packet. The `timeouts` parameter sets
the baseline; any pool overrides individual keys with the same `key=value`
syntax in its own spec, so a residential pool and a business pool can age
differently.

| key | default | applies to |
|---|---|---|
| `tcp` | 30 | SYN sent, nothing back yet |
| `tcp_est` | 300 | after the first packet from outside |
| `tcp_fin` | 10 | FIN or RST seen in either direction |
| `udp` | 30 | nothing back yet |
| `udp_est` | 300 | after the first packet from outside |
| `udp_dns` | 60 | as `udp_est`, but the destination was port 53 |
| `icmp` | 30 | echo request/reply |
| `other` | 30 | protocols with no port, nothing back yet |
| `other_est` | 300 | protocols with no port, after a reply |

```
# baseline for every pool
$ sudo modprobe xt_CGNAT nat_pool=203.0.113.1-203.0.113.4 \
      timeouts="udp_est=120:udp_dns=20"

# per pool, mixed freely with the deterministic fields
$ sudo modprobe xt_CGNAT nat_pool="retail:203.0.113.1-203.0.113.64:udp_dns=20,\
biz:198.51.100.1-198.51.100.64:10.20.0.0/20:1008:tcp_est=600"

# and at runtime, on a new pool
# echo "add trial:203.0.113.200-203.0.113.230:udp_dns=20" > /proc/net/CGNAT/pools
```

Values are seconds, 10..32760, **rounded up to a multiple of 10**. The effective
values for every pool are in `/proc/net/CGNAT/pools`.

Two things worth knowing before tuning these:

**Granularity is 10 seconds, and the phase is arbitrary.** The GC sweeps the
whole table every 10s and ages each session it passes. Which slice a session
falls in has nothing to do with when it was created, so a timeout of `T` expires
somewhere in `(T-10, T]`. At the minimum of 10 that is `(0, 10]` — a session can
be reaped almost immediately, and a burst will spend its time recreating
sessions it just made. Nothing below 30 gives a useful guaranteed lifetime.

**`udp_dns` is why per-protocol timeouts exist.** A DNS transaction is one query
and one reply, and the mapping is dead the moment the reply lands — but every
stub resolver randomises its source port per query (RFC 5452), so each query
burns a distinct mapping. Held for `udp_est`, that caps a NAT address at
`64512 / udp_est` new DNS transactions per second regardless of how little
traffic they carry:

| `udp_dns` | DNS transactions/sec per public address |
|---|---|
| 300 | ~215 |
| 60 (default) | ~1075 |
| 20 | ~3225 |

The retry windows it has to clear are small: glibc's resolver defaults to a 5s
timeout, and systemd-resolved is comparable.

> **Upgrade note.** DNS mappings previously used `udp_est`, so the default of 60
> is a behaviour change. Set `udp_dns=300` to keep exactly what you had.

## Module parameters

All are load-time only unless noted.

| parameter | default | meaning |
|---|---|---|
| `nat_pool` | `127.0.0.1-127.0.0.1` | pool definitions, see [Pools](#pools) |
| `timeouts` | none | baseline session timeouts every pool starts from, see [Timeouts](#timeouts) |
| `nat_hash_size` | 262144 | session hash buckets, 1024..16777216. Two tables of this size. At more sessions than buckets, chains lengthen and every packet walks further — size it to your expected session count |
| `users_hash_size` | 65536 | subscriber hash buckets, same range |
| `user_max_sessions` | 4096 | concurrent sessions per subscriber in each of three groups (TCP, UDP, all other protocols), 1..65535. Writable at runtime |
| `port_quarantine` | 0 | when a NAT port becomes reusable. `0` releases it as soon as the session stops being findable, which maximises capacity but lets a port be reissued while the old session is still in the table. `1` holds it until the session is unlinked, about one GC sweep later — no port is ever mapped to two sessions, at the cost of holding roughly ten seconds of expiring sessions' ports out of service. Writable at runtime; the choice is fixed per session at creation, so a change affects only new sessions |
| `nf_dest` | none | NetFlow v9 collectors, `addr:port[,addr:port]` |

Note `user_max_sessions` is a cap on top of whatever ports are available, and it
is **per accounting group** — a subscriber can hold 4096 TCP *and* 4096 UDP sessions at
the default. It limits one abusive subscriber; it does not protect a pool from
exhaustion in aggregate. See [Sizing](#sizing).

## Runtime tuning

Two parameters are writable on a running module:

```
# echo 8192 > /sys/module/xt_CGNAT/parameters/user_max_sessions
# echo 1    > /sys/module/xt_CGNAT/parameters/port_quarantine
```

Everything else, including timeouts on existing pools, needs a reload — but a
*new* pool added at runtime can carry any timeouts you like, so migrating a
subscriber group to different timeouts is a pool add, a rule swap and a pool
delete rather than an outage.

## The /proc interface

Four files under `/proc/net/CGNAT/`.

### `pools` — configuration and per-pool counters

Also the write endpoint for [runtime pool
management](#runtime-pool-management).

```
# write "add [<name>:]<start>-<end>[:<cidr>:<ports>][:<key>=<sec>...]" or "del <name>"
pool default
  range: 203.0.113.1-203.0.113.4 (4 addresses, 64512 ports each)
  timeouts: tcp=30 tcp_est=300 tcp_fin=10 udp=30 udp_est=300 udp_dns=60 icmp=30 other=30 other_est=300
  deterministic: off (shared ports)
  sessions active: 2
  sessions created: 2
  sessions tried: 2
  raced creates: 0
  failed user limit: 0
  failed no free port: 0
  failed unmapped subscriber: 0
  rules referencing: 2
```

`tried` counts every attempt to create a session, `created` the ones that
succeeded; the difference is accounted for by the three `failed` lines and
`raced creates` (two CPUs building the same mapping at once, where one wins and
the other reuses it — normal, not an error). `rules referencing` is what blocks
a `del`.

### `sessions` — live translations

```
Proto SrcIP:SrcPort -> NatIP:NatPort
1 10.0.0.2:2224 -> 203.0.113.1:2224 --- ttl: 30
17 10.0.0.2:55831 -> 203.0.113.1:55831 --- ttl: 300
Total translations: 2
```

`Proto` is the IP protocol number (1 ICMP, 6 TCP, 17 UDP). For ICMP the port
column is the echo ID. `ttl` is the remaining timeout in seconds; a session
already past zero prints `(will be removed due timeout)` instead — its port has
been released but it has not been unlinked yet.

This file walks the whole session table. On a loaded box that is expensive and
the output is large; do not poll it.

### `users` — per-subscriber session counts

```
10.0.0.2 (tcp: 0, udp: 1, other: 1)
Total users: 1
```

These are the counts `user_max_sessions` is checked against, which is why they
are split by protocol. There is no NAT address here: with several pools a
subscriber's public address depends on which rule matched, and this table is
keyed only on the private address. `sessions` has the real mapping.

### `statistics` — global counters

```
Active NAT sessions: 2
Tried NAT sessions: 2
Created NAT sessions: 2
Raced session creates: 0
DNAT dropped pkts: 0
Fragmented pkts: 0
Related ICMP pkts: 0
Active Users: 1
Max sessions per user: 4096
Port quarantine: 0
Failed sessions user limit: 0
Failed sessions no free port: 0
Failed sessions no memory: 0
Failed sessions unmapped subscriber: 0
Dropped no session: 0
Dropped bad proto: 0
Dropped ip options: 0
Dropped ip fragment: 0
Dropped truncated: 0
Dropped unwritable: 0
```

The session counters are the sum across pools; `pools` breaks them down. The
rest are global:

| counter | meaning |
|---|---|
| `DNAT dropped pkts` | inbound packets to a pool address with no matching session. **The packet is passed through untranslated**, not dropped by the target — it is normally discarded later by routing or a firewall rule. Expect a steady trickle from internet background noise |
| `Fragmented pkts` | first fragments seen, which are translated normally. Non-first fragments are counted under `Dropped ip fragment` |
| `Related ICMP pkts` | ICMP errors quoting a translated packet, rewritten inside the quoted header |
| `Failed sessions *` | why session creation was refused — see [Troubleshooting](#troubleshooting) |
| `Dropped *` | why a packet was dropped outright by the target |

## NetFlow v9 export

Socket setup and transmission run in a process-context worker. A bounded queue
holds up to 64 PDUs; overflow drops a PDU and increments `NetFlow dropped PDUs`
in `/proc/net/CGNAT/statistics`. Monitor this counter when attribution logging is
required. Collector delivery remains best-effort UDP.


Point the module at one or more collectors:

```
$ sudo modprobe xt_CGNAT nat_pool=203.0.113.1-203.0.113.4 nf_dest=127.0.0.1:2055
$ sudo modprobe xt_CGNAT nat_pool=... nf_dest="10.1.1.5:2055,10.1.1.6:2055"
```

This is **NAT event export**, not traffic accounting: one record when a mapping
is created and one when it expires. There are no byte or packet counters — the
point is attribution, so that a public address, port and timestamp can be traced
back to a subscriber.

Records use template ID 300, sent in every PDU so a collector that restarts
picks it up on the next packet. Eight fields:

| IE | field | bytes |
|---|---|---|
| 4 | protocol | 1 |
| 7 | source port (subscriber) | 2 |
| 8 | source address (subscriber) | 4 |
| 11 | destination port | 2 |
| 12 | destination address | 4 |
| 225 | post-NAT source address | 4 |
| 227 | post-NAT source port | 2 |
| 230 | NAT event type | 1 |

Event type is `1` for create and `2` for delete. Up to 30 records are batched
per PDU, flushed when full or once a second, whichever comes first. Sockets
reconnect on their own if the collector is unreachable at load time.

## Sizing

**Ports.** Each public address provides 64512 ports *per protocol*. A subscriber
consumes one port per distinct source port, not per conversation, so the
question is how many sockets your subscribers hold open — plus, importantly,
how much DNS they generate, since each query is a separate short-lived mapping
(see [Timeouts](#timeouts)).

**Hash tables.** `nat_hash_size` should be at or above your expected concurrent
session count. Both tables are that size, and each bucket is small; the cost of
oversizing is memory, the cost of undersizing is longer chains walked on every
packet.

**Memory.** A session is exactly 64 bytes — one cacheline, allocated from a
dedicated slab cache. One million concurrent sessions is about 64 MB of session
objects. Port bitmaps are 8 KB per (address, protocol), so 24 KB per public
address, or ~6 MB for a /24.

**Per-subscriber caps.** `user_max_sessions` bounds one subscriber separately
for TCP, UDP and a shared group for ICMP/other protocols. It does not bound the pool: with `N` subscribers sharing an address,
`N × 4096` is far above 64512 for any realistic `N`, so the pool exhausts first.
If you need a hard per-subscriber bound that also bounds the pool, use
[deterministic mapping](#deterministic-mapping-rfc-7422).

## Troubleshooting

**Sessions are not being created.** Check which counter is moving in
`/proc/net/CGNAT/statistics`:

| counter rising | cause | what to do |
|---|---|---|
| `Failed sessions no free port` | the subscriber's public address is out of ports for that protocol | more addresses in the pool, or shorter timeouts — start with `udp_dns` |
| `Failed sessions user limit` | one subscriber hit `user_max_sessions` for that protocol | raise it at runtime, or find out why one subscriber wants 4096 sessions |
| `Failed sessions unmapped subscriber` | deterministic mode, and the source is outside the configured CIDR | widen the CIDR or exclude that source from the rule |
| `Failed sessions no memory` | allocation failure under pressure | the box is out of memory; this is not a NAT problem |

**Return traffic is not arriving.** `DNAT dropped pkts` climbing in step with
the traffic means there is no session for it — check that the `raw`/`PREROUTING`
`--dnat` rule exists, covers the whole pool range, and names the same pool as
the outbound rule.

**Packets are being dropped by the target.** `Dropped ip options` and `Dropped
ip fragment` are the common ones and are [limitations](#limitations), not bugs.
Fragments usually mean an offload was disabled somewhere upstream.

**`iptables` says "Couldn't load target `CGNAT`".** `libxt_CGNAT.so` is not in
the xtables plugin directory — `make install` and try again.

**`insmod` says "Unknown symbol in module".** `insmod` resolves nothing; the
module needs `x_tables` already loaded. Use `modprobe` after `make install` and
`depmod -a`, or `modprobe x_tables` first.

## Features

* PAT/NAPT — many subscribers behind one public address
* Full Cone (endpoint-independent mapping and filtering): inbound connections
  are accepted from any source, as long as the mapping exists
* TCP, UDP, ICMP and generic IP protocols
* IP pooling paired — all of a subscriber's sessions use one public address
* Multiple named pools, selected per rule with `--pool`, addable and removable
  at runtime
* Per-pool session timeouts, including a separate short timer for DNS so one
  query and reply does not hold a public port for five minutes
* Optional deterministic port mapping (RFC 7422) for logless attribution
* Per-subscriber session quotas for TCP, UDP and other protocols, adjustable at runtime
* NAT event export over NetFlow v9
* Statistics and live session/pool state via /proc

## Limitations

* IPv4 only.
* IPv4 packets with IP options are dropped — the IP header must be 20 bytes.
* IPv4 fragments with a non-zero offset are dropped; only the first fragment
  passes.
* Locally generated ICMP errors (for example "Fragmentation Needed" for PMTUD)
  are not translated.
* Disabling hardware offloads (GRO/GSO/TSO) makes real fragments more likely,
  and those are dropped.
* No ALGs or helpers (FTP, SIP, PPTP, …).
* Protocols other than TCP/UDP/ICMP reserve one subscriber per public IP and
  protocol. Competing subscribers are refused until that mapping expires (and
  its quarantine ends, if enabled). Distinct flows of that protocol are not
  separated; use dedicated public addresses when concurrent subscribers need it.
* CGNAT rules are supported only in the initial network namespace. Subscriber
  and remote peers may live in other namespaces, but cannot install their own
  CGNAT rules against the host's global state.
* Inbound TCP FIN/RST does not shorten mapping lifetime: full-cone filtering
  does not authenticate the sender or validate TCP sequence numbers. Subscriber
  FIN/RST still uses the configured short close timeout.
* Timeout granularity is 10 seconds, with arbitrary phase — see
  [Timeouts](#timeouts).
* At most 8 pools, with names up to 15 characters.
* Hairpinned traffic does not get its source address translated.

## Migrating from xt_NAT

The rename is not backward compatible. Everything user-visible changed:

| was | is |
|---|---|
| `iptables ... -j NAT --snat` | `iptables ... -j CGNAT --snat` |
| `/proc/net/NAT/{sessions,users,statistics}` | `/proc/net/CGNAT/...` |
| `modprobe xt_NAT` | `modprobe xt_CGNAT` |
| `xt_NAT.ko`, `libxt_NAT.so` | `xt_CGNAT.ko`, `libxt_CGNAT.so` |
| `MODULE_ALIAS ipt_NAT` | `ipt_CGNAT` |

So: update firewall rules, any monitoring that reads `/proc/net/NAT`, and
modprobe/modules-load configuration. Old and new cannot be loaded side by side
under the same rules — the target name is what changed.

Module parameters kept their names, and `nat_pool` accepts the old syntax
unchanged, so a plain `nat_pool=<start>-<end>` still means what it always did.
The one behavioural difference to expect is the DNS timeout; see the upgrade
note under [Timeouts](#timeouts).

## Testing

Functional tests, memory and locking checks under KASAN and lockdep, and the
session-rate benchmark all run in a throwaway VM:

```
$ ./run-vm.sh                          # functional suite, ~33s warm
$ ./run-vm.sh --soak                   # + session aging and port reuse
$ ./run-vm.sh --kdir /path/to/linux    # same, under KASAN + lockdep
$ ./run-vm.sh --bench                  # + session setup rate
```

See [TESTING.md](TESTING.md) for what each mode proves, how to build a suitable
debug kernel, the benchmark modes, and the current performance baseline.
[TODO.md](TODO.md) records the ideas that have been thought through but not
built, including the ones deliberately rejected and why.

## Correctness and performance work

See [MILESTONES.md](MILESTONES.md) for the review findings, remediation status,
regression criteria and outstanding performance measurements.
