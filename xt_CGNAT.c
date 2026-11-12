#include <linux/module.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/bitmap.h>
#include <linux/jump_label.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/workqueue.h>
#include <net/tcp.h>
#include "compat.h"
#include "xt_CGNAT.h"

#define FLAG_REPLIED   (1 << 0) /* 000001 */
#define FLAG_TCP_FIN   (1 << 1) /* 000010 */
#define FLAG_QUARANTINE (1 << 2) /* 000100 - release this port at unlink, not at timeout 0 */

/* Which pool a session belongs to, in the spare flag bits. The session struct
 * is exactly one cacheline and there is no room to grow it, but flags had five
 * bits free. All updates use the packed-state CAS helpers, which preserve the immutable
 * pool index and protocol while changing timeout and mutable flags.
 */
#define FLAG_POOL_SHIFT 3
#define FLAG_POOL_BITS  3
#define CGNAT_MAX_POOLS (1 << FLAG_POOL_BITS)
#define FLAG_POOL_MASK  ((CGNAT_MAX_POOLS - 1) << FLAG_POOL_SHIFT)

/* Classified once, at creation, from the destination port - not re-derived per
 * packet. The datapath already has this byte in hand for the FLAG_REPLIED test
 * and already stores to timeout on the same cacheline, so selecting a second
 * timeout off it costs an AND and a predictable branch, and no extra memory
 * traffic. Deriving it per packet would mean reading udp->dest on the SNAT side
 * and udp->source on the DNAT side, which is both more work and easy to invert.
 *
 * Bit 7 is the last one free.
 */
#define FLAG_SHORTLIVED (1 << 6) /* 1000000 - DNS-class UDP, uses tmt.udp_dns */

/* The GC decrements every session by this many seconds per full sweep, and the
 * release and unlink windows in sessions_cleanup_timer_callback() are each
 * exactly one step wide. Timeouts are rounded to a multiple of it at parse
 * time so a session cannot step over a window.
 */
#define NAT_GC_STEP 10
#define NAT_TMT_MAX 32760       /* fits int16_t timeout, and is a whole number of steps */

#define TCP_SYN_ACK 0x12
#define TCP_FIN_RST 0x05

/* the GC timers walk 1/100th and 1/60th of the tables per tick, so a table
 * smaller than that has slices of zero buckets and never ages anything out */
#define NAT_HASH_MIN 1024
#define NAT_HASH_MAX (1 << 24)

#define USER_MAX_SESSIONS_DEF 4096

static LIST_HEAD(usock_list);
static int sndbuf = 1310720;
static int flowsetID = 300;
static unsigned int pdu_data_records = 0;
static unsigned int pdu_seq = 0;
struct netflow9_pdu pdu;
struct netflow9_template templateV9;
static DEFINE_SPINLOCK(nfsend_lock);
#define NF_QUEUE_SIZE 64
struct nf_batch {
    struct netflow9_pdu pdu;
    int len;
};
static struct nf_batch nf_queue[NF_QUEUE_SIZE];
static unsigned int nf_head, nf_tail, nf_count;
static atomic64_t nf_dropped = ATOMIC64_INIT(0);
static void nf_send_worker(struct work_struct *work);
static DECLARE_WORK(nf_send_work, nf_send_worker);

/* Counters touched during normal operation, per CPU. As shared atomic64 these
 * were three bounces of the same cacheline for every session created and a
 * fourth for every one freed, across every CPU at once - the exact shape of
 * cost that has been dominating this module. The failure counters below stay
 * atomic64: they only fire on error paths, where a contended cacheline is not
 * the problem.
 *
 * active is inc'd by the CPU creating a session and dec'd by whichever CPU
 * runs the GC, so a single CPU's value can go negative; only the sum across
 * CPUs is meaningful, which is why it is signed.
 */
struct nat_pcpu_stats {
    u64 dnat_dropped;
    u64 frags;
    u64 related_icmp;
};
static DEFINE_PER_CPU(struct nat_pcpu_stats, nat_pcpu_stats);

#define NAT_STAT_INC(f) this_cpu_inc(nat_pcpu_stats.f)
#define NAT_STAT_DEC(f) this_cpu_dec(nat_pcpu_stats.f)

static s64 nat_stat_sum(size_t off)
{
    s64 total = 0;
    int cpu;

    for_each_possible_cpu(cpu)
        total += *(s64 *)((char *)per_cpu_ptr(&nat_pcpu_stats, cpu) + off);
    return total;
}
#define NAT_STAT_READ(f) nat_stat_sum(offsetof(struct nat_pcpu_stats, f))

static atomic64_t users_active = ATOMIC_INIT(0);

/* Drop accounting. Every one of these used to be a printk on the packet path,
 * which meant a flood of malformed packets - or simply a NAT address running
 * out of ports - turned into a log storm that cost far more than the drop.
 * Counters instead: they are on the error paths only, so a shared atomic is
 * cheap enough, and they are what you actually want when the box hits a limit.
 */
static atomic64_t pkt_drop_proto = ATOMIC_INIT(0);
static atomic64_t pkt_drop_hdrlen = ATOMIC_INIT(0);
static atomic64_t pkt_drop_frag = ATOMIC_INIT(0);
static atomic64_t pkt_drop_trunc = ATOMIC_INIT(0);
static atomic64_t pkt_drop_unwritable = ATOMIC_INIT(0);
static atomic64_t pkt_drop_nosession = ATOMIC_INIT(0);
static atomic64_t ses_fail_nomem = ATOMIC_INIT(0);

static char nat_pool_buf[128] = "127.0.0.1-127.0.0.1";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool,
    "one or more pools, comma separated: [<name>:]<start>-<end>"
    "[:<subscriber_cidr>:<ports_per_subscriber>][:<key>=<seconds>...]. Without "
    "a name there is one pool called 'default'; -j CGNAT --pool <name> selects "
    "among several. The two bare trailing fields turn on deterministic RFC 7422 "
    "mapping, e.g. acme:198.51.100.1-198.51.100.8:10.0.0.0/20:1008. Any field "
    "containing '=' is a timeout override for this pool - see the `timeouts` "
    "parameter for the keys, e.g. res:100.64.0.1-100.64.0.8:udp_dns=20");

static int nat_hash_size = 256 * 1024;
module_param(nat_hash_size, int, 0444);
MODULE_PARM_DESC(nat_hash_size, "nat hash size, default = 256k");

static int users_hash_size = 64 * 1024;
module_param(users_hash_size, int, 0444);
MODULE_PARM_DESC(users_hash_size, "users hash size, default = 64k");

/* Per-user session cap, per protocol. Was hardcoded at 4096 in three places
 * while the README advertised 1000. Mode 0644, so it is writable at runtime
 * through /sys/module/xt_CGNAT/parameters/user_max_sessions without needing a
 * /proc write path. The per-user counters are uint16_t, so values above
 * USHRT_MAX cannot be represented and are clamped where it is read.
 */
/* When a NAT port becomes reusable.
 *
 * 0 (default): at timeout 0, the instant the session stops being visible to
 *   lookup_session_out(). Maximum capacity, and what the linear scan did, but
 *   a port can be reissued while the old session is still linked, so late
 *   inbound packets for the dead flow reach the new subscriber, and the pool
 *   can be oversubscribed without noport ever firing.
 *
 * 1: at unlink, one GC sweep later (~10s). A real quarantine, and noport
 *   becomes a truthful capacity signal - at the cost of holding roughly ten
 *   seconds' worth of expiring sessions' ports out of service.
 *
 * The choice is latched into the session at creation, before it is published,
 * so each session releases its port exactly once no matter how the parameter
 * is toggled at runtime. Deciding it in the GC instead would double-release
 * across a 0->1 change - freeing a port that had already been reissued - and
 * leak ports across 1->0.
 */
static int port_quarantine;
module_param(port_quarantine, int, 0644);
MODULE_PARM_DESC(port_quarantine,
                 "hold a NAT port for one GC sweep (~10s) after the session ends rather than reusing it immediately, default 0");

static int user_max_sessions = USER_MAX_SESSIONS_DEF;
module_param(user_max_sessions, int, 0644);
MODULE_PARM_DESC(user_max_sessions,
                 "max sessions per user per protocol (1-65535), default = 4096");

static char nf_dest_buf[128] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v9 collectors (addr1:port1[,addr2:port2]), default = none");

static char timeouts_buf[256] = "";
static char *timeouts = timeouts_buf;
module_param(timeouts, charp, 0444);
MODULE_PARM_DESC(timeouts,
    "default session timeouts in seconds, colon separated <key>=<value>: "
    "tcp, tcp_est, tcp_fin, udp, udp_est, udp_dns, icmp, other, other_est. "
    "Rounded up to a multiple of 10. A pool overrides any of these with the "
    "same syntax in its own spec; this only sets what pools start from.");

u_int32_t nat_htable_vector = 0;
u_int32_t users_htable_vector = 0;

/* Per-pool session accounting. Sessions belong to a pool, so counting them
 * globally stops being actionable the moment there is more than one; the
 * global view in /proc/net/CGNAT/statistics is the sum across pools.
 */
/* One bit per port per (NAT address, protocol). The outer hash is keyed on
 * (proto, nat addr, out port), so TCP 5000 and UDP 5000 are distinct mappings
 * and each protocol needs its own port space; sharing one bitmap per address
 * would quietly cut capacity to a third.
 *
 * Bits below 1024 are never set - allocation starts there - so the low 128
 * bytes of each map are wasted in exchange for the port number being the bit
 * index directly.
 */
#define NAT_PORT_BITS    65536
#define NAT_PORT_LO      1024
#define NAT_PROTO_SLOTS  3              /* TCP, UDP, ICMP */
#define NAT_PORT_LONGS   BITS_TO_LONGS(NAT_PORT_BITS)

static inline int nat_port_slot(uint8_t proto)
{
    switch (proto) {
    case IPPROTO_TCP:  return 0;
    case IPPROTO_UDP:  return 1;
    case IPPROTO_ICMP: return 2;
    }
    return -1;                          /* other protocols do not allocate */
}

struct nat_pool_stats {
    u64 tried;
    u64 created;
    u64 dup;
    u64 noport;
    u64 ulimit;
    u64 nomap;
    s64 active;
};

/* Seconds, all of them, and all a multiple of NAT_GC_STEP. The *_est values
 * apply once FLAG_REPLIED is set - for UDP that is "a reply came back", not a
 * connection state, which is why the field is not called "established".
 *
 * udp_dns exists because a DNS transaction is one query and one reply, and the
 * mapping is dead the moment the reply lands - but every stub resolver
 * randomises its source port per query (RFC 5452), so each query burns a
 * distinct mapping. Holding those for udp_est caps a NAT address at
 * (64512 / udp_est) new DNS transactions per second no matter how little
 * traffic they carry.
 */
struct nat_timeouts {
    uint16_t tcp;                       /* SYN out, nothing back yet */
    uint16_t tcp_est;
    uint16_t tcp_fin;                   /* FIN or RST seen either way */
    uint16_t udp;                       /* nothing back yet */
    uint16_t udp_est;
    uint16_t udp_dns;                   /* replied, destination was port 53 */
    uint16_t icmp;
    uint16_t other;                     /* protocols with no port to allocate */
    uint16_t other_est;
};

/* What the timeouts were before they were configurable, so an existing
 * deployment that sets nothing keeps its behaviour - with the one deliberate
 * exception of udp_dns, which did not exist and effectively was udp_est.
 *
 * Macros rather than only a struct because the packet path uses them as
 * immediates on the default path (see NAT_TMT below); the struct is built from
 * the same macros so there is one source of truth for the values.
 */
#define TMT_TCP        30
#define TMT_TCP_EST   300
#define TMT_TCP_FIN    10
#define TMT_UDP        30
#define TMT_UDP_EST   300
#define TMT_UDP_DNS    60
#define TMT_ICMP       30
#define TMT_OTHER      30
#define TMT_OTHER_EST 300

static const struct nat_timeouts nat_tmt_builtin = {
    .tcp   = TMT_TCP,   .tcp_est   = TMT_TCP_EST, .tcp_fin = TMT_TCP_FIN,
    .udp   = TMT_UDP,   .udp_est   = TMT_UDP_EST, .udp_dns = TMT_UDP_DNS,
    .icmp  = TMT_ICMP,
    .other = TMT_OTHER, .other_est = TMT_OTHER_EST,
};

/* Off until some pool actually differs from the built-in schedule. While it is
 * off, static_branch_unlikely() is a patched-out nop: the packet path does not
 * read the pool, does not touch that cacheline, and the timeout it stores is an
 * immediate - exactly the code that was there before pools had timeouts. The
 * cost of the feature is paid only by deployments that use it.
 *
 * One-way. pool_del() of the last customised pool leaves it on rather than
 * re-scanning and disabling: flipping it back while packets are in flight buys
 * nothing measurable and the reload path is the honest way to get back to a
 * clean default.
 */
static DEFINE_STATIC_KEY_FALSE(nat_custom_tmt);

/* Session timeout for one event, from the session's own pool - the pool its
 * port came from, which is not necessarily the pool named by whichever rule
 * this packet traversed. session_flags(sess) is already in hand at every call site for
 * the FLAG_REPLIED test, so the pool index costs nothing to recover.
 */
#define NAT_TMT(sess, field, builtin)                                       \
    (static_branch_unlikely(&nat_custom_tmt)                                \
        ? pool_of(sess)->tmt.field : (uint16_t)(builtin))

/* Seeded from the `timeouts` module parameter, then copied into each pool as
 * its starting point before that pool's own key=value fields are applied.
 */
static struct nat_timeouts nat_tmt_default;

struct nat_pool {
    /* First, and read on the established packet path - one line, shared by
     * every packet through this pool, so it stays resident. Everything below
     * is touched only on session creation or from /proc.
     */
    struct nat_timeouts tmt;

    bool used;                          /* slot occupied */
    atomic_t refcnt;                    /* iptables rules pointing here */
    atomic64_t sessions;                /* lifetime references, not sampled stats */
    char name[XT_CGNAT_POOL_NAMELEN];
    u_int32_t start, end;               /* network order, inclusive */
    unsigned int size;                  /* addresses */

    spinlock_t *create_lock;            /* [size], one per NAT address */
    unsigned long *port_bitmap;         /* [size][NAT_PROTO_SLOTS][NAT_PORT_LONGS] */

    /* deterministic mapping, RFC 7422; det_ports 0 means shared ports */
    u_int32_t det_base;                 /* first subscriber address, host order */
    u64 det_count;                /* addresses in the subscriber range */
    unsigned int det_ports;             /* ports per subscriber */
    unsigned int det_per_addr;          /* subscribers sharing one NAT address */

    struct nat_pool_stats __percpu *stats;
};

static struct nat_pool nat_pools[CGNAT_MAX_POOLS];

/* Pool lifetime mutex. The packet path never walks this array - a rule carries a
 * resolved pointer and a session carries its index - so readers that do walk
 * it (checkentry, /proc) are all in process context and can just take the
 * mutex.
 */
static DEFINE_MUTEX(nat_pools_mutex);

#define for_each_pool(i, p) \
    for ((i) = 0; (i) < CGNAT_MAX_POOLS; (i)++) \
        if (!(p = &nat_pools[i])->used) continue; else

static inline unsigned long *nat_ports_for(const struct nat_pool *pool,
                                           const u_int32_t nataddr, uint8_t proto)
{
    unsigned int id;
    int slot;

    slot = nat_port_slot(proto);
    if (unlikely(slot < 0 || pool->port_bitmap == NULL))
        return NULL;

    id = ntohl(nataddr) - ntohl(pool->start);
    return pool->port_bitmap + ((size_t)id * NAT_PROTO_SLOTS + slot) * NAT_PORT_LONGS;
}

#define POOL_STAT_INC(p, f) this_cpu_inc((p)->stats->f)
#define POOL_STAT_DEC(p, f) this_cpu_dec((p)->stats->f)

static s64 pool_stat_sum(const struct nat_pool *p, size_t off)
{
    s64 total = 0;
    int cpu;

    for_each_possible_cpu(cpu)
        total += *(s64 *)((char *)per_cpu_ptr(p->stats, cpu) + off);
    return total;
}
#define POOL_STAT_READ(p, f) pool_stat_sum(p, offsetof(struct nat_pool_stats, f))

/* summed across pools, for the global counters file */
static s64 all_pools_stat(size_t off)
{
    struct nat_pool *p;
    s64 total = 0;
    int i;

    for_each_pool(i, p)
        total += pool_stat_sum(p, off);
    return total;
}
#define ALL_STAT_READ(f) all_pools_stat(offsetof(struct nat_pool_stats, f))


static struct nat_pool *pool_by_name(const char *name)
{
    struct nat_pool *p;
    int i;

    for_each_pool(i, p) {
        if (!name || !name[0])
            return p;                   /* no --pool: the first one */
        if (!strncmp(p->name, name, XT_CGNAT_POOL_NAMELEN))
            return p;
    }
    return NULL;
}

static inline unsigned int pool_size(const struct nat_pool *p) { return p->size; }
static inline bool pool_det_enabled(const struct nat_pool *p) { return p->det_ports != 0; }

static DEFINE_SPINLOCK(sessions_timer_lock);
static DEFINE_SPINLOCK(users_timer_lock);
static struct timer_list sessions_cleanup_timer, users_cleanup_timer, nf_send_timer;

/* All three timers re-arm themselves from their own callback, so
 * del_timer_sync() alone is not enough to stop them - the caller has to
 * prevent the restart first. NONE means the timers were never set up, so
 * teardown after a failed init must not touch them.
 */
#define NAT_TIMERS_NONE 0
#define NAT_TIMERS_RUN  1
#define NAT_TIMERS_STOP 2
static atomic_t timers_state = ATOMIC_INIT(NAT_TIMERS_NONE);

struct proc_dir_entry *proc_net_nat;

struct netflow_sock {
    struct list_head list;
    struct socket *sock;
    struct sockaddr_storage addr;   // destination
};

struct xt_cgnat_htable {
    uint32_t use;
    spinlock_t lock;
    struct hlist_head session;
};

/* One object per session, linked into both hash tables at once. 64 bytes -
 * exactly one cacheline, so a lookup touches a single line rather than an
 * entry plus a pointer chase to a second object elsewhere in memory. This was
 * three allocations totalling 152 bytes.
 *
 * The union is what makes it fit. rcu_head is only used once the session has
 * been unlinked from both tables and can no longer be found by anyone, and the
 * only fields it overlays are the NetFlow destination - which the GC reads for
 * the session-close record one sweep *before* the unlink. No reader in the
 * packet path or in /proc ever looks at dst, so none can see it overwritten.
 * Overlaying anything else here would be a use-after-free.
 */
struct nat_session {
    union {
        struct rcu_head rcu;            /* valid only after the final unlink */
        struct {
            uint32_t addr;              /* NetFlow: original destination */
            uint16_t port;
        } dst;
    } u;
    struct hlist_node inner_node;       /* keyed (proto, in_addr, in_port)   */
    struct hlist_node outer_node;       /* keyed (proto, nat_addr, out_port) */
    uint32_t in_addr;
    uint32_t nat_addr;
    uint16_t in_port;
    uint16_t out_port;
    atomic_t state;                    /* signed timeout:16, proto:8, flags:8 */
};

/* A private cache, not the shared kmalloc pool: sessions are allocated and
 * freed constantly and in large numbers, and interleaving them with every
 * other kernel user of that size means freeing them returns few whole slabs.
 * At exactly 64 bytes SLAB_HWCACHE_ALIGN adds no padding at all, so every
 * session comes out cacheline aligned for free.
 *
 * kfree_rcu() cannot free slab-cache objects, so the callback is explicit and
 * teardown needs an rcu_barrier() before kmem_cache_destroy().
 */
static struct kmem_cache *nat_session_cache __read_mostly;

/* Packed state keeps the session at 64 bytes and gives every architecture a
 * native atomic transition. Once timeout becomes nonpositive, no packet can
 * revive it. RCU alone protects memory lifetime, not port ownership.
 */
static inline int session_timeout(const struct nat_session *s)
{
    return (s16)(u32)atomic_read(&s->state);
}

static inline u8 session_proto(const struct nat_session *s)
{
    return (u32)atomic_read(&s->state) >> 16;
}

static inline u8 session_flags(const struct nat_session *s)
{
    return (u32)atomic_read(&s->state) >> 24;
}

static inline struct nat_pool *pool_of(const struct nat_session *sess)
{
    return &nat_pools[(session_flags(sess) & FLAG_POOL_MASK) >> FLAG_POOL_SHIFT];
}

/* Returns false when GC already committed expiry; callers drop that packet.
 * Inbound FIN/RST is not evidence of a valid TCP close: this full-cone target
 * does not validate remote endpoints or sequence numbers. Only the subscriber
 * can shorten its TCP mapping. Other inbound packets retain first-reply aging.
 */
static bool session_touch(struct nat_session *s, bool inbound, bool fin_rst)
{
    u32 old = atomic_read(&s->state), next;
    unsigned int flags, proto;
    int timeout;

    for (;;) {
        timeout = (s16)old;
        if (timeout <= 0)
            return false;
        flags = old >> 24;
        proto = (old >> 16) & 0xff;
        switch (proto) {
        case IPPROTO_TCP:
            if (inbound) {
                if (!fin_rst && !(flags & (FLAG_REPLIED | FLAG_TCP_FIN))) {
                    timeout = NAT_TMT(s, tcp_est, TMT_TCP_EST);
                    flags |= FLAG_REPLIED;
                }
            } else if (fin_rst) {
                timeout = NAT_TMT(s, tcp_fin, TMT_TCP_FIN);
                flags |= FLAG_TCP_FIN;
            } else if (flags & FLAG_TCP_FIN) {
                timeout = NAT_TMT(s, tcp_fin, TMT_TCP_FIN);
                flags &= ~FLAG_TCP_FIN;
            } else {
                timeout = (flags & FLAG_REPLIED) ? NAT_TMT(s, tcp_est, TMT_TCP_EST)
                                                 : NAT_TMT(s, tcp, TMT_TCP);
            }
            break;
        case IPPROTO_UDP:
            if (!inbound || !(flags & FLAG_REPLIED)) {
                if (inbound || (flags & FLAG_REPLIED))
                    timeout = (flags & FLAG_SHORTLIVED) ? NAT_TMT(s, udp_dns, TMT_UDP_DNS)
                                                       : NAT_TMT(s, udp_est, TMT_UDP_EST);
                else
                    timeout = NAT_TMT(s, udp, TMT_UDP);
            }
            if (inbound)
                flags |= FLAG_REPLIED;
            break;
        case IPPROTO_ICMP:
            if (!inbound || !(flags & FLAG_REPLIED))
                timeout = NAT_TMT(s, icmp, TMT_ICMP);
            if (inbound)
                flags |= FLAG_REPLIED;
            break;
        default:
            if (!inbound || !(flags & FLAG_REPLIED))
                timeout = (inbound || (flags & FLAG_REPLIED))
                        ? NAT_TMT(s, other_est, TMT_OTHER_EST) : NAT_TMT(s, other, TMT_OTHER);
            if (inbound)
                flags |= FLAG_REPLIED;
        }
        next = (old & 0x00ff0000U) | ((u32)flags << 24) | (u16)timeout;
        if ((u32)atomic_cmpxchg(&s->state, old, next) == old)
            return true;
        old = atomic_read(&s->state);
    }
}

static int session_age(struct nat_session *s)
{
    u32 old = atomic_read(&s->state), next;
    int timeout;

    do {
        timeout = (s16)old - NAT_GC_STEP;
        next = (old & 0xffff0000U) | (u16)timeout;
        if ((u32)atomic_cmpxchg(&s->state, old, next) == old)
            return timeout;
        old = atomic_read(&s->state);
    } while (1);
}

static void nat_session_free_rcu(struct rcu_head *head)
{
    struct nat_session *sess = container_of(head, struct nat_session, u.rcu);
    struct nat_pool *pool = pool_of(sess);

    kmem_cache_free(nat_session_cache, sess);
    /* A different-pool rule may still have found this global mapping under
     * RCU. Keep its originating pool alive until every such reader is gone.
     */
    atomic64_dec(&pool->sessions);
}

struct xt_cgnat_users_htable {
    uint32_t use;
    spinlock_t lock;
    struct hlist_head user;
};

struct user_htable_ent {
    struct rcu_head rcu;
    struct hlist_node list_node;
    uint32_t addr;
    uint16_t tcp_count;
    uint16_t udp_count;
    uint16_t other_count;
    uint8_t idle;
};

struct xt_cgnat_users_htable *ht_users;


struct xt_cgnat_htable *ht_inner, *ht_outer;

static char *print_sockaddr(const struct sockaddr_storage *ss)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "%pISpc", ss);
    return buf;
}

static inline long timer_end(struct timespec64 start_time)
{
    struct timespec64 end_time;
    ktime_get_raw_ts64(&end_time);
    return(end_time.tv_nsec - start_time.tv_nsec);
}

static inline struct timespec64 timer_start(void)
{
    struct timespec64 start_time;
    ktime_get_raw_ts64(&start_time);
    return start_time;
}

static inline u_int32_t
get_pool_size(const struct nat_pool *pool)
{
    return ntohl(pool->end) - ntohl(pool->start) + 1;
}

/* subscriber -> (public address, port block). false when the subscriber falls
 * outside the configured range, which the caller must treat as a drop. */
static bool nat_det_map(const struct nat_pool *pool, const u_int32_t saddr,
                        u_int32_t *nat_addr, unsigned int *lo, unsigned int *hi)
{
    u_int32_t host = ntohl(saddr);
    u_int32_t idx, addr_idx, block;

    if (host < pool->det_base)
        return false;
    idx = host - pool->det_base;
    if (idx >= pool->det_count)
        return false;

    addr_idx = idx / pool->det_per_addr;
    if (addr_idx >= pool->size)        /* refused at load, so cannot happen */
        return false;
    block = idx % pool->det_per_addr;

    *nat_addr = htonl(ntohl(pool->start) + addr_idx);
    *lo = NAT_PORT_LO + block * pool->det_ports;
    *hi = *lo + pool->det_ports;
    return true;
}

static inline u_int32_t
get_nat_addr(const struct nat_pool *pool, const u_int32_t addr)
{
    u_int32_t na;
    unsigned int lo, hi;

    if (pool_det_enabled(pool))
        return nat_det_map(pool, addr, &na, &lo, &hi) ? na : 0;

    return htonl(ntohl(pool->start) + reciprocal_scale(jhash_1word(addr, 0), pool->size));
}

static inline u_int32_t
get_hash_nat_ent(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    return reciprocal_scale(jhash_3words((u32)proto, addr, (u32)port, 0), nat_hash_size);
}

static inline u_int32_t
get_hash_user_ent(const u_int32_t addr)
{
    return reciprocal_scale(jhash_1word(addr, 0), users_hash_size);
}

static int pool_table_create(struct nat_pool *pool)
{
    size_t sz, bsz;
    unsigned int i;

    if (check_mul_overflow((size_t)pool->size, sizeof(spinlock_t), &sz) ||
        check_mul_overflow((size_t)pool->size,
                           (size_t)NAT_PROTO_SLOTS * NAT_PORT_LONGS * sizeof(unsigned long), &bsz))
        return -EOVERFLOW;
    pool->create_lock = kvzalloc(sz, GFP_KERNEL);
    if (pool->create_lock == NULL)
        return -ENOMEM;
    for (i = 0; i < pool->size; i++)
        spin_lock_init(&pool->create_lock[i]);

    /* 8KB per protocol per NAT address: 24KB an address, 6MB for a /24. A pool
     * large enough for that to hurt could not hold the sessions to fill it. */
    pool->port_bitmap = kvzalloc(bsz, GFP_KERNEL);
    if (pool->port_bitmap == NULL) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': cannot allocate %zu bytes of port bitmaps\n",
               pool->name, bsz);
        kvfree(pool->create_lock);
        pool->create_lock = NULL;
        return -ENOMEM;
    }

    pool->stats = alloc_percpu(struct nat_pool_stats);
    if (pool->stats == NULL) {
        kvfree(pool->port_bitmap);
        kvfree(pool->create_lock);
        pool->port_bitmap = NULL;
        pool->create_lock = NULL;
        return -ENOMEM;
    }

    printk(KERN_INFO "xt_CGNAT: pool '%s': %pI4-%pI4 (%u addresses), locks %zu, bitmaps %zu\n",
           pool->name, &pool->start, &pool->end, pool->size, sz, bsz);
    return 0;
}

static void pool_table_remove(struct nat_pool *pool)
{
    kvfree(pool->create_lock);
    pool->create_lock = NULL;
    kvfree(pool->port_bitmap);
    pool->port_bitmap = NULL;
    free_percpu(pool->stats);
    pool->stats = NULL;
}

static int pools_create(void)
{
    struct nat_pool *p;
    int i, ret;

    for_each_pool(i, p) {
        ret = pool_table_create(p);
        if (ret < 0) {
            while (--i >= 0)
                if (nat_pools[i].used)
                    pool_table_remove(&nat_pools[i]);
            return ret;
        }
    }
    return 0;
}

static void pools_remove(void)
{
    struct nat_pool *p;
    int i;

    for_each_pool(i, p)
        pool_table_remove(p);
}

static int users_htable_create(void)
{
    size_t sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_cgnat_users_htable) * (size_t)users_hash_size;
    ht_users = kvzalloc(sz, GFP_KERNEL);

    if (ht_users == NULL)
        return -ENOMEM;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_init(&ht_users[i].lock);
        INIT_HLIST_HEAD(&ht_users[i].user);
        ht_users[i].use = 0;
    }

    printk(KERN_INFO "xt_CGNAT DEBUG: users htable mem: %zu\n", sz);
    return 0;
}

static void users_htable_remove(void)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    int i;

    if (ht_users == NULL)
        return;

    for (i = 0; i < users_hash_size; i++) {
        spin_lock_bh(&ht_users[i].lock);
        head = &ht_users[i].user;
        hlist_for_each_entry_safe(user, next, head, list_node) {
            hlist_del_rcu(&user->list_node);
            ht_users[i].use--;
            kfree_rcu(user, rcu);
        }

        if (ht_users[i].use != 0) {
            printk(KERN_WARNING "xt_CGNAT users_htable_remove ERROR: bad use value: %u in element %d\n", ht_users[i].use, i);
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    kvfree(ht_users);
    ht_users = NULL;
    printk(KERN_INFO "xt_CGNAT users_htable_remove DONE\n");
    return;
}

static void nat_htable_remove(void)
{
    struct nat_session *sess;
    struct hlist_node *next;
    unsigned int i, ohash;

    if (ht_inner == NULL || ht_outer == NULL) {
        kvfree(ht_inner);
        kvfree(ht_outer);
        ht_inner = NULL;
        ht_outer = NULL;
        return;
    }

    /* A session is one object in two chains, so walking ht_inner reaches all
     * of them; the outer chain is unlinked from the same place. */
    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        hlist_for_each_entry_safe(sess, next, &ht_inner[i].session, inner_node) {
            ohash = get_hash_nat_ent(session_proto(sess), sess->nat_addr, sess->out_port);
            spin_lock_bh(&ht_outer[ohash].lock);
            hlist_del_rcu(&sess->outer_node);
            ht_outer[ohash].use--;
            spin_unlock_bh(&ht_outer[ohash].lock);

            hlist_del_rcu(&sess->inner_node);
            ht_inner[i].use--;
            call_rcu(&sess->u.rcu, nat_session_free_rcu);
        }
        if (ht_inner[i].use != 0)
            printk(KERN_WARNING "xt_CGNAT nat_htable_remove inner ERROR: bad use value: %u in element %d\n", ht_inner[i].use, i);
        spin_unlock_bh(&ht_inner[i].lock);
    }

    for (i = 0; i < nat_hash_size; i++) {
        if (ht_outer[i].use != 0)
            printk(KERN_WARNING "xt_CGNAT nat_htable_remove outer ERROR: bad use value: %u in element %d\n", ht_outer[i].use, i);
    }

    kvfree(ht_inner);
    kvfree(ht_outer);
    ht_inner = NULL;
    ht_outer = NULL;

    printk(KERN_INFO "xt_CGNAT nat_htable_remove DONE\n");
    return;
}


static int nat_htable_create(void)
{
    size_t sz; /* (bytes) */
    int i;

    sz = sizeof(struct xt_cgnat_htable) * (size_t)nat_hash_size;
    ht_inner = kvzalloc(sz, GFP_KERNEL);
    if (ht_inner == NULL)
        return -ENOMEM;

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_inner[i].lock);
        INIT_HLIST_HEAD(&ht_inner[i].session);
        ht_inner[i].use = 0;
    }

    printk(KERN_INFO "xt_CGNAT DEBUG: sessions htable inner mem: %zu\n", sz);

    ht_outer = kvzalloc(sz, GFP_KERNEL);
    if (ht_outer == NULL) {
        kvfree(ht_inner);
        ht_inner = NULL;
        return -ENOMEM;
    }

    for (i = 0; i < nat_hash_size; i++) {
        spin_lock_init(&ht_outer[i].lock);
        INIT_HLIST_HEAD(&ht_outer[i].session);
        ht_outer[i].use = 0;
    }

    printk(KERN_INFO "xt_CGNAT DEBUG: sessions htable outer mem: %zu\n", sz);
    return 0;
}

static struct nat_session *lookup_session_in(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_session *s;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    hlist_for_each_entry_rcu(s, &ht_inner[hash].session, inner_node) {
        if (s->in_addr == addr && s->in_port == port && session_proto(s) == proto && session_timeout(s) > 0)
            return s;
    }
    return NULL;
}

static struct nat_session *lookup_session_out(const uint8_t proto, const u_int32_t addr, const uint16_t port)
{
    struct nat_session *s;
    unsigned int hash;

    hash = get_hash_nat_ent(proto, addr, port);
    hlist_for_each_entry_rcu(s, &ht_outer[hash].session, outer_node) {
        if (s->nat_addr == addr && s->out_port == port && session_proto(s) == proto && session_timeout(s) > 0)
            return s;
    }
    return NULL;
}

/* Called with create_session_lock[] for this NAT address held, so nothing else
 * sets bits in this map concurrently; the GC only ever clears them, which can
 * at worst make us miss a port that just became free.
 *
 * The old version probed lookup_session_out() for up to 64512 candidate ports,
 * each a full hash lookup, under that same spinlock with BH disabled. Average
 * cost grew as 1/(1-occupancy) and the exhausted case was a soft-lockup
 * generator.
 */
static inline void nat_release_port(struct nat_session *sess)
{
    unsigned long *map = nat_ports_for(pool_of(sess), sess->nat_addr, session_proto(sess));

    if (map)
        clear_bit(ntohs(sess->out_port), map);
}

static uint16_t search_free_l4_port(const struct nat_pool *pool, const uint8_t proto,
                                    const u_int32_t nataddr, const uint16_t userport,
                                    unsigned int lo, unsigned int hi)
{
    unsigned long *map;
    unsigned int start, port;

    map = nat_ports_for(pool, nataddr, proto);
    if (unlikely(map == NULL))
        return userport;

    /* deterministic mode narrows [lo,hi) to this subscriber's block, so a
     * subscriber can only ever consume its own ports */
    start = ntohs(userport);
    if (start < lo || start >= hi)
        start = lo + (start % (hi - lo));

    /* port preservation: the subscriber's own source port when it is free,
     * which is what the linear scan produced in the common case */
    if (!test_and_set_bit(start, map))
        return htons(start);

    port = find_next_zero_bit(map, hi, start);
    if (port >= hi)                             /* wrap to [lo, start) */
        port = find_next_zero_bit(map, start, lo);
    if (port >= hi || port < lo)
        return 0;
    if (unlikely(test_and_set_bit(port, map)))
        return 0;

    return htons(port);
}

static int update_user_limits(const u_int8_t proto, const u_int32_t addr, const int8_t operation)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    uint16_t *count;
    unsigned int hash, is_found;
    unsigned int sz, limit;

    hash = get_hash_user_ent(addr);
    spin_lock_bh(&ht_users[hash].lock);
    head = &ht_users[hash].user;
    is_found=0;
    hlist_for_each_entry(user, head, list_node) {
        if (user->addr == addr) {
            is_found=1;
            break;
        }
    }

    if (unlikely(is_found==0)) {
        /* There is nothing to decrement if the user entry is already gone.
         * Creating one here would apply -1 to a freshly zeroed counter and
         * wrap it to 65535, which locks the subscriber out permanently:
         * check_user_limits() then always refuses, and the cleanup timer
         * never reaps the entry because it only ages a user whose counters
         * are all zero.
         */
        if (operation < 0) {
            spin_unlock_bh(&ht_users[hash].lock);
            return operation < 0 ? 0 : -ENOMEM;
        }

        sz = sizeof(struct user_htable_ent);
        user = kzalloc(sz, GFP_ATOMIC);

        if (user == NULL) {
            atomic64_inc(&ses_fail_nomem);
            printk_ratelimited(KERN_WARNING "xt_CGNAT update_user_limits ERROR: Cannot allocate memory for user_session\n");
            spin_unlock_bh(&ht_users[hash].lock);
            return operation < 0 ? 0 : -ENOMEM;
        }

        user->addr = addr;

        hlist_add_head_rcu(&user->list_node, &ht_users[hash].user);
        ht_users[hash].use++;
        atomic64_inc(&users_active);
    }

    user->idle = 0;

    if (proto == IPPROTO_TCP) {
        count = &user->tcp_count;
    } else if (proto == IPPROTO_UDP) {
        count = &user->udp_count;
    } else {
        count = &user->other_count;
    }

    if (operation < 0) {
        if (likely(*count > 0)) {
            (*count)--;
        } else {
            printk(KERN_WARNING "xt_CGNAT update_user_limits ERROR: %pI4 proto %u session count underflow\n",
                   &addr, proto);
        }
    } else {
        limit = clamp_t(unsigned int, READ_ONCE(user_max_sessions), 1, USHRT_MAX);
        if (*count >= limit) {
            spin_unlock_bh(&ht_users[hash].lock);
            return -ENOSPC;
        }
        (*count)++;
    }

    spin_unlock_bh(&ht_users[hash].lock);
    return 0;
}

/* socket code */
static void nat_sk_error_report(struct sock *sk)
{
    sk->sk_err = 0;
    return;
}

static struct socket *usock_open_sock(const struct sockaddr_storage *addr, void *user_data)
{
    struct socket *sock;
    int error;

    if ((error = sock_create_kern(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP, &sock)) < 0) {
        printk(KERN_WARNING "xt_CGNAT NEL: sock_create_kern error %d\n", -error);
        return NULL;
    }
    sock->sk->sk_allocation = GFP_ATOMIC;
    sock->sk->sk_prot->unhash(sock->sk); /* hidden from input */
    sock->sk->sk_error_report = &nat_sk_error_report; /* clear ECONNREFUSED */
    sock->sk->sk_user_data = user_data; /* usock */

    if (sndbuf < SOCK_MIN_SNDBUF)
	sndbuf = SOCK_MIN_SNDBUF;

    if (sndbuf)
        sock->sk->sk_sndbuf = sndbuf;
    else
        sndbuf = sock->sk->sk_sndbuf;
    error = kernel_connect(sock, (compat_sockaddr_kern *)addr, sizeof(*addr), 0);
    if (error < 0) {
        printk(KERN_WARNING "xt_CGNAT NEL: error connecting UDP socket %d,"
               " don't worry, will try reconnect later.\n", -error);
        /* ENETUNREACH when no interfaces */
        sock_release(sock);
        return NULL;
    }
    return sock;
}

static void netflow_sendmsg(void *buffer, const int len)
{
    struct msghdr msg = { .msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL };
    struct kvec iov = { buffer, len };
    struct netflow_sock *usock;
    int ret;

    list_for_each_entry(usock, &usock_list, list) {
        if (!usock->sock)
            usock->sock = usock_open_sock(&usock->addr, usock);

        if (!usock->sock)
            continue;

        ret = kernel_sendmsg(usock->sock, &msg, &iov, 1, (size_t)len);
        if (ret == -EINVAL) {
            if (usock->sock)
                sock_release(usock->sock);
            usock->sock = NULL;
        } else if (ret == -EAGAIN) {
            printk(KERN_WARNING "xt_CGNAT NEL: increase sndbuf!\n");
        }
    }
}

/* The worker is the sole socket owner. No socket allocation, connect, send
 * or release occurs under a spinlock or in a timer/packet callback.
 */
static void nf_send_worker(struct work_struct *work)
{
    struct nf_batch batch;

    for (;;) {
        spin_lock_bh(&nfsend_lock);
        if (!nf_count) {
            spin_unlock_bh(&nfsend_lock);
            return;
        }
        batch = nf_queue[nf_tail];
        nf_tail = (nf_tail + 1) % NF_QUEUE_SIZE;
        nf_count--;
        spin_unlock_bh(&nfsend_lock);
        netflow_sendmsg(&batch.pdu, batch.len);
    }
}

static void netflow_export_pdu_v9(void)
{
    struct timespec64 ts;
    int pdusize;

    if (!pdu_data_records)
        return;

    pdu.version		= htons(9);
    pdu.nr_records	= htons(pdu_data_records + 1);
    pdu.ts_uptime	= htonl(jiffies_to_msecs(jiffies));
    ktime_get_real_ts64(&ts);
    pdu.ts_usecs	= htonl(ts.tv_sec);
    pdu.seq		= htonl(pdu_seq);
    pdu.srcID		= 0;
    pdu.template_V9	= templateV9;
    pdu.FlowSetId	= htons(flowsetID);
    pdu.FlowSetIdSize	= sizeof(struct netflow9_record) * pdu_data_records;
    pdusize = NETFLOW9_HEADER_SIZE + pdu.FlowSetIdSize;
    pdu.FlowSetIdSize	= htons(pdu.FlowSetIdSize+4);
    if (nf_count == NF_QUEUE_SIZE) {
        atomic64_inc(&nf_dropped);
    } else {
        nf_queue[nf_head].pdu = pdu;
        nf_queue[nf_head].len = pdusize;
        nf_head = (nf_head + 1) % NF_QUEUE_SIZE;
        nf_count++;
        schedule_work(&nf_send_work);
    }
    pdu_seq++;
    pdu_data_records = 0;
}

static void netflow_export_flow_v9(const uint8_t proto, const u_int32_t srcaddr, const uint16_t srcport, const u_int32_t dstaddr, const uint16_t dstport, const u_int32_t nataddr, const uint16_t natport, const int nat_event)
{
    struct netflow9_record *rec;

    if (list_empty(&usock_list))
        return;
    spin_lock_bh(&nfsend_lock);

    rec = &pdu.flow[pdu_data_records++];

    rec->protocol	= proto;
    rec->s_port		= srcport;
    rec->s_addr		= srcaddr;
    rec->d_port		= dstport;
    rec->d_addr		= dstaddr;
    rec->n_addr		= nataddr;
    rec->n_port		= natport;
    rec->event		= nat_event;

    if (pdu_data_records == NETFLOW9_RECORDS_MAX)
        netflow_export_pdu_v9();

    spin_unlock_bh(&nfsend_lock);
}

static struct nat_session *create_nat_session(struct nat_pool *pool, const uint8_t proto, const u_int32_t useraddr, const uint16_t userport, const u_int32_t dstaddr, const uint16_t dstport)
{
    struct nat_session *sess, *existing;
    unsigned int lo = NAT_PORT_LO, hi = NAT_PORT_BITS;
    u_int32_t nataddr;
    uint16_t natport;
    unsigned int nataddr_id, hash, ihash;
    int ret;
    unsigned int timeout, flags;

    POOL_STAT_INC(pool, tried);

    /* Computed here rather than per packet: an established session carries its
     * own nat_addr, so the datapath never needs this. */
    if (pool_det_enabled(pool)) {
        if (unlikely(!nat_det_map(pool, useraddr, &nataddr, &lo, &hi))) {
            POOL_STAT_INC(pool, nomap);
            printk_ratelimited(KERN_NOTICE "xt_CGNAT: %pI4 is outside the deterministic subscriber range\n",
                               &useraddr);
            return NULL;
        }
    } else {
        nataddr = get_nat_addr(pool, useraddr);
    }

    /* allocated before the lock: nothing here needs it, and on the paths that
     * bail out the object is simply freed - it was never published */
    sess = kmem_cache_zalloc(nat_session_cache, GFP_ATOMIC);
    if (unlikely(sess == NULL)) {
        atomic64_inc(&ses_fail_nomem);
        printk_ratelimited(KERN_WARNING "xt_CGNAT create_nat_session ERROR: Cannot allocate session\n");
        return NULL;
    }

    nataddr_id = ntohl(nataddr) - ntohl(pool->start);
    spin_lock_bh(&pool->create_lock[nataddr_id]);

    /* Contract with the caller: either NULL with no RCU read lock held, or a
     * session with rcu_read_lock_bh() held for it to drop.
     */
    rcu_read_lock_bh();
    existing = lookup_session_in(proto, useraddr, userport);
    if (unlikely(existing)) {
        spin_unlock_bh(&pool->create_lock[nataddr_id]);
        kmem_cache_free(nat_session_cache, sess);
        POOL_STAT_INC(pool, dup);
        if (!session_touch(existing, false, false)) {
            rcu_read_unlock_bh();
            return NULL;
        }
        return existing;
    }
    rcu_read_unlock_bh();

    ret = update_user_limits(proto, useraddr, 1);
    if (ret) {
        if (ret == -ENOSPC)
            POOL_STAT_INC(pool, ulimit);
        spin_unlock_bh(&pool->create_lock[nataddr_id]);
        kmem_cache_free(nat_session_cache, sess);
        return NULL;
    }

    if (likely(proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP)) {
        rcu_read_lock_bh();
        natport = search_free_l4_port(pool, proto, nataddr, userport, lo, hi);
        rcu_read_unlock_bh();
        if (natport == 0) {
            update_user_limits(proto, useraddr, -1);
            POOL_STAT_INC(pool, noport);
            printk_ratelimited(KERN_WARNING "xt_CGNAT create_nat_session ERROR: Not found free nat port for %d %pI4:%u -> %pI4:XXXX\n", proto, &useraddr, userport, &nataddr);
            spin_unlock_bh(&pool->create_lock[nataddr_id]);
            kmem_cache_free(nat_session_cache, sess);
            return NULL;
        }
    } else {
        /* Generic protocols have no port discriminator. Serialize ownership
         * with all creators for this public address; a quarantine reservation
         * remains occupied until GC unlinks it.
         */
        bool occupied = false;
        rcu_read_lock_bh();
        hash = get_hash_nat_ent(proto, nataddr, 0);
        hlist_for_each_entry_rcu(existing, &ht_outer[hash].session, outer_node) {
            if (session_proto(existing) == proto && existing->nat_addr == nataddr &&
                (session_timeout(existing) > 0 ||
                 (session_flags(existing) & FLAG_QUARANTINE))) {
                occupied = true;
                break;
            }
        }
        rcu_read_unlock_bh();
        if (occupied) {
            update_user_limits(proto, useraddr, -1);
            POOL_STAT_INC(pool, noport);
            spin_unlock_bh(&pool->create_lock[nataddr_id]);
            kmem_cache_free(nat_session_cache, sess);
            return NULL;
        }
        natport = userport;
    }

    sess->in_addr    = useraddr;
    sess->in_port    = userport;
    sess->nat_addr   = nataddr;
    sess->out_port   = natport;
    sess->u.dst.addr = dstaddr;
    sess->u.dst.port = dstport;
    flags = (READ_ONCE(port_quarantine) ? FLAG_QUARANTINE : 0)
                       | ((unsigned)(pool - nat_pools) << FLAG_POOL_SHIFT);

    /* Nothing has replied yet, so this is the unreplied timeout for the
     * protocol. Read from the pool unconditionally: session creation already
     * costs a port search and two locked hash inserts, so one more field off a
     * struct that is about to be touched anyway does not need the static key.
     */
    switch (proto) {
    case IPPROTO_TCP:  timeout = pool->tmt.tcp;  break;
    case IPPROTO_UDP:  timeout = pool->tmt.udp;  break;
    case IPPROTO_ICMP: timeout = pool->tmt.icmp; break;
    default:           timeout = pool->tmt.other; break;
    }

    /* Only UDP: 53/tcp is a zone transfer or a truncated-response retry, both
     * of which are ordinary connections that deserve the ordinary timeout.
     */
    if (proto == IPPROTO_UDP && dstport == htons(53))
        flags |= FLAG_SHORTLIVED;

    atomic_set(&sess->state, (flags << 24) | ((u32)proto << 16) | timeout);

    rcu_read_lock_bh();
    ihash = get_hash_nat_ent(proto, useraddr, userport);
    spin_lock_bh(&ht_inner[ihash].lock);
    /* Rules selecting different pools have different address locks. The inner
     * bucket is the common serialization point for the global subscriber key.
     */
    existing = lookup_session_in(proto, useraddr, userport);
    if (unlikely(existing)) {
        spin_unlock_bh(&ht_inner[ihash].lock);
        nat_release_port(sess);
        update_user_limits(proto, useraddr, -1);
        spin_unlock_bh(&pool->create_lock[nataddr_id]);
        kmem_cache_free(nat_session_cache, sess);
        POOL_STAT_INC(pool, dup);
        if (!session_touch(existing, false, false)) {
            rcu_read_unlock_bh();
            return NULL;
        }
        return existing;
    }
    atomic64_inc(&pool->sessions);
    POOL_STAT_INC(pool, active);
    POOL_STAT_INC(pool, created);
    netflow_export_flow_v9(proto, useraddr, userport, dstaddr, dstport, nataddr, natport, 1);
    hlist_add_head_rcu(&sess->inner_node, &ht_inner[ihash].session);
    ht_inner[ihash].use++;

    hash = get_hash_nat_ent(proto, nataddr, natport);
    spin_lock_bh(&ht_outer[hash].lock);
    hlist_add_head_rcu(&sess->outer_node, &ht_outer[hash].session);
    ht_outer[hash].use++;
    spin_unlock_bh(&ht_outer[hash].lock);
    spin_unlock_bh(&ht_inner[ihash].lock);
    spin_unlock_bh(&pool->create_lock[nataddr_id]);

    /* The read lock was acquired before publication; the caller drops it. */
    return sess;
}

static unsigned int
nat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct nat_session *session;
    uint16_t nat_port;
    unsigned int inner_hlen;
    unsigned int icmp_off;
    const struct xt_cgnat_tginfo *info = par->targinfo;
    struct nat_pool *pool = info->priv;

    if (unlikely(skb->protocol != htons(ETH_P_IP))) {
        atomic64_inc(&pkt_drop_proto);
        return NF_DROP;
    }
    if (unlikely(ip_hdrlen(skb) != sizeof(struct iphdr))) {
        atomic64_inc(&pkt_drop_hdrlen);
        return NF_DROP;
    }

    ip = (struct iphdr *)skb_network_header(skb);

    if (unlikely(ip->frag_off & htons(IP_OFFSET))) {
        atomic64_inc(&pkt_drop_frag);
        return NF_DROP;
    }
    if (unlikely(ip->version != 4)) {
        atomic64_inc(&pkt_drop_proto);
        return NF_DROP;
    }

    if (info->variant == XT_CGNAT_SNAT) {
        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            tcp = (struct tcphdr *)((char *)ip + ip->ihl * 4);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, tcp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->nat_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->source, session->out_port, false);

                ip->saddr = session->nat_addr;
                tcp->source = session->out_port;

                if (!session_touch(session, false, tcp->fin || tcp->rst)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(pool, ip->protocol, ip->saddr, tcp->source, ip->daddr, tcp->dest);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }

                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->saddr, session->nat_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, session->in_port, session->out_port, false);
                ip->saddr = session->nat_addr;
                tcp->source = session->out_port;
                rcu_read_unlock_bh();
            }

        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            udp = (struct udphdr *)((char *)ip + ip->ihl * 4);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, udp->source);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->nat_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->source, session->out_port, false);
                }
                ip->saddr = session->nat_addr;
                udp->source = session->out_port;
                if (!session_touch(session, false, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(pool, ip->protocol, ip->saddr, udp->source, ip->daddr, udp->dest);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->saddr, session->nat_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, session->in_port, session->out_port, false);
                }
                ip->saddr = session->nat_addr;
                udp->source = session->out_port;
                rcu_read_unlock_bh();
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            icmp = (struct icmphdr *)((char *)ip + ip->ihl * 4);

            if (unlikely(icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY)) {
                atomic64_inc(&pkt_drop_proto);
                return NF_DROP;
            }
            nat_port = icmp->un.echo.id;

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, nat_port);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->out_port, false);
                icmp->un.echo.id = session->out_port;
                if (!session_touch(session, false, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(pool, ip->protocol, ip->saddr, nat_port, ip->daddr, nat_port);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->out_port, false);
                icmp->un.echo.id = session->out_port;
                rcu_read_unlock_bh();
            }
        } else {
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            rcu_read_lock_bh();
            session = lookup_session_in(ip->protocol, ip->saddr, 0);
            if (session) {
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                if (!session_touch(session, false, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                session = create_nat_session(pool, ip->protocol, ip->saddr, 0, ip->daddr, 0);
                if (session == NULL) {
                    atomic64_inc(&pkt_drop_nosession);
                    return NF_DROP;
                }
                csum_replace4(&ip->check, ip->saddr, session->nat_addr);
                ip->saddr = session->nat_addr;
                rcu_read_unlock_bh();
            }
        }
    } else if (info->variant == XT_CGNAT_DNAT) {
        if (ip->protocol == IPPROTO_TCP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct tcphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(skb_headlen(skb) < ip_hdrlen(skb) + sizeof(struct tcphdr)))
                NAT_STAT_INC(frags);
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            tcp = (struct tcphdr *)((char *)ip + ip->ihl * 4);

            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, tcp->dest);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                inet_proto_csum_replace4(&tcp->check, skb, ip->daddr, session->in_addr, true);
                inet_proto_csum_replace2(&tcp->check, skb, tcp->dest, session->in_port, false);
                ip->daddr = session->in_addr;
                tcp->dest = session->in_port;
                if (!session_touch(session, true, tcp->fin || tcp->rst)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
                return NF_DROP;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct udphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(skb_headlen(skb) < ip_hdrlen(skb) + sizeof(struct udphdr)))
                NAT_STAT_INC(frags);
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            udp = (struct udphdr *)((char *)ip + ip->ihl * 4);

            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, udp->dest);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                if (udp->check) {
                    inet_proto_csum_replace4(&udp->check, skb, ip->daddr, session->in_addr, true);
                    inet_proto_csum_replace2(&udp->check, skb, udp->dest, session->in_port, false);
                }
                ip->daddr = session->in_addr;
                udp->dest = session->in_port;

                if (!session_touch(session, true, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
                return NF_DROP;
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (unlikely(skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr))) {
                atomic64_inc(&pkt_drop_trunc);
                return NF_DROP;
            }
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(struct icmphdr)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);
            icmp = (struct icmphdr *)((char *)ip + ip->ihl * 4);

            nat_port = 0;
            if (icmp->type == 0 || icmp->type == 8) {
                nat_port = icmp->un.echo.id;
            } else if (icmp->type == 3 || icmp->type == 4 || icmp->type == 5 || icmp->type == 11 || icmp->type == 12 || icmp->type == 31) {
                NAT_STAT_INC(related_icmp);
                if (skb->len < ip_hdrlen(skb) + sizeof(struct icmphdr) + sizeof(struct iphdr)) {
                    atomic64_inc(&pkt_drop_trunc);
                    return NF_DROP;
                }

                if (unlikely(compat_skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr)))) {
                    atomic64_inc(&pkt_drop_unwritable);
                    return NF_DROP;
                }

                ip = (struct iphdr *)(skb_network_header(skb) + sizeof(struct iphdr) + sizeof(struct icmphdr));

                /* The quoted header carries its own length, and the transport
                 * header below is located with ip->ihl * 4 - but the length
                 * checks only ever validated sizeof(struct iphdr) of it. An
                 * ICMP error quoting a packet that carried IP options then
                 * read, and wrote, up to 40 bytes past the validated area.
                 */
                inner_hlen = ip->ihl * 4;
                if (ip->ihl < 5) {
                    atomic64_inc(&pkt_drop_hdrlen);
                    return NF_DROP;
                }

                /* All three embedded protocols below need the quoted header
                 * plus its first 8 transport bytes, and all three write into
                 * them.
                 */
                if (skb->len < sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen + 8) {
                    atomic64_inc(&pkt_drop_trunc);
                    return NF_DROP;
                }
                if (unlikely(compat_skb_ensure_writable(skb, sizeof(struct iphdr) + sizeof(struct icmphdr) + inner_hlen + 8))) {
                    atomic64_inc(&pkt_drop_unwritable);
                    return NF_DROP;
                }
                /* the pull above may have moved the data */
                ip = (struct iphdr *)(skb_network_header(skb) + sizeof(struct iphdr) + sizeof(struct icmphdr));

                if (ip->protocol == IPPROTO_TCP) {
                    tcp = (struct tcphdr *)((char *)ip + inner_hlen);
                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, tcp->source);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                        tcp->source = session->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        NAT_STAT_INC(dnat_dropped);
                        return NF_DROP;
                    }

                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_UDP) {
                    udp = (struct udphdr *)((char *)ip + inner_hlen);
                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, udp->source);
                    if (session) {
                        if (udp->check) {
                            csum_replace4(&udp->check, ip->saddr, session->in_addr);
                            csum_replace2(&udp->check, udp->source, session->in_port);
                            if (!udp->check)
                                udp->check = CSUM_MANGLED_0;
                        }
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                        udp->source = session->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        NAT_STAT_INC(dnat_dropped);
                        return NF_DROP;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);

                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                } else if (ip->protocol == IPPROTO_ICMP) {
                    icmp = (struct icmphdr *)((char *)ip + inner_hlen);

                    if (unlikely(icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY)) {
                        NAT_STAT_INC(dnat_dropped);
                        return NF_DROP;
                    }
                    nat_port = icmp->un.echo.id;

                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, nat_port);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                        csum_replace2(&icmp->checksum, nat_port, session->in_port);
                        icmp->un.echo.id = session->in_port;
                    } else {
                        rcu_read_unlock_bh();
                        NAT_STAT_INC(dnat_dropped);
                        return NF_DROP;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                } else {
                    rcu_read_lock_bh();
                    session = lookup_session_out(ip->protocol, ip->saddr, 0);
                    if (session) {
                        csum_replace4(&ip->check, ip->saddr, session->in_addr);
                        ip->saddr = session->in_addr;
                    } else {
                        rcu_read_unlock_bh();
                        NAT_STAT_INC(dnat_dropped);
                        return NF_DROP;
                    }
                    ip = (struct iphdr *)skb_network_header(skb);
                    csum_replace4(&ip->check, ip->daddr, session->in_addr);
                    ip->daddr = session->in_addr;
                    rcu_read_unlock_bh();
                }

                /* The ICMP checksum covers the whole message, including the
                 * quoted header we just rewrote - addresses, ports and the
                 * quoted header's own checksum. Recompute it rather than try
                 * to fold in each of those edits separately; this is the
                 * error path, not the fast path.
                 */
                icmp_off = skb_network_offset(skb) + sizeof(struct iphdr);
                icmp = (struct icmphdr *)(skb_network_header(skb) + sizeof(struct iphdr));
                icmp->checksum = 0;
                icmp->checksum = csum_fold(skb_checksum(skb, icmp_off,
                                                        skb->len - icmp_off, 0));
                /* skb->csum described the packet as it arrived */
                if (skb->ip_summed == CHECKSUM_COMPLETE)
                    skb->ip_summed = CHECKSUM_NONE;
                return NF_ACCEPT;
            } else {
                NAT_STAT_INC(dnat_dropped);
                return NF_DROP;
            }
            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                ip->daddr = session->in_addr;
                inet_proto_csum_replace2(&icmp->checksum, skb, nat_port, session->in_port, false);
                icmp->un.echo.id = session->in_port;
                if (!session_touch(session, true, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
                return NF_DROP;
            }
        } else {
            if (unlikely(compat_skb_ensure_writable(skb, ip_hdrlen(skb)))) {
                atomic64_inc(&pkt_drop_unwritable);
                return NF_DROP;
            }
            ip = (struct iphdr *)skb_network_header(skb);

            nat_port = 0;
            rcu_read_lock_bh();
            session = lookup_session_out(ip->protocol, ip->daddr, nat_port);
            if (likely(session)) {
                csum_replace4(&ip->check, ip->daddr, session->in_addr);
                ip->daddr = session->in_addr;
                if (!session_touch(session, true, false)) {
                    rcu_read_unlock_bh();
                    return NF_DROP;
                }
                rcu_read_unlock_bh();
            } else {
                rcu_read_unlock_bh();
                NAT_STAT_INC(dnat_dropped);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static void users_cleanup_timer_callback( struct timer_list *timer )
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    struct hlist_node *next;
    unsigned int i;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&users_timer_lock);

    if (ht_users == NULL) {
        printk(KERN_WARNING "xt_CGNAT USERS CLEAN ERROR: Found null ptr for ht_users\n");
        spin_unlock_bh(&users_timer_lock);
        return;
    }

    vector_start = users_htable_vector * (users_hash_size/60);
    if (users_htable_vector == 60) {
        vector_end = users_hash_size;
        users_htable_vector = 0;
    } else {
        vector_end = vector_start + (users_hash_size/60);
        users_htable_vector++;
    }

    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_users[i].lock);
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_safe(user, next, head, list_node) {
                if (user->tcp_count == 0 && user->udp_count == 0 && user->other_count == 0) {
                    user->idle++;
                }
                if (user->idle >= 15) {
                    hlist_del_rcu(&user->list_node);
                    ht_users[i].use--;
                    kfree_rcu(user, rcu);
                    atomic64_dec(&users_active);
                }
            }
        }
        spin_unlock_bh(&ht_users[i].lock);
    }
    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&users_timer_lock);
}

static void sessions_cleanup_timer_callback( struct timer_list *timer )
{
    struct nat_session *sess;
    struct hlist_node *next;
    unsigned int i, ohash;
    int timeout;
    uint8_t proto;
    u_int32_t addr;
    u_int32_t vector_start, vector_end;

    spin_lock_bh(&sessions_timer_lock);

    if (ht_inner == NULL || ht_outer == NULL) {
        printk(KERN_WARNING "xt_CGNAT SESSIONS CLEAN ERROR: Found null ptr for ht_inner/ht_outer\n");
        spin_unlock_bh(&sessions_timer_lock);
        return;
    }

    vector_start = nat_htable_vector * (nat_hash_size/100);
    if (nat_htable_vector == 100) {
        vector_end = nat_hash_size;
        nat_htable_vector = 0;
    } else {
        vector_end = vector_start + (nat_hash_size/100);
        nat_htable_vector++;
    }

    /* One pass over ht_inner. The session is a single object in both chains,
     * so it is unlinked from both here and freed once. The outer table no
     * longer needs a sweep of its own - and the two unlinks can no longer be
     * separated by a sweep cycle, which is what used to let a session be freed
     * while it was still reachable through the other table.
     */
    for (i = vector_start; i < vector_end; i++) {
        spin_lock_bh(&ht_inner[i].lock);
        if (ht_inner[i].use > 0) {
            hlist_for_each_entry_safe(sess, next, &ht_inner[i].session, inner_node) {
                timeout = session_age(sess);
                /* One step wide, so exactly one sweep lands in it for any
                 * starting value. The old test was == 0, which only ever fired
                 * because every timeout assigned was a multiple of the step:
                 * anything else skipped straight past it to the unlink branch,
                 * leaking the port and losing the session-close record. Now
                 * that timeouts are configurable that is no longer a property
                 * of the code, so do not depend on it here either - parse time
                 * rounds to a step as well, and this survives if it ever
                 * stops.
                 */
                if (timeout <= 0 && timeout > -NAT_GC_STEP) {
                    /* last read of u.dst: the union becomes an rcu_head below */
                    netflow_export_flow_v9(session_proto(sess), sess->in_addr, sess->in_port,
                                           sess->u.dst.addr, sess->u.dst.port,
                                           sess->nat_addr, sess->out_port, 2);

                    /* Release the port at the same instant the session stops
                     * being visible to lookup_session_out(), which is what the
                     * old scan did. Moving this to the unlink branch below
                     * would hold the port for one more sweep (~10s) - a real
                     * quarantine, at the cost of that many ports per second of
                     * churn being unavailable.
                     */
                    if (!(session_flags(sess) & FLAG_QUARANTINE))
                        nat_release_port(sess);
                } else if (timeout <= -NAT_GC_STEP) {
                    if (session_flags(sess) & FLAG_QUARANTINE)
                        nat_release_port(sess);
                    proto = session_proto(sess);
                    addr  = sess->in_addr;

                    ohash = get_hash_nat_ent(proto, sess->nat_addr, sess->out_port);
                    spin_lock_bh(&ht_outer[ohash].lock);
                    hlist_del_rcu(&sess->outer_node);
                    ht_outer[ohash].use--;
                    spin_unlock_bh(&ht_outer[ohash].lock);

                    hlist_del_rcu(&sess->inner_node);
                    ht_inner[i].use--;

                    POOL_STAT_DEC(pool_of(sess), active);
                    update_user_limits(proto, addr, -1);
                    call_rcu(&sess->u.rcu, nat_session_free_rcu);
                }
            }
        }
        spin_unlock_bh(&ht_inner[i].lock);
    }

    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(100) );
    spin_unlock_bh(&sessions_timer_lock);
}

static void nf_send_timer_callback( struct timer_list *timer )
{
    spin_lock_bh(&nfsend_lock);
    netflow_export_pdu_v9();
    if (likely(atomic_read(&timers_state) == NAT_TIMERS_RUN))
        mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
    spin_unlock_bh(&nfsend_lock);
}

static void nat_timers_setup(void)
{
    timer_setup( &sessions_cleanup_timer, sessions_cleanup_timer_callback, 0 );
    timer_setup( &users_cleanup_timer, users_cleanup_timer_callback, 0 );
    timer_setup( &nf_send_timer, nf_send_timer_callback, 0 );

    /* has to be RUN before the first arm, otherwise the first callback to
     * run would take itself for a teardown and never re-arm */
    atomic_set(&timers_state, NAT_TIMERS_RUN);

    mod_timer( &sessions_cleanup_timer, jiffies + msecs_to_jiffies(10 * 1000) );
    mod_timer( &users_cleanup_timer, jiffies + msecs_to_jiffies(60 * 1000) );
    mod_timer( &nf_send_timer, jiffies + msecs_to_jiffies(1000) );
}

static void nat_timers_stop(void)
{
    /* Stop the callbacks re-arming before waiting for them. atomic_xchg() is
     * a full barrier, so the new state is visible to a callback that is about
     * to decide whether to re-arm. Must not be called with any lock a
     * callback takes held: compat_del_timer_sync() waits for a running
     * callback to finish, and it may sleep.
     */
    if (atomic_xchg(&timers_state, NAT_TIMERS_STOP) == NAT_TIMERS_NONE)
        return;

    compat_del_timer_sync( &sessions_cleanup_timer );
    compat_del_timer_sync( &users_cleanup_timer );
    compat_del_timer_sync( &nf_send_timer );
}

static int nat_seq_show(struct seq_file *m, void *v)
{
    struct nat_session *session;
    struct hlist_head *head;
    unsigned int i, count;

    count=0;

    seq_printf(m, "Proto SrcIP:SrcPort -> NatIP:NatPort\n");
    for (i = 0; i < nat_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_outer[i].use > 0) {
            head = &ht_outer[i].session;
            hlist_for_each_entry_rcu(session, head, outer_node) {
                if (session_timeout(session) > 0) {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- ttl: %d\n",
                               session_proto(session),
                               &session->in_addr, ntohs(session->in_port),
                               &session->nat_addr, ntohs(session->out_port),
                               session_timeout(session));
                } else {
                    seq_printf(m, "%d %pI4:%u -> %pI4:%u --- (will be removed due timeout)\n",
                               session_proto(session),
                               &session->in_addr, ntohs(session->in_port),
                               &session->nat_addr, ntohs(session->out_port));
                }
                count++;
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total translations: %d\n", count);

    return 0;
}
static int nat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, nat_seq_show, NULL);
}
static const struct proc_ops nat_seq_fops = {
    .proc_open		= nat_seq_open,
    .proc_read		= seq_read,
    .proc_lseek		= seq_lseek,
    .proc_release	= single_release,
};


static int users_seq_show(struct seq_file *m, void *v)
{
    struct user_htable_ent *user;
    struct hlist_head *head;
    unsigned int i, count;

    count=0;

    for (i = 0; i < users_hash_size; i++) {
        rcu_read_lock_bh();
        if (ht_users[i].use > 0) {
            head = &ht_users[i].user;
            hlist_for_each_entry_rcu(user, head, list_node) {
                if (user->idle < 15) {
                    /* No NAT address here any more: with several pools a
                     * subscriber's public address depends on which rule
                     * matched, and this table is keyed only on the private
                     * address. sessions has the real mapping per session. */
                    seq_printf(m, "%pI4 (tcp: %u, udp: %u, other: %u)\n",
                               &user->addr,
                               user->tcp_count,
                               user->udp_count,
                               user->other_count);
                    count++;
                }
            }
        }
        rcu_read_unlock_bh();
    }

    seq_printf(m, "Total users: %d\n", count);

    return 0;
}
static int users_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, users_seq_show, NULL);
}
static const struct proc_ops users_seq_fops = {
    .proc_open           = users_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

static int pools_seq_show(struct seq_file *m, void *v)
{
    struct nat_pool *p;
    int i;

    mutex_lock(&nat_pools_mutex);
    seq_printf(m, "# write \"add [<name>:]<start>-<end>[:<cidr>:<ports>][:<key>=<sec>...]\" or \"del <name>\"\n");
    for_each_pool(i, p) {
        seq_printf(m, "pool %s\n", p->name);
        seq_printf(m, "  range: %pI4-%pI4 (%u addresses, %u ports each)\n",
                   &p->start, &p->end, p->size,
                   NAT_PORT_BITS - NAT_PORT_LO);
        seq_printf(m, "  timeouts: tcp=%u tcp_est=%u tcp_fin=%u udp=%u udp_est=%u "
                      "udp_dns=%u icmp=%u other=%u other_est=%u\n",
                   p->tmt.tcp, p->tmt.tcp_est, p->tmt.tcp_fin,
                   p->tmt.udp, p->tmt.udp_est, p->tmt.udp_dns,
                   p->tmt.icmp, p->tmt.other, p->tmt.other_est);
        if (pool_det_enabled(p))
            seq_printf(m, "  deterministic: %llu subscribers, %u ports each, %u per address\n",
                       (unsigned long long)p->det_count, p->det_ports, p->det_per_addr);
        else
            seq_printf(m, "  deterministic: off (shared ports)\n");
        seq_printf(m, "  sessions active: %lld\n",  POOL_STAT_READ(p, active));
        seq_printf(m, "  sessions created: %lld\n", POOL_STAT_READ(p, created));
        seq_printf(m, "  sessions tried: %lld\n",   POOL_STAT_READ(p, tried));
        seq_printf(m, "  raced creates: %lld\n",    POOL_STAT_READ(p, dup));
        seq_printf(m, "  failed user limit: %lld\n",   POOL_STAT_READ(p, ulimit));
        seq_printf(m, "  failed no free port: %lld\n", POOL_STAT_READ(p, noport));
        seq_printf(m, "  failed unmapped subscriber: %lld\n", POOL_STAT_READ(p, nomap));
        seq_printf(m, "  rules referencing: %d\n", atomic_read(&p->refcnt));
    }
    mutex_unlock(&nat_pools_mutex);
    return 0;
}
static int pools_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, pools_seq_show, NULL);
}

/* defined below, next to the boot-time parser they share */
static int pool_add(char *spec);
static int pool_del(const char *name);

/* Reconfiguring the NAT is not a read-only operation and must not be available
 * to any local user: mode 0600 and CAP_NET_ADMIN, checked before anything is
 * allocated so an unprivileged writer cannot even make the module allocate.
 */
static ssize_t pools_proc_write(struct file *file, const char __user *ubuf,
                                size_t count, loff_t *ppos)
{
    char buf[512], *line, *verb, *rest;
    int ret;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (count == 0 || count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';

    line = strim(buf);
    verb = strsep(&line, " \t");
    rest = line ? strim(line) : NULL;
    if (!verb || !rest || !*rest)
        return -EINVAL;

    mutex_lock(&nat_pools_mutex);
    if (!strcmp(verb, "add"))
        ret = pool_add(rest);
    else if (!strcmp(verb, "del"))
        ret = pool_del(rest);
    else
        ret = -EINVAL;
    mutex_unlock(&nat_pools_mutex);

    return ret < 0 ? ret : count;
}

static const struct proc_ops pools_seq_fops = {
    .proc_open           = pools_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
    .proc_write          = pools_proc_write,
};

static int stat_seq_show(struct seq_file *m, void *v)
{
    mutex_lock(&nat_pools_mutex);
    seq_printf(m, "Active NAT sessions: %lld\n", ALL_STAT_READ(active));
    seq_printf(m, "Tried NAT sessions: %lld\n", ALL_STAT_READ(tried));
    seq_printf(m, "Created NAT sessions: %lld\n", ALL_STAT_READ(created));
    seq_printf(m, "Raced session creates: %lld\n", ALL_STAT_READ(dup));
    seq_printf(m, "DNAT dropped pkts: %lld\n", NAT_STAT_READ(dnat_dropped));
    seq_printf(m, "Fragmented pkts: %lld\n", NAT_STAT_READ(frags));
    seq_printf(m, "Related ICMP pkts: %lld\n", NAT_STAT_READ(related_icmp));
    seq_printf(m, "Active Users: %lld\n", atomic64_read(&users_active));
    seq_printf(m, "Max sessions per user: %d\n", READ_ONCE(user_max_sessions));
    seq_printf(m, "Port quarantine: %d\n", READ_ONCE(port_quarantine));
    seq_printf(m, "NetFlow dropped PDUs: %lld\n", atomic64_read(&nf_dropped));


    /* why session creation refused - the first two are the capacity limits */
    seq_printf(m, "Failed sessions user limit: %lld\n", ALL_STAT_READ(ulimit));
    seq_printf(m, "Failed sessions no free port: %lld\n", ALL_STAT_READ(noport));
    seq_printf(m, "Failed sessions no memory: %lld\n", atomic64_read(&ses_fail_nomem));
    seq_printf(m, "Failed sessions unmapped subscriber: %lld\n", ALL_STAT_READ(nomap));

    /* why packets were dropped */
    seq_printf(m, "Dropped no session: %lld\n", atomic64_read(&pkt_drop_nosession));
    seq_printf(m, "Dropped bad proto: %lld\n", atomic64_read(&pkt_drop_proto));
    seq_printf(m, "Dropped ip options: %lld\n", atomic64_read(&pkt_drop_hdrlen));
    seq_printf(m, "Dropped ip fragment: %lld\n", atomic64_read(&pkt_drop_frag));
    seq_printf(m, "Dropped truncated: %lld\n", atomic64_read(&pkt_drop_trunc));
    seq_printf(m, "Dropped unwritable: %lld\n", atomic64_read(&pkt_drop_unwritable));

    mutex_unlock(&nat_pools_mutex);
    return 0;
}
static int stat_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, stat_seq_show, NULL);
}
static const struct proc_ops stat_seq_fops = {
    .proc_open           = stat_seq_open,
    .proc_read           = seq_read,
    .proc_lseek          = seq_lseek,
    .proc_release        = single_release,
};

#define SEPARATORS " ,;\t\n"
static int add_nf_destinations(const char *ptr)
{
    int len;

    for (; ptr; ptr += len) {
        struct sockaddr_storage ss;
        struct netflow_sock *usock;
        struct sockaddr_in *sin;
        const char *end;
        int succ = 0;

        /* skip initial separators */
        ptr += strspn(ptr, SEPARATORS);

        len = strcspn(ptr, SEPARATORS);
        if (!len)
            break;
        memset(&ss, 0, sizeof(ss));

        sin = (struct sockaddr_in *)&ss;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(2055);
        succ = in4_pton(ptr, len, (u8 *)&sin->sin_addr, -1, &end);
        if (succ && *end == ':')
            sin->sin_port = htons(simple_strtoul(++end, NULL, 0));

        if (!succ) {
            printk(KERN_ERR "xt_CGNAT: can't parse netflow destination: %.*s\n",
                   len, ptr);
            continue;
        }

        if (!(usock = vmalloc(sizeof(*usock)))) {
            printk(KERN_ERR "xt_CGNAT: can't vmalloc socket\n");
            return -ENOMEM;
        }
        memset(usock, 0, sizeof(*usock));
        usock->addr = ss;
        list_add_tail(&usock->list, &usock_list);
        printk(KERN_INFO "xt_CGNAT NEL: add destination %s\n", print_sockaddr(&usock->addr));
    }
    return 0;
}

static void nf_destinations_remove(void)
{
    while (!list_empty(&usock_list)) {
        struct netflow_sock *usock;

        usock = list_entry(usock_list.next, struct netflow_sock, list);
        list_del(&usock->list);
        if (usock->sock)
            sock_release(usock->sock);
        usock->sock = NULL;
        vfree(usock);
    }
}

static void nat_proc_remove(void)
{
    if (!proc_net_nat)
        return;

    remove_proc_entry( "sessions", proc_net_nat );
    remove_proc_entry( "users", proc_net_nat );
    remove_proc_entry( "statistics", proc_net_nat );
    remove_proc_entry( "pools", proc_net_nat );
    proc_remove(proc_net_nat);
    proc_net_nat = NULL;
}

static int nat_tg_check(const struct xt_tgchk_param *par)
{
    struct xt_cgnat_tginfo *info = par->targinfo;
    struct nat_pool *pool;

    if (!net_eq(par->net, &init_net))
        return -EOPNOTSUPP;

    if (info->variant != XT_CGNAT_SNAT && info->variant != XT_CGNAT_DNAT) {
        printk(KERN_INFO "xt_CGNAT: rejecting rule with unknown variant %u\n", info->variant);
        return -EINVAL;
    }

    info->pool[XT_CGNAT_POOL_NAMELEN - 1] = '\0';
    mutex_lock(&nat_pools_mutex);
    pool = pool_by_name(info->pool);
    if (pool == NULL) {
        printk(KERN_INFO "xt_CGNAT: no pool named '%s'\n", info->pool);
        mutex_unlock(&nat_pools_mutex);
        return -ENOENT;
    }
    /* resolved once here so the packet path never looks a name up */
    info->priv = pool;
    atomic_inc(&pool->refcnt);
    mutex_unlock(&nat_pools_mutex);
    return 0;
}

static void nat_tg_destroy(const struct xt_tgdtor_param *par)
{
    const struct xt_cgnat_tginfo *info = par->targinfo;
    struct nat_pool *pool = info->priv;

    if (pool)
        atomic_dec(&pool->refcnt);
}

static struct xt_target nat_tg_reg __read_mostly = {
    .name     = "CGNAT",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = nat_tg,
    .checkentry = nat_tg_check,
    .destroy    = nat_tg_destroy,
    .targetsize = sizeof(struct xt_cgnat_tginfo),
    .usersize   = offsetof(struct xt_cgnat_tginfo, priv),
    .me       = THIS_MODULE,
};

/* One "<key>=<value>" timeout field, shared by the `timeouts` module parameter
 * and by the per-pool overrides so the two can never drift.
 *
 * Returns 0 if the token was consumed, -ENOENT if it is not a key=value at all
 * (the caller decides what a bare token means in its context), or -EINVAL if
 * the key is unknown or the value unusable.
 */
static int nat_tmt_parse_kv(char *tok, struct nat_timeouts *t, const char *who)
{
    static const struct { const char *key; unsigned short off; } map[] = {
        { "tcp",       offsetof(struct nat_timeouts, tcp)       },
        { "tcp_est",   offsetof(struct nat_timeouts, tcp_est)   },
        { "tcp_fin",   offsetof(struct nat_timeouts, tcp_fin)   },
        { "udp",       offsetof(struct nat_timeouts, udp)       },
        { "udp_est",   offsetof(struct nat_timeouts, udp_est)   },
        { "udp_dns",   offsetof(struct nat_timeouts, udp_dns)   },
        { "icmp",      offsetof(struct nat_timeouts, icmp)      },
        { "other",     offsetof(struct nat_timeouts, other)     },
        { "other_est", offsetof(struct nat_timeouts, other_est) },
    };
    unsigned int v;
    char *val;
    int i;

    val = strchr(tok, '=');
    if (!val)
        return -ENOENT;
    *val++ = '\0';

    for (i = 0; i < ARRAY_SIZE(map); i++) {
        if (strcmp(tok, map[i].key))
            continue;
        if (kstrtouint(val, 10, &v) || v < NAT_GC_STEP || v > NAT_TMT_MAX) {
            printk(KERN_ERR "xt_CGNAT: %s: %s must be %u..%u seconds\n",
                   who, map[i].key, NAT_GC_STEP, NAT_TMT_MAX);
            return -EINVAL;
        }
        /* Rounded up rather than rejected: the GC only ever sees a session on a
         * step boundary, so a value between two steps behaves as the lower one
         * and the configuration would quietly not mean what it says.
         */
        v = roundup(v, NAT_GC_STEP);
        *(uint16_t *)((char *)t + map[i].off) = v;
        return 0;
    }

    printk(KERN_ERR "xt_CGNAT: %s: unknown timeout '%s'\n", who, tok);
    return -EINVAL;
}

/* The `timeouts` parameter: the same colon separated key=value fields a pool
 * takes, setting what every pool starts from. */
static int __init nat_tmt_parse_defaults(void)
{
    char *buf, *p, *tok;
    int ret = 0;

    nat_tmt_default = nat_tmt_builtin;
    if (!timeouts || !*timeouts)
        return 0;

    buf = kstrdup(timeouts, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    p = buf;
    while ((tok = strsep(&p, ":")) != NULL) {
        if (!*tok)
            continue;
        ret = nat_tmt_parse_kv(tok, &nat_tmt_default, "timeouts");
        if (ret == -ENOENT) {
            printk(KERN_ERR "xt_CGNAT: timeouts: '%s' is not <key>=<value>\n", tok);
            ret = -EINVAL;
        }
        if (ret < 0)
            break;
    }

    kfree(buf);
    return ret;
}

/* nat_pool defines one or more pools, separated by commas:
 *
 *   <start>-<end>[:<sub_cidr>:<ports>]                    the single unnamed pool
 *   <name>:<start>-<end>[:<sub_cidr>:<ports>][,<name>:..] named pools
 *
 * A rule selects one with -j CGNAT --pool <name>; without --pool it gets the
 * first. The old single-pool syntax still means exactly what it did - it is
 * recognised by its first field containing '-', which a name cannot.
 */
static int nat_pool_parse_one(char *spec, struct nat_pool *pool)
{
    char *p = spec, *first, *range, *sub = NULL, *portstr = NULL, *tok, *sep;
    unsigned int ports, per_addr, prefix;
    u64 need;
    u_int32_t subnet;
    int ret;

    first = strsep(&p, ":");
    if (first && strchr(first, '-')) {           /* unnamed: <start>-<end>... */
        strscpy(pool->name, "default", sizeof(pool->name));
        range = first;
    } else {
        if (!first || !first[0] || !p) {
            printk(KERN_ERR "xt_CGNAT: pool needs <name>:<start>-<end>\n");
            return -EINVAL;
        }
        if (strlen(first) >= sizeof(pool->name) ||
            strspn(first, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") != strlen(first))
            return -EINVAL;
        strscpy(pool->name, first, sizeof(pool->name));
        range = strsep(&p, ":");
    }
    sep = range ? strchr(range, '-') : NULL;
    if (!sep) {
        printk(KERN_ERR "xt_CGNAT: pool '%s' needs <start>-<end>\n", pool->name);
        return -EINVAL;
    }
    *sep = '\0';
    if (!in4_pton(range, -1, (u8 *)&pool->start, '\0', NULL) ||
        !in4_pton(sep + 1, -1, (u8 *)&pool->end, '\0', NULL))
        return -EINVAL;
    if (!pool->start || !pool->end || ntohl(pool->start) > ntohl(pool->end)) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': bad range %pI4 to %pI4\n",
               pool->name, &pool->start, &pool->end);
        return -EINVAL;
    }
    pool->size = get_pool_size(pool);

    /* What is left is the two optional deterministic fields, which are
     * positional and must stay that way for the old syntax to keep working,
     * plus any number of <key>=<value> timeout overrides, which are not.
     * Telling them apart on the '=' is what lets the two mix in either order:
     * without it "acme:1.1.1.1-1.1.1.8:udp=30" would take the timeout for the
     * subscriber CIDR and fail asking for a ports-per-subscriber count.
     */
    while ((tok = strsep(&p, ":")) != NULL) {
        if (!*tok)
            continue;
        ret = nat_tmt_parse_kv(tok, &pool->tmt, pool->name);
        if (ret == 0)
            continue;
        if (ret != -ENOENT)
            return ret;
        if (!sub)
            sub = tok;
        else if (!portstr)
            portstr = tok;
        else {
            printk(KERN_ERR "xt_CGNAT: pool '%s': unexpected field '%s'\n",
                   pool->name, tok);
            return -EINVAL;
        }
    }

    if (!sub && !portstr)                        /* shared ports, as before */
        return 0;
    if (!sub || !portstr) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': deterministic mode needs both "
                        "<subscriber_cidr> and <ports_per_subscriber>\n", pool->name);
        return -EINVAL;
    }

    sep = strchr(sub, '/');
    if (!sep) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': subscriber range must be a CIDR\n", pool->name);
        return -EINVAL;
    }
    *sep = '\0';
    if (!in4_pton(sub, -1, (u8 *)&subnet, '\0', NULL))
        return -EINVAL;
    if (kstrtouint(sep + 1, 10, &prefix) || prefix > 32) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': bad subscriber prefix\n", pool->name);
        return -EINVAL;
    }
    if (kstrtouint(portstr, 10, &ports) || ports < 1 || ports > (NAT_PORT_BITS - NAT_PORT_LO)) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': ports_per_subscriber must be 1..%u\n",
               pool->name, NAT_PORT_BITS - NAT_PORT_LO);
        return -EINVAL;
    }

    pool->det_count = 1ULL << (32 - prefix);
    pool->det_base = prefix ? ntohl(subnet) & (0xffffffffU << (32 - prefix)) : 0;
    pool->det_ports = ports;
    per_addr = (NAT_PORT_BITS - NAT_PORT_LO) / ports;
    if (per_addr == 0) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': ports_per_subscriber larger than the port space\n",
               pool->name);
        return -EINVAL;
    }
    pool->det_per_addr = per_addr;

    need = DIV_ROUND_UP_ULL(pool->det_count, per_addr);
    if (need > pool->size) {
        printk(KERN_ERR "xt_CGNAT: pool '%s': deterministic mapping needs %llu NAT addresses "
                        "for %llu subscribers at %u ports each (%u per address); it has %u\n",
               pool->name, (unsigned long long)need, (unsigned long long)pool->det_count, ports, per_addr, pool->size);
        pool->det_ports = 0;
        return -EINVAL;
    }

    printk(KERN_INFO "xt_CGNAT: pool '%s': deterministic, %llu subscribers from %pI4/%u, "
                     "%u ports each, %u per address, %llu of %u addresses used\n",
           pool->name, (unsigned long long)pool->det_count, &subnet, prefix, ports, per_addr, (unsigned long long)need, pool->size);
    return 0;
}

/* name unique and range disjoint from every other live pool. Overlap matters:
 * an address in two pools would have two independent port bitmaps, so the
 * second allocation would not see the first and would hand out a port already
 * in use. */
static int pool_conflicts(const struct nat_pool *cand)
{
    const struct nat_pool *p;
    int i;

    for_each_pool(i, p) {
        if (p == cand)
            continue;
        if (!strncmp(p->name, cand->name, XT_CGNAT_POOL_NAMELEN)) {
            printk(KERN_ERR "xt_CGNAT: pool '%s' already exists\n", cand->name);
            return -EEXIST;
        }
        if (ntohl(cand->start) <= ntohl(p->end) && ntohl(p->start) <= ntohl(cand->end)) {
            printk(KERN_ERR "xt_CGNAT: pool '%s' overlaps '%s'\n", cand->name, p->name);
            return -EINVAL;
        }
    }
    return 0;
}

/* Runtime add. Caller holds nat_pools_mutex. The slot is only marked used once
 * it is fully built, and nothing can reach it before that: the packet path
 * needs a rule, and a rule needs checkentry to find it by name. */
/* Arm the packet path's pool lookup the first time a pool wants something other
 * than the built-in schedule. Process context under nat_pools_mutex, which is
 * where static_branch_enable() has to be called from - it patches text and
 * takes cpus_read_lock().
 */
static void nat_tmt_arm(const struct nat_pool *pool)
{
    if (memcmp(&pool->tmt, &nat_tmt_builtin, sizeof(pool->tmt)) &&
        !static_key_enabled(&nat_custom_tmt.key)) {
        static_branch_enable(&nat_custom_tmt);
        printk(KERN_INFO "xt_CGNAT: pool '%s' overrides the default timeouts; "
                         "the packet path now reads them per session\n", pool->name);
    }
}

static int pool_add(char *spec)
{
    struct nat_pool tmp = {}, *slot = NULL;
    int i, ret;

    tmp.tmt = nat_tmt_default;
    ret = nat_pool_parse_one(spec, &tmp);
    if (ret < 0)
        return ret;
    ret = pool_conflicts(&tmp);
    if (ret < 0)
        return ret;

    for (i = 0; i < CGNAT_MAX_POOLS; i++)
        if (!nat_pools[i].used) { slot = &nat_pools[i]; break; }
    if (!slot) {
        printk(KERN_ERR "xt_CGNAT: no free pool slot (max %d)\n", CGNAT_MAX_POOLS);
        return -ENOSPC;
    }

    *slot = tmp;
    atomic_set(&slot->refcnt, 0);
    atomic64_set(&slot->sessions, 0);
    ret = pool_table_create(slot);
    if (ret < 0) {
        memset(slot, 0, sizeof(*slot));
        return ret;
    }
    slot->used = true;
    nat_tmt_arm(slot);
    return 0;
}

/* Runtime delete. Refused while anything still points at the pool: a rule
 * holds a resolved pointer to the slot, and every live session holds its index
 * and dereferences it to release its port. Reusing the slot under either would
 * be a use-after-free with extra steps. */
static int pool_del(const char *name)
{
    struct nat_pool *p;
    int i, refs;
    s64 active;

    for_each_pool(i, p) {
        if (strncmp(p->name, name, XT_CGNAT_POOL_NAMELEN))
            continue;

        refs   = atomic_read(&p->refcnt);
        active = atomic64_read(&p->sessions);
        if (refs > 0 || active > 0) {
            printk(KERN_ERR "xt_CGNAT: pool '%s' still in use: %d rule(s), %lld session(s)\n",
                   p->name, refs, active);
            return -EBUSY;
        }

        pool_table_remove(p);
        memset(p, 0, sizeof(*p));       /* clears used */
        printk(KERN_INFO "xt_CGNAT: pool '%s' removed\n", name);
        return 0;
    }
    printk(KERN_ERR "xt_CGNAT: no pool named '%s'\n", name);
    return -ENOENT;
}

static int __init nat_pool_parse(void)
{
    char *buf, *p, *spec;
    struct nat_pool *slot;
    int n = 0, ret = 0;

    /* Copied rather than parsed in place because strsep() writes to it, and
     * kstrdup'd rather than into a fixed buffer because eight pools each
     * carrying timeout overrides runs well past any reasonable stack array.
     */
    buf = kstrdup(nat_pool, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    p = buf;
    while ((spec = strsep(&p, ",")) != NULL) {
        if (!*spec)
            continue;
        if (n >= CGNAT_MAX_POOLS) {
            printk(KERN_ERR "xt_CGNAT: at most %d pools\n", CGNAT_MAX_POOLS);
            ret = -EINVAL;
            goto out;
        }
        slot = &nat_pools[n];
        slot->tmt = nat_tmt_default;
        ret = nat_pool_parse_one(spec, slot);
        if (ret < 0)
            goto out;
        slot->used = true;              /* tables are built later by pools_create() */
        atomic_set(&slot->refcnt, 0);
        atomic64_set(&slot->sessions, 0);
        if (pool_conflicts(slot) < 0) {
            ret = -EINVAL;
            goto out;
        }
        nat_tmt_arm(slot);
        n++;
    }
    if (n == 0) {
        printk(KERN_ERR "xt_CGNAT: nat_pool defines no pools\n");
        ret = -EINVAL;
    }
out:
    kfree(buf);
    return ret;
}

static int __init nat_tg_init(void)
{
    int ret;

    printk(KERN_INFO "Module xt_CGNAT loaded\n");

    templateV9.FlowSetId	= 0;
    templateV9.Length		= htons(40);
    templateV9.TemplateId	= htons(flowsetID);
    templateV9.FieldsCount	= htons(8);
    templateV9.proto_id		= htons(4);
    templateV9.proto_len	= htons(1);
    templateV9.s_port_id	= htons(7);
    templateV9.s_port_len	= htons(2);
    templateV9.s_addr_id	= htons(8);
    templateV9.s_addr_len	= htons(4);
    templateV9.d_port_id	= htons(11);
    templateV9.d_port_len	= htons(2);
    templateV9.d_addr_id	= htons(12);
    templateV9.d_addr_len	= htons(4);
    templateV9.n_addr_id	= htons(225);
    templateV9.n_addr_len	= htons(4);
    templateV9.n_port_id	= htons(227);
    templateV9.n_port_len	= htons(2);
    templateV9.s_type_id	= htons(230);
    templateV9.s_type_len	= htons(1);

    /* before nat_pool_parse(): every pool starts from these */
    if (nat_tmt_parse_defaults() < 0)
        return -EINVAL;

    if (nat_pool_parse() < 0)
        return -EINVAL;

    /* Both are used as the divisor in reciprocal_scale() and are sliced by
     * the GC timers (/100 and /60), so zero or negative is not merely odd -
     * kzalloc(0) hands back ZERO_SIZE_PTR, which is not NULL, so the
     * allocation check passes and the first packet dereferences it.
     */
    if (nat_hash_size < NAT_HASH_MIN || nat_hash_size > NAT_HASH_MAX) {
        printk(KERN_ERR "xt_CGNAT: nat_hash_size must be between %d and %d\n",
               NAT_HASH_MIN, NAT_HASH_MAX);
        return -EINVAL;
    }
    if (users_hash_size < NAT_HASH_MIN || users_hash_size > NAT_HASH_MAX) {
        printk(KERN_ERR "xt_CGNAT: users_hash_size must be between %d and %d\n",
               NAT_HASH_MIN, NAT_HASH_MAX);
        return -EINVAL;
    }
    if (user_max_sessions < 1 || user_max_sessions > USHRT_MAX) {
        printk(KERN_ERR "xt_CGNAT: user_max_sessions must be between 1 and %d\n", USHRT_MAX);
        return -EINVAL;
    }

    printk(KERN_INFO "xt_CGNAT DEBUG: NAT hash size: %d\n", nat_hash_size);
    printk(KERN_INFO "xt_CGNAT DEBUG: Users hash size: %d\n", users_hash_size);

    /* The layout is load bearing: at exactly 64 bytes the object is one
     * cacheline and SLAB_HWCACHE_ALIGN adds no padding. Adding a field would
     * silently double the cost of every lookup, so say so at build time.
     */
    /* 64 bytes is a 64-bit property: rcu_head and hlist_node halve on 32-bit,
     * where the struct is 40 and the cacheline argument does not apply. Assert
     * where it means something rather than refusing to build elsewhere. */
    BUILD_BUG_ON(sizeof(void *) == 8 && sizeof(struct nat_session) != 64);

    nat_session_cache = kmem_cache_create("xt_CGNAT_session",
                                          sizeof(struct nat_session), 0,
                                          SLAB_HWCACHE_ALIGN, NULL);
    if (!nat_session_cache) {
        ret = -ENOMEM;
        goto err_caches;
    }

    ret = nat_htable_create();
    if (ret < 0)
        goto err_tables;

    ret = users_htable_create();
    if (ret < 0)
        goto err_tables;

    ret = pools_create();
    if (ret < 0)
        goto err_tables;

    ret = add_nf_destinations(nf_dest);
    if (ret < 0)
        goto err_nf_dest;

    proc_net_nat = proc_mkdir("CGNAT",init_net.proc_net);
    if (!proc_net_nat) {
        printk(KERN_ERR "xt_CGNAT ERROR: cannot create /proc/net/CGNAT\n");
        ret = -ENOMEM;
        goto err_nf_dest;
    }
    proc_create("sessions", 0644, proc_net_nat, &nat_seq_fops);
    proc_create("users", 0644, proc_net_nat, &users_seq_fops);
    proc_create("statistics", 0644, proc_net_nat, &stat_seq_fops);
    proc_create("pools", 0600, proc_net_nat, &pools_seq_fops);

    nat_timers_setup();

    ret = xt_register_target(&nat_tg_reg);
    if (ret < 0)
        goto err_register;

    return 0;

err_register:
    nat_timers_stop();
    nat_proc_remove();
err_nf_dest:
    flush_work(&nf_send_work);
    nf_destinations_remove();
err_tables:
    pools_remove();
    users_htable_remove();
    nat_htable_remove();
err_caches:
    /* nothing has been published yet, so no RCU callbacks can be outstanding */
    kmem_cache_destroy(nat_session_cache);
    nat_session_cache = NULL;
    printk(KERN_ERR "xt_CGNAT ERROR: module load failed, error %d\n", ret);
    return ret;
}

static void __exit nat_tg_exit(void)
{
    xt_unregister_target(&nat_tg_reg);

    nat_timers_stop();
    spin_lock_bh(&nfsend_lock);
    netflow_export_pdu_v9();
    spin_unlock_bh(&nfsend_lock);
    flush_work(&nf_send_work);

    nat_proc_remove();

    pools_remove();
    users_htable_remove();
    nat_htable_remove();

    nf_destinations_remove();

    /* the tables were torn down with call_rcu(); those callbacks must have run
     * before the caches they free into can be destroyed */
    rcu_barrier();
    kmem_cache_destroy(nat_session_cache);
    nat_session_cache = NULL;

    printk(KERN_INFO "Module xt_CGNAT unloaded\n");
}

module_init(nat_tg_init);
module_exit(nat_tg_exit);

MODULE_DESCRIPTION("Xtables: Carrier-Grade NAT (full cone), derived from xt_NAT");
MODULE_AUTHOR("Andrei Sharaev <andr.sharaev@gmail.com>");        /* original xt_NAT */
MODULE_AUTHOR("Denys Fedoryshchenko <denys.f@collabora.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_CGNAT");
