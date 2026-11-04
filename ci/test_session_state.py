"""Exercise the actual packed state helpers with C11 atomics, including races."""
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SessionStateTests(unittest.TestCase):
    def test_expiry_and_protocol_transitions(self):
        source = (ROOT / 'xt_CGNAT.c').read_text()
        helpers = source[source.index('static bool session_touch('):source.index('static void nat_session_free_rcu')]
        defines = '\n'.join(line for line in source.splitlines()
                            if re.match(r'#define (FLAG_|NAT_GC_STEP|TMT_)', line))
        code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <assert.h>
#include <netinet/in.h>
typedef uint32_t u32;
typedef uint16_t u16;
typedef int16_t s16;
typedef _Atomic int atomic_t;
struct nat_session { atomic_t state; };
#define atomic_read(p) atomic_load(p)
static int atomic_cmpxchg(atomic_t *p, int old, int next) {
    atomic_compare_exchange_strong(p, &old, next); return old;
}
#define NAT_TMT(s, field, fallback) (fallback)
''' + defines + '\n' + helpers + r'''
static struct nat_session s;
static void init(unsigned proto, unsigned flags, unsigned timeout) {
    atomic_store(&s.state, (flags << 24) | (proto << 16) | timeout);
}
static int timeout(void) { return (s16)atomic_load(&s.state); }
static void *refresh(void *unused) {
    for (int i=0; i<100000; i++) session_touch(&s, false, false);
    return NULL;
}
int main(void) {
    unsigned immutable = FLAG_QUARANTINE | FLAG_SHORTLIVED | (7 << FLAG_POOL_SHIFT);
    for (unsigned proto=0; proto<256; proto++) {
        init(proto, immutable, 10);
        assert(session_age(&s) == 0);
        assert(!session_touch(&s, false, false));
        assert(!session_touch(&s, true, true));
        assert(session_age(&s) == -10);
        assert(((unsigned)atomic_load(&s.state) >> 16) == ((immutable << 8) | proto));
    }
    init(IPPROTO_TCP, FLAG_REPLIED, 600);
    assert(session_touch(&s, true, true));
    assert(timeout() == 600); /* unauthenticated inbound RST does not close */
    assert(session_touch(&s, false, true));
    assert(timeout() == TMT_TCP_FIN);
    init(IPPROTO_UDP, FLAG_SHORTLIVED, 30);
    assert(session_touch(&s, true, false));
    assert(timeout() == TMT_UDP_DNS);
    init(IPPROTO_TCP, 0, 30);
    assert(session_touch(&s, true, false));
    assert(timeout() == TMT_TCP_EST);
    for (int round=0; round<20; round++) {
        pthread_t thread;
        init(IPPROTO_UDP, immutable, 10);
        assert(!pthread_create(&thread, NULL, refresh, NULL));
        while (session_age(&s) > 0) {}
        assert(!pthread_join(thread, NULL));
        assert(timeout() <= 0); /* a stale/retrying packet cannot revive it */
        assert(!session_touch(&s, true, false));
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            (path / 'state.c').write_text(code)
            subprocess.run(['gcc', '-std=c11', '-O2', '-pthread', '-o', str(path / 'state'), str(path / 'state.c')], check=True)
            subprocess.run([str(path / 'state')], check=True, timeout=30)

    def test_allocation_boundary(self):
        # The actual allocation guard, evaluated with a 32-bit destination type.
        source = (ROOT / 'xt_CGNAT.c').read_text()
        guard = re.search(r'    if \(check_mul_overflow\(\(size_t\)pool->size,.*?return -EOVERFLOW;', source, re.S).group(0)
        guard = guard.replace('(size_t)', '(uint32_t)')
        code = '''#include <stdint.h>\n#include <errno.h>\n#include <assert.h>\n#define check_mul_overflow __builtin_mul_overflow\n#define NAT_PROTO_SLOTS 3\n#define NAT_PORT_LONGS 2048\n#define spinlock_t uint32_t\n#define size_t uint32_t\nstruct pool { uint32_t size; };\nstatic int check(struct pool *pool) { uint32_t sz, bsz;\n''' + guard.replace('sizeof(unsigned long)', '4').replace('sizeof(spinlock_t)', '4') + '''\nreturn 0; }\nint main(void) { struct pool p={174762}; assert(check(&p)==0); p.size++; assert(check(&p)==-EOVERFLOW); p.size=0xffffffffU; assert(check(&p)==-EOVERFLOW); p.size=4; assert(check(&p)==0); }\n'''
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp)
            (path / 'size.c').write_text(code)
            subprocess.run(['gcc', '-o', str(path / 'size'), str(path / 'size.c')], check=True)
            subprocess.run([str(path / 'size')], check=True)
