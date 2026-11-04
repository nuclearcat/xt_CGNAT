#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_CGNAT.h"

enum {
    F_SNAT  = 1 << 0,
    F_DNAT  = 1 << 1,
    F_POOL  = 1 << 2,
};

static const struct option nat_tg_opts[] = {
    {.name = "snat", .has_arg = false, .val = 's'},
    {.name = "dnat", .has_arg = false, .val = 'd'},
    {.name = "pool", .has_arg = true,  .val = 'p'},
    {NULL},
};

static void nat_tg_help(void)
{
    printf(
        "CGNAT target options:\n"
        "  --snat    Create CGNAT translation from Inside to Outside\n"
        "  --dnat    Translate inbound traffic from Outside to Inside\n"
        "  --pool <name>\n"
        "            Select an existing pool; omit for the first pool.\n"
        "\n"
        "Define pools when loading the module (as root):\n"
        "  modprobe xt_CGNAT nat_pool=\"home:203.0.113.1-203.0.113.4\"\n"
        "  Pool spec: [name:]start-end[:subscriber_cidr:ports_per_subscriber]\n"
        "             [:key=seconds...]\n"
        "  Separate specs with commas; an unnamed pool is called 'default'.\n"
        "  Up to 8 pools with unique names (max 15 characters; letters, digits, underscore, dot only)\n"
        "  and non-overlapping IPv4 ranges. Replace example IPs with your own.\n"
        "  CIDR + ports: optional pair for deterministic port blocks.\n"
        "  key=seconds: optional per-pool timeouts, e.g. udp_dns=20.\n"
        "  Use the same --pool name on the --snat and --dnat rules.\n"
        "  For an already loaded module, add/del pools via /proc/net/CGNAT/pools.\n"
        "\n"
        "Pool guide (live updates, timeouts, sizing and complete firewall rules):\n"
        "  https://github.com/nuclearcat/xt_CGNAT#pools\n");
}

static int nat_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    struct xt_cgnat_tginfo *info = (void *)(*target)->data;

    if (invert)
        xtables_error(PARAMETER_PROBLEM, "CGNAT: inversion is not supported");
    if ((c == 's' && (*flags & F_SNAT)) ||
        (c == 'd' && (*flags & F_DNAT)) ||
        (c == 'p' && (*flags & F_POOL)))
        xtables_error(PARAMETER_PROBLEM, "CGNAT: duplicate option");

    switch (c) {
    case 's':
        info->variant = XT_CGNAT_SNAT;
        *flags |= F_SNAT;
        return true;
    case 'd':
        info->variant = XT_CGNAT_DNAT;
        *flags |= F_DNAT;
        return true;
    case 'p':
        if (!optarg[0] || strspn(optarg, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") != strlen(optarg) ||
            strlen(optarg) >= XT_CGNAT_POOL_NAMELEN)
            xtables_error(PARAMETER_PROBLEM,
                          "CGNAT: invalid pool name (maximum %d characters; no separators/whitespace)",
                          XT_CGNAT_POOL_NAMELEN - 1);
        strncpy(info->pool, optarg, XT_CGNAT_POOL_NAMELEN - 1);
        info->pool[XT_CGNAT_POOL_NAMELEN - 1] = '\0';
        *flags |= F_POOL;
        return true;
    }
    return false;
}

static void nat_tg_check(unsigned int flags)
{
    unsigned int action = flags & (F_SNAT | F_DNAT);

    if (action == (F_SNAT | F_DNAT))
        xtables_error(PARAMETER_PROBLEM,
                      "CGNAT: only one action can be used at a time");
    if (action == 0)
        xtables_error(PARAMETER_PROBLEM,
                      "CGNAT: --snat or --dnat is required");
}

static void nat_tg_save(const void *ip,
                        const struct xt_entry_target *target)
{
    const struct xt_cgnat_tginfo *info = (const void *)target->data;

    switch (info->variant) {
    case XT_CGNAT_SNAT:
        printf(" --snat ");
        break;
    case XT_CGNAT_DNAT:
        printf(" --dnat ");
        break;
    }
    /* must be emitted, or iptables-save loses which pool the rule used */
    if (info->pool[0])
        printf(" --pool %s ", info->pool);
}

static void nat_tg_print(const void *ip,
                         const struct xt_entry_target *target, int numeric)
{
    printf(" -j CGNAT");
    nat_tg_save(ip, target);
}

static struct xtables_target nat_tg_reg = {
    .version       = XTABLES_VERSION,
    .name          = "CGNAT",
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_cgnat_tginfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_cgnat_tginfo)),
    .help          = nat_tg_help,
    .parse         = nat_tg_parse,
    .final_check   = nat_tg_check,
    .print         = nat_tg_print,
    .save          = nat_tg_save,
    .extra_opts    = nat_tg_opts,
};

static __attribute__((constructor)) void nat_tg_ldr(void)
{
    xtables_register_target(&nat_tg_reg);
}

