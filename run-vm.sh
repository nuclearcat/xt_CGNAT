#!/bin/bash
#
# run-vm.sh - build, boot, test and collect, unattended.
#
# Downloads a cloud image, overlays it, drops this source tree in over 9p,
# boots QEMU, builds the module inside the guest, runs qemu-tests.sh, copies
# the results back out and shuts down. Nothing touches the host kernel.
#
#   ./run-vm.sh                          smoke test on the cloud image's kernel
#   ./run-vm.sh --kdir ~/linux           boot your own kernel - use this one
#   ./run-vm.sh --soak --keep
#   ./run-vm.sh --shell                  drop to a guest shell instead
#   ./run-vm.sh --image URL --kernel-packages "linux-generic" --transport disk
#                                       update distro kernel, reboot, then test
#   --transport disk                    use an ext4 payload disk instead of 9p
#   --strict                            fail if any functional test is skipped
#
# What runs in the guest - the two stages are independent toggles:
#
#   --tests / --no-tests    qemu-tests.sh          (default: on)
#   --bench / --no-bench    bench-cps.sh           (default: off)
#   --soak                  adds the slow aging test to the suite
#   --bench-args "..."      passed through to bench-cps.sh
#   --bench-only            shorthand for --bench --no-tests
#
# Both stages run in one boot when both are on, and report.md covers whichever
# ran. Turning both off is an error rather than a silent no-op boot.
#
# Two modes, and the difference matters:
#
#   default    Boots the image's own distro kernel. No KASAN, no lockdep -
#              distro kernels do not ship them. You get functional coverage
#              and nothing more. Fine as a smoke test.
#
#   --kdir     Direct-boots a kernel you built, so you can turn on KASAN,
#              PROVE_LOCKING, PROVE_RCU, DEBUG_OBJECTS and kmemleak. This is
#              the configuration the tests were written for; everything else
#              is a weaker version of it.
#
#              ./run-vm.sh --print-kconfig > /tmp/frag
#              cd ~/linux && ./scripts/kconfig/merge_config.sh .config /tmp/frag
#              make -j$(nproc)
#              ./run-vm.sh --kdir ~/linux
#
# Results land in ./vm-results/ : the full console, the guest's own log, the
# test output and the guest dmesg. Exit status is the test suite's.
#
# Requires: qemu-system-x86_64, qemu-img, curl or wget, and one of
# cloud-localds / genisoimage / xorriso. KVM is used when available.
#

set -u

SRCDIR=$(cd "$(dirname "$0")" && pwd)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/xt_CGNAT-vm
RESULTS=${RESULTS_DIR:-$SRCDIR/vm-results}
RUNDIR=""

# Current LTS. cloud-images.ubuntu.com serves releases under the version number
# as well as the codename, so there is no codename to keep up to date here.
# Override with UBUNTU_RELEASE=24.04, or --image for something else entirely.
UBUNTU_RELEASE=${UBUNTU_RELEASE:-26.04}
IMAGE_URL=${IMAGE_URL:-https://cloud-images.ubuntu.com/releases/$UBUNTU_RELEASE/release/ubuntu-$UBUNTU_RELEASE-server-cloudimg-amd64.img}
CPUS=4
MEMORY=4096
TIMEOUT=1800
KDIR=""
KERNEL=""
ROOTDEV=${ROOTDEV:-/dev/vda1}
SOAK=0
KEEP=0
SHELL_MODE=0
REFRESH=0
ACCEL="unknown"
BENCH=0
BENCH_ARGS=
RUN_TESTS=1
TRANSPORT=9p
KERNEL_PACKAGES=""
STRICT=0
BOOT=1
IMAGE_SHA256=${IMAGE_SHA256:-}

if [ -t 1 ]; then
    C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
    C_G=""; C_R=""; C_Y=""; C_B=""; C_0=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
warn() { printf '%s warn:%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%serror:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0; }

# The guest needs netfilter, veth, namespaces and 9p; a plain defconfig has
# none of the netfilter pieces. The debug options are the reason to be here.
print_kconfig() {
cat <<'EOF'
# --- required for the test rig to work at all ---
CONFIG_NET_NS=y
CONFIG_VETH=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XTABLES_LEGACY=y
CONFIG_NF_CONNTRACK=y
CONFIG_NETFILTER_XT_TARGET_CT=y
CONFIG_IP_NF_IPTABLES=y
# 7.0 moved the legacy xtables tables behind IP_NF_IPTABLES_LEGACY; iptables-nft
# does not need them, but enabling both means the rig works with either backend
# (older kernels simply ignore the unknown symbol)
CONFIG_IP_NF_IPTABLES_LEGACY=y
CONFIG_IP_NF_RAW=y
CONFIG_IP_NF_FILTER=y
CONFIG_NF_DEFRAG_IPV4=y
CONFIG_PACKET=y
# iptables on a current distro is the nft backend, which reaches xt targets
# through nft_compat - without these, "iptables -j CGNAT" cannot load the target
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NFT_COMPAT=y
# Older kernels make counters optional; iptables-nft puts one on every rule.
# Its CT --notrack translation also needs the native nftables CT expressions.
CONFIG_NFT_COUNTER=y
CONFIG_NFT_CT=y
# --- 9p, for getting the sources in and the results out ---
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
# --- virtio, for direct kernel boot with no initrd ---
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_EXT4_FS=y
# Populate /dev when directly booting without an initramfs.
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
# --- so the guest can report which of these are actually on: a custom kernel
# --- has no /boot/config-$(uname -r) in the cloud image's rootfs
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
# --- the point of the exercise ---
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_KERNEL=y
CONFIG_PROVE_LOCKING=y
CONFIG_PROVE_RCU=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_DEBUG_OBJECTS=y
CONFIG_DEBUG_OBJECTS_FREE=y
CONFIG_DEBUG_OBJECTS_TIMERS=y
CONFIG_DEBUG_LIST=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_SLUB_DEBUG=y
CONFIG_DEBUG_KMEMLEAK=y
CONFIG_DEBUG_KMEMLEAK_AUTO_SCAN=y
CONFIG_LOCK_STAT=y
CONFIG_DEBUG_INFO_NONE=y
EOF
}

# --------------------------------------------------------------- arguments ---

while [ $# -gt 0 ]; do
    case "$1" in
        --kdir)    shift; KDIR=${1:-} ;;
        --kernel)  shift; KERNEL=${1:-} ;;
        --rootdev) shift; ROOTDEV=${1:-/dev/vda1} ;;
        --image)   shift; IMAGE_URL=${1:-} ;;
        --transport) shift; TRANSPORT=${1:-} ;;
        --kernel-packages) shift; KERNEL_PACKAGES=${1:-} ;;
        --strict) STRICT=1 ;;
        --cpus)    shift; CPUS=${1:-4} ;;
        --memory)  shift; MEMORY=${1:-4096} ;;
        --timeout) shift; TIMEOUT=${1:-1800} ;;
        --soak)    SOAK=1 ;;
        --tests)      RUN_TESTS=1 ;;
        --no-tests)   RUN_TESTS=0 ;;
        --bench)      BENCH=1 ;;
        --no-bench)   BENCH=0 ;;
        --bench-only) BENCH=1; RUN_TESTS=0 ;;
        --bench-args) shift; BENCH_ARGS=${1:-} ;;
        --keep)    KEEP=1 ;;
        --shell)   SHELL_MODE=1 ;;
        --refresh-image) REFRESH=1 ;;
        --print-kconfig) print_kconfig; exit 0 ;;
        -h|--help) usage ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

case "$TRANSPORT" in 9p|disk) ;; *) die "--transport must be 9p or disk" ;; esac
if [ -n "$KERNEL_PACKAGES" ]; then
    [[ "$KERNEL_PACKAGES" =~ ^[a-zA-Z0-9.+\ -]+$ ]] || die "invalid kernel package names"
    [ -z "$KDIR$KERNEL" ] || die "--kernel-packages cannot be combined with a custom kernel"
    [ "$TRANSPORT" = disk ] || die "--kernel-packages requires --transport disk"
    [ "$SHELL_MODE" = 0 ] || die "--kernel-packages cannot be combined with --shell"
fi

if [ "$RUN_TESTS" = 0 ] && [ "$BENCH" = 0 ] && [ "$SHELL_MODE" = 0 ]; then
    die "--no-tests without --bench leaves nothing to run"
fi
if [ "$SOAK" = 1 ] && [ "$RUN_TESTS" = 0 ]; then
    die "--soak is part of the test suite, which --no-tests disables"
fi

# ------------------------------------------------------------ dependencies ---

need() { command -v "$1" >/dev/null 2>&1; }

need qemu-system-x86_64 || die "qemu-system-x86_64 not installed"
need qemu-img           || die "qemu-img not installed"
if [ "$TRANSPORT" = disk ]; then
    need mkfs.ext4 || die "mkfs.ext4 not installed"
    need debugfs || die "debugfs not installed"
fi

# a progress bar redrawn with \r is noise in a log file or a CI job
if [ -t 1 ]; then CURL_P=--progress-bar; WGET_P=--show-progress
else            CURL_P=--no-progress-meter; WGET_P=--no-verbose; fi

if need curl; then FETCH="curl -fL $CURL_P -o"
elif need wget; then FETCH="wget -q $WGET_P -O"
else die "need curl or wget"; fi

MKISO=""
if   need cloud-localds; then MKISO=cloud-localds
elif need genisoimage;   then MKISO=genisoimage
elif need xorriso;       then MKISO=xorriso
else die "need one of cloud-localds, genisoimage or xorriso to build the cloud-init seed"
fi

if [ -n "$KDIR" ]; then
    [ -d "$KDIR" ] || die "--kdir: no such directory: $KDIR"
    [ -f "$KDIR/.config" ] || die "--kdir: $KDIR is not a configured kernel tree"
    # An external module links against Module.symvers, which only the modules
    # build produces. Without it modpost reports every kernel symbol as
    # undefined, which looks like a code problem and is not one.
    [ -f "$KDIR/Module.symvers" ] || die "--kdir: $KDIR has no Module.symvers - run 'make -j\$(nproc)' there (bzImage alone is not enough)"
    [ -n "$KERNEL" ] || KERNEL=$KDIR/arch/x86/boot/bzImage
fi
if [ -n "$KERNEL" ]; then
    [ -f "$KERNEL" ] || die "kernel image not found: $KERNEL (build it first)"
fi

# ------------------------------------------------------------------- image ---

mkdir -p "$CACHE"
# Separate image URLs and package tracks (e.g. Ubuntu GA/HWE) in the cache.
IMAGE_KEY=$(printf '%s' "$IMAGE_URL" | sha256sum | cut -c1-16)
PREPARED_KEY=$(printf '%s\n' "$IMAGE_URL" "$KERNEL_PACKAGES" | sha256sum | cut -c1-16)
IMAGE=$CACHE/$IMAGE_KEY-$(basename "$IMAGE_URL")
# base image + the toolchain apt installed on the first run. Saved after a run
# that got far enough to build, and used as the backing file from then on, so
# later runs neither install nor download anything.
PREPARED=$CACHE/prepared-$IMAGE_KEY-$PREPARED_KEY.qcow2
# Every prepared track is an overlay of this base. Replacing the base while
# retaining another track's overlay (e.g. HWE when refreshing GA) corrupts it.
[ $REFRESH = 1 ] && rm -f "$CACHE/prepared-$IMAGE_KEY-"*.qcow2 "$IMAGE"

fetch_image() {
    if [ -f "$IMAGE" ]; then
        say "using cached image: $IMAGE"
        return
    fi
    step "downloading $(basename "$IMAGE_URL") (once, cached in $CACHE)"
    $FETCH "$IMAGE.part" "$IMAGE_URL" || die "download failed"

    if [ -n "$IMAGE_SHA256" ]; then
        have=$(sha256sum "$IMAGE.part" | cut -d' ' -f1)
        [ "$IMAGE_SHA256" = "$have" ] || { rm -f "$IMAGE.part"; die "checksum mismatch on downloaded image"; }
        mv "$IMAGE.part" "$IMAGE"
        return
    fi

    # verify against the SHA256SUMS next to it, if we can get it
    local sums="${IMAGE_URL%/*}/SHA256SUMS" want have
    if need sha256sum && $FETCH "$CACHE/SHA256SUMS" "$sums" 2>/dev/null; then
        want=$(awk -v file="$(basename "$IMAGE_URL")" '$2 == file || $2 == "*" file {print $1}' "$CACHE/SHA256SUMS")
        if [ -n "$want" ]; then
            have=$(sha256sum "$IMAGE.part" | cut -d' ' -f1)
            [ "$want" = "$have" ] || { rm -f "$IMAGE.part"; die "checksum mismatch on downloaded image"; }
            say "sha256 verified"
        else
            warn "image not listed in SHA256SUMS, skipping verification"
        fi
    else
        warn "could not fetch SHA256SUMS, skipping verification"
    fi
    mv "$IMAGE.part" "$IMAGE"
}

# ------------------------------------------------------------- guest runner ---

# Written into the share and executed by cloud-init. Everything it prints goes
# to the serial console, so a host-side tee is the full record even if the
# guest never gets far enough to write a file back.
write_guest_runner() {
cat >"$RUNDIR/share/guest-run.sh" <<'GUEST'
#!/bin/bash
set -u
# Fedora confines cloud-init. Run this privileged kernel-test harness in a
# separate unconfined service, keeping SELinux enforcing for the guest.
if command -v selinuxenabled >/dev/null && selinuxenabled && [ "${XTNAT_SERVICE:-0}" != 1 ]; then
    systemd-run --quiet --wait --pipe --collect \
        --property=SELinuxContext=system_u:system_r:unconfined_service_t:s0 \
        --setenv=XTNAT_SERVICE=1 \
        --setenv="BUILD_MODULE_IN_GUEST=${BUILD_MODULE_IN_GUEST:-0}" \
        --setenv="RUN_TESTS=${RUN_TESTS:-1}" --setenv="TEST_ARGS=${TEST_ARGS:-}" \
        --setenv="RUN_BENCH=${RUN_BENCH:-0}" --setenv="BENCH_ARGS=${BENCH_ARGS:-}" \
        --setenv="KERNEL_PACKAGES=${KERNEL_PACKAGES:-}" --setenv="STRICT=${STRICT:-0}" \
        /bin/bash /mnt/xtnat/guest-run.sh
    exit $?
fi
SHARE=/mnt/xtnat
ART=$SHARE/artifacts
mkdir -p "$ART"
exec > >(tee -a "$ART/guest.log") 2>&1

echo "### guest kernel: $(uname -r)"
echo "### $(head -1 /etc/os-release 2>/dev/null)"

fatal() { echo "### GUEST FATAL: $*"; echo 90 > "$ART/exit-code"; finish; }
finish() {
    dmesg > "$ART/dmesg.txt" 2>/dev/null
    [ -r /var/log/audit/audit.log ] && cp /var/log/audit/audit.log "$ART/audit.log" 2>/dev/null
    [ -r /proc/lock_stat ] && cp /proc/lock_stat "$ART/lock_stat.txt" 2>/dev/null
    sync
    echo "### XTNAT-DONE rc=$(cat "$ART/exit-code" 2>/dev/null || echo 91)"
    exit 0
}

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null; then
    PKGS="build-essential pkg-config libxtables-dev iptables iproute2 iputils-ping procps tcpdump ethtool python3 kmod"
    install_packages() {
        apt-get update -qq && apt-get install -y -qq "$@"
    }
elif command -v dnf >/dev/null; then
    PKGS="gcc make pkgconf-pkg-config iptables-devel iptables-nft iproute iputils procps-ng tcpdump ethtool python3 kmod"
    install_packages() { dnf install -y --refresh "$@"; }
else
    fatal "unsupported guest package manager"
fi

# Update the requested distro track before testing. Repositories may no longer
# carry headers for an old cloud image's kernel (especially Fedora).
if [ -n "${KERNEL_PACKAGES:-}" ] && [ ! -f /root/xtnat-expected-kernel ]; then
    # Package lists are intentionally split into arguments.
    install_packages $PKGS $KERNEL_PACKAGES || fatal "kernel preparation failed"
    expected=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -1)
    [ -n "$expected" ] && [ -d "/lib/modules/$expected/build" ] \
        || fatal "updated kernel has no matching build tree"
    echo "$expected" > /root/xtnat-expected-kernel
    if command -v grubby >/dev/null; then
        grubby --set-default "/boot/vmlinuz-$expected" || fatal "could not select updated kernel"
    elif command -v update-grub >/dev/null; then
        update-grub || fatal "could not update grub"
    fi
    echo "### prepared kernel $expected; requesting another boot"
    touch "$ART/reboot-request"
    sync
    exit 0
fi
if [ -n "${KERNEL_PACKAGES:-}" ]; then
    expected=$(cat /root/xtnat-expected-kernel)
    [ "$(uname -r)" = "$expected" ] || fatal "booted $(uname -r), expected $expected"
fi

if [ "${BUILD_MODULE_IN_GUEST:-0}" = 1 ]; then
    if command -v apt-get >/dev/null; then
        PKGS="$PKGS linux-headers-$(uname -r)"
    else
        PKGS="$PKGS kernel-devel-$(uname -r) kernel-modules-extra-$(uname -r)"
    fi
fi

# A prepared image already has all of this, and re-running apt is the single
# largest cost of a run - and the only step that needs the network at all.
deps_present() {
    local tool
    for tool in gcc make python3 iptables ip ping sysctl tcpdump ethtool modinfo; do
        command -v "$tool" >/dev/null 2>&1 || return 1
    done
    pkg-config --exists xtables 2>/dev/null || return 1
    [ "${BUILD_MODULE_IN_GUEST:-0}" != 1 ] || [ -d "/lib/modules/$(uname -r)/build" ] || return 1
    return 0
}

if deps_present; then
    echo "### toolchain already present, skipping package installation"
else
    echo "### installing: $PKGS"
    install_packages $PKGS || fatal "could not install build dependencies"
fi

# 9p is fine for reading, but build somewhere native
rm -rf /root/src && mkdir -p /root/src
cp -a "$SHARE"/src/. /root/src/
if command -v selinuxenabled >/dev/null && selinuxenabled; then
    # The payload filesystem has no SELinux labels; do not preserve those on
    # the native build tree. Label the resulting module as a kernel module.
    restorecon -RF /root/src || fatal "could not label the build tree"
fi
cd /root/src || fatal "no source"

if [ "${BUILD_MODULE_IN_GUEST:-0}" = 1 ]; then
    echo "### building xt_CGNAT.ko against $(uname -r)"
    make -C "/lib/modules/$(uname -r)/build" M=/root/src modules \
        || fatal "module build failed"
else
    echo "### using xt_CGNAT.ko built on the host"
    [ -f /root/src/xt_CGNAT.ko ] || fatal "no prebuilt xt_CGNAT.ko in the share"
fi

echo "### building libxt_CGNAT.so"
make libxt_CGNAT.so || fatal "userspace extension build failed"
if command -v selinuxenabled >/dev/null && selinuxenabled; then
    chcon -t modules_object_t /root/src/xt_CGNAT.ko || fatal "could not label the kernel module"
fi

modinfo /root/src/xt_CGNAT.ko | sed -n '1,6p'

{
    echo "kernel=$(uname -r)"
    echo "distro=$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release)"
    echo "vcpus=$(nproc)"
    echo "memory_mb=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 ))"
    echo "gcc=$(gcc --version 2>/dev/null | head -1)"
    echo "iptables=$(iptables --version)"
    if command -v selinuxenabled >/dev/null && selinuxenabled; then
        echo "selinux=$(getenforce)"
        echo "selinux_context=$(id -Z)"
    fi
    echo "vermagic=$(modinfo -F vermagic /root/src/xt_CGNAT.ko 2>/dev/null)"
    dbg=""
    cfg="/boot/config-$(uname -r)"; rd='cat'
    [ -r /proc/config.gz ] && { cfg=/proc/config.gz; rd='zcat'; }
    for o in KASAN PROVE_LOCKING PROVE_RCU DEBUG_ATOMIC_SLEEP DEBUG_OBJECTS_TIMERS \
             DEBUG_KMEMLEAK SLUB_DEBUG DEBUG_LIST LOCK_STAT; do
        $rd "$cfg" 2>/dev/null | grep -q "^CONFIG_$o=y" && dbg="$dbg $o"
    done
    [ -r "$cfg" ] || dbg=""
    echo "kernel_debug=${dbg:-none (no readable kernel config)}"
} > "$ART/env.txt"

chmod +x /root/src/qemu-tests.sh /root/src/bench-cps.sh
rc=0

if [ "${RUN_TESTS:-1}" = 1 ]; then
    echo "### running qemu-tests.sh ${TEST_ARGS:-}"
    MODULE=/root/src/xt_CGNAT.ko /root/src/qemu-tests.sh ${TEST_ARGS:-} 2>&1 | tee "$ART/tests.txt"
    rc=${PIPESTATUS[0]}
    if [ "${STRICT:-0}" = 1 ] && grep -q '^SKIP ' "$ART/tests.txt"; then
        echo "### strict mode: skipped tests are failures"
        rc=1
    fi
    echo "### qemu-tests.sh exited $rc"
fi

if [ "${RUN_BENCH:-0}" = 1 ]; then
    echo "### running bench-cps.sh ${BENCH_ARGS:-}"
    MODULE=/root/src/xt_CGNAT.ko /root/src/bench-cps.sh ${BENCH_ARGS:-} 2>&1 | tee "$ART/bench.txt"
    brc=${PIPESTATUS[0]}
    echo "### bench-cps.sh exited $brc"
    [ "$rc" = 0 ] && rc=$brc
fi

echo $rc > "$ART/exit-code"

cp /root/src/xt_CGNAT.ko "$ART/" 2>/dev/null
finish
GUEST
chmod +x "$RUNDIR/share/guest-run.sh"
}

write_cloud_init() {
    local testargs=""
    local mount_share="mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 xtnat /mnt/xtnat"
    if [ "$TRANSPORT" = disk ]; then
        mount_share="mount -t ext4 /dev/vdc /mnt/xtnat"
    fi
    [ $SOAK = 1 ] && testargs="--soak"

    cat >"$RUNDIR/meta-data" <<EOF
instance-id: xtnat-$(basename "$RUNDIR")-$BOOT
local-hostname: xtnat-test
EOF

    if [ $SHELL_MODE = 1 ]; then
        cat >"$RUNDIR/user-data" <<EOF
#cloud-config
password: xtnat
chpasswd: { expire: false }
ssh_pwauth: true
runcmd:
  - [ sh, -c, "mkdir -p /mnt/xtnat && $mount_share" ]
  - [ sh, -c, "echo '### share mounted at /mnt/xtnat - log in as ubuntu/xtnat' > /dev/console" ]
EOF
    else
        cat >"$RUNDIR/user-data" <<EOF
#cloud-config
runcmd:
  - [ sh, -c, "mkdir -p /mnt/xtnat && $mount_share || echo '### payload mount FAILED' > /dev/console" ]
  - [ sh, -c, "BUILD_MODULE_IN_GUEST=$BUILD_IN_GUEST RUN_TESTS=$RUN_TESTS TEST_ARGS='$testargs' RUN_BENCH=$BENCH BENCH_ARGS='$BENCH_ARGS' KERNEL_PACKAGES='$KERNEL_PACKAGES' STRICT=$STRICT bash /mnt/xtnat/guest-run.sh > /dev/console 2>&1" ]
power_state:
  mode: poweroff
  timeout: 60
  condition: true
EOF
    fi

    case $MKISO in
        cloud-localds)
            cloud-localds "$RUNDIR/seed.iso" "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
        genisoimage)
            genisoimage -quiet -output "$RUNDIR/seed.iso" -volid cidata -joliet -rock \
                        "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
        xorriso)
            xorriso -as mkisofs -quiet -output "$RUNDIR/seed.iso" -volid CIDATA -joliet -rock \
                    "$RUNDIR/user-data" "$RUNDIR/meta-data" ;;
    esac || die "could not build the cloud-init seed image"
}


# ------------------------------------------------------------------ report ---

# Assemble everything the guest recorded into one document. Printed condensed
# to the terminal, written in full to vm-results/report.md.
write_report() {
    local R=$RESULTS/report.md A=$RESULTS
    local rc=${1:-?} splats=0

    [ -f "$A/dmesg.txt" ] && splats=$(grep -cE '\bBUG:|KASAN|UBSAN|WARNING:|INFO: possible|suspicious RCU|refcount_t|use-after-free' "$A/dmesg.txt")

    {
        echo "# xt_CGNAT VM test report"
        echo
        echo "Result: **$([ "$rc" = 0 ] && echo PASS || echo "FAIL (exit $rc)")**"
        echo

        echo "## Environment"
        echo
        echo "| | |"
        echo "|---|---|"
        if [ -f "$A/env.txt" ]; then
            sed -n 's/^\([a-z_]*\)=\(.*\)$/| \1 | \2 |/p' "$A/env.txt"
        fi
        echo "| image | $(basename "$IMAGE") |"
        echo "| acceleration | $ACCEL |"
        echo "| host | $(uname -sr) |"
        echo

        if [ -f "$A/tests.txt" ]; then
            echo "## Functional tests"
            echo
            echo '```'
            grep -E '^(PASS|FAIL|SKIP) ' "$A/tests.txt" 2>/dev/null
            echo
            grep -E 'passed [0-9]+' "$A/tests.txt" 2>/dev/null | tail -1
            echo '```'
            echo
            if grep -qE '^FAIL ' "$A/tests.txt"; then
                echo "Failure detail:"
                echo
                echo '```'
                grep -A1 -E '^FAIL ' "$A/tests.txt" | head -40
                echo '```'
                echo
            fi
        fi

        if [ -f "$A/bench.txt" ]; then
            echo "## Session setup rate"
            echo
            echo '```'
            sed -n '/^pool  *tx pps/,/^$/p' "$A/bench.txt" 2>/dev/null
            echo '```'
            echo
            echo "Ballpark only - veth inside a VM. Use for comparing runs, pool"
            echo "sizes and commits, never as an absolute rate."
            echo
            if grep -q 'reading it' "$A/bench.txt"; then
                sed -n '/== reading it ==/,$p' "$A/bench.txt" | sed '1d;/ballpark only/,$d'
                echo
            fi
        fi

        echo "## NAT counters"
        echo
        echo '```'
        # whichever stage ran last printed the final statistics
        if [ -f "$A/bench.txt" ] && grep -q 'counters after the run' "$A/bench.txt"; then
            sed -n '/== counters after the run ==/,/^$/p' "$A/bench.txt" | sed '1d'
        elif [ -f "$A/tests.txt" ]; then
            sed -n '/== counters ==/,/^$/p' "$A/tests.txt" | sed '1d'
        fi
        echo '```'
        echo

        echo "## Kernel log"
        echo
        if [ "$splats" -gt 0 ]; then
            echo "**$splats suspicious line(s)** in guest dmesg:"
            echo
            echo '```'
            grep -E '\bBUG:|KASAN|UBSAN|WARNING:|INFO: possible|suspicious RCU|refcount_t|use-after-free' "$A/dmesg.txt" | head -20
            echo '```'
        else
            echo "Clean - no BUG, KASAN, lockdep or RCU reports."
        fi
        echo
        echo "Module load/unload cycles: $(grep -c 'Module xt_CGNAT loaded' "$A/dmesg.txt" 2>/dev/null || echo 0)"
        echo

        echo "## Artifacts"
        echo
        for f in "$A"/*; do
            [ -f "$f" ] && printf -- "- \`%s\` (%s)\n" "$(basename "$f")" "$(du -h "$f" | cut -f1)"
        done
    } > "$R"

    # condensed to the terminal
    say ""
    [ -f "$A/tests.txt" ] && grep -E 'passed [0-9]+' "$A/tests.txt" | tail -1 | sed 's/^/     /'
    if [ -f "$A/bench.txt" ]; then
        say ""
        sed -n '/^pool  *tx pps/,/^$/p' "$A/bench.txt" | sed 's/^/     /'
    fi
    say ""
    if [ "$splats" -gt 0 ]; then
        say "     ${C_Y}dmesg: $splats suspicious line(s)${C_0}"
    else
        say "     dmesg: clean"
    fi
    say "     report: $R"
}

# -------------------------------------------------------------------- main ---

step "xt_CGNAT VM test run"

fetch_image

RUNDIR=$(mktemp -d "${TMPDIR:-/tmp}/xtnat-vm.XXXXXX")
mkdir -p "$RUNDIR/share/src"

cleanup() {
    if [ $KEEP = 1 ]; then
        say "--keep: run directory left at $RUNDIR"
    else
        rm -rf "$RUNDIR"
    fi
}
trap cleanup EXIT INT TERM

# ---- assemble the payload

step "assembling the guest payload"
cp "$SRCDIR"/*.c "$SRCDIR"/*.h "$SRCDIR/Makefile" \
   "$SRCDIR/qemu-tests.sh" "$SRCDIR/safety-tests.py" "$SRCDIR/testnet.sh" "$SRCDIR/bench-cps.sh" "$RUNDIR/share/src/" \
    || die "could not copy the source tree"

BUILD_IN_GUEST=1
if [ -n "$KDIR" ]; then
    BUILD_IN_GUEST=0
    step "building xt_CGNAT.ko on the host against $KDIR"
    make -C "$KDIR" M="$SRCDIR" modules >/dev/null || die "host module build failed"
    cp "$SRCDIR/xt_CGNAT.ko" "$RUNDIR/share/src/" || die "no xt_CGNAT.ko produced"
    say "$(modinfo "$SRCDIR/xt_CGNAT.ko" | sed -n 's/^vermagic: */vermagic: /p')"
fi

write_guest_runner
write_cloud_init

# ---- overlay so the downloaded image is never written to

step "creating overlay disk"
if [ -f "$PREPARED" ]; then
    BACKING=$PREPARED
    say "backing: prepared image (toolchain already installed)"
else
    BACKING=$IMAGE
    say "backing: base image - this run will install the toolchain and cache it"
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$BACKING" "$RUNDIR/disk.qcow2" 20G \
    || die "qemu-img create failed"

# ---- boot

QEMU=(qemu-system-x86_64
      -m "$MEMORY" -smp "$CPUS"
      -drive "file=$RUNDIR/disk.qcow2,if=virtio,format=qcow2"
      -drive "file=$RUNDIR/seed.iso,if=virtio,format=raw,readonly=on"
      -nic "user,model=virtio-net-pci"
      -nographic -no-reboot)

if [ "$TRANSPORT" = disk ]; then
    truncate -s 256M "$RUNDIR/payload.img"
    # Avoid new ext4 features unsupported by older LTS kernels.
    mkfs.ext4 -q -F -O ^orphan_file,^metadata_csum_seed -d "$RUNDIR/share" "$RUNDIR/payload.img" \
        || die "could not create payload disk"
    QEMU+=(-drive "file=$RUNDIR/payload.img,if=virtio,format=raw")
else
    QEMU+=(-virtfs "local,path=$RUNDIR/share,mount_tag=xtnat,security_model=none,id=xtnat")
fi

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU+=(-enable-kvm -cpu host)
    ACCEL="KVM"
    say "KVM: enabled"
else
    warn "no access to /dev/kvm - falling back to emulation, this will be slow"
    ACCEL="TCG (emulated)"
    QEMU+=(-cpu max)
fi

if [ -n "$KERNEL" ]; then
    say "kernel: $KERNEL (direct boot)"
    # root= must name a device the kernel can resolve on its own: there is no
    # initramfs here, and a filesystem LABEL is resolved by userspace inside
    # one, so root=LABEL=... panics with "unknown-block(0,0)". The cloud image
    # lays out vda1 vda13 vda14 vda15, root being vda1. rootwait covers virtio
    # probing finishing after the mount attempt.
    QEMU+=(-kernel "$KERNEL"
           -append "root=$ROOTDEV rootwait rw console=ttyS0 net.ifnames=0 kmemleak=on")
else
    warn "using the cloud image's own kernel: no KASAN, no lockdep."
    warn "for real coverage build a debug kernel and pass --kdir (see --help)."
fi

mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.log "$RESULTS"/*.txt "$RESULTS"/*.md "$RESULTS"/exit-code 2>/dev/null
CONSOLE=$RESULTS/console.log

if [ $SHELL_MODE = 1 ]; then
    step "booting to a shell (login ubuntu/xtnat, share at /mnt/xtnat; Ctrl-A X to quit)"
    "${QEMU[@]}"
    exit $?
fi

step "booting (timeout ${TIMEOUT}s; console -> $CONSOLE)"
say "    Ctrl-A X to abort"
GUEST_ARTIFACTS=$RUNDIR/share/artifacts
while :; do
    timeout --foreground "$TIMEOUT" "${QEMU[@]}" 2>&1 | tee -a "$CONSOLE"
    qemu_rc=${PIPESTATUS[0]}
    if [ "$TRANSPORT" = disk ]; then
        # rdump refuses to replace an existing directory, including after the
        # preparation boot. Always extract into a fresh destination.
        mkdir -p "$RUNDIR/collected-$BOOT"
        debugfs -R "rdump /artifacts $RUNDIR/collected-$BOOT" "$RUNDIR/payload.img" >/dev/null 2>&1
        GUEST_ARTIFACTS=$RUNDIR/collected-$BOOT/artifacts
    fi
    [ "$qemu_rc" = 0 ] || break
    [ -f "$GUEST_ARTIFACTS/reboot-request" ] || break
    [ "$BOOT" = 1 ] || die "guest requested more than one kernel preparation reboot"
    debugfs -w -R 'rm /artifacts/reboot-request' "$RUNDIR/payload.img" >/dev/null 2>&1
    BOOT=2
    write_cloud_init
    step "rebooting into the updated distro kernel"
done

# ---- collect

step "collecting results"
for f in guest.log audit.log dmesg.txt lock_stat.txt exit-code env.txt tests.txt bench.txt; do
    [ -f "$GUEST_ARTIFACTS/$f" ] && cp "$GUEST_ARTIFACTS/$f" "$RESULTS/"
done

rc=""
[ -f "$RESULTS/exit-code" ] && rc=$(tr -dc '0-9' < "$RESULTS/exit-code")

say ""
if [ "$qemu_rc" = 124 ]; then
    say "${C_R}VM timed out after ${TIMEOUT}s${C_0} - see $CONSOLE"
    exit 124
fi
if [ -z "$rc" ]; then
    say "${C_R}the guest never reported a result${C_0}"
    say "the last of the console follows; full log in $CONSOLE"
    tail -30 "$CONSOLE" | sed 's/^/    | /'
    exit 1
fi
[ "$qemu_rc" = 0 ] || rc=1

# env.txt only exists if the guest installed its dependencies and built the
# module, so it is the signal that this disk is worth keeping.
if [ ! -f "$PREPARED" ] && [ -f "$RESULTS/env.txt" ] && [ "$BACKING" = "$IMAGE" ]; then
    if cp "$RUNDIR/disk.qcow2" "$PREPARED.tmp" && mv "$PREPARED.tmp" "$PREPARED"; then
        say "cached prepared image ($(du -h "$PREPARED" | cut -f1)) - later runs skip apt"
    else
        rm -f "$PREPARED.tmp"
        warn "could not cache the prepared image"
    fi
fi

write_report "$rc"

say ""
if [ "$rc" = 0 ]; then
    say "${C_G}all tests passed${C_0}"
else
    say "${C_R}tests failed (exit $rc)${C_0}"
fi
exit "$rc"
