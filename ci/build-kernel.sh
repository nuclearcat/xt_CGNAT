#!/bin/bash
# Build a bootable x86-64 debug kernel, including symbol versions for the module.
set -euo pipefail
src=$(cd "$(dirname "$0")/.." && pwd)
kdir=$(realpath "$1")
"$src/run-vm.sh" --print-kconfig > "$kdir/xtnat.config"
cd "$kdir"
make x86_64_defconfig
scripts/kconfig/merge_config.sh -m .config xtnat.config
make olddefconfig
# Fail if a dependency silently discarded one of the essential options.
for opt in 64BIT MODULES NET_NS VETH NF_CONNTRACK NETFILTER_XTABLES \
           NETFILTER_XT_TARGET_CT IP_NF_RAW IP_NF_FILTER NF_TABLES NFT_COMPAT NFT_CT \
           VIRTIO_BLK VIRTIO_NET EXT4_FS IKCONFIG_PROC KASAN PROVE_LOCKING; do
    grep -qx "CONFIG_$opt=y" .config || { echo "Missing CONFIG_$opt=y" >&2; exit 1; }
done
# NFT_COUNTER was folded into NF_TABLES in newer kernels.
if grep -q '^config NFT_COUNTER$' net/netfilter/Kconfig; then
    grep -qx 'CONFIG_NFT_COUNTER=y' .config
fi
make -j"$(nproc)" bzImage modules
test -s Module.symvers
