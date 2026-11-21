#!/bin/bash
# The container half of build.sh. Do not run on a host.
set -euo pipefail
cat > /etc/apt/sources.list.d/debian.sources <<SRC
Types: deb
URIs: http://snapshot.debian.org/archive/debian/${SNAPSHOT}/
Suites: trixie
Components: main
Check-Valid-Until: no
SRC
apt-get -qq -o Acquire::Check-Valid-Until=false update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
  ca-certificates curl xz-utils make gcc libc6-dev flex bison bc libelf-dev perl python3 >/dev/null

cd /tmp
curl -sSfLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
echo "${KERNEL_SHA256}  linux-${KERNEL_VERSION}.tar.xz" | sha256sum -c -
tar -xJf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

export ARCH=x86_64 KBUILD_BUILD_USER=rts KBUILD_BUILD_HOST=rts-guest-build
export KBUILD_BUILD_TIMESTAMP="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%d %H:%M:%S UTC')"
make -s allnoconfig
scripts/kconfig/merge_config.sh -m .config /recipe/kernel.config >/dev/null
make -s olddefconfig

# Every requested option must have survived olddefconfig, and nothing that
# would give the guest a device to reach (or a module to load) may be on.
fail=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=y) grep -qx "$line" .config || { echo "missing: $line" >&2; fail=1; } ;;
    "# CONFIG_"*" is not set") opt=${line#\# }; opt=${opt%% is not set}
      grep -q "^${opt}=" .config && { echo "must be off: $opt" >&2; fail=1; } ;;
  esac
done < /recipe/kernel.config
for opt in CONFIG_MODULES CONFIG_PCI CONFIG_NETDEVICES CONFIG_ETHERNET CONFIG_WLAN CONFIG_USB \
           CONFIG_HYPERV_NET CONFIG_HYPERV_STORAGE CONFIG_VIRTIO_NET CONFIG_NET_9P CONFIG_9P_FS \
           CONFIG_CIFS CONFIG_NFS_FS CONFIG_FUSE_FS CONFIG_VSOCKETS_LOOPBACK CONFIG_VIRTIO_VSOCKETS; do
  grep -q "^${opt}=" .config && { echo "forbidden option on: $opt" >&2; fail=1; }
done
[ "$fail" = 0 ] || exit 1

make -s -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage /out/vmlinuz
cp .config /out/kernel.config.full
(cd /out && sha256sum vmlinuz kernel.config.full | tee SHA256SUMS)
