# Build the spike initrd on the Linux VM (Ubuntu 24.04, kernel 7.0.0-1020-azure).
set -eux
K=$(uname -r)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq busybox-static zstd cpio >/dev/null
rm -rf ~/hvspike && mkdir -p ~/hvspike/root/bin ~/hvspike/root/lib && cd ~/hvspike
gcc -static -O2 -o root/bin/hvexec ~/hvexec.c
cp /bin/busybox root/bin/busybox
for m in net/vmw_vsock/vsock net/vmw_vsock/hv_sock; do
  f=$(ls /lib/modules/$K/kernel/$m.ko* | head -1)
  case $f in *.zst) zstd -dq "$f" -o root/lib/$(basename $m).ko ;; *) cp "$f" root/lib/ ;; esac
done
modinfo -F depends root/lib/hv_sock.ko; modinfo -F depends root/lib/vsock.ko
install -m 0755 ~/init root/init
(cd root && find . | cpio -o -H newc --quiet | gzip -9) > initrd.img
sudo cp /boot/vmlinuz-$K vmlinuz && sudo chown $USER vmlinuz
sha256sum vmlinuz initrd.img
ls -l vmlinuz initrd.img
