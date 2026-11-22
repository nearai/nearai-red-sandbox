#!/usr/bin/env python3
"""Build the rts Hyper-V guest initramfs from the pinned guest image.

    python3 -I guest/hyperv/build-initramfs.py <rts-guest binary> <out.cpio.gz>

Pulls the amd64 guest image by digest from Artifact Registry (anonymously,
following blob redirects), checks every manifest, config and layer against
its digest, applies the layers in order (OCI whiteouts included) into an
in-memory tree, adds /init, the rts-guest agent and an unprivileged `rts`
user, and writes a deterministic newc cpio (sorted, mtime 0, owner 0:0
except where the image says otherwise) compressed with gzip (mtime 0).
The same inputs always give the same bytes. Python standard library only.
"""

import gzip
import hashlib
import io
import json
import sys
import tarfile
import urllib.request

REGISTRY = "https://us-west1-docker.pkg.dev"
REPOSITORY = "nearai-red-sandbox/sandbox-images/guest"
# The amd64 member of guest@sha256:28197decf607aabcf0e6c64fb03aa364d59ad9b8be533ef0957f6c82c7e1acdd.
MANIFEST_DIGEST = "sha256:6b72caa2757b31d48d93cb439fc78ae7495cf1acc93feda9a3196e8ad130b882"
GUEST_UID = 1000
AGENT_PORT = 5000

INIT = f"""#!/bin/sh
# rts Hyper-V guest init. No network device exists; the agent is reached
# over hvsocket only. /tmp is per-VM tmpfs, as on mvm.
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
ip link set lo up 2>/dev/null || ifconfig lo 127.0.0.1 up
echo "rts-guest init: $(uname -r), net: $(ls /sys/class/net | tr '\\n' ' ')"
exec /usr/sbin/rts-guest {AGENT_PORT} {GUEST_UID}
"""


def fetch(path, accept=None):
    req = urllib.request.Request(REGISTRY + path, headers={"Accept": accept} if accept else {})
    with urllib.request.urlopen(req, timeout=300) as r:  # follows 30x redirects
        return r.read()


def verified(data, digest):
    algo, want = digest.split(":", 1)
    if algo != "sha256" or hashlib.sha256(data).hexdigest() != want:
        sys.exit(f"digest mismatch for {digest}")
    return data


def main():
    agent_path, out_path = sys.argv[1], sys.argv[2]
    manifest = json.loads(verified(fetch(f"/v2/{REPOSITORY}/manifests/{MANIFEST_DIGEST}",
                                         "application/vnd.oci.image.manifest.v1+json"), MANIFEST_DIGEST))
    config = json.loads(verified(fetch(f"/v2/{REPOSITORY}/blobs/{manifest['config']['digest']}"),
                                 manifest["config"]["digest"]))
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        sys.exit("the pinned image is not linux/amd64")

    # path -> (mode, uid, gid, data or None for dirs, linkname or None)
    tree = {}

    def remove(prefix):
        for p in [p for p in tree if p == prefix or p.startswith(prefix + "/")]:
            del tree[p]

    for layer in manifest["layers"]:
        blob = verified(fetch(f"/v2/{REPOSITORY}/blobs/{layer['digest']}"), layer["digest"])
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for m in tar.getmembers():
                name = m.name.lstrip("./").rstrip("/")
                if not name or ".." in name.split("/"):
                    continue
                base = name.rsplit("/", 1)[-1]
                parent = name.rsplit("/", 1)[0] if "/" in name else ""
                if base == ".wh..wh..opq":
                    for p in [p for p in tree if p.startswith(parent + "/")]:
                        del tree[p]
                    continue
                if base.startswith(".wh."):
                    remove((parent + "/" if parent else "") + base[4:])
                    continue
                if m.isdir():
                    tree[name] = (0o040000 | (m.mode & 0o7777), m.uid, m.gid, None, None)
                elif m.issym():
                    tree[name] = (0o120000 | 0o777, m.uid, m.gid, None, m.linkname)
                elif m.islnk():
                    target = tree.get(m.linkname.lstrip("./"))
                    if target is None:
                        sys.exit(f"hard link to a missing file: {name}")
                    tree[name] = target
                elif m.isfile():
                    tree[name] = (0o100000 | (m.mode & 0o7777), m.uid, m.gid, tar.extractfile(m).read(), None)

    for d in ["proc", "sys", "dev", "tmp", "usr", "usr/sbin", "etc"]:
        tree.setdefault(d, (0o040755, 0, 0, None, None))
    tree["init"] = (0o100755, 0, 0, INIT.encode(), None)
    with open(agent_path, "rb") as f:
        tree["usr/sbin/rts-guest"] = (0o100755, 0, 0, f.read(), None)
    passwd = tree.get("etc/passwd", (0o100644, 0, 0, b"", None))[3] or b""
    if b"\nrts:" not in b"\n" + passwd:
        passwd += f"rts:x:{GUEST_UID}:{GUEST_UID}:rts:/tmp:/bin/sh\n".encode()
        tree["etc/passwd"] = (0o100644, 0, 0, passwd, None)
    group = tree.get("etc/group", (0o100644, 0, 0, b"", None))[3] or b""
    if b"\nrts:" not in b"\n" + group:
        group += f"rts:x:{GUEST_UID}:\n".encode()
        tree["etc/group"] = (0o100644, 0, 0, group, None)

    cpio = io.BytesIO()
    for ino, path in enumerate(sorted(tree), start=1):
        mode, uid, gid, data, link = tree[path]
        body = link.encode() if link is not None else (data or b"")
        write_entry(cpio, path, ino, mode, uid, gid, body)
    write_entry(cpio, "TRAILER!!!", 0, 0, 0, 0, b"")
    with open(out_path, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0, compresslevel=9, filename="") as z:
            z.write(cpio.getvalue())
    print(hashlib.sha256(open(out_path, "rb").read()).hexdigest(), out_path)


def write_entry(out, name, ino, mode, uid, gid, body):
    n = name.encode() + b"\0"
    nlink = 2 if mode & 0o170000 == 0o040000 else 1
    fields = [ino, mode, uid, gid, nlink, 0, len(body), 0, 0, 0, 0, len(n), 0]
    out.write(b"070701" + b"".join(b"%08X" % v for v in fields))
    out.write(n)
    out.write(b"\0" * ((4 - (110 + len(n)) % 4) % 4))
    out.write(body)
    out.write(b"\0" * ((4 - len(body) % 4) % 4))


if __name__ == "__main__":
    main()
