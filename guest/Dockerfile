# alpine 3.24.3, the multi-arch index: linux/arm64 resolves to
# sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42, the
# base of the arm64 image rts has always pinned. The amd64 image is built with
#   docker buildx build --no-cache --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=0 \
#     --output type=oci,dest=guest-amd64.oci.tar,rewrite-timestamp=true .
# and is reproducible (manifest sha256:6b72caa2757b31d48d93cb439fc78ae7495cf1acc93feda9a3196e8ad130b882).
FROM docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

LABEL org.opencontainers.image.source="https://github.com/nearai/nearai-red-sandbox"

# mvm mounts the image root read-only; /tmp is per-VM writable tmpfs.
RUN ln -s /tmp/rts/in /in && ln -s /tmp/rts/out /out
