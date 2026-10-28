FROM docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42

LABEL org.opencontainers.image.source="https://github.com/nearai/nearai-red-sandbox"

# mvm mounts the image root read-only; /tmp is per-VM writable tmpfs.
RUN ln -s /tmp/rts/in /in && ln -s /tmp/rts/out /out
