FROM gcr.io/distroless/static:latest@sha256:87bce11be0af225e4ca761c40babb06d6d559f5767fbf7dc3c47f0f1a466b92c

ARG APP_DIR
ARG APP_BIN

COPY /$APP_DIR/$APP_BIN /app
COPY --from=ghcr.io/tarampampam/microcheck:0.1.1@sha256:a24189bb57b90950963c2a38929f48cbf55c36e900fb27eb7e69fccd32ab096d /bin/httpscheck /bin/httpscheck

HEALTHCHECK --interval=60s --timeout=3s CMD ["/bin/httpscheck", "localhost:9999/healthz"]

ENTRYPOINT ["/app"]
