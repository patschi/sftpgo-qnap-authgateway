FROM gcr.io/distroless/static:latest@sha256:cd64bec9cec257044ce3a8dd3620cf83b387920100332f2b041f19c4d2febf93

ARG APP_DIR
ARG APP_BIN

COPY /$APP_DIR/$APP_BIN /app
COPY --from=ghcr.io/tarampampam/microcheck:1.3.0@sha256:79c187c05bfa67518078bf4db117771942fa8fe107dc79a905861c75ddf28dfa /bin/httpscheck /bin/httpscheck

HEALTHCHECK --interval=60s --timeout=3s CMD ["/bin/httpscheck", "localhost:9999/healthz"]

ENTRYPOINT ["/app"]
