FROM gcr.io/distroless/static:latest@sha256:eca24e67792afe660769e84c85332d9939772e7f76071597d179af96ac4e9e4f

ARG APP_DIR
ARG APP_BIN

COPY /$APP_DIR/$APP_BIN /app
COPY --from=ghcr.io/tarampampam/microcheck:1.3.0@sha256:79c187c05bfa67518078bf4db117771942fa8fe107dc79a905861c75ddf28dfa /bin/httpscheck /bin/httpscheck

HEALTHCHECK --interval=60s --timeout=3s CMD ["/bin/httpscheck", "localhost:9999/healthz"]

ENTRYPOINT ["/app"]
