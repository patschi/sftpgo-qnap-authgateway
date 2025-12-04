FROM gcr.io/distroless/static:latest@sha256:4b2a093ef4649bccd586625090a3c668b254cfe180dee54f4c94f3e9bd7e381e

ARG APP_DIR
ARG APP_BIN

COPY /$APP_DIR/$APP_BIN /app
COPY --from=ghcr.io/tarampampam/microcheck:1.0.1@sha256:e9b979feeddb23a6632cab9eb288e6f8cbaf9907ef060da071c7afd7cc85c5c5 /bin/httpscheck /bin/httpscheck

HEALTHCHECK --interval=60s --timeout=3s CMD ["/bin/httpscheck", "localhost:9999/healthz"]

ENTRYPOINT ["/app"]
