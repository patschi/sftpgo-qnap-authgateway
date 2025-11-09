FROM gcr.io/distroless/static:latest
ARG APP_DIR
ARG APP_BIN
COPY /$APP_DIR/$APP_BIN /app
ENTRYPOINT ["/app"]
