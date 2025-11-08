FROM gcr.io/distroless/static:nonroot
COPY /app/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
