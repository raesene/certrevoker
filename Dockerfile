# Build the binary first: CGO_ENABLED=0 go build -trimpath -o bin/certrevoker ./cmd/certrevoker
FROM scratch
COPY bin/certrevoker /certrevoker
USER 65532:65532
ENTRYPOINT ["/certrevoker"]
