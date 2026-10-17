FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/polymatx/opsgate/internal/version.Version=${VERSION} -X github.com/polymatx/opsgate/internal/version.Commit=${COMMIT}" \
    -o /out/opsgate ./cmd/opsgate

FROM alpine:3.24
LABEL io.modelcontextprotocol.server.name="io.github.polymatx/opsgate" \
      org.opencontainers.image.source="https://github.com/polymatx/opsgate" \
      org.opencontainers.image.description="The safety gate between AI agents and your servers: typed, policy-checked, audited operations over MCP." \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache ca-certificates
COPY --from=build /out/opsgate /usr/local/bin/opsgate
ENTRYPOINT ["opsgate"]
CMD ["serve"]
