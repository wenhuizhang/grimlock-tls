# Minimal A2A Agent for Grimlock Demo
# This container runs a plain HTTP server - Grimlock provides mTLS transparently

FROM golang:1.21-alpine AS builder

WORKDIR /app

# Initialize Go module and copy source
RUN go mod init a2a-agent
COPY main.go .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o a2a-agent .

# Runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl

WORKDIR /app

COPY --from=builder /app/a2a-agent .

# Default environment
ENV AGENT_NAME=demo-agent
ENV AGENT_PORT=8080
ENV AGENT_HOST=0.0.0.0

EXPOSE 8080

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./a2a-agent"]
