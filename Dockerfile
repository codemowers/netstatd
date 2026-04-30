FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache \
    git \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    make
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN ARCH=$(apk --print-arch) && \
    if [ "$ARCH" = "x86_64" ]; then \
        BPF_ARCH=x86; \
    elif [ "$ARCH" = "aarch64" ]; then \
        BPF_ARCH=arm64; \
    else \
        echo "Unsupported arch: $ARCH" && exit 1; \
    fi && \
    clang -O2 -g -Wall -target bpf \
      -I/usr/include \
      -D__TARGET_ARCH_${BPF_ARCH} \
      -c internal/ebpf/bpf/tracer.bpf.c \
      -o internal/ebpf/tracer_bpfel.o
RUN go test ./...
RUN CGO_ENABLED=0 \
    go build -a -installsuffix cgo \
    -ldflags '-extldflags "-static" -s -w' \
    -tags 'netgo osusergo' \
    -o netstatd ./cmd/server

FROM scratch
WORKDIR /
COPY --from=builder /app/netstatd .
COPY --from=builder /app/internal/ebpf/tracer_bpfel.o ./internal/ebpf/
COPY --from=builder /etc/services /etc/services
COPY services /services
COPY web web
EXPOSE 5280 6280 5253 6253
ENTRYPOINT ["/netstatd"]

CMD ["-log-level", "error"]
