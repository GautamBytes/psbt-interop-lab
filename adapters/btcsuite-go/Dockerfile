FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/psbt-lab-btcsuite-go-adapter ./cmd/adapter

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

COPY --from=build /out/psbt-lab-btcsuite-go-adapter /usr/local/bin/psbt-lab-btcsuite-go-adapter
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/psbt-lab-btcsuite-go-adapter"]
