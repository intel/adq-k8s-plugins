# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Intel Corporation

# Build the manager binary
FROM golang:1.20 as builder
ARG BUILD_VERSION
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Pull and patch netlink library
COPY 0001-adq-flower-support.patch .
COPY 0002-Support-Mark-in-the-U32-filters.patch .

RUN git clone https://github.com/vishvananda/netlink.git && cd netlink && git checkout 5e915e0149386ce3d02379ff93f4c0a5601779d5
RUN cd netlink && git apply ../0001-adq-flower-support.patch && git apply ../0002-Support-Mark-in-the-U32-filters.patch

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
# Copy the go source
COPY cmd/adq-cni cmd/adq-cni
COPY cmd/adq-dp cmd/adq-dp
COPY cmd/adq-netprio cmd/adq-netprio
COPY cmd/adq-node-config cmd/adq-node-config

COPY pkg pkg

# building CNI, Device Plugin for ADQ and Prometheus exporter
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags "-X main.BuildVersion=$BUILD_VERSION" -a -o ./bin/adq-dp ./cmd/adq-dp/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=$BUILD_VERSION" -a -o ./bin/adq-cni ./cmd/adq-cni/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags "-X main.BuildVersion=$BUILD_VERSION" -a -o ./bin/adq-netprio ./cmd/adq-netprio/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags "-X main.BuildVersion=$BUILD_VERSION" -a -o ./bin/adq-node-config ./cmd/adq-node-config/main.go

FROM alpine:3.15
WORKDIR /
COPY --from=builder /workspace/bin/adq-dp .
COPY --from=builder /workspace/bin/adq-cni .
COPY --from=builder /workspace/bin/adq-netprio .
COPY --from=builder /workspace/bin/adq-node-config .

RUN apk add --no-cache bash=5.1.16-r0

COPY ./deploy/k8s/entrypoint.sh /

RUN ["chmod", "+x", "/entrypoint.sh"]

USER 1001

ENTRYPOINT ["/adq-dp"]
