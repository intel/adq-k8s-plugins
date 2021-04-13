# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Intel Corporation

# Image URL to use all building/pushing image targets
IMAGE_REGISTRY ?= <YOUR_REGISTRY>
BUILD_VERSION ?= 22.06-1
# Allows to use eg. :latest image version for development
IMAGE_VERSION ?= $(BUILD_VERSION)
CNI_BUILD_FLAGS ?= -ldflags="-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=$(BUILD_VERSION)"
DP_BUILD_FLAGS ?= -ldflags="-X main.BuildVersion=$(BUILD_VERSION)"

export CNI_IMAGE ?= $(IMAGE_REGISTRY)adq-cni-dp:$(IMAGE_VERSION)
export ADQSETUP_IMAGE ?= $(IMAGE_REGISTRY)adqsetup:$(IMAGE_VERSION)
export ADQEXPORTER_IMAGE ?= $(IMAGE_REGISTRY)adqexporter:$(IMAGE_VERSION)

.PHONY: all

all: build test

build: pull-netlink build-dp build-cni build-exporter build-netprio build-adq-node-config

build-dp:
	@echo "Building adq-dp..."
	go build $(DP_BUILD_FLAGS) -o ./bin/adq-dp ./cmd/adq-dp/

build-cni:
	@echo "Building adq-cni..."
	go build $(CNI_BUILD_FLAGS) -o ./bin/adq-cni ./cmd/adq-cni/

build-exporter:
	@echo "Building adq-exporter..."
	go build -o ./bin/adq-exporter ./cmd/adq-exporter/

build-netprio:
	@echo "Building adq-netprio..."
	go build $(DP_BUILD_FLAGS) -o ./bin/adq-netprio ./cmd/adq-netprio/

build-adq-node-config:
	@echo "Building adq-node-config..."
	go build $(DP_BUILD_FLAGS) -o ./bin/adq-node-config ./cmd/adq-node-config/

clean:
	rm -rf ./bin
	rm -rf ./netlink

pull-netlink:
	@echo "Pulling and patching vishvananda/netlink..."
	rm -rf ./netlink
	git clone https://github.com/vishvananda/netlink.git && cd netlink && git checkout 5e915e0149386ce3d02379ff93f4c0a5601779d5
	cd netlink && git apply ../0001-adq-flower-support.patch && git apply ../0002-Support-Mark-in-the-U32-filters.patch

# To pass proxy for docker build from env invoke make with make image-<IMAGE> HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy
DOCKERARGS?=
ifdef HTTP_PROXY
	DOCKERARGS += --build-arg http_proxy=$(HTTP_PROXY)
endif
ifdef HTTPS_PROXY
	DOCKERARGS += --build-arg https_proxy=$(HTTPS_PROXY)
endif
DOCKERARGS += --build-arg BUILD_VERSION=$(BUILD_VERSION)

docker-build:  docker-build-cni docker-build-adqsetup docker-build-adqexporter

docker-build-cni:
	docker build -t $(CNI_IMAGE) $(DOCKERARGS) --network host .

docker-build-adqsetup:
	docker build -t $(ADQSETUP_IMAGE) $(DOCKERARGS) --network host -f ./Dockerfile.adqsetup .

docker-build-adqexporter:
	docker build -t $(ADQEXPORTER_IMAGE) $(DOCKERARGS) --network host -f ./monitoring/Dockerfile.adqexporter .

docker-push: docker-push-cni docker-push-adqsetup docker-push-adqexporter

docker-push-cni: ## Push docker image with the manager.
	docker push $(CNI_IMAGE)

docker-push-adqsetup:
	docker push $(ADQSETUP_IMAGE)

docker-push-adqexporter:
	docker push $(ADQEXPORTER_IMAGE)

enable-adq-telemetry:
	kubectl apply -f ./monitoring/adq-monitoring.yaml

deploy-prometheus: 
	go install -a github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@latest
	go install -a github.com/google/go-jsonnet/cmd/jsonnet@latest
	go install -a github.com/brancz/gojsontoyaml@latest
	cd ./monitoring/kube-prometheus && jb install github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus@release-0.11
	cd ./monitoring/kube-prometheus && wget https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/release-0.11/build.sh -O build.sh && chmod +x build.sh
	cd ./monitoring/kube-prometheus && ./build.sh adq-monitoring.jsonnet
	kubectl apply -f ./monitoring/kube-prometheus/manifests/setup
	until kubectl get servicemonitors --all-namespaces ; do echo "Waiting for servicemonitors CRD"; sleep 1; done
	kubectl create -f ./monitoring/kube-prometheus/manifests/

undeploy-prometheus:
	cd ./monitoring/kube-prometheus && kubectl delete --ignore-not-found=true -f manifests/ -f manifests/setup

test:
	go test ./... -coverprofile cover.out

test-coverage:
	ginkgo -v -r -cover -coverprofile=coverage.out --output-dir=.
	go tool cover -html=coverage.out

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
