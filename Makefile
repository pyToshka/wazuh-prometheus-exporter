ifneq (,)
.error This Makefile requires GNU Make.
endif

.PHONY: build test pull tag login push enter

DIR = .
FILE = Dockerfile
REPO = gcr.io/security-375019
IMAGE = "wazuh-prometheus-exporter"
TAG = latest


pull:
	docker pull $(shell grep FROM Dockerfile | sed 's/^FROM//g';)

build:
	docker build --progress=plain \
		--platform=linux/amd64 \
		-t $(REPO)/$(IMAGE) -f $(DIR)/$(FILE) $(DIR)

test:
	docker run --rm --entrypoint 'ls ./main.py' $(REPO)/$(IMAGE)


tag:
	docker tag $(IMAGE):$(TAG) $(REPO)/$(IMAGE):$(TAG)

login:
ifndef DOCKER_USER
	$(error DOCKER_USER must either be set via environment or parsed as argument)
endif
ifndef DOCKER_PASS
	$(error DOCKER_PASS must either be set via environment or parsed as argument)
endif
	@yes | docker login --username $(DOCKER_USER) --password $(DOCKER_PASS)

push:
	docker push $(REPO)/$(IMAGE):$(TAG)

enter:
	docker run --rm --name $(subst /,-,$(IMAGE)) -it --entrypoint=/bin/sh $(REPO)/$(IMAGE)
