# QSSH Container Build Targets
IMAGE := paraxiom/qssh
TAG   := latest

.PHONY: build build-hardened run stop test-connect compose-up compose-down keygen clean

## Build standard image
build:
	docker build -t $(IMAGE):$(TAG) .

## Build hardened image (quantum-native frames, no hybrid)
build-hardened:
	docker build -t $(IMAGE):hardened \
		--build-arg FEATURES="sftp,quantum-native" .

## Build custom per-org image (example: T3 minimum, Falcon-only)
build-custom:
	docker build -t $(IMAGE):custom \
		--build-arg FEATURES="sftp,quantum-native" \
		--build-arg STRIP="true" .

## Generate PQ keypair on host
keygen:
	docker run --rm -v $$(pwd)/keys:/keys $(IMAGE):$(TAG) \
		qssh-keygen -t falcon512 -f /keys/id_falcon

## Run qsshd server
run:
	docker run -d --name qsshd \
		-p 22222:22222 \
		-v $$(pwd)/keys:/etc/qssh \
		$(IMAGE):$(TAG)

## Stop and remove server
stop:
	docker rm -f qsshd 2>/dev/null || true

## Test connection to running server
test-connect:
	docker run --rm --network host $(IMAGE):$(TAG) \
		qssh -p 22222 localhost

## Start full stack (server + client)
compose-up:
	docker compose up -d

## Start with QKD simulator
compose-qkd:
	docker compose --profile qkd up -d

## Start with Coherence Shield
compose-shield:
	docker compose --profile shield up -d

## Start everything
compose-all:
	docker compose --profile client --profile qkd --profile shield --profile hardened up -d

## Tear down
compose-down:
	docker compose --profile client --profile qkd --profile shield --profile hardened down -v

## Show image size
size:
	docker images $(IMAGE) --format "{{.Repository}}:{{.Tag}}\t{{.Size}}"

## Clean up
clean: stop
	docker rmi $(IMAGE):$(TAG) $(IMAGE):hardened $(IMAGE):custom 2>/dev/null || true
