.PHONY: docker

TAG    := $(shell git rev-parse --short HEAD)

docker:
	docker build --force-rm -t "docker.stackable.tech/stackable/trino-operator:${TAG}" -t "docker.stackable.tech/stackable/trino-operator:latest" -f docker/Dockerfile .
	echo "${NEXUS_PASSWORD}" | docker login --username github --password-stdin docker.stackable.tech
	docker push --all-tags docker.stackable.tech/stackable/trino-operator
