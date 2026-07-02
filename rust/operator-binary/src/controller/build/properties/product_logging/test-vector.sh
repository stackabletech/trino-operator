#!/usr/bin/env sh

# Trino emits airlift timestamps as UTC (trailing `Z`). The shared transform matches the `Z`
# literally, so `parse_timestamp` assumes the host timezone; pin it to UTC (as the pods run) to
# keep the tests deterministic regardless of the host's timezone.
TZ=UTC \
DATA_DIR=/stackable/log/_vector-state \
LOG_DIR=/stackable/log \
NAMESPACE=default \
CLUSTER_NAME=trino \
ROLE_NAME=coordinator \
ROLE_GROUP_NAME=default \
VECTOR_AGGREGATOR_ADDRESS=vector-aggregator \
VECTOR_FILE_LOG_LEVEL=info \
vector test vector.yaml vector-test.yaml
