#!/usr/bin/env sh

set -eu

export DATA_DIR=/stackable/log/_vector-state
export LOG_DIR=/stackable/log
export NAMESPACE=default
export CLUSTER_NAME=trino
export ROLE_NAME=coordinator
export ROLE_GROUP_NAME=default
export VECTOR_AGGREGATOR_ADDRESS=vector-aggregator
export VECTOR_FILE_LOG_LEVEL=info

# Required because vector.yaml contains ${...} placeholders
export VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true

vector validate --no-environment vector.yaml

vector test vector.yaml vector-test.yaml
