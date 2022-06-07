#!/bin/bash
git clone -b "$GIT_BRANCH" https://github.com/stackabletech/trino-operator.git
(cd trino-operator/ && ./scripts/run_tests.sh --parallel 1)
exit_code=$?
./operator-logs.sh trino > /target/trino-operator.log
exit $exit_code
