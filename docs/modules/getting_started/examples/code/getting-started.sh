#!/usr/bin/env bash
set -euo pipefail

# The getting started guide script
# It uses tagged regions which are included in the documentation
# https://docs.asciidoctor.org/asciidoc/latest/directives/include-tagged-regions/
#
# There are two variants to go through the guide - using stackablectl or helm
# The script takes either 'stackablectl' or 'helm' as an argument
#
# The script can be run as a test as well, to make sure that the tutorial works
# It includes some assertions throughout, and at the end especially.

if [ $# -eq 0 ]
then
  echo "Installation method argument ('helm' or 'stackablectl') required."
  exit 1
fi

case "$1" in
"helm")
echo "Adding 'stackable-dev' Helm Chart repository"
# tag::helm-add-repo[]
helm repo add stackable-dev https://repo.stackable.tech/repository/helm-dev/
# end::helm-add-repo[]
echo "Installing Operators with Helm"
# tag::helm-install-operators[]
helm install --wait commons-operator stackable-dev/commons-operator --version 0.4.0-nightly
helm install --wait secret-operator stackable-dev/secret-operator --version 0.6.0-nightly
helm install --wait trino-operator stackable-dev/trino-operator --version 0.7.0-nightly
# end::helm-install-operators[]
;;
"stackablectl")
echo "installing Operators with stackablectl"
# tag::stackablectl-install-operators[]
stackablectl operator install \
  commons=0.4.0-nightly \
  secret=0.6.0-nightly \
  trino=0.7.0-nightly
# end::stackablectl-install-operators[]
;;
*)
echo "Need to provide 'helm' or 'stackablectl' as an argument for which installation method to use!"
exit 1
;;
esac

echo "Installing Trino cluster from trino.yaml"
# tag::install-trino[]
kubectl apply -f trino.yaml
# end::install-trino[]

sleep 5

echo "Awaiting Trino rollout finish"
# tag::watch-trino-rollout[]
kubectl rollout status --watch statefulset/simple-trino-coordinator-default
kubectl rollout status --watch statefulset/simple-trino-worker-default
# end::watch-trino-rollout[]

sleep 5

echo "Starting port-forwarding of coordinator port 8443"
# tag::port-forwarding[]
kubectl port-forward svc/simple-trino-coordinator 8443 2>&1 >/dev/null &
# end::port-forwarding[]
PORT_FORWARD_PID=$!
trap "kill $PORT_FORWARD_PID" EXIT

sleep 5

echo "Start testing Trino"
echo "Downloading Trino CLI tool as trino.jar"
# tag::download-trino-cli[]
curl --output trino.jar https://repo.stackable.tech/repository/packages/trino-cli/trino-cli-387-executable.jar
# end::download-trino-cli[]

echo "Run chmod +x for trino.jar"
# tag::chmod-trino-cli[]
chmod +x trino.jar
# end::chmod-trino-cli[]

echo "Retrieve catalogs"
# tag::retrieve-trino-catalogs[]
./trino.jar --insecure --output-format=CSV_UNQUOTED --server https://localhost:8443 --user admin --execute "SHOW CATALOGS"
# end::retrieve-trino-catalogs[]

# for testing
catalogs=$(./trino.jar --insecure --output-format=CSV_UNQUOTED --server https://localhost:8443 --user admin --execute "SHOW CATALOGS" 2>/dev/null)
if [ "$catalogs" != "system" ]; then
  echo "Received $catalogs as catalogs. Expected 'system'"
  exit 1
fi

echo "Retrieve amount of worker(s)"
# tag::retrieve-trino-workers[]
./trino.jar --insecure --output-format=CSV_UNQUOTED --server https://localhost:8443 --user admin --execute "SELECT COUNT(*) as nodes FROM system.runtime.nodes WHERE coordinator=false AND state='active'"
# end::retrieve-trino-workers[]

# for testing
nodes=$(./trino.jar --insecure --output-format=CSV_UNQUOTED --server https://localhost:8443 --user admin --execute "SELECT COUNT(*) as nodes FROM system.runtime.nodes WHERE coordinator=false AND state='active'" 2>/dev/null)
if [ "$nodes" != "1" ]; then
  echo "Received $nodes workers(s). Expected 1."
  exit 1
fi

# cleanup
# tag::cleanup-trino-cli[]
rm trino.jar
# end::cleanup-trino-cli[]

echo "All tests finished successfully!"
