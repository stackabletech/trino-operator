#!/usr/bin/env python
import trino
import argparse
import sys
import yaml


if not sys.warnoptions:
    import warnings
warnings.simplefilter("ignore")


def get_http_connection(host, user):
    return trino.dbapi.connect(
        host=host,
        port=8080,
        user=user,
        http_scheme='http',
    )


def get_https_connection(host, user, verify):
    return trino.dbapi.connect(
        host=host,
        port=8443,
        user=user,
        http_scheme='https',
        verify=verify
    )


def get_authenticated_https_connection(host, user, password, verify):
    return trino.dbapi.connect(
        host=host,
        port=8443,
        user=user,
        http_scheme='https',
        auth=trino.auth.BasicAuthentication(user, password),
        verify=verify
    )


def test_query(conn, query):
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        print("[SUCCESS] Received: " + str(result))
    except Exception as e:
        print("[ERROR] " + str(e))
        exit(-1)


def test_query_failure(conn, query, failure_message):
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        print("[ERROR] " + failure_message)
        exit(-1)
    except Exception as e:
        print("[SUCCESS] Received expected exception: " + str(e))


def read_yaml(config_path):
    with open(config_path, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print("Could not load " + str(config_path) + ": " + str(e))
            exit(-1)
    return config


if __name__ == '__main__':
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-n", "--namespace", required=True, help="Namespace the test is running in")

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    conf = read_yaml("/tmp/test-config.yaml")  # config file to indicate our test script if auth / tls is used or not
    coordinator_host = 'trino-coordinator-default-0.trino-coordinator-default.' + namespace + '.svc.cluster.local'
    trusted_ca = "/tmp/ca.crt"  # will be copied via kubectl from the coordinator pod
    untrusted_ca = "/tmp/untrusted-ca.crt"  # some random CA
    query = "SHOW CATALOGS"

    # We expect these to work
    if conf["useAuthentication"]:
        conn = get_authenticated_https_connection(coordinator_host, "admin", "admin", trusted_ca)
        test_query(conn, query)
    elif conf["useTls"]:
        conn = get_https_connection(coordinator_host, "admin", trusted_ca)
        test_query(conn, query)
    else:
        conn = get_http_connection(coordinator_host, "admin")
        test_query(conn, query)

    # We expect these to fail
    if conf["useAuthentication"]:
        conn = get_authenticated_https_connection(coordinator_host, "admin", "admin", untrusted_ca)
        test_query_failure(conn, query, "Could query coordinator with untrusted CA!")
        conn = get_authenticated_https_connection(coordinator_host, "admin", "wrong_password", trusted_ca)
        test_query_failure(conn, query, "Could query coordinator with wrong admin password!")
        conn = get_authenticated_https_connection(coordinator_host, "wrong_user", "wrong_password", trusted_ca)
        test_query_failure(conn, query, "Could query coordinator with wrong user and password!")
    elif conf["useTls"]:
        conn = get_https_connection(coordinator_host, "admin", untrusted_ca)
        test_query_failure(conn, query, "Could query coordinator with untrusted CA!")

    print("All TLS tests finished successfully!")
