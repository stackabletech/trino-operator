#!/usr/bin/env python
import trino
import argparse
import json
import requests


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
    cursor.execute(query)


def test_query_failure(conn, query, expected_error, failure_message):
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        raise Exception(failure_message)
    except expected_error:
        pass


def read_json(config_path):
    with open(config_path, 'r') as stream:
        config = json.load(stream)
    return config


if __name__ == '__main__':
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-n", "--namespace", required=True, help="Namespace the test is running in")

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    conf = read_json("/tmp/test-config.json")  # config file to indicate our test script if auth / tls is used or not
    coordinator_host = 'trino-coordinator-default-0.trino-coordinator-default.' + namespace + '.svc.cluster.local'
    trusted_ca = "/tmp/ca.crt"  # will be copied via kubectl from the coordinator pod
    untrusted_ca = "/tmp/untrusted-cert.crt"  # some random CA
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
        test_query_failure(conn, query, requests.exceptions.SSLError, "Could connect with wrong certificate")
        conn = get_authenticated_https_connection(coordinator_host, "admin", "wrong_password", trusted_ca)
        test_query_failure(conn, query, trino.exceptions.HttpError, "Could connect with wrong password")
        conn = get_authenticated_https_connection(coordinator_host, "wrong_user", "wrong_password", trusted_ca)
        test_query_failure(conn, query, trino.exceptions.HttpError, "Could connect with wrong user and password")
    elif conf["useTls"]:
        conn = get_https_connection(coordinator_host, "admin", untrusted_ca)
        test_query_failure(conn, query, requests.exceptions.SSLError, "Could connect with wrong certificate")

    print("All TLS tests finished successfully!")
