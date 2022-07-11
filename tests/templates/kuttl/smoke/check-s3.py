#!/usr/bin/env python
import trino
import argparse
import sys

if not sys.warnoptions:
    import warnings
warnings.simplefilter("ignore")


def get_connection(username, password, namespace):
    host = 'trino-coordinator-default-0.trino-coordinator-default.' + namespace + '.svc.cluster.local'
    conn = trino.dbapi.connect(
        host=host,
        port=8443,
        user=username,
        http_scheme='https',
        auth=trino.auth.BasicAuthentication(username, password),
    )
    conn._http_session.verify = False
    return conn


def test_query(user, password, ns, query):
    conn = get_connection(user, password, ns)
    cursor = conn.cursor()
    cursor.execute(query)
    try:
        result = cursor.fetchone()
        print("[SUCCESS] Received: " + str(result))
    except Exception as e:
        print("[ERROR] " + str(e))
        exit(-1)


if __name__ == '__main__':
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-n", "--namespace", required=True, help="Namespace the test is running in")

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    print("Starting S3 tests...")
    print("Trying to create SCHEMA...")
    test_query("admin", "admin", namespace, "CREATE SCHEMA IF NOT EXISTS hive.taxi WITH (location = 's3a://trino/')")

    print("Trying to create TABLE...")
    test_query("admin", "admin", namespace,
               ("CREATE TABLE IF NOT EXISTS hive.taxi.csv ( "
                "vendor_id VARCHAR,"
                "pickup VARCHAR,"
                "dropoff VARCHAR)"
                " WITH ("
                "external_location = 's3a://trino/',"
                "format = 'CSV',"
                "skip_header_line_count=1)"
                ))

    print("Trying to SELECT from TABLE...")
    test_query("admin", "admin", namespace, "SELECT * FROM hive.taxi.csv LIMIT 1")

    print("[SUCCESS] All tests in check-s3.py succeeded!")
