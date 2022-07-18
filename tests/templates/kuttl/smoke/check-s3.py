#!/usr/bin/env python
import trino
import argparse
import sys

if not sys.warnoptions:
    import warnings
warnings.simplefilter("ignore")


def get_connection(username, password, namespace):
    host = 'trino-coordinator-default-0.trino-coordinator-default.' + namespace + '.svc.cluster.local'
    # If you want to debug this locally use
    # kubectl -n kuttl-test-XXX port-forward svc/trino-coordinator-default-0 8443
    # host = '127.0.0.1'

    conn = trino.dbapi.connect(
        host=host,
        port=8443,
        user=username,
        http_scheme='https',
        auth=trino.auth.BasicAuthentication(username, password),
    )
    conn._http_session.verify = False
    return conn


def run_query(connection, query):
    print(f"[DEBUG] Executing query {query}")
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

if __name__ == '__main__':
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-n", "--namespace", required=True, help="Namespace the test is running in")

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    print("Starting S3 tests...")
    connection = get_connection("admin", "admin", namespace)

    assert run_query(connection, "CREATE SCHEMA IF NOT EXISTS hive.taxi WITH (location = 's3a://trino/')")[0][0] is True
    assert run_query(connection, """
CREATE TABLE IF NOT EXISTS hive.taxi.taxi_data (
    vendor_id VARCHAR,
    tpep_pickup_datetime VARCHAR,
    tpep_dropoff_datetime VARCHAR,
    passenger_count VARCHAR,
    trip_distance VARCHAR,
    ratecode_id VARCHAR
) WITH (
    external_location = 's3a://trino/',
    format = 'csv',
    skip_header_line_count = 1
)
    """)[0][0] is True
    assert run_query(connection, "SELECT COUNT(*) FROM hive.taxi.taxi_data")[0][0] == 5000
    rows_written = run_query(connection, "CREATE TABLE IF NOT EXISTS hive.taxi.taxi_data_copy AS SELECT * FROM hive.taxi.taxi_data")[0][0]
    assert rows_written == 0 or rows_written == 5000
    assert run_query(connection, "SELECT COUNT(*) FROM hive.taxi.taxi_data_copy")[0][0] == 5000

    rows_written = run_query(connection, """
CREATE TABLE IF NOT EXISTS hive.taxi.taxi_data_tranformed AS
SELECT
    CAST(vendor_id as BIGINT) as vendor_id,
    tpep_pickup_datetime,
    tpep_dropoff_datetime,
    CAST(passenger_count as BIGINT) as passenger_count,
    CAST(trip_distance as DOUBLE) as trip_distance,
    CAST(ratecode_id as BIGINT) as ratecode_id
FROM hive.taxi.taxi_data
""")[0][0]
    assert rows_written == 0 or rows_written == 5000
    assert run_query(connection, "SELECT COUNT(*) FROM hive.taxi.taxi_data_tranformed")[0][0] == 5000

    print("[SUCCESS] All tests in check-s3.py succeeded!")
