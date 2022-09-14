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
    host = '127.0.0.1'

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

    assert run_query(connection, "CREATE SCHEMA IF NOT EXISTS hive.minio WITH (location = 's3a://trino/')")[0][0] is True
    assert run_query(connection, """
CREATE TABLE IF NOT EXISTS hive.minio.taxi_data (
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
    assert run_query(connection, "SELECT COUNT(*) FROM hive.minio.taxi_data")[0][0] == 5000
    rows_written = run_query(connection, "CREATE TABLE IF NOT EXISTS hive.minio.taxi_data_copy AS SELECT * FROM hive.minio.taxi_data")[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert run_query(connection, "SELECT COUNT(*) FROM hive.minio.taxi_data_copy")[0][0] == 5000

    rows_written = run_query(connection, """
CREATE TABLE IF NOT EXISTS hive.minio.taxi_data_transformed AS
SELECT
    CAST(vendor_id as BIGINT) as vendor_id,
    tpep_pickup_datetime,
    tpep_dropoff_datetime,
    CAST(passenger_count as BIGINT) as passenger_count,
    CAST(trip_distance as DOUBLE) as trip_distance,
    CAST(ratecode_id as BIGINT) as ratecode_id
FROM hive.minio.taxi_data
""")[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert run_query(connection, "SELECT COUNT(*) FROM hive.minio.taxi_data_transformed")[0][0] == 5000

    print("[INFO] Testing HDFS")

    # We have to put in the Namenode address *temporary* until hive metastore supports adding a HDFS connection based on the discovery configmap
    # You can see that based on the error stacktrace:
    #  Caused by: org.apache.hadoop.hive.metastore.api.MetaException: java.lang.IllegalArgumentException: java.net.UnknownHostException: hdfs
    # When hive supports the HDFS connection we should switch to the following command
    # assert run_query(connection, "CREATE SCHEMA IF NOT EXISTS hive.hdfs WITH (location = 'hdfs://hdfs/trino/')")[0][0] is True
    assert run_query(connection, "CREATE SCHEMA IF NOT EXISTS hive.hdfs WITH (location = 'hdfs://hdfs-namenode-default-0/trino/')")[0][0] is True
    rows_written = run_query(connection, "CREATE TABLE IF NOT EXISTS hive.hdfs.taxi_data_copy AS SELECT * FROM hive.minio.taxi_data")[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert run_query(connection, "SELECT COUNT(*) FROM hive.hdfs.taxi_data_copy")[0][0] == 5000

    print("[INFO] Testing Iceberg")
    assert run_query(connection, "DROP TABLE IF EXISTS iceberg.minio.taxi_data_copy_iceberg")[0][0] is True # Clean up table to don't fail an second run
    assert run_query(connection, """
CREATE TABLE IF NOT EXISTS iceberg.minio.taxi_data_copy_iceberg
WITH (partitioning = ARRAY['vendor_id', 'passenger_count'], format = 'parquet')
AS SELECT * FROM hive.minio.taxi_data
""")[0][0] == 5000
    # Check current count
    assert run_query(connection, "SELECT COUNT(*) FROM iceberg.minio.taxi_data_copy_iceberg")[0][0] == 5000
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$snapshots"')[0][0] == 1
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$partitions"')[0][0] == 12
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$files"')[0][0] == 12

    assert run_query(connection, "INSERT INTO iceberg.minio.taxi_data_copy_iceberg SELECT * FROM hive.minio.taxi_data")[0][0] == 5000

    # Check current count
    assert run_query(connection, "SELECT COUNT(*) FROM iceberg.minio.taxi_data_copy_iceberg")[0][0] == 10000
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$snapshots"')[0][0] == 2
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$partitions"')[0][0] == 12
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$files"')[0][0] == 24
    # Check count for first snapshot
    first_snapshot = run_query(connection, 'select snapshot_id from iceberg.minio."taxi_data_copy_iceberg$snapshots" order by committed_at limit 1')[0][0]
    assert run_query(connection, f"SELECT COUNT(*) FROM iceberg.minio.taxi_data_copy_iceberg FOR VERSION AS OF {first_snapshot}")[0][0] == 5000

    # Compact files
    run_query(connection, "ALTER TABLE iceberg.minio.taxi_data_copy_iceberg EXECUTE optimize")
    # Check current count
    assert run_query(connection, "SELECT COUNT(*) FROM iceberg.minio.taxi_data_copy_iceberg")[0][0] == 10000
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$snapshots"')[0][0] == 3
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$partitions"')[0][0] == 12
    assert run_query(connection, 'SELECT COUNT(*) FROM iceberg.minio."taxi_data_copy_iceberg$files"')[0][0] == 12 # Compaction yeah :)

    # We can't test UPDATEs and DELETEs as well as table spec version 2 as Trino 377 is too old for that

    print("Dropping tables")

    assert run_query(connection, "DROP TABLE hive.minio.taxi_data")[0][0] is True
    assert run_query(connection, "DROP TABLE hive.minio.taxi_data_copy")[0][0] is True
    assert run_query(connection, "DROP TABLE hive.minio.taxi_data_transformed")[0][0] is True
    assert run_query(connection, "DROP TABLE hive.hdfs.taxi_data_copy")[0][0] is True
    assert run_query(connection, "DROP TABLE iceberg.minio.taxi_data_copy_iceberg")[0][0] is True

    print("[SUCCESS] All tests in check-s3.py succeeded!")
