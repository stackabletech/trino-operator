#!/usr/bin/env python
import trino
import argparse
import sys
import re

if not sys.warnoptions:
    import warnings
warnings.simplefilter("ignore")


def get_connection(username, password, coordinator):
    # If you want to debug this locally use
    # kubectl -n kuttl-test-XXX port-forward svc/trino-coordinator-default 8443
    # host = '127.0.0.1'
    conn = trino.dbapi.connect(
        host=coordinator,
        port=8443,
        user=username,
        http_scheme="https",
        auth=trino.auth.BasicAuthentication(username, password),
        session_properties={"query_max_execution_time": "60s"},
    )
    conn._http_session.verify = False
    return conn


def run_query(connection, query):
    print(f"[DEBUG] Executing query {query}")
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()


if __name__ == "__main__":
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument(
        "-c",
        "--coordinator",
        required=True,
        help="Trino Coordinator Host to connect to",
    )
    all_args.add_argument(
        "-b", "--bucket", required=True, help="The S3 bucket name to use"
    )

    args = vars(all_args.parse_args())
    coordinator = args["coordinator"]
    bucket_name = args["bucket"]

    print("Starting S3 tests...")
    connection = get_connection("admin", "admin", coordinator)

    trino_version = run_query(
        connection,
        "select node_version from system.runtime.nodes where coordinator = true and state = 'active'",
    )[0][0]
    print(f'[INFO] Testing against Trino version "{trino_version}"')

    # Strip SDP release suffix from the version string
    trino_product_version = re.split(r"-stackable", trino_version, maxsplit=1)[0]

    assert len(trino_product_version) >= 3
    assert trino_product_version.isnumeric()
    assert trino_version == run_query(connection, "select version()")[0][0]

    run_query(
        connection,
        f"CREATE SCHEMA IF NOT EXISTS hive.s3 WITH (location = 's3a://{bucket_name}/')",
    )

    run_query(connection, "DROP TABLE IF EXISTS hive.s3.taxi_data")
    run_query(connection, "DROP TABLE IF EXISTS hive.s3.taxi_data_copy")
    run_query(connection, "DROP TABLE IF EXISTS hive.s3.taxi_data_transformed")
    run_query(connection, "DROP TABLE IF EXISTS hive.hdfs.taxi_data_copy")
    run_query(connection, "DROP TABLE IF EXISTS iceberg.s3.taxi_data_copy_iceberg")

    run_query(
        connection,
        f"""
CREATE TABLE IF NOT EXISTS hive.s3.taxi_data (
    vendor_id VARCHAR,
    tpep_pickup_datetime VARCHAR,
    tpep_dropoff_datetime VARCHAR,
    passenger_count VARCHAR,
    trip_distance VARCHAR,
    ratecode_id VARCHAR
) WITH (
    external_location = 's3a://{bucket_name}/taxi-data/',
    format = 'csv',
    skip_header_line_count = 1
)
    """,
    )
    assert run_query(connection, "SELECT COUNT(*) FROM hive.s3.taxi_data")[0][0] == 5000
    rows_written = run_query(
        connection,
        "CREATE TABLE IF NOT EXISTS hive.s3.taxi_data_copy AS SELECT * FROM hive.s3.taxi_data",
    )[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert (
        run_query(connection, "SELECT COUNT(*) FROM hive.s3.taxi_data_copy")[0][0]
        == 5000
    )

    rows_written = run_query(
        connection,
        """
CREATE TABLE IF NOT EXISTS hive.s3.taxi_data_transformed AS
SELECT
    CAST(vendor_id as BIGINT) as vendor_id,
    tpep_pickup_datetime,
    tpep_dropoff_datetime,
    CAST(passenger_count as BIGINT) as passenger_count,
    CAST(trip_distance as DOUBLE) as trip_distance,
    CAST(ratecode_id as BIGINT) as ratecode_id
FROM hive.s3.taxi_data
""",
    )[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert (
        run_query(connection, "SELECT COUNT(*) FROM hive.s3.taxi_data_transformed")[0][
            0
        ]
        == 5000
    )

    print("[INFO] Testing HDFS")

    run_query(
        connection,
        "CREATE SCHEMA IF NOT EXISTS hive.hdfs WITH (location = 'hdfs://hdfs/trino/')",
    )
    rows_written = run_query(
        connection,
        "CREATE TABLE IF NOT EXISTS hive.hdfs.taxi_data_copy AS SELECT * FROM hive.s3.taxi_data",
    )[0][0]
    assert rows_written == 5000 or rows_written == 0
    assert (
        run_query(connection, "SELECT COUNT(*) FROM hive.hdfs.taxi_data_copy")[0][0]
        == 5000
    )

    print("[INFO] Testing Iceberg")
    run_query(
        connection, "DROP TABLE IF EXISTS iceberg.s3.taxi_data_copy_iceberg"
    )  # Clean up table to don't fail an second run
    assert (
        run_query(
            connection,
            """
CREATE TABLE IF NOT EXISTS iceberg.s3.taxi_data_copy_iceberg
WITH (partitioning = ARRAY['vendor_id', 'passenger_count'], format = 'parquet')
AS SELECT * FROM hive.s3.taxi_data
""",
        )[0][0]
        == 5000
    )
    # Check current count
    assert (
        run_query(connection, "SELECT COUNT(*) FROM iceberg.s3.taxi_data_copy_iceberg")[
            0
        ][0]
        == 5000
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$snapshots"',
        )[0][0]
        == 1
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$partitions"',
        )[0][0]
        == 12
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$files"',
        )[0][0]
        == 12
    )

    assert (
        run_query(
            connection,
            "INSERT INTO iceberg.s3.taxi_data_copy_iceberg SELECT * FROM hive.s3.taxi_data",
        )[0][0]
        == 5000
    )

    # Check current count
    assert (
        run_query(connection, "SELECT COUNT(*) FROM iceberg.s3.taxi_data_copy_iceberg")[
            0
        ][0]
        == 10000
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$snapshots"',
        )[0][0]
        == 2
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$partitions"',
        )[0][0]
        == 12
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$files"',
        )[0][0]
        == 24
    )

    if trino_version == "377":
        # io.trino.spi.TrinoException: This connector [iceberg] does not support versioned tables
        print(
            "[INFO] Skipping the Iceberg tests reading versioned tables for trino version 377 as it does not support versioned tables"
        )
    else:
        # Check count for first snapshot
        first_snapshot = run_query(
            connection,
            'select snapshot_id from iceberg.s3."taxi_data_copy_iceberg$snapshots" order by committed_at limit 1',
        )[0][0]
        assert (
            run_query(
                connection,
                f"SELECT COUNT(*) FROM iceberg.s3.taxi_data_copy_iceberg FOR VERSION AS OF {first_snapshot}",
            )[0][0]
            == 5000
        )

    # Compact files
    run_query(
        connection, "ALTER TABLE iceberg.s3.taxi_data_copy_iceberg EXECUTE optimize"
    )

    # Check current count
    assert (
        run_query(connection, "SELECT COUNT(*) FROM iceberg.s3.taxi_data_copy_iceberg")[
            0
        ][0]
        == 10000
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$snapshots"',
        )[0][0]
        == 3
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$partitions"',
        )[0][0]
        == 12
    )
    assert (
        run_query(
            connection,
            'SELECT COUNT(*) FROM iceberg.s3."taxi_data_copy_iceberg$files"',
        )[0][0]
        == 12
    )  # Compaction yeah :)

    # Test could be improved by also testing update and deletes

    # # Test postgres connection
    # run_query(connection, "SHOW SCHEMAS IN postgresgeneric")
    # run_query(connection, "CREATE SCHEMA IF NOT EXISTS postgresgeneric.tpch")
    # run_query(
    #     connection,
    #     "CREATE TABLE IF NOT EXISTS postgresgeneric.tpch.nation AS SELECT * FROM tpch.tiny.nation",
    # )
    # assert (
    #     run_query(connection, "SELECT COUNT(*) FROM postgresgeneric.tpch.nation")[0][0]
    #     == 25
    # )

    print("[SUCCESS] All tests in check-s3.py succeeded!")
