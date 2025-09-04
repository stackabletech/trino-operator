#!/usr/bin/env python
import trino
import argparse
import urllib3


def get_connection(coordinator):
    """Create anonymous connection for basic cluster health check"""
    conn = trino.dbapi.connect(
        host=coordinator,
        port=8443,
        user="test",
        http_scheme="https",
        verify=False,
        session_properties={"query_max_execution_time": "60s"},
    )
    return conn


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Construct an argument parser
    all_args = argparse.ArgumentParser()

    # Add arguments to the parser
    all_args.add_argument(
        "-c",
        "--coordinator",
        required=True,
        help="Trino Coordinator Host to connect to",
    )

    args = vars(all_args.parse_args())

    conn = get_connection(args["coordinator"])

    try:
        cursor = conn.cursor()

        # The table tpch.sf100.customer has 15 million rows but Python consumes
        # too much memory to retrieve all of them at once.
        # Fetching them one by one is too slow, so we fetch enough rows
        # for Trino to use the spooling protocol.
        # Fetching too few rows is risky as Trino might decide to not use spooling.

        print("🚜 fetching many rows from Trino to trigger spooling...")

        customer_count = 0
        batch_count = 50
        batch_size = 1_000
        expected_customers = batch_count * 1_000

        cursor.execute("SELECT * FROM tpch.sf100.customer")
        while batch_count > 0:
            print(f"⏳ fetching batch {batch_count} of {batch_size} rows...")
            _ = cursor.fetchmany(batch_size)
            customer_count += batch_size
            batch_count = batch_count - 1

        assert customer_count == expected_customers, (
            f"💀 crap! expected {expected_customers} customers, got {customer_count}"
        )

        print("🎉 major success!")

        cursor.close()

    except Exception as e:
        print(f"💀 oh noes! cannot fetch customers from Trino: {e}")
        raise e

    finally:
        conn.close()
