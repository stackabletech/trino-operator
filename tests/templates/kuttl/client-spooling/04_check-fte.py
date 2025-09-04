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

        print("🚜 fetching many rows from Trino to trigger spooling...")

        cursor.execute("SELECT * FROM tpch.sf100.customer")
        customer_count = 0
        batch = 10
        while batch > 0:
            print(f"⏳ fetching batch {batch} of 1000 rows...")
            cursor.fetchmany(1_000)
            customer_count += 1_000
            batch = batch - 1
        # assert customer_count == 15_000_000, f"TPCH test failed: expected 15 mil customers, got {customer_count}"

        print("🎉 major success!")

        cursor.close()

    except Exception as e:
        print(f"💀 oh noes! cannot fetch customers from Trino: {e}")
        raise e

    finally:
        conn.close()
