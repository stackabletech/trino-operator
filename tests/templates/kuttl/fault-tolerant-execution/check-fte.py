#!/usr/bin/env python
import trino
import argparse

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
        "-w",
        "--workers",
        required=True,
        help="Expected amount of workers to be present",
    )

    args = vars(all_args.parse_args())

    expected_workers = args["workers"]
    conn = get_connection(args["coordinator"])

    try:
        cursor = conn.cursor()

        # Check that workers are active
        cursor.execute(
            "SELECT COUNT(*) as nodes FROM system.runtime.nodes WHERE coordinator=false AND state='active'"
        )
        (active_workers,) = cursor.fetchone()

        if int(active_workers) != int(expected_workers):
            print(
                "Mismatch: [expected/active] workers ["
                + str(expected_workers)
                + "/"
                + str(active_workers)
                + "]"
            )
            exit(-1)

        print(f"Active workers check passed: {active_workers}/{expected_workers}")

        # Test that TPCH connector is working
        cursor.execute("SELECT COUNT(*) FROM tpch.tiny.nation")
        result = cursor.fetchone()
        if result[0] != 25:  # TPCH tiny.nation has 25 rows
            print(f"TPCH test failed: expected 25 nations, got {result[0]}")
            exit(-1)

        print("TPCH connector test passed")

        # Test a more complex query
        cursor.execute("""
            SELECT
                nation.name,
                COUNT(*) AS num_cust
            FROM
                tpch.tiny.customer
            JOIN
                tpch.tiny.nation ON customer.nationkey = nation.nationkey
            GROUP BY
                nation.name
            ORDER BY
                num_cust DESC
        """)
        results = cursor.fetchall()
        if len(results) == 0:
            print("Complex query returned no results")
            exit(-1)

    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(-1)
