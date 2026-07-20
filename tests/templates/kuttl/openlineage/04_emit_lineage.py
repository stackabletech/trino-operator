#!/usr/bin/env python
"""Run a query against Trino to make the OpenLineage event listener emit lineage events."""

import argparse

import trino


def get_connection(coordinator):
    return trino.dbapi.connect(
        host=coordinator,
        port=8443,
        user="test",
        http_scheme="https",
        verify=False,
        session_properties={"query_max_execution_time": "60s"},
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--coordinator",
        required=True,
        help="Trino Coordinator Host to connect to",
    )
    args = vars(parser.parse_args())

    conn = get_connection(args["coordinator"])
    cursor = conn.cursor()
    # Reads the built-in tpch dataset; the OpenLineage listener reports `tpch.tiny.nation` as an
    # input dataset in the emitted (START + COMPLETE) query events.
    cursor.execute("SELECT COUNT(*) FROM tpch.tiny.nation")
    result = cursor.fetchone()
    assert result[0] == 25, f"unexpected tpch.tiny.nation row count: {result[0]}"
    print("query executed, OpenLineage events should have been emitted")
