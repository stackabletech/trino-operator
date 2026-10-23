#!/usr/bin/env python
"""Run a data-modifying query against Trino so the OpenLineage event listener emits lineage events.

A plain SELECT is filtered out by the plugin's default `include-query-types`; a CREATE TABLE AS
SELECT (INSERT / DATA_DEFINITION) is emitted, with `tpch.tiny.nation` as the input dataset and the
blackhole table as the output dataset.
"""

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

    cursor.execute("CREATE SCHEMA IF NOT EXISTS blackhole.lineage_test")
    cursor.fetchall()
    cursor.execute("DROP TABLE IF EXISTS blackhole.lineage_test.nation_copy")
    cursor.fetchall()
    cursor.execute(
        "CREATE TABLE blackhole.lineage_test.nation_copy AS SELECT * FROM tpch.tiny.nation"
    )
    result = cursor.fetchone()
    assert result[0] == 25, f"unexpected CTAS row count: {result[0]}"
    print("CTAS executed, OpenLineage events should have been emitted")
