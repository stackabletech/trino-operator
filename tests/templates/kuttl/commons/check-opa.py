#!/usr/bin/env python
import argparse
import sys

import trino
import trino.exceptions as trino_ex

if not sys.warnoptions:
    import warnings
warnings.simplefilter("ignore")


def get_connection(username, password, coordinator):
    conn = trino.dbapi.connect(
        host=coordinator,
        port=8443,
        user=username,
        http_scheme="https",
        auth=trino.auth.BasicAuthentication(username, password),
        verify=False,
        # Commented out because it apparently breaks the OPA rules.
        # With this enabled, the script fails to validate that user bob can
        # show catalogs.
        # session_properties={"query_max_execution_time": "60s"},
    )
    return conn


def test_user(user, password, coordinator, query):
    conn = get_connection(user, password, coordinator)
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        cursor.fetchone()
        return True
    except trino_ex.Error:
        return False


def main():
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-c", "--coordinator", required=True, help="Trino Coordinator Host to connect to")

    args = vars(all_args.parse_args())
    coordinator = args["coordinator"]

    # We expect the admin user query to pass
    if not test_user("admin", "admin", coordinator, "SHOW CATALOGS"):
        print("User admin cannot show catalogs!")
        sys.exit(-1)
    # We expect the admin user query to pass
    if not test_user("admin", "admin", coordinator, "SHOW SCHEMAS FROM system"):
        print("User admin cannot select schemas from system")
        sys.exit(-1)
    # We expect the bob query for catalogs to pass
    if not test_user("bob", "bob", coordinator, "SHOW CATALOGS"):
        print("User bob cannot show catalogs!")
        sys.exit(-1)
    # We expect the bob query for schemas to fail
    if test_user("bob", "bob", coordinator, "SHOW SCHEMAS FROM system"):
        print("User bob can show schemas from system. This should not be happening!")
        sys.exit(-1)

    print("Test check-opa.py succeeded!")


if __name__ == "__main__":
    main()
