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


def test_user(user, password, ns, query):
    conn = get_connection(user, password, ns)
    cursor = conn.cursor()
    cursor.execute(query)
    try:
        cursor.fetchone()
        return True
    except Exception:
        return False


if __name__ == '__main__':
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument("-n", "--namespace", required=True, help="Namespace the test is running in")

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    # We expect the admin user query to pass
    if not test_user("admin", "admin", namespace, "SHOW CATALOGS"):
        print("User admin cannot show catalogs!")
        exit(-1)
    # We expect the admin user query to pass
    if not test_user("admin", "admin", namespace, "SHOW SCHEMAS FROM system"):
        print("User admin cannot select schemas from system")
        exit(-1)
    # We expect the bob query for catalogs to pass
    if not test_user("bob", "bob", namespace, "SHOW CATALOGS"):
        print("User bob cannot show catalogs!")
        exit(-1)
    # We expect the bob query for schemas to fail
    if test_user("bob", "bob", namespace, "SHOW SCHEMAS FROM system"):
        print("User bob can show schemas from system. This should not be happening!")
        exit(-1)

    print("Test check-opa.py succeeded!")
