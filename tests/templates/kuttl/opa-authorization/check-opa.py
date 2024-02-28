#!/usr/bin/env python
import argparse
import pytest
import trino

from datetime import datetime
from trino.exceptions import TrinoUserError

import urllib3
urllib3.disable_warnings()


TEST_DATA = [
    {
        "user": {
            "name": "admin",
            "password": "admin",
            "groups": ["admin"],
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "expected": [["lakehouse"],["system"],["tpcds"],["tpch"]],
            },
            {
                "query": "SHOW SCHEMAS in lakehouse",
                "expected": [["information_schema"],["sf1"],["sf100"],["sf1000"],["sf10000"],["sf100000"],["sf300"],["sf3000"],["sf30000"],["tiny"]],
            },
            {
                "query": "SHOW SCHEMAS in system",
                "expected": [["information_schema"],["jdbc"],["metadata"],["runtime"]],
            },
            {
                "query": "SHOW SCHEMAS in tpcds",
                "expected": [["information_schema"],["sf1"],["sf10"],["sf100"],["sf1000"],["sf10000"],["sf100000"],["sf300"],["sf3000"],["sf30000"],["tiny"]],
            },    
            {
                "query": "SHOW TABLES in lakehouse.sf1",
                "expected": [["customer"],["lineitem"],["nation"],["orders"],["part"],["partsupp"],["region"],["supplier"]],
            },                       
        ]
    },
    {
        "user": {
            "name": "bob",
            "password": "bob",
            "groups": [],
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "expected": [["lakehouse"]],
            },
            {
                "query": "SELECT * from lakehouse.sf1.customer",
                "error": "Access Denied: Cannot select from columns",
            },            
        ]
    }    
]

class TestOpa:

    def __init__(self, test_data, namespace):
        self.data = test_data
        self.namespace = namespace


    def run(self):
        for test_case in self.data:
            user = test_case["user"]["name"]

            connection = TestOpa.get_connection(user, test_case["user"]["password"], self.namespace)

            for test in test_case["tests"]:
                query = test["query"]

                if "error" in test:
                    error = test["error"]
                    with pytest.raises(TrinoUserError, match=error):
                        TestOpa.log(user, query)
                        TestOpa.run_query(connection, query)
                else:
                    TestOpa.log(user, query)
                    assert TestOpa.run_query(connection, query) == test["expected"]

            print("")

    def log(user, query):
        timestamp = datetime.utcnow().isoformat(sep=' ', timespec='milliseconds')
        print(f'[{timestamp}] - {user:20s} -> {query}')


    def run_query(connection, query):
        cursor = connection.cursor()
        cursor.execute(query)
        return cursor.fetchall()


    def run_query_with_error(connection, query):
        cursor = connection.cursor()
        cursor.execute(query)
        return cursor.fetchall()


    def get_connection(username, password, namespace):
        connection = trino.dbapi.connect(
            host="trino-coordinator.{0}.svc.cluster.local".format(namespace),
            port=8443,
            user=username,
            http_scheme="https",
            auth=trino.auth.BasicAuthentication(username, password),
            verify=False,
        )
        return connection
    

def main():
    # Construct an argument parser
    all_args = argparse.ArgumentParser()
    # Add arguments to the parser
    all_args.add_argument(
        "-n", "--namespace", required=True, help="Namespace the test is running in"
    )

    args = vars(all_args.parse_args())
    namespace = args["namespace"]

    test = TestOpa(TEST_DATA, namespace)
    test.run()


if __name__ == "__main__":
    main()
