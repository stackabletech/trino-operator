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
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "expected": [["iceberg"],["lakehouse"],["system"],["tpcds"],["tpch"]],
            },
            {
                "query": "SHOW SCHEMAS in tpch",
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
                "query": "SHOW TABLES in tpch.sf1",
                "expected": [["customer"],["lineitem"],["nation"],["orders"],["part"],["partsupp"],["region"],["supplier"]],
            },
            {
                "query": "CREATE SCHEMA IF NOT EXISTS iceberg.sf1 WITH (location = 's3a://trino/sf1/')",
                "expected": [],
            },
            {
                "query": "CREATE OR REPLACE VIEW iceberg.sf1.v_customer AS SELECT * FROM tpch.sf1.customer",
                "expected": [],
            },            
            {
                "query": "SELECT AVG(nationkey) FROM iceberg.sf1.v_customer",
                "expected": [[12.0067]],
            },
            {
                "query": "CREATE TABLE IF NOT EXISTS iceberg.sf1.small_customer (orderkey bigint)",
                "expected": [],
            },  
            {
                "query": "INSERT INTO iceberg.sf1.small_customer VALUES (2)",
                "expected": [[1]],
            }, 
            {
                "query": "SELECT * FROM iceberg.sf1.small_customer",
                "expected": [[2]],
            },
            {
                "query": "ALTER TABLE iceberg.sf1.small_customer RENAME TO iceberg.sf1.big_customer",
                "expected": [],
            },             
            {
                "query": "DROP TABLE iceberg.sf1.big_customer",
                "expected": [],
            }, 
            {
                "query": "DROP VIEW iceberg.sf1.v_customer",
                "expected": [],
            },     
            {
                "query": "DROP SCHEMA iceberg.sf1",
                "expected": [],
            },             
        ]
    },
    {
        "user": {
            "name": "lakehouse",
            "password": "lakehouse",
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
    },
    {
        "user": {
            "name": "banned-user",
            "password": "banned-user",
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "error": "Access Denied: Cannot execute query",
            },
        ]
    },
    {
        "user": {
            "name": "select-columns",
            "password": "select-columns",
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "expected": [["tpch"]],
            },
            {
                "query": "SELECT * FROM tpch.sf1.customer",
                "error": "Access Denied: Cannot select from columns",
            },
            {
                "query": "SELECT name FROM tpch.sf1.customer ORDER BY name LIMIT 1",
                "expected": [["Customer#000000001"]],
            },
        ]
    },
    {
        "user": {
            "name": "iceberg",
            "password": "iceberg",
        },
        "tests": [
            {
                "query": "SHOW CATALOGS",
                "expected": [["iceberg"]],
            },
            {
                "query": "CREATE SCHEMA IF NOT EXISTS iceberg.test WITH (location = 's3a://trino/test/')",
                "expected": [],
            },
            {
                "query": "CREATE TABLE IF NOT EXISTS iceberg.test.small_customer (orderkey bigint)",
                "expected": [],
            },
            {
                "query": "SELECT * FROM iceberg.test.small_customer",
                "expected": [[2]],
            },
            {
                "query": "DELETE FROM iceberg.test.small_customer WHERE orderkey=2",
                "error": "Access Denied: Cannot delete from table",
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
                    result = TestOpa.run_query(connection, query)
                    print(result)
                    assert result == test["expected"]

            print("")

    def log(user, query):
        timestamp = datetime.utcnow().isoformat(sep=' ', timespec='milliseconds')
        print(f'[{timestamp}] - {user:20s} -> {query}')


    def run_query(connection, query):
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
