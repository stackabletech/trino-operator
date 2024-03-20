#!/usr/bin/env python
import argparse
import pytest
import trino

from datetime import datetime
from trino.exceptions import TrinoUserError

import urllib3
urllib3.disable_warnings()

# Currently missing operation checks:
#
# CreateViewWithExecuteFunction
# CreateViewWithSelectFromColumns
# ExecuteFunction
# ExecuteTableProcedure
# FilterFunctions
# KillQueryOwnedBy
# ReadSystemInformation
# ViewQueryOwnedBy
# WriteSystemInformation
TEST_DATA = [
    {
        # Admin user with all permissions
        "user": {
            "name": "admin",
            "password": "admin",
        },
        "tests": [
            # ## CATALOG ##
            # ExecuteQuery, FilterCatalogs
            {
                "query": "SHOW CATALOGS",
                "expected": [["iceberg"], ["lakehouse"], ["system"], ["tpcds"], ["tpch"]],
            },
            # ExecuteQuery, FilterCatalogs, ImpersonateUser
            {
                "query": "SHOW CATALOGS",
                "expected": [["iceberg"]],
                "impersonation": "iceberg",
            },
            # ExecuteQuery, AccessCatalog, SetCatalogSessionProperty
            {
                "query": "SET SESSION iceberg.test=true",
                # The requests are authorized, just a fake property
                "error": "Session property 'iceberg.test' does not exist",
            },
            # ## SCHEMA ##
            # ExecuteQuery, AccessCatalog, ShowSchemas, SelectFromColumns, FilterCatalogs, FilterSchemas
            {
                "query": "SHOW SCHEMAS in tpch",
                "expected": [["information_schema"], ["sf1"], ["sf100"], ["sf1000"], ["sf10000"], ["sf100000"], ["sf300"], ["sf3000"], ["sf30000"], ["tiny"]],
            },
            # ExecuteQuery, AccessCatalog, ShowSchemas, SelectFromColumns, FilterCatalogs, FilterSchemas
            {
                "query": "SHOW SCHEMAS in system",
                "expected": [["information_schema"], ["jdbc"], ["metadata"], ["runtime"]],
            },
            # ExecuteQuery, AccessCatalog, CreateSchema
            {
                "query": "CREATE SCHEMA IF NOT EXISTS iceberg.test WITH (location = 's3a://trino/iceberg/test')",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, ShowCreateSchema
            {
                "query": "SHOW CREATE SCHEMA iceberg.test",
                "expected": [["CREATE SCHEMA iceberg.test\nAUTHORIZATION USER admin\nWITH (\n   location = 's3a://trino/iceberg/test'\n)"]],
            },
            # ExecuteQuery, AccessCatalog, SetSchemaAuthorization
            {
                "query": "ALTER SCHEMA iceberg.test SET AUTHORIZATION admin",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetSchemaAuthorization
            {
                "query": "ALTER SCHEMA iceberg.test SET AUTHORIZATION ROLE public",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support roles",
            },
            # ExecuteQuery, AccessCatalog, RenameSchema
            {
                "query": "ALTER SCHEMA iceberg.test RENAME TO test1",
                # The requests are authorized, just the hive connector does not support this
                "error": "Hive metastore does not support renaming schemas",
            },
            # ## TABLE ##
            # ExecuteQuery, AccessCatalog, ShowTables, SelectFromColumns, FilterCatalogs, FilterTables
            {
                "query": "SHOW TABLES in tpch.sf1",
                "expected": [["customer"], ["lineitem"], ["nation"], ["orders"], ["part"], ["partsupp"], ["region"], ["supplier"]],
            },
            # ExecuteQuery, AccessCatalog, CreateTable
            {
                "query": "CREATE TABLE IF NOT EXISTS iceberg.test.test (col1 bigint, col2 bigint)",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetTableComment
            {
                "query": "COMMENT ON TABLE iceberg.test.test IS 'This is a test table!'",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetColumnComment
            {
                "query": "COMMENT ON COLUMN iceberg.test.test.col1 IS 'This is a column comment!'",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetTableAuthorization
            {
                "query": "ALTER TABLE iceberg.test.test SET AUTHORIZATION admin",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support setting an owner on a table",
            },
            # ExecuteQuery, AccessCatalog, AddColumn
            {
                "query": "ALTER TABLE iceberg.test.test ADD COLUMN col3 bigint",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, RenameColumn
            {
                "query": "ALTER TABLE iceberg.test.test RENAME COLUMN col3 TO col_renamed",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, DropColumn
            {
                "query": "ALTER TABLE iceberg.test.test DROP COLUMN col_renamed",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, ShowColumns, SelectFromColumns, FilterCatalogs, FilterTables, FilterColumns
            {
                "query": "DESCRIBE iceberg.test.test",
                "expected": [["col1", "bigint", "", "This is a column comment!"], ["col2", "bigint", "", ""]],
            },
            # ExecuteQuery, AccessCatalog, InsertIntoTable
            {
                "query": "INSERT INTO iceberg.test.test VALUES (1,2),(3,4),(5,6)",
                # 3 rows inserted
                "expected": [[3]],
            },
            # ExecuteQuery, AccessCatalog, SelectFromColumns
            {
                "query": "SELECT * FROM iceberg.test.test",
                "expected": [[1, 2], [3, 4], [5, 6]],
            },
            # ExecuteQuery, AccessCatalog, UpdateTableColumns
            {
                "query": "UPDATE iceberg.test.test SET col1=1 WHERE col1>1",
                # 2 rows updated
                "expected": [[2]],
            },
            # ExecuteQuery, AccessCatalog, SelectFromColumns, DeleteFromTable
            {
                "query": "DELETE FROM iceberg.test.test WHERE col2=6",
                # 1 row deleted
                "expected": [[1]],
            },
            # ExecuteQuery, AccessCatalog, RenameTable
            {
                "query": "ALTER TABLE iceberg.test.test RENAME TO test2",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, TruncateTable
            {
                "query": "TRUNCATE TABLE iceberg.test.test2",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support truncating tables",
            },
            # ExecuteQuery, AccessCatalog, DropTable
            {
                "query": "DROP TABLE iceberg.test.test2",
                "expected": [],
            },
            # ## VIEW ##
            # ExecuteQuery, AccessCatalog, SelectFromColumns, CreateView
            {
                "query": "CREATE VIEW iceberg.test.v_customer AS SELECT name, address FROM tpch.sf1.customer",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetViewComment
            {
                "query": "COMMENT ON VIEW iceberg.test.v_customer IS 'This is a test view!'",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, SetViewAuthorization
            {
                "query": "ALTER VIEW iceberg.test.v_customer SET AUTHORIZATION admin",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support setting an owner on a table",
            },
            # ExecuteQuery, AccessCatalog, RenameView
            {
                "query": "ALTER VIEW iceberg.test.v_customer RENAME TO iceberg.test.v_customer_renamed",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, ShowCreateTable
            {
                "query": "SHOW CREATE VIEW iceberg.test.v_customer_renamed",
                "expected": [["CREATE VIEW iceberg.test.v_customer_renamed COMMENT 'This is a test view!' SECURITY DEFINER AS\nSELECT\n  name\n, address\nFROM\n  tpch.sf1.customer"]],
            },
            # ExecuteQuery, AccessCatalog, DropView
            {
                "query": "DROP VIEW iceberg.test.v_customer_renamed",
                "expected": [],
            },
            # ## MATERIALIZED VIEW ##
            # ExecuteQuery, AccessCatalog, SelectFromColumns, CreateMaterializedView
            {
                "query": "CREATE MATERIALIZED VIEW IF NOT EXISTS iceberg.test.mv_customer AS SELECT name, address FROM tpch.sf1.customer",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, RefreshMaterializedView
            {
                "query": "REFRESH MATERIALIZED VIEW iceberg.test.mv_customer",
                # refreshed 150000 rows
                "expected": [[150000]],
            },
            # ExecuteQuery, AccessCatalog, SetMaterializedViewProperties
            {
                "query": "ALTER MATERIALIZED VIEW iceberg.test.mv_customer set properties format = 'PARQUET'",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support setting materialized view properties",
            },
            # ExecuteQuery, AccessCatalog, RenameMaterializedView
            {
                "query": "ALTER MATERIALIZED VIEW iceberg.test.mv_customer RENAME TO iceberg.test.mv_customer_renamed",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, DropMaterializedView
            {
                "query": "DROP MATERIALIZED VIEW iceberg.test.mv_customer_renamed",
                "expected": [],
            },
            # ## FUNCTIONS ##
            # ExecuteQuery, AccessCatalog, ShowFunctions
            {
                "query": "SHOW FUNCTIONS IN iceberg.test",
                "expected": [],
            },
            # ExecuteQuery, AccessCatalog, CreateFunction
            {
                "query": "CREATE FUNCTION iceberg.test.meaning_of_life() RETURNS bigint RETURN 42",
                # The requests are authorized, just the hive connector does not support this
                "error": "This connector does not support creating functions",
            },
            # ExecuteQuery, AccessCatalog, DropFunction
            {
                "query": "DROP FUNCTION iceberg.test.meaning_of_life()",
                # The requests are authorized, was not created in the step above due to hive connector not supporting this
                "error": "Function not found",
            },
            # ## SystemSessionProperties ##
            # ExecuteQuery, SetSystemSessionProperty
            {
                "query": "SET SESSION optimize_hash_generation = true",
                "expected": [],
            },
            # ## PROCEDURES ##
            # ExecuteQuery, AccessCatalog, ExecuteProcedure
            {
                "query": "CALL system.runtime.kill_query(query_id => '20151207_215727_00146_tx3nr', message => 'Using too many resources')",
                # The requests are authorized, task did not exist..
                "error": "Target query not found: 20151207_215727_00146_tx3nr",
            },
            # ## QUERIES ##
            # ExecuteQuery, AccessCatalog, SelectFromColumns, FilterViewQueryOwnedBy
            {
                "query": "SELECT COUNT(*) FROM (SELECT * FROM system.runtime.queries LIMIT 1)",
                "expected": [[1]],
            },

            # ## CLEAN UP ##
            # ExecuteQuery, AccessCatalog, DropSchema
            {
                "query": "DROP SCHEMA iceberg.test",
                "expected": [],
            },
        ]
    },
    {
        # User lakehouse can:
        # - execute queries
        # - only access read-only lakehouse catalog
        # - access schemas tiny and sf1 in catalog lakehouse
        # - select only the column name in table 'customer' in schema lakehouse.tiny (not in lakehouse.sf1)
        # - select all columns in table 'customer' in lakehouse.sf1
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
                "query": "SHOW SCHEMAS IN lakehouse",
                "expected": [["information_schema"], ["sf1"], ["tiny"]],
            },
            {
                "query": "SHOW SCHEMAS IN tpch",
                "error": "Access Denied: Cannot access catalog tpch",
            },
            {
                "query": "SHOW TABLES IN lakehouse.sf1",
                "expected": [["customer"]],
            },
            {
                "query": "SELECT name FROM lakehouse.tiny.customer ORDER BY name LIMIT 1",
                "expected": [["Customer#000000001"]],
            },
            {
                "query": "SELECT * FROM lakehouse.tiny.customer ORDER BY name LIMIT 1",
                "error": "Access Denied: Cannot select from columns",
            },
            {
                "query": "SELECT * FROM lakehouse.sf1.customer ORDER BY name LIMIT 1",
                "expected": [[1, 'Customer#000000001', 'IVhzIApeRb ot,c,E', 15, '25-989-741-2988', 711.56, 'BUILDING', 'to the even, regular platelets. regular, ironic epitaphs nag e']],
            },
            {
                "query": "SELECT * FROM tpch.tiny.customer ORDER BY name LIMIT 1",
                "error": "Access Denied: Cannot access catalog tpch",
            },
            {
                # fake values, authorization is checked first
                "query": "INSERT INTO lakehouse.tiny.customer VALUES(1)",
                "error": "Access Denied: Cannot insert into table lakehouse.tiny.customer",
            }
        ]
    },
    {
        # User banned-user cannot do anything
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
        # User iceberg can:
        # - execute queries
        # - access iceberg catalog
        # - create, drop and access all schemas
        # - select, insert, delete in all tables in iceberg.* (not update!)
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
                "query": "CREATE SCHEMA IF NOT EXISTS iceberg.test2 WITH (location = 's3a://trino/test2/')",
                "expected": [],
            },
            {
                "query": "CREATE TABLE IF NOT EXISTS iceberg.test2.test (test bigint)",
                "expected": [],
            },
            {
                "query": "INSERT INTO iceberg.test2.test VALUES (1),(2)",
                "expected": [[2]],
            },
            {
                "query": "SELECT * FROM iceberg.test2.test",
                "expected": [[1], [2]],
            },
            {
                "query": "UPDATE iceberg.test2.test SET test=3 WHERE test=2",
                "error": "Access Denied: Cannot update columns",
            },
            {
                "query": "DELETE FROM iceberg.test2.test WHERE test=2",
                "expected": [[1]],
            },
            {
                "query": "DROP TABLE iceberg.test2.test",
                "expected": [],
            },
            {
                "query": "DROP SCHEMA iceberg.test2",
                "expected": [],
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
            password = test_case["user"]["password"]

            for test in test_case["tests"]:
                impersonation = None
                query = test["query"]

                if "impersonation" in test:
                    impersonation = test["impersonation"]

                # could be optimized to not create a connection for every call (currently due to user impersonation)
                connection = TestOpa.get_connection(user, password, self.namespace, impersonation)

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

    def get_connection(username, password, namespace, impersonation=None):
        connection = trino.dbapi.connect(
            host="trino-coordinator.{0}.svc.cluster.local".format(namespace),
            port=8443,
            user=impersonation if impersonation is not None else username,
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
