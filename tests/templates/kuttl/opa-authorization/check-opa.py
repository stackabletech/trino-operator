#!/usr/bin/env python
import pytest

import trino
from trino.exceptions import TrinoUserError

USER_PASSWORDS = {
    "admin": "admin",
    "superset": "superset",
    "data-analyst-1": "data-analyst-1",
    "data-analyst-2": "data-analyst-2",
    "data-analyst-3": "data-analyst-3",
    "customer-1-user-1": "customer-1-user-1",
    "customer-1-user-2": "customer-1-user-2",
    "customer-2-user-1": "customer-2-user-1",
    "customer-2-user-2": "customer-2-user-2",
}

def get_connection(username):
    conn = trino.dbapi.connect(
        host="127.0.0.1",
        port=8443,
        user=username,
        http_scheme="https",
        auth=trino.auth.BasicAuthentication(username, USER_PASSWORDS[username]),
        verify=False,
    )
    return conn

def run(connection, query):
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def test_can_execute_queries():
    """Everyone should be able to execute queries"""
    for username in USER_PASSWORDS.keys():
        connection = get_connection(username)
        assert run(connection, "select 42")[0][0] == 42

def test_admin_access():
    admin = get_connection("admin")
    assert run(admin, "show catalogs")[:][:] == [["lakehouse"],["system"],["tpcds"],["tpch"]]
    assert run(admin, "show schemas in system")[:][:] == [["information_schema"],["jdbc"],["metadata"],["runtime"]]
    assert run(admin, "show schemas in tpcds")[:][:] == [["information_schema"],["sf1"],["sf10"],["sf100"],["sf1000"],["sf10000"],["sf100000"],["sf300"],["sf3000"],["sf30000"],["tiny"]]
    assert run(admin, "show schemas in tpch")[:][:] == [["information_schema"],["sf1"],["sf100"],["sf1000"],["sf10000"],["sf100000"],["sf300"],["sf3000"],["sf30000"],["tiny"]]

def test_data_analyst_1_access():
    for user in ["data-analyst-1", "data-analyst-1"]:
        admin = get_connection(user)
        assert run(admin, "show catalogs")[:][:] == [["lakehouse"],["system"],["tpch"]]
        assert run(admin, "show schemas in system")[:][:] == [["information_schema"],["jdbc"],["metadata"],["runtime"]]
        with pytest.raises(TrinoUserError) as e:
            run(admin, "show schemas in tpcds")
        assert run(admin, "show schemas in tpch")[:][:] == [["information_schema"],["sf1"],["sf100"],["sf1000"],["sf10000"],["sf100000"],["sf300"],["sf3000"],["sf30000"],["tiny"]]
