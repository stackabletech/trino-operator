package verification_test

import data.trino
import rego.v1

testcontext := {
	"identity": {
		"groups": ["testgroup1", "testgroup2"],
		"user": "testuser",
	},
	"softwareStack": {"trinoVersion": "440"},
}

test_allow_with_authorization_request if {
	request := {
		"action": {
			"operation": "SetSchemaAuthorization",
			"resource": {"schema": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
			}},
			"grantee": {
				"name": "testuser",
				"type": "testusertype",
			},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"authorization": [{"new_user": "testuser"}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"authorization": [{"new_user": "otheruser"}]}
}

test_allow_with_catalog_request if {
	request := {
		"action": {
			"operation": "AccessCatalog",
			"resource": {"catalog": {"name": "testcatalog"}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"catalogs": [{"allow": "all"}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"catalogs": [{"allow": "none"}]}
}

test_allow_with_catalog_session_properties_request if {
	request := {
		"action": {
			"operation": "SetCatalogSessionProperty",
			"resource": {"catalogSessionProperty": {
				"catalogName": "testcatalog",
				"propertyName": "testproperty",
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"catalog_session_properties": [{"allow": true}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"catalog_session_properties": [{"allow": false}]}
}

test_allow_with_column_request if {
	request := {
		"action": {
			"operation": "SelectFromColumns",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columns": ["testcolumn1", "testcolumn2"],
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"tables": [{
			"privileges": ["SELECT"],
			"columns": [{
				"name": "testcolumn1",
				"allow": true,
			}],
		}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"tables": [{
			"privileges": ["SELECT"],
			"columns": [{
				"name": "testcolumn1",
				"allow": false,
			}],
		}]}
}

test_allow_with_function_request if {
	request := {
		"action": {
			"operation": "ExecuteFunction",
			"resource": {"function": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"functionName": "testfunction",
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"functions": [{"privileges": ["EXECUTE"]}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"functions": [{"privileges": []}]}
}

test_allow_with_impersonation_request if {
	request := {
		"action": {
			"operation": "ImpersonateUser",
			"resource": {"user": {"user": "otheruser"}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"impersonation": [{
			"new_user": "otheruser",
			"allow": true,
		}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"impersonation": [{
			"new_user": "otheruser",
			"allow": false,
		}]}
}

test_allow_with_procedure_request if {
	request := {
		"action": {
			"operation": "ExecuteProcedure",
			"resource": {"function": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"functionName": "testprocedure",
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"procedures": [{"privileges": ["EXECUTE"]}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"procedures": [{"privileges": []}]}
}

test_allow_with_query_request if {
	request := {
		"action": {"operation": "ExecuteQuery"},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"queries": [{"allow": ["execute"]}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"queries": [{"allow": []}]}
}

test_allow_with_schema_request if {
	request := {
		"action": {
			"operation": "CreateSchema",
			"resource": {"schema": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"properties": {},
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"schemas": [{"owner": true}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"schemas": [{"owner": false}]}
}

test_allow_with_table_request if {
	request := {
		"action": {
			"operation": "CreateTable",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"properties": {},
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"tables": [{"privileges": ["OWNERSHIP"]}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"tables": [{"privileges": []}]}
}

test_allow_with_system_information_request if {
	request := {
		"action": {"operation": "ReadSystemInformation"},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"system_information": [{"allow": ["read"]}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"system_information": [{"allow": []}]}
}

test_allow_with_system_session_properties_request if {
	request := {
		"action": {
			"operation": "SetSystemSessionProperty",
			"resource": {"systemSessionProperty": {"name": "testproperty"}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"system_session_properties": [{"allow": true}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"system_session_properties": [{"allow": false}]}
}
