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

test_allow_with_catalog_visibility_request if {
	request := {
		"action": {
			"operation": "ShowSchemas",
			"resource": {"catalog": {"name": "testcatalog"}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {"catalogs": [{"allow": "all"}]}

	not trino.allow with input as request
		with data.trino_policies.policies as {"catalogs": [{"allow": "none"}]}
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

test_allow_with_schema_visibility_request if {
	request := {
		"action": {
			"operation": "FilterSchemas",
			"resource": {"schema": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
			}},
		},
		"context": testcontext,
	}

	trino.allow with input as request
		with data.trino_policies.policies as {
			"schemas": [{"owner": true}],
			"tables": [],
			"functions": [],
			"procedures": [],
		}

	not trino.allow with input as request
		with data.trino_policies.policies as {
			"schemas": [{"owner": false}],
			"tables": [],
			"functions": [],
			"procedures": [],
		}
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

test_batch if {
	request := {
		"action": {
			"operation": "FilterCatalogs",
			"filterResources": [
				{"catalog": {"name": "testcatalog1"}},
				{"catalog": {"name": "testcatalog2"}},
				{"catalog": {"name": "testcatalog3"}},
			],
		},
		"context": testcontext,
	}

	trino.batch == {0, 2} with input as request
		with data.trino_policies.policies as {"catalogs": [
			{
				"catalog": "testcatalog1",
				"allow": "all",
			},
			{
				"catalog": "testcatalog2",
				"allow": "none",
			},
			{"allow": "read-only"},
		]}
}

test_batch_with_filter_columns if {
	request := {
		"action": {
			"operation": "FilterColumns",
			"filterResources": [{"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columns": [
					"testcolumn1",
					"testcolumn2",
					"testcolumn3",
				],
			}}],
		},
		"context": testcontext,
	}

	trino.batch == {0, 2} with input as request
		with data.trino_policies.policies as {"tables": [{
			"privileges": ["SELECT"],
			"columns": [
				{
					"name": "testcolumn1",
					"allow": true,
				},
				{
					"name": "testcolumn2",
					"allow": false,
				},
			],
		}]}
}

test_column_mask_with_expression_and_identity if {
	request := {
		"action": {
			"operation": "GetColumnMask",
			"resource": {"column": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columnName": "testcolumn",
			}},
		},
		"context": testcontext,
	}
	policies := {"tables": [{
		"privileges": ["SELECT"],
		"columns": [{
			"name": "testcolumn",
			"mask": "testmask",
			"mask_environment": {"user": "testmaskenvironmentuser"},
		}],
	}]}

	column_mask := trino.columnMask with input as request
		with data.trino_policies.policies as policies

	column_mask == {
		"expression": "testmask",
		"identity": "testmaskenvironmentuser",
	}
}

test_column_mask_with_expression_and_no_identity if {
	request := {
		"action": {
			"operation": "GetColumnMask",
			"resource": {"column": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columnName": "testcolumn",
			}},
		},
		"context": testcontext,
	}
	policies := {"tables": [{
		"privileges": ["SELECT"],
		"columns": [{
			"name": "testcolumn",
			"mask": "testmask",
		}],
	}]}

	column_mask := trino.columnMask with input as request
		with data.trino_policies.policies as policies

	column_mask == {"expression": "testmask"}
}

test_column_mask_with_no_matching_rule if {
	request := {
		"action": {
			"operation": "GetColumnMask",
			"resource": {"column": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columnName": "testcolumn",
			}},
		},
		"context": testcontext,
	}
	policies := {}

	not trino.columnMask with input as request
		with data.trino_policies.policies as policies
}

test_row_filters_with_expression_and_identity if {
	request := {
		"action": {
			"operation": "GetRowFilters",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
			}},
		},
		"context": testcontext,
	}
	policies := {"tables": [{
		"privileges": ["SELECT"],
		"filter": "testfilter",
		"filter_environment": {"user": "testfilterenvironmentuser"},
	}]}

	row_filters := trino.rowFilters with input as request
		with data.trino_policies.policies as policies

	row_filters == {
		"expression": "testfilter",
		"identity": "testfilterenvironmentuser",
	}
}

test_row_filters_with_expression_and_no_identity if {
	request := {
		"action": {
			"operation": "GetRowFilters",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
			}},
		},
		"context": testcontext,
	}
	policies := {"tables": [{
		"privileges": ["SELECT"],
		"filter": "testfilter",
	}]}

	row_filters := trino.rowFilters with input as request
		with data.trino_policies.policies as policies

	row_filters == {"expression": "testfilter"}
}

test_row_filters_with_no_matching_rule if {
	request := {
		"action": {
			"operation": "GetColumnMask",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
			}},
		},
		"context": testcontext,
	}
	policies := {}

	not trino.rowFilters with input as request
		with data.trino_policies.policies as policies
}
