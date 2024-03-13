package requested_permissions_test

import data.trino
import rego.v1

# These tests check that the returned rules are well-formed. Typos and
# copy-and-paste errors should be detected. It is not checked if the
# rules are sensible, e.g. that the InsertIntoTable operation requests
# the INSERT privilege.

default permissions_valid(_) := false

permissions_valid(permissions) if {
	every permission in permissions {
		permission_valid(permission)
	}
}

default permission_valid(_) := false

permission_valid(permission) if {
	permission.resource == "authorization"

	object.keys(permission) == {
		"resource",
		"granteeName",
		"granteeType",
		"allow",
	}

	is_string(permission.granteeName)
	is_string(permission.granteeType)
	is_boolean(permission.allow)
}

permission_valid(permission) if {
	permission.resource == "catalog"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"allow",
	}

	is_string(permission.catalogName)
	permission.allow in {"all", "read-only", "none"}
}

permission_valid(permission) if {
	permission.resource == "catalog_session_properties"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"propertyName",
		"allow",
	}

	is_string(permission.catalogName)
	is_string(permission.propertyName)
	is_boolean(permission.allow)
}

permission_valid(permission) if {
	permission.resource == "column"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"tableName",
		"columnName",
		"allow",
	}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_string(permission.tableName)
	is_string(permission.columnName)
	is_boolean(permission.allow)
}

permission_valid(permission) if {
	permission.resource == "function"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"functionName",
		"privileges",
	}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_string(permission.functionName)
	object.subset(
		{
			"GRANT_EXECUTE",
			"EXECUTE",
			"OWNERSHIP",
		},
		permission.privileges,
	)
}

permission_valid(permission) if {
	permission.resource == "impersonation"

	object.keys(permission) == {
		"resource",
		"user",
		"allow",
	}

	is_string(permission.user)
	is_boolean(permission.allow)
}

permission_valid(permission) if {
	permission.resource == "procedure"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"functionName",
		"privileges",
	}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_string(permission.functionName)
	object.subset({"GRANT_EXECUTE", "EXECUTE"}, permission.privileges)
}

permission_valid(permission) if {
	permission.resource == "query"

	object.keys(permission) == {
		"resource",
		"allow",
	}

	object.subset({"execute", "kill", "view"}, permission.allow)
}

permission_valid(permission) if {
	permission.resource == "query_owned_by"

	object.keys(permission) == {
		"resource",
		"user",
		"groups",
		"allow",
	}

	is_string(permission.user)
	is_array(permission.groups)
	object.subset({"kill", "view"}, permission.allow)
}

permission_valid(permission) if {
	permission.resource == "schema"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"owner",
	}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_boolean(permission.owner)
}

permission_valid(permission) if {
	permission.resource == "system_information"

	object.keys(permission) == {
		"resource",
		"allow",
	}

	object.subset({"read", "write"}, permission.allow)
}

permission_valid(permission) if {
	permission.resource == "system_session_properties"

	object.keys(permission) == {
		"resource",
		"propertyName",
		"allow",
	}

	is_string(permission.propertyName)
	is_boolean(permission.allow)
}

permission_valid(permission) if {
	permission.resource == "table"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"tableName",
		"privileges",
	}
	object.keys(permission.privileges) == {"allOf"}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_string(permission.tableName)
	object.subset(
		{
			"DELETE",
			"GRANT_SELECT",
			"INSERT",
			"OWNERSHIP",
			"SELECT",
			"UPDATE",
		},
		permission.privileges.allOf,
	)
}

permission_valid(permission) if {
	permission.resource == "table"

	object.keys(permission) == {
		"resource",
		"catalogName",
		"schemaName",
		"tableName",
		"privileges",
	}
	object.keys(permission.privileges) == {"anyOf"}

	is_string(permission.catalogName)
	is_string(permission.schemaName)
	is_string(permission.tableName)
	object.subset(
		{
			"DELETE",
			"GRANT_SELECT",
			"INSERT",
			"OWNERSHIP",
			"SELECT",
			"UPDATE",
		},
		permission.privileges.anyOf,
	)
}

testcontext := {
	"identity": {
		"groups": ["testgroup1", "testgroup2"],
		"user": "testuser",
	},
	"softwareStack": {"trinoVersion": "440"},
}

test_access_filter_catalog if {
	operations := {
		"AccessCatalog",
		"FilterCatalogs",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"catalog": {"name": "testcatalog"}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_create_schema if {
	permissions := trino.requested_permissions with input as {
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

	permissions_valid(permissions)
}

test_filter_columns if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "FilterColumns",
			"resource": {"table": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
				"tableName": "testtable",
				"columnName": "testcolumn",
			}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_function_resource_actions if {
	operations := {
		"CreateFunction",
		"CreateViewWithExecuteFunction",
		"DropFunction",
		"ExecuteFunction",
		"ExecuteProcedure",
		"FilterFunctions",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"function": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"functionName": "testfunction",
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_no_resource_action if {
	operations := {
		"ExecuteQuery",
		"ReadSystemInformation",
		"WriteSystemInformation",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {"operation": operation},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_execute_table_procedure if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "ExecuteTableProcedure",
			"resource": {
				"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
				},
				"function": {"functionName": "testprocedure"},
			},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_column_operations_on_table_like_objects if {
	operations := {
		"CreateViewWithSelectFromColumns",
		"SelectFromColumns",
		"UpdateTableColumns",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
					"columns": ["testcolumn1", "testcolumn2"],
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_show_schemas if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "ShowSchemas",
			"resource": {"catalog": {"name": "testcatalog"}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_table_resource_actions if {
	operations := {
		"AddColumn",
		"AlterColumn",
		"CreateView",
		"DeleteFromTable",
		"DropColumn",
		"DropMaterializedView",
		"DropTable",
		"DropView",
		"FilterTables",
		"InsertIntoTable",
		"RefreshMaterializedView",
		"RenameColumn",
		"SetColumnComment",
		"SetTableComment",
		"SetViewComment",
		"ShowColumns",
		"ShowCreateTable",
		"TruncateTable",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_table_with_properties_actions if {
	operations := {
		"CreateMaterializedView",
		"CreateTable",
		"SetMaterializedViewProperties",
		"SetTableProperties",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
					"properties": {
						"string_item": "string_value",
						"empty_item": null,
						"boxed_number_item": 32,
					},
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_identity_resource_actions if {
	operations := {
		"FilterViewQueryOwnedBy",
		"KillQueryOwnedBy",
		"ViewQueryOwnedBy",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"user": {
					"user": "testuser",
					"groups": ["testgroup1", "testgroup2"],
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_schema_resource_actions if {
	operations := {
		"DropSchema",
		"FilterSchemas",
		"ShowCreateSchema",
		"ShowFunctions",
		"ShowTables",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"schema": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_rename_table_like_object if {
	operations := {
		"RenameMaterializedView",
		"RenameTable",
		"RenameView",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
				}},
				"targetResource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "newtesttable",
				}},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_rename_schema if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "RenameSchema",
			"resource": {"schema": {
				"catalogName": "testcatalog",
				"schemaName": "testschema",
			}},
			"targetResource": {"schema": {
				"catalogName": "testcatalog",
				"schemaName": "newtestschema",
			}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_set_catalog_session_properties if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "SetCatalogSessionProperty",
			"resource": {"catalogSessionProperty": {
				"catalogName": "testcatalog",
				"propertyName": "testproperty",
			}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_set_system_session_properties if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "SetSystemSessionProperty",
			"resource": {"systemSessionProperty": {"name": "testproperty"}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}

test_set_schema_authorization if {
	permissions := trino.requested_permissions with input as {
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

	permissions_valid(permissions)
}

test_set_authorization_on_table_like_object if {
	operations := {
		"SetTableAuthorization",
		"SetViewAuthorization",
	}
	every operation in operations {
		permissions := trino.requested_permissions with input as {
			"action": {
				"operation": operation,
				"resource": {"table": {
					"catalogName": "testcatalog",
					"schemaName": "testschema",
					"tableName": "testtable",
				}},
				"grantee": {
					"name": "testuser",
					"type": "testusertype",
				},
			},
			"context": testcontext,
		}

		permissions_valid(permissions)
	}
}

test_impersonate_user if {
	permissions := trino.requested_permissions with input as {
		"action": {
			"operation": "ImpersonateUser",
			"resource": {"user": {"user": "testuser"}},
		},
		"context": testcontext,
	}

	permissions_valid(permissions)
}
