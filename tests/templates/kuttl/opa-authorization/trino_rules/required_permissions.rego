package trino

import rego.v1

# These rules replicate the file-based access control
# (https://trino.io/docs/current/security/file-system-access-control.html#table-rules).
#
# But there are differences:
# * Only `user` and `group` are matched but not `role`.
# * Filters and masks are not supported.
# * The visibility is not checked.

action := input.action

operation := action.operation

# Required permissions

required_permissions := permissions if {
	operation in {
		"AccessCatalog",
		"FilterCatalogs",
	}
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.catalog.name,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation == "CreateSchema"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.schema.catalogName,
			"allow": "read-only",
		},
		{
			"resource": "schema",
			"catalogName": action.resource.schema.catalogName,
			"schemaName": action.resource.schema.schemaName,
			"owner": true,
		},
	}
}

required_permissions := permissions if {
	operation in {
		"AddColumn",
		"AlterColumn",
		"CreateMaterializedView",
		"CreateTable",
		"CreateView",
		"CreateViewWithSelectFromColumns",
		"DropColumn",
		"DropMaterializedView",
		"DropTable",
		"DropView",
		"RenameColumn",
		"SetColumnComment",
		"SetMaterializedViewProperties",
		"SetTableComment",
		"SetTableProperties",
		"SetViewComment",
		"ShowCreateTable",
		"UpdateTableColumns",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"OWNERSHIP"}},
		},
	}
}

required_permissions := permissions if {
	operation in {
		"DeleteFromTable",
		"TruncateTable",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"DELETE"}},
		},
	}
}

required_permissions := permissions if {
	operation == "ExecuteQuery"
	permissions := {{
		"resource": "query",
		"allow": {"execute"},
	}}
}

required_permissions := permissions if {
	operation == "ExecuteTableProcedure"

	# Executing table procedures is always allowed
	permissions := set()
}

required_permissions := permissions if {
	operation == "FilterColumns"
	permissions := {{
		"resource": "column",
		"catalogName": action.resource.table.catalogName,
		"schemaName": action.resource.table.schemaName,
		"tableName": action.resource.table.tableName,
		"columnName": action.resource.table.columnName,
		"allow": true,
	}}
}

required_permissions := permissions if {
	operation == "KillQueryOwnedBy"
	permissions := {{
		"resource": "query_owned_by",
		"user": action.resource.user.user,
		"groups": action.resource.user.groups,
		"allow": {"kill"},
	}}
}

required_permissions := permissions if {
	operation in {
		"FilterViewQueryOwnedBy",
		"ViewQueryOwnedBy",
	}
	permissions := {{
		"resource": "query_owned_by",
		"user": action.resource.user.user,
		"groups": action.resource.user.groups,
		"allow": {"view"},
	}}
}

required_permissions := permissions if {
	operation == "FilterTables"
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.table.catalogName,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation in {
		"CreateFunction",
		"DropFunction",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.function.catalogName,
			"allow": "all",
		},
		{
			"resource": "function",
			"catalogName": action.resource.function.catalogName,
			"schemaName": action.resource.function.schemaName,
			"functionName": action.resource.function.functionName,
			"privileges": {"OWNERSHIP"},
		},
	}
}

required_permissions := permissions if {
	operation in {
		"ExecuteFunction",
		"ExecuteProcedure",
		"FilterFunctions",
	}
	permissions := {{
		"resource": "function",
		"catalogName": action.resource.function.catalogName,
		"schemaName": action.resource.function.schemaName,
		"functionName": action.resource.function.functionName,
		"privileges": {"EXECUTE"},
	}}
}

required_permissions := permissions if {
	operation == "CreateViewWithExecuteFunction"
	permissions := {{
		"resource": "function",
		"catalogName": action.resource.function.catalogName,
		"schemaName": action.resource.function.schemaName,
		"functionName": action.resource.function.functionName,
		"privileges": {"GRANT_EXECUTE"},
	}}
}

required_permissions := permissions if {
	operation in {
		"DropSchema",
		"ShowCreateSchema",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.schema.catalogName,
			"allow": "all",
		},
		{
			"resource": "schema",
			"catalogName": action.resource.schema.catalogName,
			"schemaName": action.resource.schema.schemaName,
			"owner": true,
		},
	}
}

required_permissions := permissions if {
	operation == "ImpersonateUser"
	permissions := {{
		"resource": "impersonation",
		"user": action.resource.user.user,
		"allow": true,
	}}
}

required_permissions := permissions if {
	operation == "InsertIntoTable"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"INSERT"}},
		},
	}
}

required_permissions := permissions if {
	operation == "ReadSystemInformation"
	permissions := {{
		"resource": "system_information",
		"allow": {"read"},
	}}
}

required_permissions := permissions if {
	operation == "RefreshMaterializedView"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"UPDATE"}},
		},
	}
}

required_permissions := permissions if {
	operation == "RenameSchema"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.schema.catalogName,
			"allow": "all",
		},
		{
			"resource": "catalog",
			"catalogName": action.targetResource.schema.catalogName,
			"allow": "all",
		},
		{
			"resource": "schema",
			"catalogName": action.resource.schema.catalogName,
			"schemaName": action.resource.schema.schemaName,
			"owner": true,
		},
		{
			"resource": "schema",
			"catalogName": action.targetResource.schema.catalogName,
			"schemaName": action.targetResource.schema.schemaName,
			"owner": true,
		},
	}
}

required_permissions := permissions if {
	operation in {
		"RenameMaterializedView",
		"RenameTable",
		"RenameView",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "catalog",
			"catalogName": action.targetResource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"OWNERSHIP"}},
		},
		{
			"resource": "table",
			"catalogName": action.targetResource.table.catalogName,
			"schemaName": action.targetResource.table.schemaName,
			"tableName": action.targetResource.table.tableName,
			"privileges": {"allOf": {"OWNERSHIP"}},
		},
	}
}

required_permissions := permissions if {
	operation == "SelectFromColumns"
	column_permissions := {
	{
		"resource": "column",
		"catalogName": action.resource.table.catalogName,
		"schemaName": action.resource.table.schemaName,
		"tableName": action.resource.table.tableName,
		"columnName": columnName,
		"allow": true,
	} |
		some columnName in action.resource.table.columns
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "read-only",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"SELECT"}},
		},
	} | column_permissions
}

required_permissions := permissions if {
	operation == "SetSchemaAuthorization"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.schema.catalogName,
			"allow": "all",
		},
		{
			"resource": "schema",
			"catalogName": action.resource.schema.catalogName,
			"schemaName": action.resource.schema.schemaName,
			"owner": true,
		},
		{
			"resource": "authorization",
			"granteeName": action.grantee.name,
			"granteeType": action.grantee.type,
			"allow": true,
		},
	}
}

required_permissions := permissions if {
	operation in {
		"SetTableAuthorization",
		"SetViewAuthorization",
	}
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"allOf": {"OWNERSHIP"}},
		},
		{
			"resource": "authorization",
			"granteeName": action.grantee.name,
			"granteeType": action.grantee.type,
			"allow": true,
		},
	}
}

required_permissions := permissions if {
	operation == "ShowColumns"
	permissions := {
		{
			"resource": "catalog",
			"catalogName": action.resource.table.catalogName,
			"allow": "all",
		},
		{
			"resource": "table",
			"catalogName": action.resource.table.catalogName,
			"schemaName": action.resource.table.schemaName,
			"tableName": action.resource.table.tableName,
			"privileges": {"anyOf": {
				"SELECT",
				"INSERT",
				"DELETE",
				"UPDATE",
				"OWNERSHIP",
				"GRANT_SELECT",
			}},
		},
	}
}

required_permissions := permissions if {
	operation == "ShowSchemas"
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.catalog.name,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation in {
		"FilterSchemas",
		"ShowFunctions",
		"ShowTables",
	}
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.schema.catalogName,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation == "SetCatalogSessionProperty"
	permissions := {{
		"resource": "catalog_session_properties",
		"catalogName": action.resource.catalogSessionProperty.catalogName,
		"propertyName": action.resource.catalogSessionProperty.propertyName,
		"allow": true,
	}}
}

required_permissions := permissions if {
	operation == "SetSystemSessionProperty"
	permissions := {{
		"resource": "system_session_properties",
		"propertyName": action.resource.systemSessionProperty.name,
		"allow": true,
	}}
}

required_permissions := permissions if {
	operation == "WriteSystemInformation"
	permissions := {{
		"resource": "system_information",
		"allow": {"write"},
	}}
}

required_authorization_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "authorization"
}

required_catalog_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "catalog"
}

required_column_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "column"
}

required_function_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "function"
}

required_impersonation_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "impersonation"
}

required_query_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "query"
}

required_query_owned_by_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "query_owned_by"
}

required_schema_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "schema"
}

required_table_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "table"
}

required_system_information_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "system_information"
}

required_catalog_session_properties_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "catalog_session_properties"
}

required_system_session_properties_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "system_session_properties"
}
