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

# TODO Implement the following operations:
# * CreateFunction
# * CreateSchema
# * CreateViewWithExecuteFunction
# * CreateViewWithSelectFromColumns
# * DeleteFromTable
# * DropFunction
# * DropTable
# * DropView
# * ExecuteFunction
# * ExecuteProcedure
# * ExecuteTableProcedure
# * FilterColumns
# * FilterFunctions
# * FilterViewQueryOwnedBy
# * ImpersonateUser
# * RenameMaterializedView
# * RenameSchema
# * RenameView
# * SetSchemaAuthorization
# * SetTableAuthorization
# * SetViewAuthorization
# * ShowColumns
# * UpdateTableColumns

required_permissions := permissions if {
	operation == "AccessCatalog"
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.catalog.name,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation in {
		"AddColumn",
		"AlterColumn",
		"CreateTable",
		"CreateView",
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
		"CreateMaterializedView",
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
	operation == "KillQueryOwnedBy"
	permissions := {{
		"resource": "query_owned_by",
		"user": action.resource.user.user,
		"allow": {"kill"},
	}}
}

required_permissions := permissions if {
	operation == "ViewQueryOwnedBy"
	permissions := {{
		"resource": "query_owned_by",
		"user": action.resource.user.user,
		"allow": {"view"},
	}}
}

required_permissions := permissions if {
	operation == "FilterCatalogs"
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.catalog.name,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation == "FilterSchemas"

	# SHOW SCHEMAS requires read-only access on the catalog. Ownership
	# of the schema is not required and therefore the schemaName is not
	# checked.
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.schema.catalogName,
		"allow": "read-only",
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
		"ShowCreateSchema",
		"DropSchema",
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
	operation == "RenameTable"
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
			"columns": action.resource.table.columns,
			"privileges": {"allOf": {"SELECT"}},
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

required_catalog_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "catalog"
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
