# METADATA
# schemas:
#   - input: schema.input
#   - data.policies: schema.policies
package trino

import rego.v1

# These rules replicate the file-based access control
# (https://trino.io/docs/current/security/file-system-access-control.html#table-rules).
#
# But there are differences:
# * Only `user` and `group` are matched but not `role`.
# * Filters and masks are not supported.
# * The visibility is not checked.

identity := input.context.identity

action := input.action

operation := action.operation

# Required permissions

# TODO Implement the following operations:
# * AddColumn
# * AlterColumn
# * CreateCatalog
# * CreateFunction
# * CreateMaterializedView
# * CreateSchema
# * CreateTable
# * CreateView
# * CreateViewWithExecuteFunction
# * CreateViewWithSelectFromColumns
# * DeleteFromTable
# * DropCatalog
# * DropColumn
# * DropFunction
# * DropMaterializedView
# * DropSchema
# * DropTable
# * DropView
# * ExecuteFunction
# * ExecuteProcedure
# * ExecuteTableProcedure
# * FilterColumns
# * FilterFunctions
# * FilterTables
# * FilterViewQueryOwnedBy
# * InsertIntoTable
# * KillQueryOwnedBy
# * ReadSystemInformation
# * RefreshMaterializedView
# * RenameColumn
# * RenameMaterializedView
# * RenameSchema
# * RenameView
# * SelectFromColumns
# * SetCatalogSessionProperty
# * SetColumnComment
# * SetMaterializedViewProperties
# * SetSchemaAuthorization
# * SetSystemSessionProperty
# * SetTableAuthorization
# * SetTableComment
# * SetTableProperties
# * SetViewAuthorization
# * SetViewComment
# * ShowColumns
# * ShowCreateSchema
# * ShowCreateTable
# * ShowFunctions
# * ShowTables
# * TruncateTable
# * UpdateTableColumns
# * ViewQueryOwnedBy
# * WriteSystemInformation

required_permissions := permissions if {
	operation == "AccessCatalog"
	permissions := {{
		"resource": "catalog",
		"catalogName": action.resource.catalog.name,
		"allow": "read-only",
	}}
}

required_permissions := permissions if {
	operation == "ExecuteQuery"
	permissions := {{
		"resource": "query",
		"allow": ["execute"],
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
			"columns": [],
			"privileges": ["OWNERSHIP"],
		},
		{
			"resource": "table",
			"catalogName": action.targetResource.table.catalogName,
			"schemaName": action.targetResource.table.schemaName,
			"tableName": action.targetResource.table.tableName,
			"columns": [],
			"privileges": ["OWNERSHIP"],
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
			"privileges": ["SELECT"],
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

required_catalog_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "catalog"
}

required_query_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "query"
}

required_schema_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "schema"
}

required_table_permissions contains permission if {
	some permission in required_permissions
	permission.resource == "table"
}

# Policies

# Filter policies so that only rules matching the identity are contained
policies_matching_identity[resource] := matching_rules if {
	some resource, rules in data.trino_policies.policies
	matching_rules := [rule |
		some rule in rules

		# Add an empty dummy group to iterate at least once
		some group in array.concat(identity.groups, [""])

		user_pattern := object.get(rule, "user", ".*")
		group_pattern := object.get(rule, "group", ".*")

		regex.match(user_pattern, identity.user)
		regex.match(group_pattern, group)
	]
}

# Actual permissions
#
# Functions are used instead of rules to avoid the binding to a specific
# property in the actions structure.

catalog_access_map := {
	"all": {"all", "read-only"},
	"read-only": {"read-only"},
	"none": {"none"},
}

# Catalog access of the first matching rule
default catalog_access(_) := "none"

catalog_access(catalog_name) := access if {
	rules := [rule |
		some rule in policies_matching_identity.catalogs

		catalog_pattern := object.get(rule, "catalog", ".*")

		regex.match(catalog_pattern, catalog_name)
	]
	access := catalog_access_map[rules[0].allow]
}

# Query access of the first matching rule
default query_access := ["execute", "kill", "view"]

query_access := policies_matching_identity.queries[0].allow

# Schema ownership of the first matching rule
default schema_owner(_, _) := false

schema_owner(catalog_name, schema_name) := owner if {
	rules := [rule |
		some rule in policies_matching_identity.schemas

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
	]
	owner := rules[0].owner
}

not_allowed_columns(columns) := {column.name |
	some column in columns
	column.allow == false
}

# Table privileges of the first matching rule
default table_privileges(_, _, _, _) := []

table_privileges(catalog_name, schema_name, table_name, columns) := privileges if {
	rules := [rule |
		some rule in policies_matching_identity.tables

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")
		column_constraints := object.get(rule, "columns", {})

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
		regex.match(table_pattern, table_name)

		requested_columns := {column | some column in columns}
		restricted_columns = not_allowed_columns(column_constraints)
		requested_columns & restricted_columns == set()
	]
	privileges := rules[0].privileges
}

# METADATA
# description: Comparision of required and actual permissions
# entrypoint: true
default allow := false

allow if {
	# Fail if the required permissions for the given operation are not
	# implemented yet
	required_permissions

	every required_catalog_permission in required_catalog_permissions {
		access := catalog_access(required_catalog_permission.catalogName)
		required_catalog_permission.allow in access
	}
	every required_query_permission in required_query_permissions {
		object.subset(query_access, required_query_permission.allow)
	}
	every required_schema_permission in required_schema_permissions {
		schema_owner(
			required_schema_permission.catalogName,
			required_schema_permission.schemaName,
		)
	}
	every required_table_permission in required_table_permissions {
		privileges := table_privileges(
			required_table_permission.catalogName,
			required_table_permission.schemaName,
			required_table_permission.tableName,
			required_table_permission.columns,
		)
		object.subset(privileges, required_table_permission.privileges)
	}
}

# METADATA
# description: Comparision of required and actual permissions
# entrypoint: true
batch contains index if {
	some index, resource in input.action.filterResources
	allow with input.action.resource as resource
}
