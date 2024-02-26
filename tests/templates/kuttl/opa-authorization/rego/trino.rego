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
# * CreateCatalog
# * CreateFunction
# * CreateMaterializedView
# * CreateSchema
# * CreateTable
# * CreateViewWithExecuteFunction
# * CreateViewWithSelectFromColumns
# * DeleteFromTable
# * DropCatalog
# * DropFunction
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
# * ImpersonateUser
# * KillQueryOwnedBy
# * RenameMaterializedView
# * RenameSchema
# * RenameView
# * SetCatalogSessionProperty
# * SetMaterializedViewProperties
# * SetSchemaAuthorization
# * SetSystemSessionProperty
# * SetTableAuthorization
# * SetTableProperties
# * SetViewAuthorization
# * ShowColumns
# * ShowCreateSchema
# * ShowFunctions
# * ShowTables
# * UpdateTableColumns
# * ViewQueryOwnedBy

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
		"CreateView",
		"DropColumn",
		"DropMaterializedView",
		"DropTable",
		"DropView",
		"RenameColumn",
		"SetColumnComment",
		"SetTableComment",
		"SetViewComment",
		"ShowCreateTable",
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
	privileges := {privilege | some privilege in rules[0].privileges}
}

# System information access of the first matching rule
default system_information_access := []

system_information_access := policies_matching_identity.system_information[0].allow

# METADATA
# description: Comparision of required and actual permissions
# entrypoint: true
default allow := false

allow if {
	# Fail if the required permissions for the given operation are not
	# implemented yet
	required_permissions

	every required_permission in required_catalog_permissions {
		access := catalog_access(required_permission.catalogName)
		required_permission.allow in access
	}
	every required_permission in required_query_permissions {
		object.subset(query_access, required_permission.allow)
	}
	every required_permission in required_schema_permissions {
		schema_owner(
			required_permission.catalogName,
			required_permission.schemaName,
		)
	}
	every required_permission in required_table_permissions {
		privileges := table_privileges(
			required_permission.catalogName,
			required_permission.schemaName,
			required_permission.tableName,
			object.get(required_permission, "columns", {}),
		)
		all_of_required := object.get(required_permission.privileges, "allOf", set())
		any_of_required := object.get(required_permission.privileges, "anyOf", privileges)
		object.subset(privileges, all_of_required)
		privileges & any_of_required != set()
	}
	every required_permission in required_system_information_permissions {
		object.subset(system_information_access, required_permission.allow)
	}
}

# METADATA
# description: Comparision of required and actual permissions
# entrypoint: true
batch contains index if {
	some index, resource in input.action.filterResources
	allow with input.action.resource as resource
}
