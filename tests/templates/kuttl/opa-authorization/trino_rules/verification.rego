# METADATA
# schemas:
#   - input: schema.input
#   - data.trino_policies.policies: schema.policies
package trino

import rego.v1

# METADATA
# description: Comparison of requested and actual permissions
# entrypoint: true
default allow := false

allow if {
	# Fail if the requested permissions for the given operation are not
	# implemented yet
	#
	# The following operations are intentionally not supported:
	# - CreateCatalog
	# - DropCatalog
	requested_permissions

	every requested_permission in requested_authorization_permissions {
		permission := authorization_permission(requested_permission.granteeName)
		requested_permission.allow == permission
	}
	every requested_permission in requested_catalog_permissions {
		access := catalog_access(requested_permission.catalogName)
		requested_permission.allow in access
	}
	every requested_permission in requested_catalog_session_properties_permissions {
		access := catalog_session_properties_access(
			requested_permission.catalogName,
			requested_permission.propertyName,
		)
		requested_permission.allow == access
	}
	every requested_permission in requested_catalog_visibility_permissions {
		catalog_visibility(requested_permission.catalogName)
	}
	every requested_permission in requested_column_permissions {
		access := column_access(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.tableName,
			requested_permission.columnName,
		)
		requested_permission.allow == access
	}
	every requested_permission in requested_function_permissions {
		privileges := function_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.functionName,
		)
		object.subset(privileges, requested_permission.privileges)
	}
	every requested_permission in requested_impersonation_permissions {
		access := impersonation_access(requested_permission.user)
		requested_permission.allow == access
	}
	every requested_permission in requested_procedure_permissions {
		privileges := procedure_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.functionName,
		)
		object.subset(privileges, requested_permission.privileges)
	}
	every requested_permission in requested_query_permissions {
		object.subset(query_access, requested_permission.allow)
	}
	every requested_permission in requested_query_owned_by_permissions {
		object.subset(
			query_owned_by_access(requested_permission.user),
			requested_permission.allow,
		)
	}
	every requested_permission in requested_schema_permissions {
		schema_owner(
			requested_permission.catalogName,
			requested_permission.schemaName,
		) == requested_permission.owner
	}
	every requested_permission in requested_schema_visibility_permissions {
		schema_visibility(
			requested_permission.catalogName,
			requested_permission.schemaName,
		)
	}
	every requested_permission in requested_table_permissions {
		privileges := table_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.tableName,
		)
		all_of_requested := object.get(
			requested_permission.privileges,
			"allOf",
			set(),
		)
		any_of_requested := object.get(
			requested_permission.privileges,
			"anyOf",
			privileges,
		)
		object.subset(privileges, all_of_requested)
		privileges & any_of_requested != set()
	}
	every requested_permission in requested_system_information_permissions {
		object.subset(
			system_information_access,
			requested_permission.allow,
		)
	}
	every requested_permission in requested_system_session_properties_permissions {
		access := system_session_properties_access(requested_permission.propertyName)
		requested_permission.allow == access
	}
}

# METADATA
# description: Comparison of requested and actual permissions
# entrypoint: true
batch contains index if {
	input.action.operation != "FilterColumns"

	some index, resource in input.action.filterResources

	# regal ignore:with-outside-test-context
	allow with input.action.resource as resource
}

batch contains index if {
	input.action.operation == "FilterColumns"

	table := input.action.filterResources[0].table
	some index, column_name in table.columns

	# regal ignore:with-outside-test-context
	allow with input.action.resource as {"table": {
		"catalogName": table.catalogName,
		"schemaName": table.schemaName,
		"tableName": table.tableName,
		"columnName": column_name,
	}}
}

# METADATA
# description: Column mask for a given column
# entrypoint: true
columnMask := column_mask if {
	column := column_constraints(
		requested_column_mask.catalogName,
		requested_column_mask.schemaName,
		requested_column_mask.tableName,
		requested_column_mask.columnName,
	)

	is_string(column.mask)
	is_string(column.mask_environment.user)

	column_mask := {
		"expression": column.mask,
		"identity": column.mask_environment.user,
	}
}

columnMask := column_mask if {
	column := column_constraints(
		requested_column_mask.catalogName,
		requested_column_mask.schemaName,
		requested_column_mask.tableName,
		requested_column_mask.columnName,
	)

	is_string(column.mask)
	is_null(column.mask_environment.user)

	column_mask := {"expression": column.mask}
}

# METADATA
# description: Row filters for a given table
# entrypoint: true
rowFilters := [row_filter] if {
	rule := first_matching_table_rule(
		requested_row_filters.catalogName,
		requested_row_filters.schemaName,
		requested_row_filters.tableName,
	)

	is_string(rule.filter)
	is_string(rule.filter_environment.user)

	row_filter := {
		"expression": rule.filter,
		"identity": rule.filter_environment.user,
	}
}

rowFilters := [row_filter] if {
	rule := first_matching_table_rule(
		requested_row_filters.catalogName,
		requested_row_filters.schemaName,
		requested_row_filters.tableName,
	)

	is_string(rule.filter)
	is_null(rule.filter_environment.user)

	row_filter := {"expression": rule.filter}
}
