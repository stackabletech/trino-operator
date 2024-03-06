# METADATA
# schemas:
#   - input: schema.input
#   - data.policies: schema.policies
package trino

import rego.v1

# METADATA
# description: Comparision of requested and actual permissions
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
	every requested_permission in requested_table_permissions {
		privileges := table_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.tableName,
		)
		all_of_requested := object.get(requested_permission.privileges, "allOf", set())
		any_of_requested := object.get(requested_permission.privileges, "anyOf", privileges)
		object.subset(privileges, all_of_requested)
		privileges & any_of_requested != set()
	}
	every requested_permission in requested_system_information_permissions {
		object.subset(system_information_access, requested_permission.allow)
	}
	every requested_permission in requested_catalog_session_properties_permissions {
		access := catalog_session_properties_access(
			requested_permission.catalogName,
			requested_permission.propertyName,
		)
		requested_permission.allow == access
	}
	every requested_permission in requested_system_session_properties_permissions {
		access := system_session_properties_access(requested_permission.propertyName)
		requested_permission.allow == access
	}
}

# METADATA
# description: Comparision of requested and actual permissions
# entrypoint: true
batch contains index if {
	input.action.operation != "FilterColumns"

	some index, resource in input.action.filterResources
	allow with input.action.resource as resource
}

batch contains index if {
	input.action.operation == "FilterColumns"

	table := input.action.filterResources[0].table
	some index, column_name in table.columns

	allow with input.action.resource as {"table": {
		"catalogName": table.catalogName,
		"schemaName": table.schemaName,
		"tableName": table.tableName,
		"columnName": column_name,
	}}
}
