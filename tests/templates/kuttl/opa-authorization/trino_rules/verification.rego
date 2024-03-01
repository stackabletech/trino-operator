# METADATA
# schemas:
#   - input: schema.input
#   - data.policies: schema.policies
package trino

import rego.v1

# METADATA
# description: Comparision of required and actual permissions
# entrypoint: true
default allow := false

allow if {
	# Fail if the required permissions for the given operation are not
	# implemented yet
	#
	# The following operations are intentionally not supported:
	# - CreateCatalog
	# - DropCatalog
	required_permissions

	every required_permission in required_authorization_permissions {
		permission := authorization_permission(required_permission.granteeName)
		required_permission.allow == permission
	}
	every required_permission in required_catalog_permissions {
		access := catalog_access(required_permission.catalogName)
		required_permission.allow in access
	}
	every required_permission in required_column_permissions {
		access := column_access(
			required_permission.catalogName,
			required_permission.schemaName,
			required_permission.tableName,
			required_permission.columnName,
		)
		required_permission.allow == access
	}
	every required_permission in required_function_permissions {
		privileges := function_privileges(
			required_permission.catalogName,
			required_permission.schemaName,
			required_permission.functionName,
		)
		object.subset(privileges, required_permission.privileges)
	}
	every required_permission in required_impersonation_permissions {
		access := impersonation_access(required_permission.user)
		required_permission.allow == access
	}
	every required_permission in required_query_permissions {
		object.subset(query_access, required_permission.allow)
	}
	every required_permission in required_query_owned_by_permissions {
		object.subset(
			query_owned_by_access(required_permission.user),
			required_permission.allow,
		)
	}
	every required_permission in required_schema_permissions {
		schema_owner(
			required_permission.catalogName,
			required_permission.schemaName,
		) == required_permission.owner
	}
	every required_permission in required_table_permissions {
		privileges := table_privileges(
			required_permission.catalogName,
			required_permission.schemaName,
			required_permission.tableName,
		)
		all_of_required := object.get(required_permission.privileges, "allOf", set())
		any_of_required := object.get(required_permission.privileges, "anyOf", privileges)
		object.subset(privileges, all_of_required)
		privileges & any_of_required != set()
	}
	every required_permission in required_system_information_permissions {
		object.subset(system_information_access, required_permission.allow)
	}
	every required_permission in required_catalog_session_properties_permissions {
		access := catalog_session_properties_access(
			required_permission.catalogName,
			required_permission.propertyName,
		)
		required_permission.allow == access
	}
	every required_permission in required_system_session_properties_permissions {
		access := system_session_properties_access(required_permission.propertyName)
		required_permission.allow == access
	}
}

# METADATA
# description: Comparision of required and actual permissions
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
