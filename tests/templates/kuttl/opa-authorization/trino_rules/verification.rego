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
	required_permissions

	every required_permission in required_catalog_permissions {
		access := catalog_access(required_permission.catalogName)
		required_permission.allow in access
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
