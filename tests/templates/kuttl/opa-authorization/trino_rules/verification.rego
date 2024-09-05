# METADATA
# description: |
#   The file verification.rego contains the entry points which are
#   queried from outside. These are:
#     - allow
#     - batch
#     - columnMask
#     - rowFilters
#   These rules use the rules and functions in requested_permission.rego
#   and actual_permissions.rego to calculate the result.
#
#   The file requested_permissions.rego contains the
#   requested_permissions rule which returns a set of required
#   permissions for the given operation including the requested
#   resource.
#
#   The file actual_permissions.rego contains functions to determine the
#   actual permissions defined in the Trino policies for the given user
#   and requested resource.
# schemas:
#   - input: schema.input
#   - data.trino_policies.policies: schema.policies
package trino

import rego.v1

# METADATA
# description: |
#   Entry point for OPA policies, configured in the Trino property
#   `opa.policy.uri`.
#
#   The input has the following form:
#
#   {
#     "action": {
#       "operation": "OperationName",
#       "resource": {
#         ...
#       },
#     },
#     "context": {
#       "identity": {
#         "groups": ["group1", ...],
#         "user": "username",
#       },
#       "softwareStack": {"trinoVersion": "455"},
#     }
#   }
#
#   The result is a boolean value indicating if the operation is allowed
#   or not on the given resource by the given user.
#
#   The allow rule compares the permissions configured in the
#   requested_permissions rule for the given operation with the Trino
#   policies given in data.trino_policies.policies for the given
#   identity.
#
#   For instance, if the user wants to insert data into a table then the
#   requested_permissions rule requires for the "InsertIntoTable"
#   operation "all" access to the catalog and the "INSERT" privilege on
#   the table. The functions catalog_access and table_privileges defined
#   in actual_permissions.rego are called to check if these requirements
#   are fulfilled by the policies for the given user.
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
# description: |
#   Entry point for batch OPA policies, configured in the Trino property
#   `opa.policy.batched-uri`.
#
#   The input has the following form:
#
#   {
#     "action": {
#       "operation": "FilterOperationName",
#       "filterResources": [
#         {"resource1": ...},
#         {"resource2": ...},
#         ...
#       ],
#     },
#     "context": {
#       "identity": {
#         "groups": ["group1", ...],
#         "user": "username",
#       },
#       "softwareStack": {"trinoVersion": "455"},
#     }
#   }
#
#   The result is a list of indices which are allowed.
#
#   The batch rule just calls the allow rule for each resource.
#
#   FilterColumns is different to the other filter operations because
#   "filterResources" contains exactly one table with a list of
#   columns and the expected result is the list of allowed column
#   indices and not of allowed tables.
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
# description: |
#   Entry point for fetching column masks, configured in the Trino
#   property `opa.policy.column-masking-uri`.
#
#   The input has the following form:
#
#   {
#     "action": {
#       "operation": "GetColumnMask",
#       "resource": {
#         "column": {
#           "catalogName": "catalog",
#           "schemaName": "schema",
#           "tableName": "table",
#           "columnName": "column",
#         },
#       },
#     },
#     "context": {
#       "identity": {
#         "groups": ["group1", ...],
#         "user": "username",
#       },
#       "softwareStack": {"trinoVersion": "455"},
#     }
#   }
#
#   The result is an object containing the mask expression and the
#   identity for the mask evaluation.
#
#   The columnMask rule queries the column constraints in the Trino
#   policies and returns the expression if any is set. A column mask
#   is an SQL expression, e.g. "'XXX-XX-' + substring(credit_card, -4)".
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
# description: |
#   Entry point for fetching row filters, configured in the Trino
#   property `opa.policy.row-filters-uri`.
#
#   The input has the following form:
#
#   {
#     "action": {
#       "operation": "GetRowFilters",
#       "resource": {
#         "table": {
#           "catalogName": "catalog",
#           "schemaName": "schema",
#           "tableName": "table",
#         },
#       },
#     },
#     "context": {
#       "identity": {
#         "groups": ["group1", ...],
#         "user": "username",
#       },
#       "softwareStack": {"trinoVersion": "455"},
#     }
#   }
#
#   The result is a list containing one object which consists of the
#   row filter expression and the identity for the filter evaluation.
#
#   The rowFilters rule queries the column constraints in the Trino
#   policies and returns the expression if any is set. A row filter is
#   an SQL condition, e.g. "user = current_user".
# entrypoint: true
rowFilters contains row_filter if {
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

rowFilters contains row_filter if {
	rule := first_matching_table_rule(
		requested_row_filters.catalogName,
		requested_row_filters.schemaName,
		requested_row_filters.tableName,
	)

	is_string(rule.filter)
	is_null(rule.filter_environment.user)

	row_filter := {"expression": rule.filter}
}
