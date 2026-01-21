# METADATA
# description: |
#   The file verification.rego contains the entry points which are
#   queried from outside. These are:
#     - allow
#     - batch
#     - columnMask
#     - batchColumnMasks
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

allow := allowWith(input.action)

allowWith(action) if {
	# Fail if the requested permissions for the given operation are not
	# implemented yet
	#
	# The following operations are intentionally not supported:
	# - CreateCatalog
	# - DropCatalog
	requested_permissions(action)

	every requested_permission in requested_authorization_permissions(action) {
		permission := authorization_permission(requested_permission.granteeName)
		requested_permission.allow == permission
	}
	every requested_permission in requested_catalog_permissions(action) {
		access := catalog_access(requested_permission.catalogName)
		requested_permission.allow in access
	}
	every requested_permission in requested_catalog_session_properties_permissions(action) {
		access := catalog_session_properties_access(
			requested_permission.catalogName,
			requested_permission.propertyName,
		)
		requested_permission.allow == access
	}
	every requested_permission in requested_catalog_visibility_permissions(action) {
		catalog_visibility(requested_permission.catalogName)
	}
	every requested_permission in requested_column_permissions(action) {
		access := column_access(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.tableName,
			requested_permission.columnName,
		)
		requested_permission.allow == access
	}
	every requested_permission in requested_function_permissions(action) {
		privileges := function_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.functionName,
		)
		object.subset(privileges, requested_permission.privileges)
	}
	every requested_permission in requested_impersonation_permissions(action) {
		access := impersonation_access(requested_permission.user)
		requested_permission.allow == access
	}
	every requested_permission in requested_procedure_permissions(action) {
		privileges := procedure_privileges(
			requested_permission.catalogName,
			requested_permission.schemaName,
			requested_permission.functionName,
		)
		object.subset(privileges, requested_permission.privileges)
	}
	every requested_permission in requested_query_permissions(action) {
		object.subset(query_access, requested_permission.allow)
	}
	every requested_permission in requested_query_owned_by_permissions(action) {
		object.subset(
			query_owned_by_access(requested_permission.user),
			requested_permission.allow,
		)
	}
	every requested_permission in requested_schema_permissions(action) {
		schema_owner(
			requested_permission.catalogName,
			requested_permission.schemaName,
		) == requested_permission.owner
	}
	every requested_permission in requested_schema_visibility_permissions(action) {
		schema_visibility(
			requested_permission.catalogName,
			requested_permission.schemaName,
		)
	}
	every requested_permission in requested_table_permissions(action) {
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
	every requested_permission in requested_system_information_permissions(action) {
		object.subset(
			system_information_access,
			requested_permission.allow,
		)
	}
	every requested_permission in requested_system_session_properties_permissions(action) {
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

	action := object.union(object.remove(input.action, {"filterResources"}), {"resource": resource})

	allowWith(action)
}

batch contains index if {
	input.action.operation == "FilterColumns"

	table := input.action.filterResources[0].table
	some index, column_name in table.columns

	action := object.union(object.remove(input.action, {"filterResources"}), {"resource": {"table": {
		"catalogName": table.catalogName,
		"schemaName": table.schemaName,
		"tableName": table.tableName,
		"columnName": column_name,
	}}})

	allowWith(action)
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
	request := requested_column_mask(input.action)

	column := column_constraints(
		request.catalogName,
		request.schemaName,
		request.tableName,
		request.columnName,
	)

	is_string(column.mask)
	is_string(column.mask_environment.user)

	column_mask := {
		"expression": column.mask,
		"identity": column.mask_environment.user,
	}
}

columnMask := column_mask if {
	request := requested_column_mask(input.action)

	column := column_constraints(
		request.catalogName,
		request.schemaName,
		request.tableName,
		request.columnName,
	)

	is_string(column.mask)
	is_null(column.mask_environment.user)

	column_mask := {"expression": column.mask}
}

# METADATA
# description: |
#   Entry point for fetching column masks in batch, configured in the
#   Trino property `opa.policy.batch-column-masking-uri`.
#
#   The input has the following form:
#
#   {
#     "action": {
#       "operation": "GetColumnMasks",
#       "filterResources": [{
#         "column": {
#           "catalogName": "catalog",
#           "schemaName": "schema",
#           "tableName": "table",
#           "columnName": "column",
#           "columnType": "varchar",
#         }},
#         {"column": ...},
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
#   The batchColumnMask rule queries the column constraints in the
#   Trino policies for each of the resources in the "filterResources"
#   list of the request and returns a list of viewExpressions, containing
#   the column mask if any set and optionally the identity for the mask
#   evaluation, and the index of the corresponding resource in the
#   "filterResources" list of the request.
#   A column mask is an SQL expression,
#   e.g. "'XXX-XX-' + substring(credit_card, -4)".
# entrypoint: true
batchColumnMasks contains column_mask if {
	input.action.operation == "GetColumnMask"
	some index, resource in input.action.filterResources

	column := column_constraints(
		resource.column.catalogName,
		resource.column.schemaName,
		resource.column.tableName,
		resource.column.columnName,
	)

	is_string(column.mask)
	is_string(column.mask_environment.user)

	column_mask := {
		"index": index,
		"viewExpression": {
			"expression": column.mask,
			"identity": column.mask_environment.user,
		},
	}
}

batchColumnMasks contains column_mask if {
	input.action.operation == "GetColumnMask"
	some index, resource in input.action.filterResources

	column := column_constraints(
		resource.column.catalogName,
		resource.column.schemaName,
		resource.column.tableName,
		resource.column.columnName,
	)

	is_string(column.mask)
	is_null(column.mask_environment.user)

	column_mask := {
		"index": index,
		"viewExpression": {"expression": column.mask},
	}
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
	request := requested_row_filters(input.action)

	rule := first_matching_table_rule(
		request.catalogName,
		request.schemaName,
		request.tableName,
	)

	is_string(rule.filter)
	is_string(rule.filter_environment.user)

	row_filter := {
		"expression": rule.filter,
		"identity": rule.filter_environment.user,
	}
}

rowFilters contains row_filter if {
	request := requested_row_filters(input.action)

	rule := first_matching_table_rule(
		request.catalogName,
		request.schemaName,
		request.tableName,
	)

	is_string(rule.filter)
	is_null(rule.filter_environment.user)

	row_filter := {"expression": rule.filter}
}
