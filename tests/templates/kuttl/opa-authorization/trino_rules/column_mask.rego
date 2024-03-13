# METADATA
# schemas:
#   - input: schema.column_mask_input
#   - data.trino_policies.policies: schema.policies
package trino_column_mask

import data.util
import rego.v1

policies := data.trino_policies.policies

requested_column := input.resource.column

matching_rules := [rule |
	some rule in policies.tables

	catalog_pattern := object.get(rule, "catalog", ".*")
	schema_pattern := object.get(rule, "schema", ".*")
	table_pattern := object.get(rule, "table", ".*")

	util.match_entire(catalog_pattern, requested_column.catalogName)
	util.match_entire(schema_pattern, requested_column.schemaName)
	util.match_entire(table_pattern, requested_column.tableName)
]

first_matching_rule := matching_rules[0]

matching_columns := [column |
	some column in first_matching_rule.columns
	column.name == requested_column.columnName
]

first_matching_column := matching_columns[0]

# METADATA
# description: Column mask for a given column
# entrypoint: true
column_masks contains column_mask if {
	input.operation == "GetColumnMask"
}

column_mask := {
	"expression": first_matching_column.mask,
	"identity": first_matching_column.mask_environment.user,
}

column_mask := {"expression": first_matching_column.mask} if {
	not first_matching_column.mask_environment.user
}
