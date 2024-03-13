# METADATA
# schemas:
#   - input: schema.row_filters_input
#   - data.trino_policies.policies: schema.policies
package trino_row_filters

import data.util
import rego.v1

policies := data.trino_policies.policies

requested_table := input.resource.table

matching_rules := [rule |
	some rule in policies.tables

	catalog_pattern := object.get(rule, "catalog", ".*")
	schema_pattern := object.get(rule, "schema", ".*")
	table_pattern := object.get(rule, "table", ".*")

	util.match_entire(catalog_pattern, requested_table.catalogName)
	util.match_entire(schema_pattern, requested_table.schemaName)
	util.match_entire(table_pattern, requested_table.tableName)
]

first_matching_rule := matching_rules[0]

# METADATA
# description: Row filters for a given table
# entrypoint: true
row_filters contains row_filter if {
	input.operation == "GetRowFilters"
}

row_filter := {
	"expression": first_matching_rule.filter,
	"identity": first_matching_rule.filter_environment.user,
}

row_filter := {"expression": first_matching_rule.filter} if {
	not first_matching_rule.filter_environment.user
}
