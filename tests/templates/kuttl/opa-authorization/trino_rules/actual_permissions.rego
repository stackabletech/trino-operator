package trino

import rego.v1

identity := input.context.identity

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
default query_access := set()

query_access := policies_matching_identity.queries[0].allow

# Query access of the first matching rule
default query_owned_by_access(_) := set()

query_owned_by_access(user) := access if {
	rules := [rule |
		some rule in policies_matching_identity.queries

		query_owner_pattern := object.get(rule, "queryOwner", ".*")

		regex.match(query_owner_pattern, user)
	]
	access := rules[0].allow
}

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
