package trino

import rego.v1

identity := input.context.identity

raw_policies := data.trino_policies.policies

filter_by_user_group(resource) := matching_rules if {
	matching_rules := [rule |
		some rule in resource

		# Add an empty dummy group to iterate at least once
		some group in array.concat(identity.groups, [""])

		user_pattern := object.get(rule, "user", ".*")
		group_pattern := object.get(rule, "group", ".*")

		regex.match(user_pattern, identity.user)
		regex.match(group_pattern, group)
	]
}

filter_by_original_user_group(resource) := matching_rules if {
	matching_rules := [rule |
		some rule in resource

		# Add an empty dummy group to iterate at least once
		some group in array.concat(identity.groups, [""])

		user_pattern := object.get(rule, "original_user", ".*")
		group_pattern := object.get(rule, "original_group", ".*")

		regex.match(user_pattern, identity.user)
		regex.match(group_pattern, group)
	]
}

default authorization_rules := []

authorization_rules := filter_by_original_user_group(raw_policies.authorization)

# Authorization permission of the first matching rule
default authorization_permission(_) := false

authorization_permission(grantee_name) := permission if {
	rules := [rule |
		some rule in authorization_rules

		new_user_pattern := object.get(rule, "new_user", ".*")

		regex.match(new_user_pattern, grantee_name)
	]
	permission := object.get(rules[0], "allow", true)
}

default catalog_rules := [{"allow": "all"}]

catalog_rules := filter_by_user_group(raw_policies.catalogs)

catalog_access_map := {
	"all": {"all", "read-only"},
	"read-only": {"read-only"},
	"none": {"none"},
}

# Catalog access of the first matching rule
default catalog_access(_) := "none"

catalog_access(catalog_name) := access if {
	rules := [rule |
		some rule in catalog_rules

		catalog_pattern := object.get(rule, "catalog", ".*")

		regex.match(catalog_pattern, catalog_name)
	]
	access := catalog_access_map[rules[0].allow]
}

default catalog_session_property_rules := [{"allow": true}]

catalog_session_property_rules := filter_by_user_group(raw_policies.catalog_session_properties)

# Catalog session property access of the first matching rule
default catalog_session_properties_access(_, _) := false

catalog_session_properties_access(catalog_name, property_name) := access if {
	rules := [rule |
		some rule in catalog_session_property_rules

		catalog_name_pattern := object.get(rule, "catalogName", ".*")
		property_name_pattern := object.get(rule, "propertyName", ".*")

		regex.match(catalog_name_pattern, catalog_name)
		regex.match(property_name_pattern, property_name)
	]
	access := rules[0].allow
}

default function_rules := [{
	"catalog": "system",
	"schema": "builtin",
	"privileges": [
		"GRANT_EXECUTE",
		"EXECUTE",
	],
}]

function_rules := filter_by_user_group(raw_policies.functions)

# Function privileges of the first matching rule
default function_privileges(_, _, _) := set()

function_privileges(catalog_name, schema_name, function_name) := privileges if {
	rules := [rule |
		some rule in function_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		function_pattern := object.get(rule, "function", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
		regex.match(function_pattern, function_name)
	]
	privileges := {privilege | some privilege in rules[0].privileges}
}

default impersonation_rules := []

impersonation_rules := filter_by_original_user_group(raw_policies.impersonation)

# Impersonation access of the first matching rule
default impersonation_access(_) := false

impersonation_access(user) if {
	user == identity.user
}

impersonation_access(user) := access if {
	user != identity.user
	rules := [rule |
		some rule in impersonation_rules

		original_user_pattern := object.get(rule, "original_user", ".*")
		unsubstituted_new_user_pattern := object.get(rule, "new_user", ".*")

		matches := regex.find_all_string_submatch_n(
			original_user_pattern,
			identity.user, -1,
		)
		substitutes := {var: match |
			some i, match in matches[0]
			var := concat("", ["$", format_int(i, 10)])
		}
		new_user_pattern := strings.replace_n(
			substitutes,
			unsubstituted_new_user_pattern,
		)

		regex.match(new_user_pattern, user)
	]
	access := object.get(rules[0], "allow", true)
}

default procedure_rules := [{
	"catalog": "system",
	"schema": "builtin",
	"privileges": [
		"GRANT_EXECUTE",
		"EXECUTE",
	],
}]

procedure_rules := filter_by_user_group(raw_policies.procedures)

# Procedure privileges of the first matching rule
default procedure_privileges(_, _, _) := set()

# Matching the "function name" with the "procedure pattern" is intended.
# The requested procedure name is contained in
# `input.action.resource.function.functionName`. A rule applies if this
# name matches the pattern in
# `data.trino_policies.policies.procedures[_].procedure`.
procedure_privileges(catalog_name, schema_name, function_name) := privileges if {
	rules := [rule |
		some rule in procedure_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		procedure_pattern := object.get(rule, "procedure", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
		regex.match(procedure_pattern, function_name)
	]
	privileges := {privilege | some privilege in rules[0].privileges}
}

default query_rules := []

query_rules := filter_by_user_group(raw_policies.queries)

# Query access of the first matching rule
default query_access := set()

query_access := query_rules[0].allow

# Query access of the first matching rule
default query_owned_by_access(_) := set()

query_owned_by_access(user) := access if {
	rules := [rule |
		some rule in query_rules

		query_owner_pattern := object.get(rule, "queryOwner", ".*")

		regex.match(query_owner_pattern, user)
	]
	access := rules[0].allow
}

default schema_rules := [{"owner": true}]

schema_rules := filter_by_user_group(raw_policies.schemas)

# Schema ownership of the first matching rule
default schema_owner(_, _) := false

schema_owner(catalog_name, schema_name) := owner if {
	rules := [rule |
		some rule in schema_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
	]
	owner := rules[0].owner
}

default table_rules := [{"privileges": [
	"DELETE",
	"GRANT_SELECT",
	"INSERT",
	"OWNERSHIP",
	"SELECT",
	"UPDATE",
]}]

table_rules := filter_by_user_group(raw_policies.tables)

# Table privileges of the first matching rule
default table_privileges(_, _, _) := []

table_privileges(catalog_name, schema_name, table_name) := privileges if {
	rules := [rule |
		some rule in table_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
		regex.match(table_pattern, table_name)
	]
	privileges := {privilege | some privilege in rules[0].privileges}
}

not_allowed_columns(columns) := {column.name |
	some column in columns
	not column.allow
}

# Column access of the first matching rule
default column_access(_, _, _, _) := false

column_access(catalog_name, schema_name, table_name, column_name) if {
	rules := [rule |
		some rule in table_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")

		regex.match(catalog_pattern, catalog_name)
		regex.match(schema_pattern, schema_name)
		regex.match(table_pattern, table_name)
	]

	count(rules[0].privileges) != 0

	column_constraints := object.get(rules[0], "columns", {})
	restricted_columns := not_allowed_columns(column_constraints)
	not column_name in restricted_columns
}

default system_information_rules := []

system_information_rules := filter_by_user_group(raw_policies.system_information)

# System information access of the first matching rule
default system_information_access := []

system_information_access := system_information_rules[0].allow

default system_session_property_rules := [{"allow": true}]

system_session_property_rules := filter_by_user_group(raw_policies.system_session_properties)

# System session property access of the first matching rule
default system_session_properties_access(_) := false

system_session_properties_access(property_name) := access if {
	rules := [rule |
		some rule in system_session_property_rules

		property_name_pattern := object.get(rule, "name", ".*")

		regex.match(property_name_pattern, property_name)
	]
	access := rules[0].allow
}
