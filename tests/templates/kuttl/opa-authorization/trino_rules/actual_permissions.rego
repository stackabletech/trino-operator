package trino

import rego.v1

# These rules replicate the file-based access control
# (https://trino.io/docs/current/security/file-system-access-control.html#table-rules).
#
# But there are differences:
# * Only `user` and `group` are matched but not `role`.
# * Filters and masks are not yet supported.
# * The visibility is not checked.

identity := input.context.identity

raw_policies := data.trino_policies.policies

match_entire(pattern, value) if {
	# Add the anchors ^ and $
	pattern_with_anchors := concat("", ["^", pattern, "$"])

	regex.match(pattern_with_anchors, value)
}

match_any_group(group_pattern) if {
	# Add an empty dummy group because the default pattern ".*" should
	# match even if the user is not a member of a group.
	some group in array.concat(identity.groups, [""])
	match_entire(group_pattern, group)
}

filter_by_user_group(resource) := [rule |
	some rule in resource

	user_pattern := object.get(rule, "user", ".*")
	group_pattern := object.get(rule, "group", ".*")

	match_entire(user_pattern, identity.user)
	match_any_group(group_pattern)
]

filter_by_original_user_group(resource) := [rule |
	some rule in resource

	user_pattern := object.get(rule, "original_user", ".*")
	group_pattern := object.get(rule, "original_group", ".*")

	match_entire(user_pattern, identity.user)
	match_any_group(group_pattern)
]

default authorization_rules := []

authorization_rules := filter_by_original_user_group(raw_policies.authorization)

# Authorization permission of the first matching rule
default authorization_permission(_) := false

authorization_permission(grantee_name) := permission if {
	rules := [rule |
		some rule in authorization_rules

		new_user_pattern := object.get(rule, "new_user", ".*")

		match_entire(new_user_pattern, grantee_name)
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
default catalog_access(_) := {"none"}

catalog_access(catalog_name) := access if {
	rules := [rule |
		some rule in catalog_rules

		catalog_pattern := object.get(rule, "catalog", ".*")

		match_entire(catalog_pattern, catalog_name)
	]
	access := catalog_access_map[rules[0].allow]
}

default catalog_session_property_rules := [{"allow": true}]

catalog_session_property_rules := filter_by_user_group(raw_policies.catalog_session_properties)

# Catalog session property access of the first matching rule
default catalog_session_properties_access(_, _) := false

catalog_session_properties_access(
	catalog_name,
	property_name,
) := access if {
	rules := [rule |
		some rule in catalog_session_property_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		property_pattern := object.get(rule, "property", ".*")

		match_entire(catalog_pattern, catalog_name)
		match_entire(property_pattern, property_name)
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

function_privileges(
	catalog_name,
	schema_name,
	function_name,
) := privileges if {
	rules := [rule |
		some rule in function_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		function_pattern := object.get(rule, "function", ".*")

		match_entire(catalog_pattern, catalog_name)
		match_entire(schema_pattern, schema_name)
		match_entire(function_pattern, function_name)
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

		# strings.replace_n replaces "$10" with "$1" followed by "0".
		# Therefore only nine capture groups are supported.
		new_user_pattern := strings.replace_n(
			substitutes,
			unsubstituted_new_user_pattern,
		)

		match_entire(new_user_pattern, user)
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
procedure_privileges(
	catalog_name,
	schema_name,
	function_name,
) := privileges if {
	rules := [rule |
		some rule in procedure_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		procedure_pattern := object.get(rule, "procedure", ".*")

		match_entire(catalog_pattern, catalog_name)
		match_entire(schema_pattern, schema_name)
		match_entire(procedure_pattern, function_name)
	]
	privileges := {privilege | some privilege in rules[0].privileges}
}

default query_rules := [{"allow": ["execute", "kill", "view"]}]

query_rules := filter_by_user_group(raw_policies.queries)

# Query access of the first matching rule
default query_access := set()

query_access := {access | some access in query_rules[0].allow}

# Query access of the first matching rule
default query_owned_by_access(_) := set()

query_owned_by_access(user) := {"kill", "view"} if {
	user == identity.user
}

query_owned_by_access(user) := access if {
	user != identity.user
	rules := [rule |
		some rule in query_rules

		query_owner_pattern := object.get(rule, "queryOwner", ".*")

		match_entire(query_owner_pattern, user)
	]
	access := {access | some access in rules[0].allow}
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

		match_entire(catalog_pattern, catalog_name)
		match_entire(schema_pattern, schema_name)
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
default table_privileges(_, _, _) := set()

table_privileges(_, "information_schema", _) := {
	"DELETE",
	"GRANT_SELECT",
	"INSERT",
	"OWNERSHIP",
	"SELECT",
	"UPDATE",
}

table_privileges(
	catalog_name,
	schema_name,
	table_name,
) := privileges if {
	schema_name != "information_schema"
	rules := [rule |
		some rule in table_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")

		match_entire(catalog_pattern, catalog_name)
		match_entire(schema_pattern, schema_name)
		match_entire(table_pattern, table_name)
	]
	privileges := {privilege | some privilege in rules[0].privileges}
}

not_allowed_columns(columns) := {column.name |
	some column in columns
	not column.allow
}

# Column access of the first matching rule
default column_access(_, _, _, _) := false

column_access(_, "information_schema", _, _)

column_access(catalog_name, schema_name, table_name, column_name) if {
	schema_name != "information_schema"
	rules := [rule |
		some rule in table_rules

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")

		match_entire(catalog_pattern, catalog_name)
		match_entire(schema_pattern, schema_name)
		match_entire(table_pattern, table_name)
	]

	count(rules[0].privileges) != 0

	column_constraints := object.get(rules[0], "columns", {})
	restricted_columns := not_allowed_columns(column_constraints)
	not column_name in restricted_columns
}

default system_information_rules := []

system_information_rules := filter_by_user_group(raw_policies.system_information)

# System information access of the first matching rule
default system_information_access := set()

system_information_access := {access |
	some access in system_information_rules[0].allow
}

default system_session_property_rules := [{"allow": true}]

system_session_property_rules := filter_by_user_group(raw_policies.system_session_properties)

# System session property access of the first matching rule
default system_session_properties_access(_) := false

system_session_properties_access(property_name) := access if {
	rules := [rule |
		some rule in system_session_property_rules

		property_name_pattern := object.get(rule, "property", ".*")

		match_entire(property_name_pattern, property_name)
	]
	access := rules[0].allow
}
