package trino

import data.util
import rego.v1

# These rules replicate the file-based access control
# (https://trino.io/docs/current/security/file-system-access-control.html).
# All rules are implemented but roles are not matched.

identity := input.context.identity

policies := data.trino_policies.policies

default extra_groups := []

extra_groups := data.trino_policies.extra_groups

# Add an empty dummy group because the default pattern ".*" should match
# even if the user is not a member of a group.
groups := array.concat(
	array.concat(identity.groups, extra_groups),
	[""],
)

default match_any_group(_) := false

match_any_group(group_pattern) if {
	some group in groups
	util.match_entire(group_pattern, group)
}

default match_user_group(_) := false

match_user_group(rule) if {
	user_pattern := object.get(rule, "user", ".*")
	group_pattern := object.get(rule, "group", ".*")

	util.match_entire(user_pattern, identity.user)
	match_any_group(group_pattern)
}

default match_original_user_group(_) := false

match_original_user_group(rule) if {
	user_pattern := object.get(rule, "original_user", ".*")
	group_pattern := object.get(rule, "original_group", ".*")

	util.match_entire(user_pattern, identity.user)
	match_any_group(group_pattern)
}

default authorization_rules := []

authorization_rules := policies.authorization

first_matching_authorization_rule(grantee_name) := rule if {
	rules := [rule |
		some rule in authorization_rules

		match_original_user_group(rule)

		new_user_pattern := object.get(rule, "new_user", ".*")

		util.match_entire(new_user_pattern, grantee_name)
	]
	rule := object.union(
		{"allow": true},
		rules[0],
	)
}

# Authorization permission of the first matching rule
default authorization_permission(_) := false

authorization_permission(grantee_name) := first_matching_authorization_rule(grantee_name).allow

default catalog_rules := [{"allow": "all"}]

catalog_rules := policies.catalogs

first_matching_catalog_rule(catalog_name) := rule if {
	rules := [rule |
		some rule in catalog_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")

		util.match_entire(catalog_pattern, catalog_name)
	]
	rule := rules[0]
}

catalog_access_map := {
	"all": {"all", "read-only"},
	"read-only": {"read-only"},
	"none": {"none"},
}

# Catalog access of the first matching rule
default catalog_access(_) := {"none"}

catalog_access(catalog_name) := catalog_access_map[first_matching_catalog_rule(catalog_name).allow]

default catalog_session_properties_rules := [{"allow": true}]

catalog_session_properties_rules := policies.catalog_session_properties

first_matching_catalog_session_properties_rule(
	catalog_name,
	property_name,
) := rule if {
	rules := [rule |
		some rule in catalog_session_properties_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")
		property_pattern := object.get(rule, "property", ".*")

		util.match_entire(catalog_pattern, catalog_name)
		util.match_entire(property_pattern, property_name)
	]
	rule := rules[0]
}

# Catalog session property access of the first matching rule
default catalog_session_properties_access(_, _) := false

catalog_session_properties_access(
	catalog_name,
	property_name,
) := first_matching_catalog_session_properties_rule(
	catalog_name,
	property_name,
).allow

default function_rules := [{
	"catalog": "system",
	"schema": "builtin",
	"privileges": [
		"GRANT_EXECUTE",
		"EXECUTE",
	],
}]

default catalog_visibility(_) := false

catalog_visibility(catalog_name) if {
	"all" in catalog_access(catalog_name)
}

catalog_visibility(catalog_name) if {
	catalog_access(catalog_name) == {"read-only"}

	some rule in schema_rules

	match_user_group(rule)

	catalog_pattern := object.get(rule, "catalog", ".*")

	util.match_entire(catalog_pattern, catalog_name)

	rule.owner == true
}

catalog_visibility(catalog_name) if {
	catalog_access(catalog_name) == {"read-only"}

	rules := array.concat(
		array.concat(
			table_rules,
			function_rules,
		),
		procedure_rules,
	)

	some rule in rules

	match_user_group(rule)

	catalog_pattern := object.get(rule, "catalog", ".*")

	util.match_entire(catalog_pattern, catalog_name)

	count(rule.privileges) != 0
}

catalog_visibility(catalog_name) if {
	catalog_access(catalog_name) == {"read-only"}

	some rule in catalog_session_properties_rules

	match_user_group(rule)

	catalog_pattern := object.get(rule, "catalog", ".*")

	util.match_entire(catalog_pattern, catalog_name)

	rule.allow == true
}

function_rules := policies.functions

first_matching_function_rule(
	catalog_name,
	schema_name,
	function_name,
) := rule if {
	rules := [rule |
		some rule in function_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		function_pattern := object.get(rule, "function", ".*")

		util.match_entire(catalog_pattern, catalog_name)
		util.match_entire(schema_pattern, schema_name)
		util.match_entire(function_pattern, function_name)
	]
	rule := rules[0]
}

# Function privileges of the first matching rule
default function_privileges(_, _, _) := set()

function_privileges(
	catalog_name,
	schema_name,
	function_name,
) := {privilege |
	some privilege in first_matching_function_rule(
		catalog_name,
		schema_name,
		function_name,
	).privileges
}

default impersonation_rules := []

impersonation_rules := policies.impersonation

first_matching_impersonation_rule(user) := rule if {
	rules := [rule |
		some rule in impersonation_rules

		match_original_user_group(rule)

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

		util.match_entire(new_user_pattern, user)
	]
	rule := object.union(
		{"allow": true},
		rules[0],
	)
}

# Impersonation access of the first matching rule
default impersonation_access(_) := false

impersonation_access(user) if {
	user == identity.user
}

impersonation_access(user) := access if {
	user != identity.user
	access := first_matching_impersonation_rule(user).allow
}

default procedure_rules := [{
	"catalog": "system",
	"schema": "builtin",
	"privileges": [
		"GRANT_EXECUTE",
		"EXECUTE",
	],
}]

procedure_rules := policies.procedures

# Matching the "function name" with the "procedure pattern" is intended.
# The requested procedure name is contained in
# `input.action.resource.function.functionName`. A rule applies if this
# name matches the pattern in
# `data.trino_policies.policies.procedures[_].procedure`.
first_matching_procedure_rule(
	catalog_name,
	schema_name,
	function_name,
) := rule if {
	rules := [rule |
		some rule in procedure_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		procedure_pattern := object.get(rule, "procedure", ".*")

		util.match_entire(catalog_pattern, catalog_name)
		util.match_entire(schema_pattern, schema_name)
		util.match_entire(procedure_pattern, function_name)
	]
	rule := rules[0]
}

# Procedure privileges of the first matching rule
default procedure_privileges(_, _, _) := set()

procedure_privileges(
	catalog_name,
	schema_name,
	function_name,
) := {privilege |
	some privilege in first_matching_procedure_rule(
		catalog_name,
		schema_name,
		function_name,
	).privileges
}

default query_rules := [{"allow": ["execute", "kill", "view"]}]

query_rules := policies.queries

first_matching_query_rule := rule if {
	rules := [rule |
		some rule in query_rules

		match_user_group(rule)
	]
	rule := rules[0]
}

# Query access of the first matching rule
default query_access := set()

query_access := {access | some access in first_matching_query_rule.allow}

first_matching_query_owned_by_rule(user) := rule if {
	rules := [rule |
		some rule in query_rules

		match_user_group(rule)

		query_owner_pattern := object.get(rule, "queryOwner", ".*")

		util.match_entire(query_owner_pattern, user)
	]
	rule := rules[0]
}

# Query access of the first matching rule
default query_owned_by_access(_) := set()

query_owned_by_access(user) := {"kill", "view"} if {
	user == identity.user
}

query_owned_by_access(user) := access if {
	user != identity.user
	access := {access |
		some access in first_matching_query_owned_by_rule(user).allow
	}
}

default schema_rules := [{"owner": true}]

schema_rules := policies.schemas

first_matching_schema_rule(catalog_name, schema_name) := rule if {
	rules := [rule |
		some rule in schema_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")

		util.match_entire(catalog_pattern, catalog_name)
		util.match_entire(schema_pattern, schema_name)
	]
	rule := rules[0]
}

# Schema ownership of the first matching rule
default schema_owner(_, _) := false

schema_owner(catalog_name, schema_name) := first_matching_schema_rule(
	catalog_name,
	schema_name,
).owner

default schema_visibility(_, _) := false

schema_visibility(catalog_name, schema_name) if {
	schema_owner(catalog_name, schema_name)
}

schema_visibility(_, "information_schema") := true

schema_visibility(catalog_name, schema_name) if {
	schema_name != "information_schema"

	rules := array.concat(
		array.concat(
			table_rules,
			function_rules,
		),
		procedure_rules,
	)

	some rule in rules

	match_user_group(rule)

	catalog_pattern := object.get(rule, "catalog", ".*")
	schema_pattern := object.get(rule, "schema", ".*")

	util.match_entire(catalog_pattern, catalog_name)
	util.match_entire(schema_pattern, schema_name)

	count(rule.privileges) != 0
}

default table_rules := [{
	"privileges": [
		"DELETE",
		"GRANT_SELECT",
		"INSERT",
		"OWNERSHIP",
		"SELECT",
		"UPDATE",
	],
	"filter": null,
	"filter_environment": {"user": null},
}]

table_rules := policies.tables

first_matching_table_rule(_, "information_schema", _) := {
	"schema": "information_schema",
	"privileges": [
		"DELETE",
		"GRANT_SELECT",
		"INSERT",
		"OWNERSHIP",
		"SELECT",
		"UPDATE",
	],
	"filter": null,
	"filter_environment": {"user": null},
}

first_matching_table_rule(
	catalog_name,
	schema_name,
	table_name,
) := rule if {
	schema_name != "information_schema"
	rules := [rule |
		some rule in table_rules

		match_user_group(rule)

		catalog_pattern := object.get(rule, "catalog", ".*")
		schema_pattern := object.get(rule, "schema", ".*")
		table_pattern := object.get(rule, "table", ".*")

		util.match_entire(catalog_pattern, catalog_name)
		util.match_entire(schema_pattern, schema_name)
		util.match_entire(table_pattern, table_name)
	]
	rule := object.union(
		{
			"filter": null,
			"filter_environment": {"user": null},
		},
		rules[0],
	)
}

default column_constraints(_, _, _, _) := {
	"allow": true,
	"mask": null,
	"mask_environment": {"user": null},
}

column_constraints(_, "information_schema", _, _) := {
	"allow": true,
	"mask": null,
	"mask_environment": {"user": null},
}

column_constraints(
	catalog_name,
	schema_name,
	table_name,
	column_name,
) := constraints if {
	schema_name != "information_schema"

	rule := first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	)

	some column in rule.columns
	column.name == column_name

	constraints := object.union(
		{
			"allow": true,
			"mask": null,
			"mask_environment": {"user": null},
		},
		column,
	)
}

# Table privileges of the first matching rule
default table_privileges(_, _, _) := set()

table_privileges(
	catalog_name,
	schema_name,
	table_name,
) := {privilege |
	some privilege in first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	).privileges
}

# Column access of the first matching rule
default column_access(_, _, _, _) := false

column_access(
	catalog_name,
	schema_name,
	table_name,
	column_name,
) := access if {
	table_privileges(
		catalog_name,
		schema_name,
		table_name,
	) != set()

	column := column_constraints(
		catalog_name,
		schema_name,
		table_name,
		column_name,
	)

	access := column.allow
}

default system_information_rules := []

system_information_rules := policies.system_information

first_matching_system_information_rule := rule if {
	rules := [rule |
		some rule in system_information_rules

		match_user_group(rule)
	]
	rule := rules[0]
}

# System information access of the first matching rule
default system_information_access := set()

system_information_access := {access |
	some access in first_matching_system_information_rule.allow
}

default system_session_properties_rules := [{"allow": true}]

system_session_properties_rules := policies.system_session_properties

first_matching_system_session_properties_rule(property_name) := rule if {
	rules := [rule |
		some rule in system_session_properties_rules

		match_user_group(rule)

		property_name_pattern := object.get(rule, "property", ".*")

		util.match_entire(property_name_pattern, property_name)
	]
	rule := rules[0]
}

# System session property access of the first matching rule
default system_session_properties_access(_) := false

system_session_properties_access(property_name) := first_matching_system_session_properties_rule(property_name).allow
