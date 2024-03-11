package actual_permissions_test

import data.trino
import rego.v1

test_match_entire if {
	trino.match_entire(`a`, "a")
	trino.match_entire(`^a`, "a")
	trino.match_entire(`a$`, "a")
	trino.match_entire(`^a$`, "a")
	not trino.match_entire(`a`, "abc")
	not trino.match_entire(`b`, "abc")
	not trino.match_entire(`c`, "abc")
}

test_match_any_group_with_no_group_memberships_and_the_default_group_pattern if {
	identity := {"user": "testuser", "groups": []}
	group_pattern := ".*"

	trino.match_any_group(group_pattern) with input.context.identity as identity
}

test_match_any_group_with_no_group_memberships_and_a_specific_group_pattern if {
	identity := {"user": "testuser", "groups": []}
	group_pattern := "testgroup"

	not trino.match_any_group(group_pattern) with input.context.identity as identity
}

test_match_any_group_with_groups if {
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	group_pattern := "testgroup2"

	trino.match_any_group(group_pattern) with input.context.identity as identity
}

test_match_any_group_with_no_matching_group if {
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	group_pattern := "othergroup"

	not trino.match_any_group(group_pattern) with input.context.identity as identity
}

test_filter_by_user_group_with_no_rules if {
	rules := []
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_user_group(rules) with input.context.identity as identity

	filtered_rules == []
}

test_filter_by_user_group_with_default_user_and_group_pattern if {
	rules := [{"allow": "all"}]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_user_group(rules) with input.context.identity as identity

	filtered_rules == [{"allow": "all"}]
}

test_filter_by_user_group_with_no_group_memberships if {
	rules := [
		{"group": "othergroup", "allow": "none"},
		{"allow": "all"},
	]
	identity := {"user": "testuser", "groups": []}

	filtered_rules := trino.filter_by_user_group(rules) with input.context.identity as identity

	filtered_rules == [{"allow": "all"}]
}

test_filter_by_user_group_with_matching_user_and_groups if {
	rules := [
		{"user": "testuser"},
		{"group": "testgroup2"},
		{"user": "testuser", "group": "testgroup1"},
		{"user": "otheruser"},
		{"group": "othergroup"},
		{"user": "otheruser", "group": "othergroup"},
	]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_user_group(rules) with input.context.identity as identity

	filtered_rules == [
		{"user": "testuser"},
		{"group": "testgroup2"},
		{"user": "testuser", "group": "testgroup1"},
	]
}

test_filter_by_user_group_with_matching_user_and_groups_regexes if {
	rules := [
		{"user": "test.*"},
		{"group": "test.*"},
		{"user": "test.*", "group": "test.*"},
		{"user": "other.*"},
		{"group": "other.*"},
		{"user": "other.*", "group": "other.*"},
	]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_user_group(rules) with input.context.identity as identity

	filtered_rules == [
		{"user": "test.*"},
		{"group": "test.*"},
		{"user": "test.*", "group": "test.*"},
	]
}

test_filter_by_original_user_group_with_no_rules if {
	rules := []
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_original_user_group(rules) with input.context.identity as identity

	filtered_rules == []
}

test_filter_by_original_user_group_with_default_user_and_group_pattern if {
	rules := [{"allow": "all"}]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_original_user_group(rules) with input.context.identity as identity

	filtered_rules == [{"allow": "all"}]
}

test_filter_by_original_user_group_with_no_group_memberships if {
	rules := [
		{"original_group": "othergroup", "allow": "none"},
		{"allow": "all"},
	]
	identity := {"user": "testuser", "groups": []}

	filtered_rules := trino.filter_by_original_user_group(rules) with input.context.identity as identity

	filtered_rules == [{"allow": "all"}]
}

test_filter_by_original_user_group_with_matching_user_and_groups if {
	rules := [
		{"original_user": "testuser"},
		{"original_group": "testgroup2"},
		{"original_user": "testuser", "original_group": "testgroup1"},
		{"original_user": "otheruser"},
		{"original_group": "othergroup"},
		{"original_user": "otheruser", "original_group": "othergroup"},
	]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_original_user_group(rules) with input.context.identity as identity

	filtered_rules == [
		{"original_user": "testuser"},
		{"original_group": "testgroup2"},
		{"original_user": "testuser", "original_group": "testgroup1"},
	]
}

test_filter_by_original_user_group_with_matching_user_and_groups_regexes if {
	rules := [
		{"original_user": "test.*"},
		{"original_group": "test.*"},
		{"original_user": "test.*", "original_group": "test.*"},
		{"original_user": "other.*"},
		{"original_group": "other.*"},
		{"original_user": "other.*", "original_group": "other.*"},
	]
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	filtered_rules := trino.filter_by_original_user_group(rules) with input.context.identity as identity

	filtered_rules == [
		{"original_user": "test.*"},
		{"original_group": "test.*"},
		{"original_user": "test.*", "original_group": "test.*"},
	]
}

test_authorization_permission_with_matching_rule if {
	policies := {"authorization": [
		{
			"new_user": "non_matching_user",
			"allow": false,
		},
		{
			"original_user": "test.*",
			"original_group": "test.*",
			"new_user": "other.*",
			"allow": true,
		},
		{
			"new_user": ".*",
			"allow": false,
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	grantee_name := "otheruser"

	allowed := trino.authorization_permission(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_authorization_permission_with_no_matching_rule if {
	policies := {"authorization": [
		{
			"original_user": "non_matching_user",
			"new_user": ".*",
		},
		{
			"original_group": "non_matching_group",
			"new_user": ".*",
		},
		{"new_user": "non_matching_user"},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	grantee_name := "otheruser"

	allowed := trino.authorization_permission(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not allowed
}

test_authorization_permission_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	grantee_name := "otheruser"

	allowed := trino.authorization_permission(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not allowed
}

test_catalog_access_with_matching_rule if {
	policies := {"catalogs": [
		{
			"catalog": "non_matching_catalog",
			"allow": "all",
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"allow": "read-only",
		},
		{"allow": "none"},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"

	access := trino.catalog_access(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"read-only"}
}

test_catalog_access_with_no_matching_rule if {
	policies := {"catalogs": [
		{
			"user": "non_matching_user",
			"allow": "all",
		},
		{
			"group": "non_matching_group",
			"allow": "all",
		},
		{
			"catalog": "non_matching_catalog",
			"allow": "all",
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"

	access := trino.catalog_access(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"none"}
}

test_catalog_access_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"

	access := trino.catalog_access(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"all", "read-only"}
}

test_catalog_session_properties_access_with_matching_rule if {
	policies := {"catalog_session_properties": [
		{
			"catalog": "non_matching_catalog",
			"allow": false,
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"property": "testproperty",
			"allow": true,
		},
		{"allow": false},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	allowed := trino.catalog_session_properties_access(catalog_name, property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_catalog_session_properties_access_with_no_matching_rule if {
	policies := {"catalog_session_properties": [
		{
			"user": "non_matching_user",
			"allow": true,
		},
		{
			"group": "non_matching_group",
			"allow": true,
		},
		{
			"catalog": "non_matching_catalog",
			"allow": true,
		},
		{
			"property": "non_matching_property",
			"allow": true,
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	allowed := trino.catalog_session_properties_access(catalog_name, property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not allowed
}

test_catalog_session_properties_access_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	allowed := trino.catalog_session_properties_access(catalog_name, property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_function_privileges_with_matching_rule if {
	policies := {"functions": [
		{
			"function": "non_matching_function",
			"privileges": [],
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"schema": "testschema",
			"function": "testfunction",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
		{"privileges": []},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	privileges := trino.function_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"}
}

test_function_privileges_with_no_matching_rule if {
	policies := {"functions": [
		{
			"user": "non_matching_user",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
		{
			"group": "non_matching_group",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
		{
			"catalog": "non_matching_catalog",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
		{
			"schema": "non_matching_schema",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
		{
			"function": "non_matching_function",
			"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	privileges := trino.function_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == set()
}

test_function_privileges_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	privileges := trino.function_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == set()
}

test_function_privileges_with_no_rules_on_system_builtin if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "system"
	schema_name := "builtin"
	function_name := "testfunction"

	privileges := trino.function_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"GRANT_EXECUTE", "EXECUTE"}
}

test_impersonation_access_with_matching_user if {
	policies := {"impersonation": [
		{
			"new_user": "non_matching_user",
			"allow": false,
		},
		{
			"original_user": "testuser",
			"new_user": "otheruser",
			"allow": true,
		},
		{
			"new_user": ".*",
			"allow": false,
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "otheruser"

	allowed := trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_impersonation_access_with_self_impersonation if {
	policies := {"impersonation": [{
		"original_user": "testuser",
		"new_user": "testuser",
		"allow": false,
	}]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "testuser"

	allowed := trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_impersonation_access_with_matching_capture_groups if {
	policies := {"impersonation": [
		{
			"new_user": "non_matching_user",
			"allow": false,
		},
		{
			"original_user": "user_(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
			"new_user": "user_$10$9$8$7$6$5$4$3$2$1",
			"allow": true,
		},
		{
			"new_user": ".*",
			"allow": false,
		},
	]}
	identity := {"user": "user_abcdefghij", "groups": ["testgroup1", "testgroup2"]}

	# Only nine capture groups are supported, therefore "$10" is seen as
	# "$1" and "0" and will be substituted with "a0" and not "j":
	user := "user_a0ihgfedcba"

	allowed := trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed
}

test_impersonation_access_with_no_matching_rule if {
	policies := {"impersonation": [
		{
			"original_user": "non_matching_user",
			"new_user": "otheruser",
			"allow": true,
		},
		{
			"new_user": "non_matching_user",
			"allow": true,
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "otheruser"

	allowed := trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not allowed
}

test_impersonation_access_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "otheruser"

	allowed := trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not allowed
}

test_procedure_privileges_with_matching_rule if {
	policies := {"procedures": [
		{
			"procedure": "non_matching_procedure",
			"privileges": [],
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"schema": "testschema",
			"procedure": "testprocedure",
			"privileges": ["EXECUTE"],
		},
		{"privileges": []},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	privileges := trino.procedure_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"EXECUTE"}
}

test_procedure_privileges_with_no_matching_rule if {
	policies := {"procedures": [
		{
			"user": "non_matching_user",
			"privileges": ["GRANT_EXECUTE", "EXECUTE"],
		},
		{
			"group": "non_matching_group",
			"privileges": ["GRANT_EXECUTE", "EXECUTE"],
		},
		{
			"catalog": "non_matching_catalog",
			"privileges": ["GRANT_EXECUTE", "EXECUTE"],
		},
		{
			"schema": "non_matching_schema",
			"privileges": ["GRANT_EXECUTE", "EXECUTE"],
		},
		{
			"procedure": "non_matching_function",
			"privileges": ["GRANT_EXECUTE", "EXECUTE"],
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	privileges := trino.procedure_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == set()
}

test_procedure_privileges_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	privileges := trino.procedure_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == set()
}

test_procedure_privileges_with_no_rules_on_system_builtin if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "system"
	schema_name := "builtin"
	function_name := "testprocedure"

	privileges := trino.procedure_privileges(catalog_name, schema_name, function_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"GRANT_EXECUTE", "EXECUTE"}
}

test_query_access_with_matching_rule if {
	policies := {"queries": [
		{
			"user": "non_matching_user",
			"allow": [],
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"allow": ["execute"],
		},
		{"allow": []},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	access := trino.query_access with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"execute"}
}

test_query_access_with_no_matching_rule if {
	policies := {"queries": [
		{
			"user": "non_matching_user",
			"allow": ["execute", "kill", "view"],
		},
		{
			"group": "non_matching_group",
			"allow": ["execute", "kill", "view"],
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	access := trino.query_access with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == set()
}

test_query_access_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}

	access := trino.query_access with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"execute", "kill", "view"}
}

test_query_owned_by_access_with_matching_rule if {
	policies := {"queries": [
		{
			"queryOwner": "non_matching_query_owner",
			"allow": [],
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"queryOwner": "testowner",
			"allow": ["view"],
		},
		{"allow": []},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "testowner"

	access := trino.query_owned_by_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"view"}
}

test_query_owned_by_access_with_no_matching_rule if {
	policies := {"queries": [
		{
			"user": "non_matching_user",
			"allow": ["kill", "view"],
		},
		{
			"group": "non_matching_group",
			"allow": ["kill", "view"],
		},
		{
			"queryOwner": "non_matching_query_owner",
			"allow": ["kill", "view"],
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "testowner"

	access := trino.query_owned_by_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == set()
}

test_query_owned_by_access_with_self_ownership if {
	policies := {"queries": [{
		"user": "testuser",
		"group": "testgroup1",
		"queryOwner": "testuser",
		"allow": [],
	}]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "testuser"

	access := trino.query_owned_by_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"kill", "view"}
}

test_query_owned_by_access_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	user := "testowner"

	access := trino.query_owned_by_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"execute", "kill", "view"}
}

test_schema_owner_with_matching_rule if {
	policies := {"schemas": [
		{
			"schema": "non_matching_schema",
			"owner": false,
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"schema": "testschema",
			"owner": true,
		},
		{"owner": false},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	owner := trino.schema_owner(catalog_name, schema_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	owner
}

test_schema_owner_with_no_matching_rule if {
	policies := {"schemas": [
		{
			"user": "non_matching_user",
			"owner": true,
		},
		{
			"group": "non_matching_group",
			"owner": true,
		},
		{
			"catalog": "non_matching_catalog",
			"owner": true,
		},
		{
			"schema": "non_matching_schema",
			"owner": true,
		},
	]}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	owner := trino.schema_owner(catalog_name, schema_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	not owner
}

test_schema_owner_with_no_rules if {
	policies := {}
	identity := {"user": "testuser", "groups": ["testgroup1", "testgroup2"]}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	owner := trino.schema_owner(catalog_name, schema_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	owner
}
