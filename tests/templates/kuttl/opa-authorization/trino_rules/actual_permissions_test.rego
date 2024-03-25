package actual_permissions_test

import data.trino
import rego.v1

# These tests check that all rules and functions return the expected
# result for the given test identity and action.
#
# In most cases, there are the following tests for each resource:
#   * test_first_matching_resource_rule_with_matching_rule
#     The policies usually contain three entries where only the second
#     and third one match. It is expected that the second one is
#     returned.
#   * test_first_matching_resource_rule_with_no_matching_rule
#     In every rule of the policies, there is one condition which is not
#     met and therefore the first_matching_resource_rule function should
#     return undefined.
#   * test_first_matching_resource_rule_with_no_rules
#     If no rules are defined in the policies for the given resource,
#     then the first_matching_resource_rule function should return
#     either the default rule or undefined.
#   * test_resource_permission
#     Checks that the resource_permission function returns the expected
#     permission

test_match_any_group_with_no_group_memberships_and_the_default_group_pattern if {
	identity := {"user": "testuser", "groups": []}
	group_pattern := ".*"

	matches := trino.match_any_group(group_pattern) with input.context.identity as identity

	matches == true
}

test_match_any_group_with_no_group_memberships_and_a_specific_group_pattern if {
	identity := {"user": "testuser", "groups": []}
	group_pattern := "testgroup"

	matches := trino.match_any_group(group_pattern) with input.context.identity as identity

	matches == false
}

test_match_any_group_with_groups if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	group_pattern := "testgroup2"

	matches := trino.match_any_group(group_pattern) with input.context.identity as identity

	matches == true
}

test_match_any_group_with_no_matching_group if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	group_pattern := "othergroup"

	matches := trino.match_any_group(group_pattern) with input.context.identity as identity

	matches == false
}

test_match_user_group_with_default_user_and_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches := trino.match_user_group({}) with input.context.identity as identity

	matches == true
}

test_match_user_group_with_user_and_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_user_and_group := trino.match_user_group({
		"user": "test.*",
		"group": "test.*",
	}) with input.context.identity as identity
	matches_user_and_group == true

	matches_other_group := trino.match_user_group({
		"user": "test.*",
		"group": "other.*",
	}) with input.context.identity as identity
	matches_other_group == false

	matches_other_user := trino.match_user_group({
		"user": "other.*",
		"group": "test.*",
	}) with input.context.identity as identity
	matches_other_user == false
}

test_match_user_group_with_user_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_user := trino.match_user_group({"user": "test.*"}) with input.context.identity as identity
	matches_user == true

	matches_other_user := trino.match_user_group({"user": "other.*"}) with input.context.identity as identity
	matches_other_user == false
}

test_match_user_group_with_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_group := trino.match_user_group({"group": "test.*"}) with input.context.identity as identity
	matches_group == true

	matches_other_group := trino.match_user_group({"group": "other.*"}) with input.context.identity as identity
	matches_other_group == false
}

test_match_original_user_group_with_default_user_and_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches := trino.match_original_user_group({}) with input.context.identity as identity

	matches == true
}

test_match_original_user_group_with_user_and_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_user_and_group := trino.match_original_user_group({
		"original_user": "test.*",
		"original_group": "test.*",
	}) with input.context.identity as identity
	matches_user_and_group == true

	matches_other_group := trino.match_original_user_group({
		"original_user": "test.*",
		"original_group": "other.*",
	}) with input.context.identity as identity
	matches_other_group == false

	matches_other_user := trino.match_original_user_group({
		"original_user": "other.*",
		"original_group": "test.*",
	}) with input.context.identity as identity
	matches_other_user == false
}

test_match_original_user_group_with_user_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_user := trino.match_original_user_group({"original_user": "test.*"}) with input.context.identity as identity
	matches_user == true

	matches_other_user := trino.match_original_user_group({"original_user": "other.*"}) with input.context.identity as identity
	matches_other_user == false
}

test_match_original_user_group_with_group_pattern if {
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	matches_group := trino.match_original_user_group({"original_group": "test.*"}) with input.context.identity as identity
	matches_group == true

	matches_other_group := trino.match_original_user_group({"original_group": "other.*"}) with input.context.identity as identity
	matches_other_group == false
}

test_first_matching_authorization_rule_with_matching_rule if {
	policies := {"authorization": [
		{
			"new_user": "non_matching_user",
			"allow": false,
		},
		{
			"original_user": "test.*",
			"original_group": "test.*",
			"new_user": "other.*",
			"allow": false,
		},
		{
			"new_user": ".*",
			"allow": false,
		},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	grantee_name := "otheruser"

	rule := trino.first_matching_authorization_rule(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"original_user": "test.*",
		"original_group": "test.*",
		"new_user": "other.*",
		"allow": false,
	}
}

test_first_matching_authorization_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	grantee_name := "otheruser"

	not trino.first_matching_authorization_rule(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_authorization_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	grantee_name := "otheruser"

	not trino.first_matching_authorization_rule(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_authorization_permission if {
	policies := {"authorization": [{"new_user": "other.*"}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	grantee_name := "otheruser"

	allowed := trino.authorization_permission(grantee_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	allowed == true
}

test_first_matching_catalog_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"

	rule := trino.first_matching_catalog_rule(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"allow": "read-only",
	}
}

test_first_matching_catalog_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"

	not trino.first_matching_catalog_rule(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_catalog_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"

	rule := trino.first_matching_catalog_rule(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"allow": "all"}
}

test_catalog_access if {
	policies := {"catalogs": [{"allow": "all"}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"

	access := trino.catalog_access(catalog_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"all", "read-only"}
}

test_first_matching_catalog_session_properties_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	rule := trino.first_matching_catalog_session_properties_rule(
		catalog_name,
		property_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"property": "testproperty",
		"allow": true,
	}
}

test_first_matching_catalog_session_properties_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	not trino.first_matching_catalog_session_properties_rule(
		catalog_name,
		property_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_catalog_session_properties_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	rule := trino.first_matching_catalog_session_properties_rule(
		catalog_name,
		property_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"allow": true}
}

test_catalog_session_properties_access if {
	policies := {"catalog_session_properties": [{"allow": true}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	property_name := "testproperty"

	access := trino.catalog_session_properties_access(
		catalog_name,
		property_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == true
}

test_catalog_visibility if {
	policies := {
		"catalogs": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_catalogs_and_all_access",
				"allow": "all",
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_catalogs_and_read_only_access",
				"allow": "read-only",
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_catalogs_and_no_access",
				"allow": "none",
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_(schemas|tables|functions|procedures|catalog_session_properties)_.*",
				"allow": "read-only",
			},
		],
		"schemas": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_schemas_with_ownership",
				"owner": true,
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_schemas_with_no_ownership",
				"owner": false,
			},
		],
		"tables": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_tables_and_privileges",
				"privileges": ["SELECT"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_tables_and_no_privileges",
				"privileges": [],
			},
		],
		"functions": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_functions_and_privileges",
				"privileges": ["EXECUTE"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_functions_and_no_privileges",
				"privileges": [],
			},
		],
		"procedures": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_procedures_and_privileges",
				"privileges": ["EXECUTE"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_procedures_and_no_privileges",
				"privileges": [],
			},
		],
		"catalog_session_properties": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_catalog_session_properties_and_access_allowed",
				"allow": true,
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog_on_catalog_session_properties_and_no_access_allowed",
				"allow": false,
			},
		],
	}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	testcatalog_on_catalogs_and_all_access_visible := trino.catalog_visibility("testcatalog_on_catalogs_and_all_access") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_catalogs_and_all_access_visible == true

	testcatalog_on_catalogs_and_read_only_access_visible := trino.catalog_visibility("testcatalog_on_catalogs_and_read_only_access") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_catalogs_and_read_only_access_visible == false

	testcatalog_on_catalogs_and_no_access_visible := trino.catalog_visibility("testcatalog_on_catalogs_and_no_access") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_catalogs_and_no_access_visible == false

	testcatalog_on_schemas_and_ownership_visible := trino.catalog_visibility("testcatalog_on_schemas_with_ownership") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_schemas_and_ownership_visible == true

	testcatalog_on_schemas_and_no_ownership_visible := trino.catalog_visibility("testcatalog_on_schemas_with_no_ownership") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_schemas_and_no_ownership_visible == false

	testcatalog_on_tables_and_privileges_visible := trino.catalog_visibility("testcatalog_on_tables_and_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_tables_and_privileges_visible == true

	testcatalog_on_tables_and_no_privileges_visible := trino.catalog_visibility("testcatalog_on_tables_and_no_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_tables_and_no_privileges_visible == false

	testcatalog_on_functions_and_privileges_visible := trino.catalog_visibility("testcatalog_on_functions_and_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_functions_and_privileges_visible == true

	testcatalog_on_functions_and_no_privileges_visible := trino.catalog_visibility("testcatalog_on_functions_and_no_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_functions_and_no_privileges_visible == false

	testcatalog_on_procedures_and_privileges_visible := trino.catalog_visibility("testcatalog_on_procedures_and_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_procedures_and_privileges_visible == true

	testcatalog_on_procedures_and_no_privileges_visible := trino.catalog_visibility("testcatalog_on_procedures_and_no_privileges") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_procedures_and_no_privileges_visible == false

	testcatalog_on_catalog_session_properties_and_access_allowed_visible := trino.catalog_visibility("testcatalog_on_catalog_session_properties_and_access_allowed") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_catalog_session_properties_and_access_allowed_visible == true

	testcatalog_on_catalog_session_properties_and_no_access_allowed_visible := trino.catalog_visibility("testcatalog_on_catalog_session_properties_and_no_access_allowed") with data.trino_policies.policies as policies
		with input.context.identity as identity
	testcatalog_on_catalog_session_properties_and_no_access_allowed_visible == false

	non_matching_catalog_visible := trino.catalog_visibility("non_matching_catalog") with data.trino_policies.policies as policies
		with input.context.identity as identity
	non_matching_catalog_visible == false

	non_matching_user_on_schemas_visible := trino.catalog_visibility("testcatalog_on_schemas_with_ownership") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "non_matching_user",
			"groups": [
				"testgroup1",
				"testgroup2",
			],
		}
	non_matching_user_on_schemas_visible == false

	non_matching_group_on_schemas_visible := trino.catalog_visibility("testcatalog_on_schemas_with_ownership") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "testuser",
			"groups": ["non_matching_group"],
		}
	non_matching_group_on_schemas_visible == false

	non_matching_user_on_tables_visible := trino.catalog_visibility("testcatalog_on_tables_and_privileges") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "non_matching_user",
			"groups": [
				"testgroup1",
				"testgroup2",
			],
		}
	non_matching_user_on_tables_visible == false

	non_matching_group_on_tables_visible := trino.catalog_visibility("testcatalog_on_tables_and_privileges") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "testuser",
			"groups": ["non_matching_group"],
		}
	non_matching_group_on_tables_visible == false

	non_matching_user_on_catalog_session_properties_visible := trino.catalog_visibility("testcatalog_on_catalog_session_properties_and_access_allowed") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "non_matching_user",
			"groups": [
				"testgroup1",
				"testgroup2",
			],
		}
	non_matching_user_on_catalog_session_properties_visible == false

	non_matching_group_on_catalog_session_properties_visible := trino.catalog_visibility("testcatalog_on_catalog_session_properties_and_access_allowed") with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "testuser",
			"groups": ["non_matching_group"],
		}
	non_matching_group_on_catalog_session_properties_visible == false
}

test_first_matching_function_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	rule := trino.first_matching_function_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"schema": "testschema",
		"function": "testfunction",
		"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"],
	}
}

test_first_matching_function_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	not trino.first_matching_function_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_function_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "system"
	schema_name := "builtin"
	function_name := "testfunction"

	rule := trino.first_matching_function_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"catalog": "system",
		"schema": "builtin",
		"privileges": [
			"GRANT_EXECUTE",
			"EXECUTE",
		],
	}
}

test_function_privileges if {
	policies := {"functions": [{"privileges": ["GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testfunction"

	privileges := trino.function_privileges(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"GRANT_EXECUTE", "EXECUTE", "OWNERSHIP"}
}

test_first_matching_impersonation_rule_with_matching_rule if {
	policies := {"impersonation": [
		{
			"new_user": "non_matching_user",
			"allow": false,
		},
		{
			"original_user": "user_(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
			"new_user": "user_$10$9$8$7$6$5$4$3$2$1",
			"allow": false,
		},
		{
			"new_user": ".*",
			"allow": false,
		},
	]}
	identity := {
		"user": "user_abcdefghij",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	# Only nine capture groups are supported, therefore "$10" is seen as
	# "$1" and "0" and will be substituted with "a0" and not "j":
	user := "user_a0ihgfedcba"

	rule := trino.first_matching_impersonation_rule(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"original_user": "user_(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)",
		"new_user": "user_$10$9$8$7$6$5$4$3$2$1",
		"allow": false,
	}
}

test_first_matching_impersonation_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	user := "otheruser"

	not trino.first_matching_impersonation_rule(user) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_impersonation_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	user := "otheruser"

	not trino.impersonation_access(user) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_impersonation_access if {
	policies := {"impersonation": [{"new_user": "otheruser"}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	impersonate_as_otheruser := trino.impersonation_access("otheruser") with data.trino_policies.policies as policies
		with input.context.identity as identity
	impersonate_as_otheruser == true

	impersonate_as_self := trino.impersonation_access("testuser") with data.trino_policies.policies as policies
		with input.context.identity as identity
	impersonate_as_self == true
}

test_first_matching_procedure_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	rule := trino.first_matching_procedure_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"schema": "testschema",
		"procedure": "testprocedure",
		"privileges": ["EXECUTE"],
	}
}

test_first_matching_procedure_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	not trino.first_matching_procedure_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_procedure_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "system"
	schema_name := "builtin"
	function_name := "testprocedure"

	rule := trino.first_matching_procedure_rule(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"catalog": "system",
		"schema": "builtin",
		"privileges": [
			"GRANT_EXECUTE",
			"EXECUTE",
		],
	}
}

test_procedure_privileges if {
	policies := {"procedures": [{"privileges": ["EXECUTE"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	function_name := "testprocedure"

	privileges := trino.procedure_privileges(
		catalog_name,
		schema_name,
		function_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"EXECUTE"}
}

test_first_matching_query_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	rule := trino.first_matching_query_rule with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"allow": ["execute"],
	}
}

test_first_matching_query_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	not trino.first_matching_query_rule with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_query_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	rule := trino.first_matching_query_rule with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"allow": ["execute", "kill", "view"]}
}

test_query_access if {
	policies := {"queries": [{"allow": ["execute"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	access := trino.query_access with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"execute"}
}

test_first_matching_query_owned_by_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	user := "testowner"

	rule := trino.first_matching_query_owned_by_rule(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"queryOwner": "testowner",
		"allow": ["view"],
	}
}

test_first_matching_query_owned_by_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	user := "testowner"

	not trino.first_matching_query_owned_by_rule(user) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_query_owned_by_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	user := "testowner"

	rule := trino.first_matching_query_owned_by_rule(user) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"allow": ["execute", "kill", "view"]}
}

test_query_owned_by_access if {
	policies := {"queries": [{"allow": ["view"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	access_owned_by_other := trino.query_owned_by_access("testowner") with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_owned_by_other == {"view"}

	access_owned_by_self := trino.query_owned_by_access("testuser") with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_owned_by_self == {"kill", "view"}
}

test_first_matching_schema_rule_with_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	rule := trino.first_matching_schema_rule(
		catalog_name,
		schema_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"schema": "testschema",
		"owner": true,
	}
}

test_first_matching_schema_rule_with_no_matching_rule if {
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
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	not trino.first_matching_schema_rule(
		catalog_name,
		schema_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_schema_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	rule := trino.first_matching_schema_rule(
		catalog_name,
		schema_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"owner": true}
}

test_schema_owner if {
	policies := {"schemas": [{"owner": true}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"

	owner := trino.schema_owner(
		catalog_name,
		schema_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	owner == true
}

test_schema_visibility if {
	policies := {
		"schemas": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_schemas_and_ownership",
				"owner": true,
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_schemas_and_no_ownership",
				"owner": false,
			},
		],
		"tables": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_tables_and_privileges",
				"privileges": ["SELECT"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_tables_and_no_privileges",
				"privileges": [],
			},
		],
		"functions": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_functions_and_privileges",
				"privileges": ["EXECUTE"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_functions_and_no_privileges",
				"privileges": [],
			},
		],
		"procedures": [
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_procedures_and_privileges",
				"privileges": ["EXECUTE"],
			},
			{
				"user": "testuser",
				"group": "testgroup1",
				"catalog": "testcatalog",
				"schema": "testschema_on_procedures_and_no_privileges",
				"privileges": [],
			},
		],
	}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	testschema_on_schemas_and_ownership_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_schemas_and_ownership",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_schemas_and_ownership_visible == true

	testschema_on_schemas_and_no_ownership_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_schemas_and_no_ownership",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_schemas_and_no_ownership_visible == false

	information_schema_visible := trino.schema_visibility(
		"testcatalog",
		"information_schema",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	information_schema_visible == true

	testschema_on_tables_and_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_tables_and_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_tables_and_privileges_visible == true

	testschema_on_tables_and_no_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_tables_and_no_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_tables_and_no_privileges_visible == false

	testschema_on_functions_and_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_functions_and_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_functions_and_privileges_visible == true

	testschema_on_functions_and_no_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_functions_and_no_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_functions_and_no_privileges_visible == false

	testschema_on_procedures_and_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_procedures_and_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_procedures_and_privileges_visible == true

	testschema_on_procedures_and_no_privileges_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_procedures_and_no_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	testschema_on_procedures_and_no_privileges_visible == false

	non_matching_catalog_visible := trino.schema_visibility(
		"non_matching_catalog",
		"testschema_on_schemas_and_ownership",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	non_matching_catalog_visible == false

	non_matching_schema_visible := trino.schema_visibility(
		"testcatalog",
		"non_matching_schema",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	non_matching_schema_visible == false

	non_matching_user_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_tables_and_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "non_matching_user",
			"groups": [
				"testgroup1",
				"testgroup2",
			],
		}
	non_matching_user_visible == false

	non_matching_group_visible := trino.schema_visibility(
		"testcatalog",
		"testschema_on_tables_and_privileges",
	) with data.trino_policies.policies as policies
		with input.context.identity as {
			"user": "testuser",
			"groups": ["non_matching_group"],
		}
	non_matching_group_visible == false
}

test_first_matching_table_rule_with_matching_rule if {
	policies := {"tables": [
		{
			"table": "non_matching_table",
			"privileges": [],
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"catalog": "testcatalog",
			"schema": "testschema",
			"table": "testtable",
			"privileges": ["DELETE", "INSERT", "SELECT"],
		},
		{"privileges": []},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"

	rule := trino.first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"catalog": "testcatalog",
		"schema": "testschema",
		"table": "testtable",
		"filter": null,
		"filter_environment": {"user": null},
		"privileges": ["DELETE", "INSERT", "SELECT"],
	}
}

test_first_matching_table_rule_with_no_matching_rule if {
	policies := {"tables": [
		{
			"user": "non_matching_user",
			"privileges": ["OWNERSHIP"],
		},
		{
			"group": "non_matching_group",
			"privileges": ["OWNERSHIP"],
		},
		{
			"catalog": "non_matching_catalog",
			"privileges": ["OWNERSHIP"],
		},
		{
			"schema": "non_matching_schema",
			"privileges": ["OWNERSHIP"],
		},
		{
			"table": "non_matching_table",
			"privileges": ["OWNERSHIP"],
		},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"

	not trino.first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_table_rule_with_information_schema if {
	policies := {"tables": [{
		"schema": "information_schema",
		"privileges": [],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "information_schema"
	table_name := "testtable"

	rule := trino.first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
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
}

test_first_matching_table_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"

	rule := trino.first_matching_table_rule(
		catalog_name,
		schema_name,
		table_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
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
}

test_column_constraints_with_matching_rule_and_all_fields if {
	policies := {"tables": [{
		"columns": [
			{"name": "non_matching_column1"},
			{
				"name": "testcolumn",
				"allow": false,
				"mask": "testmask",
				"mask_environment": {"user": "testmaskenvironmentuser"},
			},
			{"name": "non_matching_column2"},
		],
		"privileges": ["DELETE", "INSERT", "SELECT"],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"
	column_name := "testcolumn"

	column := trino.column_constraints(
		catalog_name,
		schema_name,
		table_name,
		column_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	column == {
		"name": "testcolumn",
		"allow": false,
		"mask": "testmask",
		"mask_environment": {"user": "testmaskenvironmentuser"},
	}
}

test_column_constraints_with_matching_rule_and_required_fields if {
	policies := {"tables": [{
		"columns": [
			{"name": "non_matching_column1"},
			{"name": "testcolumn"},
			{"name": "non_matching_column2"},
		],
		"privileges": ["DELETE", "INSERT", "SELECT"],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"
	column_name := "testcolumn"

	column := trino.column_constraints(
		catalog_name,
		schema_name,
		table_name,
		column_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	column == {
		"name": "testcolumn",
		"allow": true,
		"mask": null,
		"mask_environment": {"user": null},
	}
}

test_column_constraints_with_information_schema if {
	policies := {"tables": [{
		"columns": [{
			"name": "testcolumn",
			"allow": false,
		}],
		"privileges": ["DELETE", "INSERT", "SELECT"],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "information_schema"
	table_name := "testtable"
	column_name := "testcolumn"

	column := trino.column_constraints(
		catalog_name,
		schema_name,
		table_name,
		column_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	column == {
		"allow": true,
		"mask": null,
		"mask_environment": {"user": null},
	}
}

test_column_constraints_with_no_matching_column if {
	policies := {"tables": [{
		"columns": [{"name": "non_matching_column"}],
		"privileges": ["DELETE", "INSERT", "SELECT"],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"
	column_name := "testcolumn"

	column := trino.column_constraints(
		catalog_name,
		schema_name,
		table_name,
		column_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	column == {
		"allow": true,
		"mask": null,
		"mask_environment": {"user": null},
	}
}

test_table_privileges if {
	policies := {"tables": [{"privileges": ["DELETE", "INSERT", "SELECT"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	catalog_name := "testcatalog"
	schema_name := "testschema"
	table_name := "testtable"

	privileges := trino.table_privileges(
		catalog_name,
		schema_name,
		table_name,
	) with data.trino_policies.policies as policies
		with input.context.identity as identity

	privileges == {"DELETE", "INSERT", "SELECT"}
}

test_column_access if {
	policies := {"tables": [
		{
			"table": "testtable1",
			"columns": [
				{
					"name": "testcolumn1",
					"allow": true,
				},
				{
					"name": "testcolumn2",
					"allow": false,
				},
			],
			"privileges": ["SELECT"],
		},
		{
			"table": "testtable2",
			"columns": [
				{
					"name": "testcolumn1",
					"allow": true,
				},
				{
					"name": "testcolumn2",
					"allow": false,
				},
			],
			"privileges": [],
		},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	access_allowed_column_with_privileges := trino.column_access(
		"testcatalog",
		"testschema",
		"testtable1",
		"testcolumn1",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_allowed_column_with_privileges == true

	access_disallowed_column_with_privileges := trino.column_access(
		"testcatalog",
		"testschema",
		"testtable1",
		"testcolumn2",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_disallowed_column_with_privileges == false

	access_allowed_column_without_privileges := trino.column_access(
		"testcatalog",
		"testschema",
		"testtable2",
		"testcolumn1",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_allowed_column_without_privileges == false

	access_disallowed_column_without_privileges := trino.column_access(
		"testcatalog",
		"testschema",
		"testtable2",
		"testcolumn2",
	) with data.trino_policies.policies as policies
		with input.context.identity as identity
	access_disallowed_column_without_privileges == false
}

test_first_matching_system_information_rule_with_matching_rule if {
	policies := {"system_information": [
		{
			"user": "non_matching_user",
			"allow": [],
		},
		{
			"user": "testuser",
			"allow": ["read", "write"],
		},
		{"allow": []},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	rule := trino.first_matching_system_information_rule with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"allow": ["read", "write"],
	}
}

test_first_matching_system_information_rule_with_no_matching_rule if {
	policies := {"system_information": [{
		"user": "non_matching_user",
		"allow": ["read", "write"],
	}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	not trino.first_matching_system_information_rule with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_system_information_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	not trino.first_matching_system_information_rule with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_system_information_access if {
	policies := {"system_information": [{"allow": ["read", "write"]}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}

	access := trino.system_information_access with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == {"read", "write"}
}

test_first_matching_system_session_properties_rule_with_matching_rule if {
	policies := {"system_session_properties": [
		{
			"property": "non_matching_property",
			"allow": false,
		},
		{
			"user": "testuser",
			"group": "testgroup1",
			"property": "testproperty",
			"allow": true,
		},
		{"allow": false},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	property_name := "testproperty"

	rule := trino.first_matching_system_session_properties_rule(property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {
		"user": "testuser",
		"group": "testgroup1",
		"property": "testproperty",
		"allow": true,
	}
}

test_first_matching_system_session_properties_rule_with_no_matching_rule if {
	policies := {"system_session_properties": [
		{
			"user": "non_matching_user",
			"allow": true,
		},
		{
			"group": "non_matching_group",
			"allow": true,
		},
		{
			"property": "non_matching_property",
			"allow": true,
		},
	]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	property_name := "testproperty"

	not trino.first_matching_system_session_properties_rule(property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity
}

test_first_matching_system_session_properties_rule_with_no_rules if {
	policies := {}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	property_name := "testproperty"

	rule := trino.first_matching_system_session_properties_rule(property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	rule == {"allow": true}
}

test_system_session_properties_access if {
	policies := {"system_session_properties": [{"allow": true}]}
	identity := {
		"user": "testuser",
		"groups": [
			"testgroup1",
			"testgroup2",
		],
	}
	property_name := "testproperty"

	access := trino.system_session_properties_access(property_name) with data.trino_policies.policies as policies
		with input.context.identity as identity

	access == true
}
