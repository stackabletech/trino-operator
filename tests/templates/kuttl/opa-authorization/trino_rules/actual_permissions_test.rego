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
		{"group": "banned_group", "allow": "none"},
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
		{"original_group": "banned_group", "allow": "none"},
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
	policies := {"authorization": [{
		"original_user": "test.*",
		"original_group": "test.*",
		"new_user": "other.*",
		"allow": true,
	}]}
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

test_impersonation_access_with_matching_user if {
	policies := {"impersonation": [{
		"original_user": "testuser",
		"new_user": "otheruser",
		"allow": true,
	}]}
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
	policies := {"impersonation": [{
		"original_user": "user_(a)(b)(c)(d)(e)(f)(g)(h)(i)",
		"new_user": "user_$9$8$7$6$5$4$3$2$1",
		"allow": true,
	}]}
	identity := {"user": "user_abcdefghi", "groups": ["testgroup1", "testgroup2"]}
	user := "user_ihgfedcba"

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
