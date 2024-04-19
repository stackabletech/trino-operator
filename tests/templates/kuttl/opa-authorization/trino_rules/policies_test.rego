package policies_test

import data.trino
import rego.v1

# These tests check that all rule lists are concatenated as expected and
# that defaults are applied if necessary.
# If the stackable_policies are changed then these tests must also be
# adapted.

test_policies_with_external_policies if {
	external_policies := {
		"authorization": [{"original_user": "testuser"}],
		"catalogs": [{
			"user": "testuser",
			"allow": "read-only",
		}],
		"catalog_session_properties": [{
			"user": "testuser",
			"allow": true,
		}],
		"functions": [{
			"user": "testuser",
			"privileges": ["EXECUTE"],
		}],
		"impersonation": [{"original_user": "testuser"}],
		"procedures": [{
			"user": "testuser",
			"privileges": ["EXECUTE"],
		}],
		"queries": [{
			"user": "testuser",
			"allow": ["view"],
		}],
		"schemas": [{
			"user": "testuser",
			"owner": true,
		}],
		"tables": [{
			"user": "testuser",
			"privileges": ["SELECT"],
		}],
		"system_information": [{
			"user": "testuser",
			"allow": ["read"],
		}],
		"system_session_properties": [{
			"user": "testuser",
			"allow": true,
		}],
	}

	policies := trino.policies with data.trino_policies.policies as external_policies

	policies == {
		"authorization": [
			{"original_user": "admin"},
			{"original_user": "testuser"},
		],
		"catalogs": [
			{
				"user": "admin",
				"allow": "all",
			},
			{
				"user": "testuser",
				"allow": "read-only",
			},
		],
		"catalog_session_properties": [
			{
				"user": "admin",
				"allow": true,
			},
			{
				"user": "testuser",
				"allow": true,
			},
		],
		"functions": [
			{
				"user": "admin",
				"privileges": [
					"EXECUTE",
					"GRANT_EXECUTE",
					"OWNERSHIP",
				],
			},
			{
				"user": "testuser",
				"privileges": ["EXECUTE"],
			},
		],
		"impersonation": [
			{"original_user": "admin"},
			{"original_user": "testuser"},
		],
		"procedures": [
			{
				"user": "admin",
				"privileges": [
					"EXECUTE",
					"GRANT_EXECUTE",
				],
			},
			{
				"user": "testuser",
				"privileges": ["EXECUTE"],
			},
		],
		"queries": [
			{
				"user": "admin",
				"allow": [
					"execute",
					"kill",
					"view",
				],
			},
			{
				"user": "testuser",
				"allow": ["view"],
			},
		],
		"schemas": [
			{
				"user": "admin",
				"owner": true,
			},
			{
				"user": "testuser",
				"owner": true,
			},
		],
		"tables": [
			{
				"user": "admin",
				"privileges": [
					"DELETE",
					"GRANT_SELECT",
					"INSERT",
					"OWNERSHIP",
					"SELECT",
					"UPDATE",
				],
			},
			{
				"user": "testuser",
				"privileges": ["SELECT"],
			},
		],
		"system_information": [
			{
				"user": "admin",
				"allow": [
					"read",
					"write",
				],
			},
			{
				"user": "testuser",
				"allow": ["read"],
			},
		],
		"system_session_properties": [
			{
				"user": "admin",
				"allow": true,
			},
			{
				"user": "testuser",
				"allow": true,
			},
		],
	}
}

test_policies_with_no_external_policies if {
	external_policies := {}

	policies := trino.policies with data.trino_policies.policies as external_policies

	policies == {
		"authorization": [{"original_user": "admin"}],
		"catalogs": [
			{
				"user": "admin",
				"allow": "all",
			},
			{"allow": "all"},
		],
		"catalog_session_properties": [
			{
				"user": "admin",
				"allow": true,
			},
			{"allow": true},
		],
		"functions": [
			{
				"user": "admin",
				"privileges": [
					"EXECUTE",
					"GRANT_EXECUTE",
					"OWNERSHIP",
				],
			},
			{
				"catalog": "system",
				"schema": "builtin",
				"privileges": [
					"GRANT_EXECUTE",
					"EXECUTE",
				],
			},
		],
		"impersonation": [{"original_user": "admin"}],
		"procedures": [
			{
				"user": "admin",
				"privileges": [
					"EXECUTE",
					"GRANT_EXECUTE",
				],
			},
			{
				"catalog": "system",
				"schema": "builtin",
				"privileges": [
					"GRANT_EXECUTE",
					"EXECUTE",
				],
			},
		],
		"queries": [
			{
				"user": "admin",
				"allow": [
					"execute",
					"kill",
					"view",
				],
			},
			{"allow": [
				"execute",
				"kill",
				"view",
			]},
		],
		"schemas": [
			{
				"user": "admin",
				"owner": true,
			},
			{"owner": true},
		],
		"tables": [
			{
				"user": "admin",
				"privileges": [
					"DELETE",
					"GRANT_SELECT",
					"INSERT",
					"OWNERSHIP",
					"SELECT",
					"UPDATE",
				],
			},
			{
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
			},
		],
		"system_information": [{
			"user": "admin",
			"allow": [
				"read",
				"write",
			],
		}],
		"system_session_properties": [
			{
				"user": "admin",
				"allow": true,
			},
			{"allow": true},
		],
	}
}
