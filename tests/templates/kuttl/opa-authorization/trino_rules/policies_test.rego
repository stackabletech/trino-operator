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
		"system_information": [
			{
				"user": "graceful-shutdown-user",
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
		"system_session_properties": [{
			"user": "testuser",
			"allow": true,
		}],
	}
}

test_policies_with_no_external_policies if {
	external_policies := {}

	policies := trino.policies with data.trino_policies.policies as external_policies

	policies == {
		"authorization": [],
		"catalogs": [{"allow": "all"}],
		"catalog_session_properties": [{"allow": true}],
		"functions": [{
			"catalog": "system",
			"schema": "builtin",
			"privileges": [
				"GRANT_EXECUTE",
				"EXECUTE",
			],
		}],
		"impersonation": [],
		"procedures": [{
			"catalog": "system",
			"schema": "builtin",
			"privileges": [
				"GRANT_EXECUTE",
				"EXECUTE",
			],
		}],
		"queries": [{"allow": [
			"execute",
			"kill",
			"view",
		]}],
		"schemas": [{"owner": true}],
		"tables": [{
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
		}],
		"system_information": [{
			"user": "graceful-shutdown-user",
			"allow": [
				"read",
				"write",
			],
		}],
		"system_session_properties": [{"allow": true}],
	}
}
