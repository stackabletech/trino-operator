package trino

import data.util
import rego.v1

# The final policies are a combination of policies offered by Stackable,
# policies provided externally, and default policies.
# Stackable's policies form the beginnings of the rule lists, i.e. they
# are evaluated first and therefore cannot be overridden by the external
# policies. The external policies then follow. For each rule list which
# is not defined externally, default rules are appended.

stackable_policies := {
	"authorization": [{"original_user": "admin"}],
	"catalogs": [{
		"user": "admin",
		"allow": "all",
	}],
	"catalog_session_properties": [{
		"user": "admin",
		"allow": true,
	}],
	"functions": [{
		"user": "admin",
		"privileges": [
			"EXECUTE",
			"GRANT_EXECUTE",
			"OWNERSHIP",
		],
	}],
	"impersonation": [{"original_user": "admin"}],
	"procedures": [{
		"user": "admin",
		"privileges": [
			"EXECUTE",
			"GRANT_EXECUTE",
		],
	}],
	"queries": [{
		"user": "admin",
		"allow": [
			"execute",
			"kill",
			"view",
		],
	}],
	"schemas": [{
		"user": "admin",
		"owner": true,
	}],
	"tables": [{
		"user": "admin",
		"privileges": [
			"DELETE",
			"GRANT_SELECT",
			"INSERT",
			"OWNERSHIP",
			"SELECT",
			"UPDATE",
		],
	}],
	"system_information": [{
		"user": "admin",
		"allow": [
			"read",
			"write",
		],
	}],
	"system_session_properties": [{
		"user": "admin",
		"allow": true,
	}],
}

policies := {
	"authorization": array.concat(
		object.get(stackable_policies, "authorization", []),
		object.get(
			external_policies,
			"authorization",
			[],
		),
	),
	"catalogs": array.concat(
		object.get(stackable_policies, "catalogs", []),
		object.get(
			external_policies,
			"catalogs",
			[{"allow": "all"}],
		),
	),
	"catalog_session_properties": array.concat(
		object.get(
			stackable_policies,
			"catalog_session_properties",
			[],
		),
		object.get(
			external_policies,
			"catalog_session_properties",
			[{"allow": true}],
		),
	),
	"functions": array.concat(
		object.get(stackable_policies, "functions", []),
		object.get(
			external_policies,
			"functions",
			[{
				"catalog": "system",
				"schema": "builtin",
				"privileges": [
					"GRANT_EXECUTE",
					"EXECUTE",
				],
			}],
		),
	),
	"impersonation": array.concat(
		object.get(stackable_policies, "impersonation", []),
		object.get(
			external_policies,
			"impersonation",
			[],
		),
	),
	"procedures": array.concat(
		object.get(stackable_policies, "procedures", []),
		object.get(
			external_policies,
			"procedures",
			[{
				"catalog": "system",
				"schema": "builtin",
				"privileges": [
					"GRANT_EXECUTE",
					"EXECUTE",
				],
			}],
		),
	),
	"queries": array.concat(
		object.get(stackable_policies, "queries", []),
		object.get(
			external_policies,
			"queries",
			[{"allow": [
				"execute",
				"kill",
				"view",
			]}],
		),
	),
	"schemas": array.concat(
		object.get(stackable_policies, "schemas", []),
		object.get(
			external_policies,
			"schemas",
			[{"owner": true}],
		),
	),
	"tables": array.concat(
		object.get(stackable_policies, "tables", []),
		object.get(
			external_policies,
			"tables",
			[{
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
		),
	),
	"system_information": array.concat(
		object.get(stackable_policies, "system_information", []),
		object.get(
			external_policies,
			"system_information",
			[],
		),
	),
	"system_session_properties": array.concat(
		object.get(stackable_policies, "system_session_properties", []),
		object.get(
			external_policies,
			"system_session_properties",
			[{"allow": true}],
		),
	),
}
