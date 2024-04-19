package trino_policies

import rego.v1

policies := {
	"catalogs": [
		{
			"user": "banned-user",
			"allow": "none",
		},
		{
			"group": "banned-group",
			"allow": "none",
		},
		{
			"group": "users",
			"catalog": "user_.*",
			"allow": "read-only",
		},
		{
			"user": "lakehouse",
			"catalog": "lakehouse",
			"allow": "read-only",
		},
		{
			"user": "iceberg",
			"catalog": "iceberg",
			"allow": "all",
		},
	],
	"queries": [
		{
			"user": "banned-user",
			"allow": [],
		},
		{
			"group": "banned-group",
			"allow": [],
		},
		{
			"group": "users",
			"allow": ["execute", "view"],
		},
		{
			"user": "lakehouse",
			"allow": ["execute"],
		},
		{
			"user": "iceberg",
			"allow": ["execute", "view"],
		},
	],
	"schemas": [
		{
			"user": "banned-user",
			"owner": false,
		},
		{
			"group": "banned-group",
			"owner": false,
		},
		{
			"group": "users",
			"catalog": "user_.*",
			"schema": "user_.*",
			"owner": true,
		},
		{
			"user": "lakehouse",
			"catalog": "lakehouse",
			"schema": "sf1|tiny",
		},
		{
			"user": "iceberg",
			"catalog": "iceberg",
			"owner": true,
		},
	],
	"tables": [
		{
			"user": "banned-user",
			"privileges": [],
		},
		{
			"user": "banned-group",
			"privileges": [],
		},
		{
			"group": "users",
			"table": "user_.*",
			"privileges": ["SELECT", "OWNERSHIP"],
			"columns": [
				{
					"name": "public_column",
					"allow": true,
				},
				{
					"name": "secret_column",
					"allow": false,
				},
			],
		},
		{
			"user": "lakehouse",
			"catalog": "lakehouse",
			"schema": "tiny",
			"table": "customer",
			"privileges": ["SELECT"],
			"columns": [
				{
					"name": "name",
					"allow": true,
				},
				{
					"name": "custkey",
					"allow": false,
				},
				{
					"name": "address",
					"allow": false,
				},
				{
					"name": "nationkey",
					"allow": false,
				},
				{
					"name": "phone",
					"allow": false,
				},
				{
					"name": "acctbal",
					"allow": false,
				},
				{
					"name": "mktsegment",
					"allow": false,
				},
				{
					"name": "comment",
					"allow": false,
				},
			],
		},
		{
			"user": "lakehouse",
			"catalog": "lakehouse",
			"schema": "sf1",
			"table": "customer",
			"privileges": ["SELECT"],
		},
		{
			"user": "iceberg",
			"catalog": "iceberg",
			"table": "test",
			"privileges": ["SELECT", "INSERT", "DELETE", "OWNERSHIP"],
			"filter": "test BETWEEN 2 AND 4",
			"filterEnvironment": {"user": "admin"},
		},
		{
			"user": "iceberg",
			"catalog": "iceberg",
			"table": "test_square",
			"privileges": ["SELECT", "OWNERSHIP"],
			"columns": [{
				"name": "test",
				"mask": "CAST(POWER(test, 2) AS bigint)",
				"mask_environment": {"user": "admin"},
			}],
		},
	],
	"system_information": [
		{
			"user": "banned-user",
			"allow": [],
		},
		{
			"group": "banned-group",
			"allow": [],
		},
		{
			"group": "users",
			"allow": ["read"],
		},
	],
	"catalog_session_properties": [
		{
			"user": "banned-user",
			"allow": false,
		},
		{
			"group": "banned-group",
			"allow": false,
		},
		{
			"group": "users",
			"catalog": "user_.*",
			"property": "bucket_execution_enabled",
			"allow": true,
		},
	],
	"system_session_properties": [
		{
			"user": "banned-user",
			"allow": false,
		},
		{
			"group": "banned-group",
			"allow": false,
		},
		{
			"group": "users",
			"property": "resource_overcommit",
			"allow": true,
		},
	],
	"impersonation": [
		{
			"original_user": "team_(.*)",
			"new_user": "team_$1_sandbox",
			"allow": true,
		},
	],
}

extra_groups := groups if {
	request := {
		"method": "POST",
		"url": "http://127.0.0.1:9476/user",
		"headers": {"Content-Type": "application/json"},
		"body": {"username": input.context.identity.user},
	}
	response := http.send(request)

	response.status_code == 200

	groups := response.body.groups
}
