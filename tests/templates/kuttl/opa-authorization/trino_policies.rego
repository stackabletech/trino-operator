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
			"user": "admin",
			"allow": "all",
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
			"user": "admin",
			"allow": ["execute", "kill", "view"],
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
			"user": "admin",
			"owner": true,
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
			"user": "admin",
			"privileges": [
				"SELECT",
				"INSERT",
				"DELETE",
				"UPDATE",
				"OWNERSHIP",
				"GRANT_SELECT",
			],
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
			"privileges": ["SELECT", "INSERT", "DELETE", "OWNERSHIP"],
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
			"user": "admin",
			"allow": ["read", "write"],
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
			"user": "admin",
			"allow": true,
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
			"user": "admin",
			"allow": true,
		},
		{
			"group": "users",
			"property": "resource_overcommit",
			"allow": true,
		},
	],
	"impersonation": [
		{
			"original_user": "admin",
			"new_user": ".*",
			"allow": true,
		},
		{
			"original_user": "team_(.*)",
			"new_user": "team_$1_sandbox",
			"allow": true,
		},
	],
	"authorization": [{
		"original_user": "admin",
		"new_user": ".*",
		"allow": true,
	}],
	"functions": [{
		"user": "admin",
		"catalog": ".*",
		"schema": ".*",
		"function": ".*",
		"privileges": [
			"EXECUTE",
			"GRANT_EXECUTE",
			"OWNERSHIP",
		],
	}],
	"procedures": [{
		"user": "admin",
		"catalog": ".*",
		"schema": ".*",
		"procedure": ".*",
		"privileges": [
			"EXECUTE",
			"GRANT_EXECUTE",
		],
	}],
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
