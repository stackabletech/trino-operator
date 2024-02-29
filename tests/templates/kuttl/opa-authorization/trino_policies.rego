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
			"user": "select-columns",
			"catalog": "tpch",
			"allow": "read-only",
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
			"allow": ["execute", "view"],
		},
		{
			"user": "select-columns",
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
			"user": "select-columns",
			"catalog": "tpch",
			"schema": "sf1",
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
			"user": "select-columns",
			"table": "customer",
			"privileges": ["SELECT", "OWNERSHIP"],
			"columns": [
				{
					"name": "name",
					"allow": true,
				},
				{
					"name": "address",
					"allow": false,
				},
			],
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
		{
			"user": "select-columns",
			"allow": ["read", "write"],
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
}
