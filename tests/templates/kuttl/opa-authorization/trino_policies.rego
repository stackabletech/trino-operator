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
}
