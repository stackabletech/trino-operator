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
			"catalog": "secret_catalog",
			"allow": "none",
		},
		{
			"group": "some-group",
			"catalog": "example_.*",
			"allow": "all",
		},
		{
			"group": "some-group",
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
			"group": "some-group",
			"catalog": "example_.*",
			"schema": "example_.*",
			"owner": true,
		},
		{
			"schema": "archive",
			"owner": false,
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
			"group": "some-group",
			"table": "example_.*",
			"privileges": ["SELECT", "OWNERSHIP"],
			"columns": [
				{
					"name": "column1",
					"allow": true,
				},
				{
					"name": "column2",
					"allow": true,
				},
				{
					"name": "column3",
					"allow": true,
				},
				{
					"name": "secret_column",
					"allow": false,
				},
			],
		},
		{
			"group": "some-group",
			"table": "new_table_name",
			"privileges": ["OWNERSHIP"],
		},
	],
}
